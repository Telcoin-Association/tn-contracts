// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ERC1967Utils } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import { Stablecoin } from "../../src/testnet/Stablecoin.sol";
import { Blacklist } from "../../src/testnet/Blacklist.sol";
import { IShieldedStablecoin } from "../../src/shield/IShieldedStablecoin.sol";
import { ShieldPrecompileSelectors } from "../../src/shield/ShieldPrecompileSelectors.sol";
import { ShieldVault } from "../../src/shield/ShieldVault.sol";

/// @title ShieldVaultTest
/// @notice Wave-3 unit suite for `ShieldVault` against the real `Stablecoin` (no token mock)
///         behind an `ERC1967Proxy`; only the precompile leg is mocked (`vm.mockCall` /
///         `vm.mockCallRevert`, StablecoinManager.t.sol pattern) on top of the real genesis
///         state of the precompile account, a single `0xfe` (INVALID) byte, so an un-mocked call
///         halts exactly as a precompile refusal does instead of being absorbed by a codeless
///         account.
/// @notice Coverage areas:
///         - **Selector parity:** every hardcoded `ShieldPrecompileSelectors` constant equals
///           `bytes4(keccak256(signature))` recomputed here from the exact TN-SHIELD v1 signatures,
///           and equals the selector the typed `IShieldedStablecoin` mirror produces; the vault's
///           `abi.encodeCall` calldata is byte-identical to the selector-library encoding.
///         - **shield/unshield happy paths:** burn leg + exact precompile calldata; mint to the
///           precompile-returned recipient.
///         - **Compliance:** a blacklisted user's `shield` reverts atomically in `burnFrom`'s
///           `_update` hook; an `unshield` whose proven recipient is blacklisted reverts the WHOLE
///           transaction in `mintTo`'s `_update` hook - no balance or supply change either way.
///         - **Allowance prerequisite:** `Stablecoin.burnFrom` spends the vault's allowance even
///           though the vault holds BURNER_ROLE, so `shield` without a prior
///           `approve(vault, amount)` reverts with the token's allowance error; with exact
///           allowance it succeeds and consumes it.
///         - **Pause:** `pause` gates both `shield` and `unshield`; `unpause` restores; both are
///           owner-only.
///         - **Ownership:** `transferOwnership` only nominates and the nominee must accept;
///           `renounceOwnership` reverts for everyone, so a paused vault can never be orphaned.
///         - **Upgrade auth:** non-owner `upgradeToAndCall` reverts; owner upgrade succeeds and
///           preserves the ERC-7201 namespaced storage (token pointer, owner, paused flag).
///         - **ERC-7201 slot:** the slot constant equals the formula applied to the annotated
///           namespace id and is the slot the proxy really writes the token pointer into.
///         - **Precompile-failure propagation:** per the frozen error idiom, precompile failures
///           are frame halts with EMPTY returndata - the vault surfaces `LowLevelCallFailure`
///           carrying empty bytes and the revert restores all token pre-state.
///         - **Precompile liveness:** while the precompile account has no code, `shield` and
///           `unshield` revert with `PrecompileNotLive` instead of burning into a codeless CALL.
///         - **Gas on refusal (accepted behavior):** an un-mocked call hits the 0xfe byte and
///           halts; the vault reverts atomically and the halt consumes the default all-but-1/64
///           forwarded gas (no stipend until the node's charges are calibrated).
///         - **Token binding:** `unshield` requires a `PV_LEN`-byte blob whose token field is the
///           vault's own token, so a T-bound proof through a T2 vault (the registry re-point case)
///           reverts before the precompile leg instead of minting T2.
///         - **Malformed unshield returndata:** returndata other than exactly 64 bytes (too short
///           or too long) makes the vault revert; no mint happens.
///         - **Implementation lock:** `initialize` on the bare implementation reverts
///           (`_disableInitializers` in the constructor), so only a proxy can ever be initialized.
///         - **Fuzz:** shield amount over (0, type(uint128).max] with allowance == amount - the
///           burn leg and the precompile calldata encoding are exact for every input
///           (`vm.expectCall` with computed calldata).
///         - **Events:** `shield` emits `Shielded(from, ownerAddr, amount)` once the precompile leg
///           succeeded and `unshield` emits `Unshielded(recipient, amount)` after the mint.
contract ShieldVaultTest is Test {
    ShieldVault vaultImpl;
    ShieldVault vault;
    Stablecoin token;
    address precompile;

    // stands in for the governance safe as vault owner
    address governance = address(0x7A0);
    address user = address(0xBEEF);
    address blacklister = address(0xB1AC);

    // shared shield-note constants (arbitrary fixed values)
    bytes32 internal constant OWNER_ADDR = keccak256("shielded owner address");
    bytes32 internal constant SALT = keccak256("note salt");

    function setUp() public {
        token = new Stablecoin();
        token.initialize("Telcoin eUSD", "eUSD", 6);

        vaultImpl = new ShieldVault();
        bytes memory initCall = abi.encodeWithSelector(ShieldVault.initialize.selector, address(token), governance);
        vault = ShieldVault(address(new ERC1967Proxy(address(vaultImpl), initCall)));
        precompile = vault.PRECOMPILE();
        // the real chain state: genesis gives the precompile account one 0xfe (INVALID) byte, so
        // any call that no mock intercepts halts with empty returndata like a precompile refusal
        vm.etch(precompile, hex"fe");

        // the vault operationally holds both supply roles on its token (granted by the token
        // admin out-of-band on the real chain)
        token.grantRole(token.MINTER_ROLE(), address(vault));
        token.grantRole(token.BURNER_ROLE(), address(vault));

        // this test contract holds DEFAULT_ADMIN_ROLE (granted to `Stablecoin.initialize`'s
        // caller); give it MINTER_ROLE to seed user balances and a compliance officer the
        // BLACKLISTER_ROLE
        token.grantRole(token.MINTER_ROLE(), address(this));
        token.grantRole(token.BLACKLISTER_ROLE(), blacklister);
    }

    // -------------
    // helpers
    // -------------

    /// @dev Exact calldata the vault must send for `shield` (asserted via `vm.expectCall`).
    function _shieldCalldata(uint128 amount, bytes32 ownerAddr, bytes32 salt) internal view returns (bytes memory) {
        return abi.encodeWithSelector(ShieldPrecompileSelectors.SHIELD, address(token), ownerAddr, salt, amount);
    }

    /// @dev Exact calldata the vault must send for `unshield`.
    function _unshieldCalldata(bytes memory proof, bytes memory publicValues) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(ShieldPrecompileSelectors.UNSHIELD, proof, publicValues);
    }

    /// @dev A TNEP §4.8 public-values blob (1192 bytes) bound to `token_`: version 1, op unshield
    ///      (0x03), the token at offset 10; every other field zero (opaque to the vault). The
    ///      length and offset are written out here so the test pins the vault's constants
    ///      independently.
    function _publicValues(address token_) internal pure returns (bytes memory pv) {
        pv = new bytes(1192);
        pv[0] = 0x01;
        pv[1] = 0x03;
        bytes20 t = bytes20(token_);
        for (uint256 i = 0; i < 20; ++i) {
            pv[10 + i] = t[i];
        }
    }

    /// @dev Seeds `user` with `amount` and sets the burnFrom-prerequisite allowance for the vault.
    function _mintAndApprove(uint128 amount) internal {
        token.mintTo(user, amount);
        vm.prank(user);
        token.approve(address(vault), amount);
    }

    // -------------
    // selector parity
    // -------------

    /// @dev Each hardcoded selector must equal `bytes4(keccak256(signature))` for the exact
    ///      TN-SHIELD v1 precompile signature (the node's `sol!` block is the source of truth).
    function testSelectorParity() public pure {
        assertEq(ShieldPrecompileSelectors.SHIELD, bytes4(keccak256("shield(address,bytes32,bytes32,uint128)")));
        assertEq(ShieldPrecompileSelectors.UNSHIELD, bytes4(keccak256("unshield(bytes,bytes)")));
        assertEq(ShieldPrecompileSelectors.TRANSFER, bytes4(keccak256("transfer(bytes,bytes)")));
        assertEq(ShieldPrecompileSelectors.APPROVE, bytes4(keccak256("approve(bytes,bytes)")));
        assertEq(ShieldPrecompileSelectors.TRANSFER_FROM, bytes4(keccak256("transferFrom(bytes,bytes)")));
        assertEq(ShieldPrecompileSelectors.RECLAIM, bytes4(keccak256("reclaim(bytes,bytes)")));
        assertEq(
            ShieldPrecompileSelectors.SET_TOKEN_CONFIG, bytes4(keccak256("setTokenConfig(address,address,bytes32)"))
        );
        assertEq(ShieldPrecompileSelectors.ROOT, bytes4(keccak256("root()")));
        assertEq(ShieldPrecompileSelectors.IS_KNOWN_ROOT, bytes4(keccak256("isKnownRoot(bytes32)")));
        assertEq(ShieldPrecompileSelectors.IS_SPENT, bytes4(keccak256("isSpent(bytes32)")));
        assertEq(ShieldPrecompileSelectors.NEXT_INDEX, bytes4(keccak256("nextIndex()")));
        assertEq(ShieldPrecompileSelectors.TOTAL_SHIELDED, bytes4(keccak256("totalShielded(address)")));
        assertEq(ShieldPrecompileSelectors.TOKEN_CONFIG, bytes4(keccak256("tokenConfig(address)")));
    }

    /// @dev The typed `IShieldedStablecoin` mirror must produce exactly the selectors the library
    ///      pins: a parameter type or order drift in the interface changes the selector and fails
    ///      here, so the interface cannot silently diverge from the node's `sol!` block.
    function testInterfaceSelectorParity() public pure {
        assertEq(IShieldedStablecoin.shield.selector, ShieldPrecompileSelectors.SHIELD);
        assertEq(IShieldedStablecoin.unshield.selector, ShieldPrecompileSelectors.UNSHIELD);
        assertEq(IShieldedStablecoin.transfer.selector, ShieldPrecompileSelectors.TRANSFER);
        assertEq(IShieldedStablecoin.approve.selector, ShieldPrecompileSelectors.APPROVE);
        assertEq(IShieldedStablecoin.transferFrom.selector, ShieldPrecompileSelectors.TRANSFER_FROM);
        assertEq(IShieldedStablecoin.reclaim.selector, ShieldPrecompileSelectors.RECLAIM);
        assertEq(IShieldedStablecoin.setTokenConfig.selector, ShieldPrecompileSelectors.SET_TOKEN_CONFIG);
        assertEq(IShieldedStablecoin.root.selector, ShieldPrecompileSelectors.ROOT);
        assertEq(IShieldedStablecoin.isKnownRoot.selector, ShieldPrecompileSelectors.IS_KNOWN_ROOT);
        assertEq(IShieldedStablecoin.isSpent.selector, ShieldPrecompileSelectors.IS_SPENT);
        assertEq(IShieldedStablecoin.nextIndex.selector, ShieldPrecompileSelectors.NEXT_INDEX);
        assertEq(IShieldedStablecoin.totalShielded.selector, ShieldPrecompileSelectors.TOTAL_SHIELDED);
        assertEq(IShieldedStablecoin.tokenConfig.selector, ShieldPrecompileSelectors.TOKEN_CONFIG);
    }

    /// @dev The vault encodes with `abi.encodeCall` against the typed interface; the expected
    ///      calldata in this suite is built with `abi.encodeWithSelector` against the selector
    ///      library. The two must be byte-identical or every `vm.expectCall` below would miss.
    function testEncodeCallMatchesSelectorEncoding() public view {
        uint128 amount = 1_000_000;
        assertEq(
            abi.encodeCall(IShieldedStablecoin.shield, (address(token), OWNER_ADDR, SALT, amount)),
            _shieldCalldata(amount, OWNER_ADDR, SALT),
            "shield calldata must be byte-identical across encoders"
        );
        bytes memory proof = hex"1234";
        bytes memory publicValues = _publicValues(address(token));
        assertEq(
            abi.encodeCall(IShieldedStablecoin.unshield, (proof, publicValues)),
            _unshieldCalldata(proof, publicValues),
            "unshield calldata must be byte-identical across encoders"
        );
    }

    // -------------
    // shield / unshield happy paths (precompile leg mocked)
    // -------------

    function testShieldHappyPath() public {
        uint128 amount = 1_000_000; // 1.0 eUSD at 6 decimals
        _mintAndApprove(amount);

        bytes memory precompileCalldata = _shieldCalldata(amount, OWNER_ADDR, SALT);
        vm.mockCall(precompile, precompileCalldata, abi.encode());

        // the burn leg, then the precompile leg with exact calldata, then the vault's own event
        vm.expectCall(address(token), abi.encodeWithSelector(Stablecoin.burnFrom.selector, user, uint256(amount)));
        vm.expectCall(precompile, precompileCalldata);
        vm.expectEmit(true, true, true, true, address(vault));
        emit ShieldVault.Shielded(user, OWNER_ADDR, amount);

        vm.prank(user);
        vault.shield(amount, OWNER_ADDR, SALT);

        assertEq(token.balanceOf(user), 0, "shield should burn the user's public balance");
        assertEq(token.totalSupply(), 0, "shield should reduce public supply");
        assertEq(token.allowance(user, address(vault)), 0, "shield should spend the vault's allowance");
    }

    function testUnshieldHappyPath() public {
        address recipient = address(0xCAFE);
        uint128 amount = 5_000_000;
        // proof + public values are opaque to the vault; the mocked precompile "verifies" them
        bytes memory proof = hex"1234";
        bytes memory publicValues = _publicValues(address(token));

        bytes memory precompileCalldata = _unshieldCalldata(proof, publicValues);
        vm.mockCall(precompile, precompileCalldata, abi.encode(recipient, amount));
        vm.expectCall(precompile, precompileCalldata);
        vm.expectEmit(true, true, true, true, address(vault));
        emit ShieldVault.Unshielded(recipient, amount);

        // relayable: any caller may submit the proof
        vm.prank(user);
        vault.unshield(proof, publicValues);

        assertEq(token.balanceOf(recipient), amount, "unshield should mint the proven amount to the recipient");
        assertEq(token.totalSupply(), amount, "unshield should restore public supply");
    }

    // -------------
    // compliance: blacklist reverts are atomic
    // -------------

    /// @dev A BLACKLISTER-blacklisted user cannot shield: `burnFrom` hits `Stablecoin._update`'s
    ///      `Blacklisted(from)` check and the whole call reverts before the precompile leg runs.
    function testShieldRevertsForBlacklistedUser() public {
        uint128 amount = 1_000_000;
        _mintAndApprove(amount);

        // blacklisting sweeps the user's balance to the blacklister (`_onceBlacklisted`) BEFORE
        // the flag is set, then blocks the user in `_update`
        vm.prank(blacklister);
        token.addBlackList(user);
        assertEq(token.balanceOf(user), 0, "blacklisting sweeps the user's balance");
        assertEq(token.balanceOf(blacklister), amount, "sweep target is the blacklister");

        uint256 supplyBefore = token.totalSupply();

        // the precompile leg must never run
        vm.expectCall(precompile, _shieldCalldata(amount, OWNER_ADDR, SALT), 0);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Blacklist.Blacklisted.selector, user));
        vault.shield(amount, OWNER_ADDR, SALT);

        // atomic: no balance, supply, or allowance movement from the failed shield
        assertEq(token.totalSupply(), supplyBefore, "reverted shield must not change supply");
        assertEq(token.balanceOf(user), 0, "reverted shield must not change the user's balance");
        assertEq(token.balanceOf(blacklister), amount, "reverted shield must not change the blacklister's balance");
        assertEq(token.allowance(user, address(vault)), amount, "reverted shield must not consume allowance");
    }

    /// @dev An unshield whose proven recipient is blacklisted reverts the WHOLE transaction:
    ///      the precompile leg "succeeds" (mocked) but `mintTo` hits `_update`'s `Blacklisted(to)`
    ///      check, rolling everything back - the shielded note stays spendable elsewhere.
    function testUnshieldRevertsForBlacklistedRecipient() public {
        address recipient = address(0xBADD);
        uint128 amount = 5_000_000;

        vm.prank(blacklister);
        token.addBlackList(recipient);

        bytes memory proof = hex"1234";
        bytes memory publicValues = _publicValues(address(token));
        vm.mockCall(precompile, _unshieldCalldata(proof, publicValues), abi.encode(recipient, amount));

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Blacklist.Blacklisted.selector, recipient));
        vault.unshield(proof, publicValues);

        // the whole tx reverted: no mint, no supply change
        assertEq(token.totalSupply(), 0, "reverted unshield must not mint");
        assertEq(token.balanceOf(recipient), 0, "blacklisted recipient must receive nothing");
    }

    // -------------
    // allowance prerequisite (Stablecoin.burnFrom spends allowance despite BURNER_ROLE)
    // -------------

    /// @dev Without a prior `approve(vault, amount)`, `shield` reverts with the token's own
    ///      allowance error even though the vault holds BURNER_ROLE.
    function testShieldWithoutAllowanceReverts() public {
        uint128 amount = 1_000_000;
        token.mintTo(user, amount); // deliberately NO approve

        // the precompile leg must never run
        vm.expectCall(precompile, _shieldCalldata(amount, OWNER_ADDR, SALT), 0);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, address(vault), 0, uint256(amount))
        );
        vault.shield(amount, OWNER_ADDR, SALT);

        assertEq(token.balanceOf(user), amount, "burn must not happen without allowance");
        assertEq(token.totalSupply(), amount, "supply must be unchanged without allowance");
    }

    /// @dev With exact allowance the shield succeeds and the allowance is fully consumed.
    function testShieldWithExactAllowanceSucceedsAndConsumesIt() public {
        uint128 amount = 1_000_000;
        _mintAndApprove(amount);
        assertEq(token.allowance(user, address(vault)), amount, "exact allowance set");

        bytes memory precompileCalldata = _shieldCalldata(amount, OWNER_ADDR, SALT);
        vm.mockCall(precompile, precompileCalldata, abi.encode());
        vm.expectCall(precompile, precompileCalldata);

        vm.prank(user);
        vault.shield(amount, OWNER_ADDR, SALT);

        assertEq(token.allowance(user, address(vault)), 0, "exact allowance fully consumed");
        assertEq(token.balanceOf(user), 0, "shield burned the approved amount");
    }

    // -------------
    // pause gating
    // -------------

    function testPausedShieldReverts() public {
        uint128 amount = 1_000_000;
        _mintAndApprove(amount);

        vm.prank(governance);
        vault.pause();
        assertTrue(vault.paused(), "vault should be paused");

        vm.prank(user);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        vault.shield(amount, OWNER_ADDR, SALT);

        assertEq(token.balanceOf(user), amount, "paused shield must not burn");
    }

    function testPausedUnshieldReverts() public {
        vm.prank(governance);
        vault.pause();

        vm.prank(user);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        vault.unshield(hex"1234", _publicValues(address(token)));

        assertEq(token.totalSupply(), 0, "paused unshield must not mint");
    }

    /// @dev `unpause` restores both entrypoints end-to-end.
    function testUnpauseRestoresShieldAndUnshield() public {
        uint128 amount = 1_000_000;
        _mintAndApprove(amount);

        vm.prank(governance);
        vault.pause();
        vm.prank(governance);
        vault.unpause();
        assertFalse(vault.paused(), "vault should be unpaused");

        // shield works again
        bytes memory shieldCd = _shieldCalldata(amount, OWNER_ADDR, SALT);
        vm.mockCall(precompile, shieldCd, abi.encode());
        vm.prank(user);
        vault.shield(amount, OWNER_ADDR, SALT);
        assertEq(token.balanceOf(user), 0, "shield should work after unpause");

        // unshield works again
        address recipient = address(0xCAFE);
        bytes memory proof = hex"aaaa";
        bytes memory publicValues = _publicValues(address(token));
        vm.mockCall(precompile, _unshieldCalldata(proof, publicValues), abi.encode(recipient, amount));
        vm.prank(user);
        vault.unshield(proof, publicValues);
        assertEq(token.balanceOf(recipient), amount, "unshield should work after unpause");
    }

    function testPauseOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vault.pause();
        assertFalse(vault.paused(), "non-owner pause must not take effect");
    }

    function testUnpauseOnlyOwner() public {
        vm.prank(governance);
        vault.pause();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vault.unpause();
        assertTrue(vault.paused(), "non-owner unpause must not take effect");
    }

    // -------------
    // ownership: two-step transfer, no renounce
    // -------------

    /// @dev `transferOwnership` only nominates: the owner stays until the nominee accepts, and a
    ///      non-nominee cannot accept, so a mistyped address cannot take the vault from governance.
    function testOwnershipTransferIsTwoStep() public {
        address newGovernance = address(0x7A1);

        vm.prank(governance);
        vault.transferOwnership(newGovernance);
        assertEq(vault.owner(), governance, "owner unchanged until acceptance");
        assertEq(vault.pendingOwner(), newGovernance, "nominee recorded");

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vault.acceptOwnership();

        vm.prank(newGovernance);
        vault.acceptOwnership();
        assertEq(vault.owner(), newGovernance, "nominee owns after accepting");
        assertEq(vault.pendingOwner(), address(0), "nomination cleared");

        // the old owner lost the gate and the new one holds it
        vm.prank(governance);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, governance));
        vault.pause();
        vm.prank(newGovernance);
        vault.pause();
        assertTrue(vault.paused(), "new owner can pause");
    }

    /// @dev Renouncing would orphan the vault (a paused vault could never be unpaused or
    ///      upgraded); it reverts for the owner and everyone else and the vault stays operable.
    function testRenounceOwnershipReverts() public {
        vm.prank(governance);
        vault.pause();

        vm.prank(governance);
        vm.expectRevert(ShieldVault.OwnershipNotRenounceable.selector);
        vault.renounceOwnership();
        vm.prank(user);
        vm.expectRevert(ShieldVault.OwnershipNotRenounceable.selector);
        vault.renounceOwnership();

        assertEq(vault.owner(), governance, "vault still owned");
        vm.prank(governance);
        vault.unpause();
        assertFalse(vault.paused(), "vault still operable");
    }

    // -------------
    // upgrade authorization (_authorizeUpgrade is onlyOwner)
    // -------------

    function testUpgradeNonOwnerReverts() public {
        ShieldVaultV2Harness v2Impl = new ShieldVaultV2Harness();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vault.upgradeToAndCall(address(v2Impl), "");

        assertEq(
            vm.load(address(vault), ERC1967Utils.IMPLEMENTATION_SLOT),
            bytes32(uint256(uint160(address(vaultImpl)))),
            "failed upgrade must leave the implementation slot untouched"
        );
    }

    /// @dev Owner upgrade rotates the ERC-1967 implementation slot and preserves every ERC-7201
    ///      namespaced storage family: the vault's token pointer, the owner, and the paused flag.
    function testUpgradeByOwnerPreservesErc7201Storage() public {
        // put nontrivial state in the pausable namespace so preservation is observable
        vm.prank(governance);
        vault.pause();

        ShieldVaultV2Harness v2Impl = new ShieldVaultV2Harness();
        vm.prank(governance);
        vault.upgradeToAndCall(address(v2Impl), "");

        // implementation slot rotated to the new implementation
        assertEq(
            vm.load(address(vault), ERC1967Utils.IMPLEMENTATION_SLOT),
            bytes32(uint256(uint160(address(v2Impl)))),
            "upgrade must rotate the ERC-1967 implementation slot"
        );
        // new code is live behind the proxy
        assertEq(ShieldVaultV2Harness(address(vault)).shieldVaultVersion(), 2, "V2 code should answer via the proxy");
        // ERC-7201 storage survives the upgrade
        assertEq(address(vault.token()), address(token), "token pointer must survive the upgrade");
        assertEq(vault.owner(), governance, "owner must survive the upgrade");
        assertTrue(vault.paused(), "paused flag must survive the upgrade");

        // and the surviving token pointer still drives a functional shield
        vm.prank(governance);
        vault.unpause();
        uint128 amount = 1_000_000;
        _mintAndApprove(amount);
        bytes memory precompileCalldata = _shieldCalldata(amount, OWNER_ADDR, SALT);
        vm.mockCall(precompile, precompileCalldata, abi.encode());
        vm.expectCall(precompile, precompileCalldata);
        vm.prank(user);
        vault.shield(amount, OWNER_ADDR, SALT);
        assertEq(token.balanceOf(user), 0, "post-upgrade shield should burn against the preserved token");
    }

    // -------------
    // ERC-7201 storage slot
    // -------------

    /// @dev The slot constant must be the ERC-7201 slot of the annotated namespace id
    ///      `telcoin.storage.ShieldVault` (not an `erc7201.`-prefixed string), so upgrade tooling
    ///      that derives the slot from the annotation agrees with the code, and it must be the slot
    ///      the proxy really writes the token pointer into.
    function testErc7201SlotMatchesAnnotatedNamespace() public {
        bytes32 expected =
            keccak256(abi.encode(uint256(keccak256("telcoin.storage.ShieldVault")) - 1)) & ~bytes32(uint256(0xff));
        bytes32 slot = new ShieldVaultV2Harness().storageSlot();
        assertEq(slot, expected, "slot constant must derive from the annotated namespace id");
        assertEq(
            vm.load(address(vault), slot),
            bytes32(uint256(uint160(address(token)))),
            "the proxy must store the token pointer in that slot"
        );
    }

    // -------------
    // precompile liveness (a CALL to a codeless account succeeds, so the vault checks for code)
    // -------------

    /// @dev Without the guard a `shield` against a codeless precompile would "succeed" and burn
    ///      with no note ever created; both entrypoints refuse instead, leaving all token state
    ///      untouched.
    function testShieldAndUnshieldRefuseCodelessPrecompile() public {
        vm.etch(precompile, "");
        assertEq(precompile.code.length, 0, "precompile account emptied");
        uint128 amount = 1_000_000;
        _mintAndApprove(amount);

        vm.prank(user);
        vm.expectRevert(ShieldVault.PrecompileNotLive.selector);
        vault.shield(amount, OWNER_ADDR, SALT);
        assertEq(token.balanceOf(user), amount, "no burn into a codeless precompile");
        assertEq(token.totalSupply(), amount, "supply untouched");
        assertEq(token.allowance(user, address(vault)), amount, "allowance untouched");

        vm.prank(user);
        vm.expectRevert(ShieldVault.PrecompileNotLive.selector);
        vault.unshield(hex"1234", _publicValues(address(token)));
        assertEq(token.totalSupply(), amount, "no mint either");
    }

    // -------------
    // precompile-failure propagation (frozen error idiom: frame halts carry EMPTY returndata)
    // -------------

    /// @dev A failing precompile `shield` surfaces as `LowLevelCallFailure` carrying EMPTY bytes
    ///      (never a decodable reason) and the revert restores the burned balance atomically.
    function testShieldPrecompileFailureRevertsWithEmptyReturndata() public {
        uint128 amount = 1_000_000;
        _mintAndApprove(amount);

        // frozen error idiom: precompile failures halt the frame with EMPTY returndata
        vm.mockCallRevert(precompile, _shieldCalldata(amount, OWNER_ADDR, SALT), "");

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ShieldVault.LowLevelCallFailure.selector, bytes("")));
        vault.shield(amount, OWNER_ADDR, SALT);

        // the burn leg rolled back with the revert: full pre-state restored
        assertEq(token.balanceOf(user), amount, "failed shield must restore the user's burned balance");
        assertEq(token.totalSupply(), amount, "failed shield must restore supply");
        assertEq(token.allowance(user, address(vault)), amount, "failed shield must restore the allowance");
    }

    /// @dev A failing precompile `unshield` surfaces the same empty-bytes `LowLevelCallFailure`
    ///      and no mint happens.
    function testUnshieldPrecompileFailureRevertsWithEmptyReturndata() public {
        bytes memory proof = hex"1234";
        bytes memory publicValues = _publicValues(address(token));
        vm.mockCallRevert(precompile, _unshieldCalldata(proof, publicValues), "");

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ShieldVault.LowLevelCallFailure.selector, bytes("")));
        vault.unshield(proof, publicValues);

        assertEq(token.totalSupply(), 0, "failed unshield must not mint");
    }

    /// @dev Pins the accepted gas behavior (TNEP §4.17): with the genesis 0xfe byte and no mock
    ///      the call halts, the vault reverts `LowLevelCallFailure("")` with the burn rolled back,
    ///      and the halt consumes the default all-but-1/64 forwarded gas. A fixed stipend is
    ///      deferred until the node's per-selector charges are calibrated.
    function testShieldRefusalHaltsAndConsumesForwardedGas() public {
        uint128 amount = 1_000_000;
        _mintAndApprove(amount);

        uint256 budget = 2_000_000;
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ShieldVault.LowLevelCallFailure.selector, bytes("")));
        vault.shield{ gas: budget }(amount, OWNER_ADDR, SALT);
        assertEq(token.balanceOf(user), amount, "burn rolled back");

        // how much of the same budget does the refused shield consume?
        vm.prank(user);
        uint256 gasBefore = gasleft();
        try vault.shield{ gas: budget }(amount, OWNER_ADDR, SALT) { } catch { }
        uint256 used = gasBefore - gasleft();
        assertGt(used, budget * 60 / 64, "a halt consumes nearly everything forwarded");
        assertEq(token.balanceOf(user), amount, "second attempt rolled back too");
    }

    // -------------
    // malformed unshield returndata
    // -------------

    /// @dev Precompile returndata other than exactly `abi.encode(address, uint128)` (64 bytes)
    ///      makes the vault revert with `MalformedReturndata` (TNEP §4.11: mint only when
    ///      `returndata.length == 64`); no mint happens in either direction.
    function testUnshieldMalformedReturndataReverts() public {
        bytes memory publicValues = _publicValues(address(token));

        // round 1: junk bytes far too short for any head
        bytes memory proof1 = hex"aa";
        vm.mockCall(precompile, _unshieldCalldata(proof1, publicValues), hex"1234");

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ShieldVault.MalformedReturndata.selector, 2));
        vault.unshield(proof1, publicValues);

        // round 2: one valid word (the recipient) but the amount word missing
        bytes memory proof2 = hex"cc";
        vm.mockCall(precompile, _unshieldCalldata(proof2, publicValues), abi.encode(address(0xCAFE)));

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ShieldVault.MalformedReturndata.selector, 32));
        vault.unshield(proof2, publicValues);

        // round 3: a well-formed pair followed by an extra word (a future layout the vault was
        // not written for) - `abi.decode` alone would have accepted it
        bytes memory proof3 = hex"ee";
        vm.mockCall(
            precompile,
            _unshieldCalldata(proof3, publicValues),
            abi.encode(address(0xCAFE), uint128(5), uint256(0xdead))
        );

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ShieldVault.MalformedReturndata.selector, 96));
        vault.unshield(proof3, publicValues);

        assertEq(token.totalSupply(), 0, "malformed returndata must not mint");
        assertEq(token.balanceOf(address(0xCAFE)), 0, "malformed returndata must not mint to the decoded word");
    }

    // -------------
    // token binding: unshield mints only against a proof bound to this vault's token
    // -------------

    /// @dev A registry re-point (`setTokenConfig(T, V2, k)`) lets a T-bound proof reach a vault
    ///      whose token is T2; the vault binds the mint to the proof's token field (TNEP §4.8,
    ///      offset 10) and reverts before the precompile leg instead of minting T2.
    function testUnshieldRejectsProofBoundToAnotherToken() public {
        // a second token T2 with its own vault V2
        Stablecoin t2 = new Stablecoin();
        t2.initialize("Telcoin eABC", "eABC", 6);
        ShieldVault v2 = ShieldVault(
            address(
                new ERC1967Proxy(
                    address(vaultImpl), abi.encodeWithSelector(ShieldVault.initialize.selector, address(t2), governance)
                )
            )
        );
        t2.grantRole(t2.MINTER_ROLE(), address(v2));
        t2.grantRole(t2.BURNER_ROLE(), address(v2));

        bytes memory proof = hex"1234";
        bytes memory publicValues = _publicValues(address(token)); // bound to T, not T2
        bytes memory precompileCalldata = _unshieldCalldata(proof, publicValues);
        // even a cooperative precompile answer must never reach the mint: the leg is not called
        vm.mockCall(precompile, precompileCalldata, abi.encode(address(0xCAFE), uint128(7_000_000)));
        vm.expectCall(precompile, precompileCalldata, 0);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ShieldVault.TokenMismatch.selector, address(token), address(t2)));
        v2.unshield(proof, publicValues);

        assertEq(t2.totalSupply(), 0, "V2 must not mint T2 against a T-bound proof");
        assertEq(token.totalSupply(), 0, "nothing was minted as T either");
    }

    /// @dev The blob must be exactly `PV_LEN` (1192) bytes: the token offset is only meaningful
    ///      inside the frozen v1 layout, so any other length is rejected before the precompile leg.
    function testUnshieldRejectsWrongLengthPublicValues() public {
        bytes memory proof = hex"1234";

        bytes memory tooShort = hex"5678";
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ShieldVault.PublicValuesLength.selector, 2));
        vault.unshield(proof, tooShort);

        bytes memory tooLong = bytes.concat(_publicValues(address(token)), hex"00");
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ShieldVault.PublicValuesLength.selector, 1193));
        vault.unshield(proof, tooLong);

        assertEq(token.totalSupply(), 0, "a rejected blob must not mint");
    }

    // -------------
    // zero-amount shield
    // -------------

    function testShieldZeroAmountReverts() public {
        vm.prank(user);
        vm.expectRevert(ShieldVault.ZeroAmount.selector);
        vault.shield(0, OWNER_ADDR, SALT);
    }

    // -------------
    // initializer
    // -------------

    function testInitializeZeroTokenReverts() public {
        bytes memory initCall = abi.encodeWithSelector(ShieldVault.initialize.selector, address(0), governance);
        vm.expectRevert(ShieldVault.ZeroAddress.selector);
        new ERC1967Proxy(address(vaultImpl), initCall);
    }

    function testReinitializeReverts() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        vault.initialize(address(token), user);
    }

    /// @dev The bare implementation is locked by its constructor (`_disableInitializers`): only a
    ///      proxy can ever run `initialize`, so nobody can claim ownership of the implementation.
    function testImplementationInitializeReverts() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        vaultImpl.initialize(address(token), user);
        assertEq(vaultImpl.owner(), address(0), "locked implementation must have no owner");

        // a freshly deployed implementation is locked the same way
        ShieldVault fresh = new ShieldVault();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        fresh.initialize(address(token), user);
    }

    // -------------
    // fuzz: exact burn + precompile calldata encoding over the full u128 domain
    // -------------

    /// @dev For every amount in (0, type(uint128).max] with allowance == amount, the burn leg and
    ///      the precompile calldata encoding are byte-exact. If the vault's encoding ever drifted,
    ///      the mock would not match, the call would hit the account's 0xfe byte and halt, and the
    ///      shield would revert with `LowLevelCallFailure` (and the exact-calldata `vm.expectCall`
    ///      would fail the run).
    function testFuzzShieldBurnAndPrecompileEncoding(uint128 amountSeed, bytes32 ownerAddr, bytes32 salt) public {
        uint128 amount = uint128(bound(uint256(amountSeed), 1, type(uint128).max));

        token.mintTo(user, amount);
        vm.prank(user);
        token.approve(address(vault), amount);

        bytes memory precompileCalldata = _shieldCalldata(amount, ownerAddr, salt);
        vm.mockCall(precompile, precompileCalldata, abi.encode());

        vm.expectCall(address(token), abi.encodeWithSelector(Stablecoin.burnFrom.selector, user, uint256(amount)));
        vm.expectCall(precompile, precompileCalldata);

        vm.prank(user);
        vault.shield(amount, ownerAddr, salt);

        assertEq(token.balanceOf(user), 0, "fuzzed shield should burn the full amount");
        assertEq(token.totalSupply(), 0, "fuzzed shield should reduce supply to zero");
        assertEq(token.allowance(user, address(vault)), 0, "fuzzed shield should consume the exact allowance");
    }
}

/// @dev Upgrade-target harness: `ShieldVault` plus a version marker so tests can prove the new
///      implementation is live behind the proxy after `upgradeToAndCall`. Adds NO storage, so the
///      ERC-7201 layout is unchanged.
contract ShieldVaultV2Harness is ShieldVault {
    /// @notice Marker distinguishing the upgraded implementation from the original.
    function shieldVaultVersion() external pure returns (uint256) {
        return 2;
    }

    /// @notice Exposes the ERC-7201 slot constant so the suite can pin it against its formula.
    function storageSlot() external pure returns (bytes32) {
        return ShieldVaultStorageSlot;
    }
}
