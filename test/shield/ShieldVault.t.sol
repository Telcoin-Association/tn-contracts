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
import { ShieldPrecompileSelectors } from "../../src/shield/ShieldPrecompileSelectors.sol";
import { ShieldVault } from "../../src/shield/ShieldVault.sol";

/// @title ShieldVaultTest
/// @notice Wave-3 unit suite for `ShieldVault` against the real `Stablecoin` (no token mock)
///         behind an `ERC1967Proxy`; only the precompile leg is mocked (`vm.mockCall` /
///         `vm.mockCallRevert`, StablecoinManager.t.sol pattern).
/// @notice Coverage areas:
///         - **Selector parity:** every hardcoded `ShieldPrecompileSelectors` constant equals
///           `bytes4(keccak256(signature))` recomputed here from the exact TN-SHIELD v1 signatures.
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
///         - **Upgrade auth:** non-owner `upgradeToAndCall` reverts; owner upgrade succeeds and
///           preserves the ERC-7201 namespaced storage (token pointer, owner, paused flag).
///         - **Precompile-failure propagation:** per the frozen error idiom, precompile failures
///           are frame halts with EMPTY returndata - the vault surfaces `LowLevelCallFailure`
///           carrying empty bytes and the revert restores all token pre-state.
///         - **Malformed unshield returndata:** too-short precompile returndata makes
///           `abi.decode` revert; no mint happens.
///         - **Fuzz:** shield amount over (0, type(uint128).max] with allowance == amount - the
///           burn leg and the precompile calldata encoding are exact for every input
///           (`vm.expectCall` with computed calldata).
///         `ShieldVault` declares no events of its own, so there are no vault event assertions.
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

    // -------------
    // shield / unshield happy paths (precompile leg mocked)
    // -------------

    function testShieldHappyPath() public {
        uint128 amount = 1_000_000; // 1.0 eUSD at 6 decimals
        _mintAndApprove(amount);

        bytes memory precompileCalldata = _shieldCalldata(amount, OWNER_ADDR, SALT);
        vm.mockCall(precompile, precompileCalldata, abi.encode());

        // the burn leg, then the precompile leg with exact calldata
        vm.expectCall(address(token), abi.encodeWithSelector(Stablecoin.burnFrom.selector, user, uint256(amount)));
        vm.expectCall(precompile, precompileCalldata);

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
        bytes memory publicValues = hex"5678";

        bytes memory precompileCalldata = _unshieldCalldata(proof, publicValues);
        vm.mockCall(precompile, precompileCalldata, abi.encode(recipient, amount));
        vm.expectCall(precompile, precompileCalldata);

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
        bytes memory publicValues = hex"5678";
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
        vault.unshield(hex"1234", hex"5678");

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
        bytes memory publicValues = hex"bbbb";
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
        bytes memory publicValues = hex"5678";
        vm.mockCallRevert(precompile, _unshieldCalldata(proof, publicValues), "");

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ShieldVault.LowLevelCallFailure.selector, bytes("")));
        vault.unshield(proof, publicValues);

        assertEq(token.totalSupply(), 0, "failed unshield must not mint");
    }

    // -------------
    // malformed unshield returndata
    // -------------

    /// @dev Precompile returndata shorter than `abi.encode(address, uint128)` (64 bytes) makes
    ///      the vault's `abi.decode` revert; no mint happens.
    function testUnshieldMalformedReturndataReverts() public {
        // round 1: junk bytes far too short for any head
        bytes memory proof1 = hex"aa";
        bytes memory publicValues1 = hex"bb";
        vm.mockCall(precompile, _unshieldCalldata(proof1, publicValues1), hex"1234");

        vm.prank(user);
        vm.expectRevert();
        vault.unshield(proof1, publicValues1);

        // round 2: one valid word (the recipient) but the amount word missing
        bytes memory proof2 = hex"cc";
        bytes memory publicValues2 = hex"dd";
        vm.mockCall(precompile, _unshieldCalldata(proof2, publicValues2), abi.encode(address(0xCAFE)));

        vm.prank(user);
        vm.expectRevert();
        vault.unshield(proof2, publicValues2);

        assertEq(token.totalSupply(), 0, "malformed returndata must not mint");
        assertEq(token.balanceOf(address(0xCAFE)), 0, "malformed returndata must not mint to the decoded word");
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

    // -------------
    // fuzz: exact burn + precompile calldata encoding over the full u128 domain
    // -------------

    /// @dev For every amount in (0, type(uint128).max] with allowance == amount, the burn leg and
    ///      the precompile calldata encoding are byte-exact. If the vault's encoding ever drifted,
    ///      the un-mocked (codeless) precompile would absorb the call and the exact-calldata
    ///      `vm.expectCall` would fail the run.
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
}
