// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Stablecoin } from "../../src/testnet/Stablecoin.sol";
import { ShieldPrecompileSelectors } from "../../src/shield/ShieldPrecompileSelectors.sol";
import { ShieldVault } from "../../src/shield/ShieldVault.sol";

/// @title ShieldVaultTest
/// @notice Minimal wave-1 unit tests for `ShieldVault` (the full suite lands with the
///         fixture-driven wave).
/// @notice Coverage areas:
///         - **Selector parity:** every hardcoded `ShieldPrecompileSelectors` constant equals
///           `bytes4(keccak256(signature))` recomputed here from the exact TN-SHIELD v1 signatures.
///         - **shield happy path:** precompile leg mocked (`vm.mockCall`, StablecoinManager.t.sol
///           pattern); expects the `burnFrom` leg then the precompile call with exact calldata.
///         - **unshield happy path:** precompile returndata mocked; expects the mint to the
///           precompile-returned recipient.
contract ShieldVaultTest is Test {
    ShieldVault vaultImpl;
    ShieldVault vault;
    Stablecoin token;

    // stands in for the governance safe as vault owner
    address governance = address(0x7A0);
    address user = address(0xBEEF);

    function setUp() public {
        token = new Stablecoin();
        token.initialize("Telcoin eUSD", "eUSD", 6);

        vaultImpl = new ShieldVault();
        bytes memory initCall = abi.encodeWithSelector(ShieldVault.initialize.selector, address(token), governance);
        vault = ShieldVault(address(new ERC1967Proxy(address(vaultImpl), initCall)));

        // the vault operationally holds both supply roles on its token (granted by the token
        // admin out-of-band on the real chain)
        token.grantRole(token.MINTER_ROLE(), address(vault));
        token.grantRole(token.BURNER_ROLE(), address(vault));

        // this test contract holds DEFAULT_ADMIN_ROLE (granted to `Stablecoin.initialize`'s
        // caller); give it MINTER_ROLE to seed user balances
        token.grantRole(token.MINTER_ROLE(), address(this));
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
        bytes32 ownerAddr = keccak256("shielded owner address");
        bytes32 salt = keccak256("note salt");
        address precompile = vault.PRECOMPILE();

        token.mintTo(user, amount);

        // burnFrom prerequisite: Stablecoin.burnFrom spends the vault's allowance even though
        // the vault holds BURNER_ROLE
        vm.prank(user);
        token.approve(address(vault), amount);

        bytes memory precompileCalldata =
            abi.encodeWithSelector(ShieldPrecompileSelectors.SHIELD, address(token), ownerAddr, salt, amount);
        vm.mockCall(precompile, precompileCalldata, abi.encode());

        // the burn leg, then the precompile leg with exact calldata
        vm.expectCall(address(token), abi.encodeWithSelector(Stablecoin.burnFrom.selector, user, uint256(amount)));
        vm.expectCall(precompile, precompileCalldata);

        vm.prank(user);
        vault.shield(amount, ownerAddr, salt);

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
        address precompile = vault.PRECOMPILE();

        bytes memory precompileCalldata =
            abi.encodeWithSelector(ShieldPrecompileSelectors.UNSHIELD, proof, publicValues);
        vm.mockCall(precompile, precompileCalldata, abi.encode(recipient, amount));
        vm.expectCall(precompile, precompileCalldata);

        // relayable: any caller may submit the proof
        vm.prank(user);
        vault.unshield(proof, publicValues);

        assertEq(token.balanceOf(recipient), amount, "unshield should mint the proven amount to the recipient");
        assertEq(token.totalSupply(), amount, "unshield should restore public supply");
    }
}
