// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Test } from "forge-std/Test.sol";
import { ERC1967Utils } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { DeployShieldVault } from "../../script/DeployShieldVault.s.sol";
import { Stablecoin } from "../../src/testnet/Stablecoin.sol";
import { ShieldVault } from "../../src/shield/ShieldVault.sol";

/// @title DeployShieldVault deploy-script tests
///
/// @notice Runs the deploy script end-to-end against the in-repo `Stablecoin`
///         (TestnetDeployWTEL.t.sol pattern: instantiate the script, `setUp()`, `run()`): the
///         implementation and an ERC1967 proxy initialized for the token and owner read from the
///         env, the inline role grant when the broadcaster administers the token's roles, and the
///         checklist path (no grant, vault still fully initialized) when it does not.
/// @dev The env is set once in `setUp` and never changed by a test: `vm.setEnv` is process-wide
///      and foundry runs the tests of a contract in parallel, so per-test env edits would race.
contract DeployShieldVaultTest is Test {
    Stablecoin token;
    address governance = address(0x7A0);

    /// @dev `vm.startBroadcast()` with no sender broadcasts from the transaction origin, which in
    ///      a test is the runner's default sender; the tests grant or withhold the token admin
    ///      role for exactly that address.
    address broadcaster;

    function setUp() public {
        broadcaster = tx.origin;
        // this test contract holds DEFAULT_ADMIN_ROLE (granted to `Stablecoin.initialize`'s caller)
        token = new Stablecoin();
        token.initialize("Telcoin eUSD", "eUSD", 6);

        vm.setEnv("SHIELD_TOKEN", vm.toString(address(token)));
        vm.setEnv("SHIELD_VAULT_OWNER", vm.toString(governance));
    }

    function _runScript() internal returns (DeployShieldVault script) {
        script = new DeployShieldVault();
        script.setUp();
        script.run();
    }

    /// @dev The proxy must point at the freshly deployed implementation and be initialized for the
    ///      env-provided token and owner.
    function _assertDeployed(DeployShieldVault script) internal view {
        ShieldVault vault = script.vault();
        ShieldVault impl = script.vaultImpl();
        assertGt(address(impl).code.length, 0, "implementation not deployed");
        assertGt(address(vault).code.length, 0, "proxy not deployed");
        assertEq(
            vm.load(address(vault), ERC1967Utils.IMPLEMENTATION_SLOT),
            bytes32(uint256(uint160(address(impl)))),
            "proxy must point at the script's implementation"
        );
        assertEq(address(vault.token()), address(token), "vault token must come from SHIELD_TOKEN");
        assertEq(vault.owner(), governance, "vault owner must come from SHIELD_VAULT_OWNER");
        assertFalse(vault.paused(), "fresh vault must not be paused");
    }

    function test_DeploysAndGrantsRolesWhenBroadcasterAdministersToken() public {
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), broadcaster);

        DeployShieldVault script = _runScript();
        _assertDeployed(script);

        ShieldVault vault = script.vault();
        assertTrue(script.rolesGranted(), "script should report the inline grant");
        assertTrue(token.hasRole(token.MINTER_ROLE(), address(vault)), "vault must hold MINTER_ROLE");
        assertTrue(token.hasRole(token.BURNER_ROLE(), address(vault)), "vault must hold BURNER_ROLE");
    }

    function test_DeploysAndLeavesRolesToTokenAdminOtherwise() public {
        assertFalse(
            token.hasRole(token.DEFAULT_ADMIN_ROLE(), broadcaster), "precondition: broadcaster is not the token admin"
        );

        DeployShieldVault script = _runScript();
        _assertDeployed(script);

        ShieldVault vault = script.vault();
        assertFalse(script.rolesGranted(), "script must not report a grant it could not make");
        assertFalse(token.hasRole(token.MINTER_ROLE(), address(vault)), "no MINTER_ROLE without the admin");
        assertFalse(token.hasRole(token.BURNER_ROLE(), address(vault)), "no BURNER_ROLE without the admin");

        // the printed checklist: the token admin grants both roles afterwards and the vault is whole
        token.grantRole(token.MINTER_ROLE(), address(vault));
        token.grantRole(token.BURNER_ROLE(), address(vault));
        assertTrue(token.hasRole(token.MINTER_ROLE(), address(vault)), "admin grant of MINTER_ROLE");
        assertTrue(token.hasRole(token.BURNER_ROLE(), address(vault)), "admin grant of BURNER_ROLE");
    }

    /// @dev The deployed implementation is locked by its constructor, so nobody can initialize it
    ///      directly and claim its owner slot.
    function test_DeployedImplementationIsLocked() public {
        ShieldVault impl = _runScript().vaultImpl();

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(address(token), address(this));
    }
}
