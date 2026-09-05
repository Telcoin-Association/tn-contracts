// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Stablecoin } from "../src/testnet/Stablecoin.sol";
import { ShieldVault } from "../src/shield/ShieldVault.sol";

/// @title Deploy a ShieldVault for one eXYZ stablecoin
///
/// @notice Deploys the `ShieldVault` implementation and an `ERC1967Proxy` initialized with
///         `initialize(token, owner)`, then grants the token's `MINTER_ROLE` and `BURNER_ROLE` to
///         the proxy when the broadcaster administers those roles on the token, or prints the two
///         grant calls as a checklist for the token admin when it does not. One vault is deployed
///         per token, so run the script once per stablecoin.
///
/// @dev The vault stays inert until the governance safe registers it on the precompile with
///      `setTokenConfig(token, vault, auditorKey)`; the script prints that call as the final
///      checklist item and never attempts it.
///
/// @dev A zero token or owner is rejected by the proxy's `initialize` call (`ShieldVault.ZeroAddress`
///      and OpenZeppelin's `OwnableInvalidOwner`), so forge's pre-broadcast simulation fails before
///      any transaction is sent.
///
/// @dev Env vars:
///      - `SHIELD_TOKEN`: the eXYZ `Stablecoin` proxy the vault shields
///      - `SHIELD_VAULT_OWNER`: the vault owner (gates pause/unpause and upgrades); intended to be
///        the governance safe
///
/// @dev Usage: `SHIELD_TOKEN=0x... SHIELD_VAULT_OWNER=0x... forge script script/DeployShieldVault.s.sol \
///      --rpc-url $TN_RPC_URL --private-key $ADMIN_PK -vvvv --broadcast`
contract DeployShieldVault is Script {
    Stablecoin public token;
    address public owner;

    /// @notice Populated by run(). Public so tests can read the deployed addresses back.
    ShieldVault public vaultImpl;
    ShieldVault public vault;
    /// @notice Whether run() granted the token roles itself (the broadcaster administers them).
    bool public rolesGranted;

    function setUp() public {
        token = Stablecoin(vm.envAddress("SHIELD_TOKEN"));
        owner = vm.envAddress("SHIELD_VAULT_OWNER");
    }

    function run() public {
        bytes32 minterRole = token.MINTER_ROLE();
        bytes32 burnerRole = token.BURNER_ROLE();

        vm.startBroadcast();
        (, address broadcaster,) = vm.readCallers();

        vaultImpl = new ShieldVault();
        bytes memory initCall = abi.encodeCall(ShieldVault.initialize, (address(token), owner));
        vault = ShieldVault(address(new ERC1967Proxy(address(vaultImpl), initCall)));

        // `grantRole` is gated on the role's admin role (DEFAULT_ADMIN_ROLE on Stablecoin), so
        // grant inline only when the broadcaster holds it and otherwise leave both calls to the
        // token admin: the roles live on the token, not on the vault
        rolesGranted = token.hasRole(token.getRoleAdmin(minterRole), broadcaster)
            && token.hasRole(token.getRoleAdmin(burnerRole), broadcaster);
        if (rolesGranted) {
            token.grantRole(minterRole, address(vault));
            token.grantRole(burnerRole, address(vault));
        }

        vm.stopBroadcast();

        // asserts
        assert(address(vault.token()) == address(token));
        assert(vault.owner() == owner);
        assert(!vault.paused());
        assert(token.hasRole(minterRole, address(vault)) == rolesGranted);
        assert(token.hasRole(burnerRole, address(vault)) == rolesGranted);

        // logs
        console2.log("ShieldVault implementation deployed at:", address(vaultImpl));
        console2.log("ShieldVault proxy deployed at:", address(vault));
        console2.log("  token:", address(token));
        console2.log("  owner:", owner);
        if (rolesGranted) {
            console2.log("Granted MINTER_ROLE and BURNER_ROLE on the token to the vault as", broadcaster);
        } else {
            console2.log("Broadcaster", broadcaster, "does not administer the token's roles; the token admin must run:");
            console2.log(_grantCommand(minterRole));
            console2.log(_grantCommand(burnerRole));
        }
        console2.log("The governance safe must then register the vault on the precompile at", vault.PRECOMPILE());
        console2.log(
            string.concat(
                "  setTokenConfig(", vm.toString(address(token)), ", ", vm.toString(address(vault)), ", <auditorKey>)"
            )
        );
    }

    /// @dev A copy-pasteable `cast send` granting `role` on the token to the vault.
    function _grantCommand(bytes32 role) internal view returns (string memory) {
        return string.concat(
            "  cast send ",
            vm.toString(address(token)),
            ' "grantRole(bytes32,address)" ',
            vm.toString(role),
            " ",
            vm.toString(address(vault))
        );
    }
}
