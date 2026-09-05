// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Stablecoin } from "../src/testnet/Stablecoin.sol";
import { ShieldVault } from "../src/shield/ShieldVault.sol";
import { Deployments } from "../deployments/Deployments.sol";
import { DeploymentsResolver } from "../deployments/DeploymentsResolver.sol";

/// @title Deploy a ShieldVault for one eXYZ stablecoin
///
/// @notice Deploys the `ShieldVault` implementation and an `ERC1967Proxy` initialized with
///         `initialize(token, owner)`, then grants the token's `MINTER_ROLE` and `BURNER_ROLE` to
///         the proxy when the broadcaster administers those roles on the token, or prints the two
///         grant calls as a checklist for the token admin when it does not. One vault is deployed
///         per token, so run the script once per stablecoin.
///
/// @notice Every address is bound to the chain's address book, `deployments/deployments-*.json`
///         resolved by chain id through `DeploymentsResolver`:
///         - the script refuses any chain id the resolver does not map, so a stale `--rpc-url`
///           cannot deploy against the wrong live network;
///         - `SHIELD_TOKEN` must be one of the file's `eXYZs` entries and carry that entry's
///           symbol on-chain, which rules out the `StablecoinImpl` address (it answers the role
///           reads but administers nothing, so a vault bound to it would be inert for good);
///         - the owner defaults to the governance safe (`Safe`, 0x...07a0 on every network) and
///           any other owner is refused unless `SHIELD_ALLOW_NON_SAFE_OWNER=true` asks for it,
///           because a wrong owner is permanent: ownership can never be renounced and only the
///           owner can transfer it;
///         - the proxy is written back under `shieldVaults.<symbol>` so the role grant and the
///           precompile registration hand-offs never depend on terminal scrollback.
///
/// @notice A redeploy supersedes the vault the address book records for the token, and that vault
///         keeps its `MINTER_ROLE`/`BURNER_ROLE` on the token until someone revokes them: through
///         its owner's upgrade authority that is a way to mint without any proof, and it is
///         invisible to the precompile registry, the one place an auditor would look. The script
///         therefore revokes both roles from the superseded vault when the broadcaster
///         administers them and otherwise stops before deploying anything, with the exact
///         `revokeRole` commands in the failure message; it never leaves two vaults with mint
///         authority silently.
///
/// @dev The vault stays inert until the governance safe registers it on the precompile with
///      `setTokenConfig(token, vault, auditorKey)`; the script prints that call as the final
///      checklist item and never attempts it. It also warns when the precompile account has no
///      code on the target chain (a genesis without the account, before the fork injects it):
///      the vault refuses `shield`/`unshield` with `PrecompileNotLive` until then, so the role
///      grants are safe to make early but nothing can be shielded yet.
///
/// @dev A zero owner is rejected by the proxy's `initialize` call (OpenZeppelin's
///      `OwnableInvalidOwner`), so forge's pre-broadcast simulation fails before any transaction
///      is sent; a zero token never reaches `initialize` because it is not an `eXYZs` entry.
///
/// @dev Env vars:
///      - `SHIELD_TOKEN`: the eXYZ `Stablecoin` proxy the vault shields; must be listed under
///        `eXYZs` in the resolved deployments file
///      - `SHIELD_VAULT_OWNER` (optional): the vault owner (gates pause/unpause and upgrades);
///        defaults to `Safe` and must equal it unless `SHIELD_ALLOW_NON_SAFE_OWNER=true`
///      - `SHIELD_ALLOW_NON_SAFE_OWNER` (optional, default `false`): devnet-only opt-out from the
///        owner check
///
/// @dev The environment and the address-book path are read through `_config` and
///      `_deploymentsPath`, which are virtual so the test suite can pin a configuration per test
///      and write to a scratch copy of the address book instead of touching the process-wide
///      environment or the committed file.
///
/// @dev Usage: `SHIELD_TOKEN=0x... forge script script/DeployShieldVault.s.sol \
///      --rpc-url $TN_RPC_URL --private-key $ADMIN_PK -vvvv --broadcast`
contract DeployShieldVault is Script {
    /// @notice The run configuration; see `_config` for the environment variables behind it.
    struct Config {
        /// @dev `SHIELD_TOKEN`.
        address token;
        /// @dev `SHIELD_VAULT_OWNER`; zero means "the governance safe".
        address owner;
        /// @dev `SHIELD_ALLOW_NON_SAFE_OWNER`.
        bool allowNonSafeOwner;
    }

    Deployments deployments;
    /// @notice The address book this run reads and writes back to.
    string public deploymentsPath;

    Stablecoin public token;
    /// @notice The token's key under `eXYZs`, and the key the vault is recorded under in
    ///         `shieldVaults`.
    string public symbol;
    address public owner;
    /// @notice The vault the address book recorded for the token before this run, or zero.
    address public previousVault;

    /// @notice Populated by run(). Public so tests can read the deployed addresses back.
    ShieldVault public vaultImpl;
    ShieldVault public vault;
    /// @notice Whether run() granted the token roles itself (the broadcaster administers them).
    bool public rolesGranted;
    /// @notice Whether run() revoked the token roles from `previousVault`, which this run superseded.
    bool public rolesRevoked;
    /// @notice Whether the precompile account had code on the target chain when run() executed.
    bool public precompileLive;

    function setUp() public {
        require(
            block.chainid == DeploymentsResolver.TESTNET_CHAIN_ID
                || block.chainid == DeploymentsResolver.DEVNET_CHAIN_ID,
            string.concat("DeployShieldVault: unsupported chain id ", vm.toString(block.chainid))
        );
        deploymentsPath = _deploymentsPath();
        string memory json = vm.readFile(deploymentsPath);
        deployments = abi.decode(vm.parseJson(json), (Deployments));

        Config memory config = _config();

        // the token must be an address-book entry: the StablecoinImpl address a few lines above
        // the eXYZs block answers MINTER_ROLE/BURNER_ROLE like a token but administers nothing,
        // so a vault bound to it would deploy cleanly and stay inert for good
        require(
            config.token != deployments.StablecoinImpl,
            "DeployShieldVault: SHIELD_TOKEN is the Stablecoin implementation, not an eXYZ proxy"
        );
        symbol = _symbolOf(json, config.token);
        require(
            bytes(symbol).length != 0,
            string.concat(
                "DeployShieldVault: SHIELD_TOKEN ", vm.toString(config.token), " is not an eXYZ in ", deploymentsPath
            )
        );
        token = Stablecoin(config.token);
        require(
            LibString.eq(token.symbol(), symbol),
            string.concat("DeployShieldVault: SHIELD_TOKEN is recorded as ", symbol, " but reports ", token.symbol())
        );
        previousVault = vm.parseJsonAddress(json, string.concat(".shieldVaults.", symbol));

        // the owner holds the vault's upgrade authority, which reaches the token's mint path, so
        // it is the governance safe unless the operator says otherwise in so many words
        owner = config.owner == address(0) ? deployments.Safe : config.owner;
        if (owner == deployments.Safe) {
            require(owner.code.length > 0, "DeployShieldVault: the governance safe has no code on this chain");
        } else {
            require(
                config.allowNonSafeOwner,
                "DeployShieldVault: SHIELD_VAULT_OWNER is not the governance safe; set SHIELD_ALLOW_NON_SAFE_OWNER=true to deploy with another owner (devnet only)"
            );
        }
    }

    function run() public {
        bytes32 minterRole = token.MINTER_ROLE();
        bytes32 burnerRole = token.BURNER_ROLE();

        vm.startBroadcast();
        (, address broadcaster,) = vm.readCallers();

        // `grantRole`/`revokeRole` are gated on the role's admin role (DEFAULT_ADMIN_ROLE on
        // Stablecoin), so manage the roles inline only when the broadcaster holds it and
        // otherwise leave the calls to the token admin: the roles live on the token, not on the vault
        bool canManageRoles = token.hasRole(token.getRoleAdmin(minterRole), broadcaster)
            && token.hasRole(token.getRoleAdmin(burnerRole), broadcaster);

        // a redeploy supersedes the recorded vault, whose roles nobody else is told to revoke:
        // revoke them here or stop before anything is deployed
        bool supersedes = previousVault != address(0)
            && (token.hasRole(minterRole, previousVault) || token.hasRole(burnerRole, previousVault));
        if (supersedes && !canManageRoles) {
            revert(
                string.concat(
                    "DeployShieldVault: the vault recorded for ",
                    symbol,
                    " at ",
                    vm.toString(previousVault),
                    " still holds MINTER_ROLE/BURNER_ROLE on the token; the token admin must revoke them before a redeploy:\n",
                    _roleCommand("revokeRole", minterRole, previousVault),
                    "\n",
                    _roleCommand("revokeRole", burnerRole, previousVault)
                )
            );
        }

        vaultImpl = new ShieldVault();
        bytes memory initCall = abi.encodeCall(ShieldVault.initialize, (address(token), owner));
        vault = ShieldVault(address(new ERC1967Proxy(address(vaultImpl), initCall)));

        if (canManageRoles) {
            if (supersedes) {
                token.revokeRole(minterRole, previousVault);
                token.revokeRole(burnerRole, previousVault);
                rolesRevoked = true;
            }
            token.grantRole(minterRole, address(vault));
            token.grantRole(burnerRole, address(vault));
            rolesGranted = true;
        }

        vm.stopBroadcast();

        address precompile = vault.PRECOMPILE();
        precompileLive = precompile.code.length > 0;

        // asserts
        assert(address(vault.token()) == address(token));
        assert(vault.owner() == owner);
        assert(!vault.paused());
        assert(token.hasRole(minterRole, address(vault)) == rolesGranted);
        assert(token.hasRole(burnerRole, address(vault)) == rolesGranted);
        assert(!rolesRevoked || !token.hasRole(minterRole, previousVault));
        assert(!rolesRevoked || !token.hasRole(burnerRole, previousVault));

        // record the proxy under the token's symbol so the hand-offs below read the address book
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(vault))), 20),
            deploymentsPath,
            string.concat(".shieldVaults.", symbol)
        );

        // logs
        console2.log("ShieldVault implementation deployed at:", address(vaultImpl));
        console2.log("ShieldVault proxy deployed at:", address(vault));
        console2.log("  token:", address(token), symbol);
        console2.log("  owner:", owner);
        console2.log(string.concat("  recorded under shieldVaults.", symbol, " in ", deploymentsPath));
        if (rolesRevoked) {
            console2.log("Revoked MINTER_ROLE and BURNER_ROLE on the token from the superseded vault", previousVault);
        }
        if (rolesGranted) {
            console2.log("Granted MINTER_ROLE and BURNER_ROLE on the token to the vault as", broadcaster);
        } else {
            console2.log("Broadcaster", broadcaster, "does not administer the token's roles; the token admin must run:");
            console2.log(_roleCommand("grantRole", minterRole, address(vault)));
            console2.log(_roleCommand("grantRole", burnerRole, address(vault)));
        }
        if (!precompileLive) {
            console2.log(
                "WARNING: the precompile account has no code on this chain; the vault refuses shield/unshield with"
            );
            console2.log("         PrecompileNotLive until the TN-SHIELD fork injects it at", precompile);
        }
        console2.log("The governance safe must then register the vault on the precompile at", precompile);
        console2.log(
            string.concat(
                "  setTokenConfig(", vm.toString(address(token)), ", ", vm.toString(address(vault)), ", <auditorKey>)"
            )
        );
    }

    /// @dev The run configuration, from the environment.
    function _config() internal view virtual returns (Config memory) {
        return Config({
            token: vm.envOr("SHIELD_TOKEN", address(0)),
            owner: vm.envOr("SHIELD_VAULT_OWNER", address(0)),
            allowNonSafeOwner: vm.envOr("SHIELD_ALLOW_NON_SAFE_OWNER", false)
        });
    }

    /// @dev The chain's address book, resolved by chain id.
    function _deploymentsPath() internal view virtual returns (string memory) {
        return string.concat(vm.projectRoot(), DeploymentsResolver.relativePath());
    }

    /// @dev The `eXYZs` key whose address is `token_`, or the empty string when there is none.
    function _symbolOf(string memory json, address token_) internal pure returns (string memory) {
        string[] memory symbols = vm.parseJsonKeys(json, ".eXYZs");
        for (uint256 i; i < symbols.length; ++i) {
            if (vm.parseJsonAddress(json, string.concat(".eXYZs.", symbols[i])) == token_) return symbols[i];
        }
        return "";
    }

    /// @dev A copy-pasteable `cast send` calling `action(role, account)` on the token.
    function _roleCommand(string memory action, bytes32 role, address account) internal view returns (string memory) {
        return string.concat(
            "  cast send ",
            vm.toString(address(token)),
            ' "',
            action,
            '(bytes32,address)" ',
            vm.toString(role),
            " ",
            vm.toString(account)
        );
    }
}
