// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Script } from "forge-std/Script.sol";
import { VmSafe } from "forge-std/Vm.sol";
import { console2 } from "forge-std/console2.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ERC1967Utils } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import { Stablecoin } from "../src/testnet/Stablecoin.sol";
import { ShieldVault } from "../src/shield/ShieldVault.sol";
import { Deployments } from "../deployments/Deployments.sol";
import { DeploymentsResolver } from "../deployments/DeploymentsResolver.sol";

/// @title Deploy a ShieldVault for one eXYZ stablecoin
///
/// @notice Deploys the `ShieldVault` implementation and an `ERC1967Proxy` initialized with
///         `initialize(token, owner)`, then prints the token's `MINTER_ROLE` and `BURNER_ROLE`
///         grants to the proxy as a checklist for the token admin, or makes them itself when
///         `SHIELD_GRANT_INLINE=true` and the broadcaster administers those roles on the token.
///         One vault is deployed per token, so run the script once per stablecoin.
///
/// @notice The deployment itself needs no privilege, so broadcast it with a plain deployer key.
///         The token's `DEFAULT_ADMIN_ROLE` key mints without limit and administers itself, and
///         the rollout exposes it once per token, so the script only touches the roles when asked
///         to in so many words; by default the grants are a printed hand-off to whoever holds
///         that key.
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
/// @notice One implementation per chain, at deterministic addresses: the implementation is the one
///         recorded under `ShieldVaultImpl` in the address book (failing that, the CREATE2 address
///         of the current source, deployed when nothing is there yet), and the proxy is CREATE2-
///         salted on the token, so its address is a pure function of the implementation, the
///         token, and the owner. A dry run therefore prints the vault address before anything is
///         broadcast, which lets the governance safe collect signatures on `setTokenConfig` in
///         parallel with the deploy; a re-run for the same token finds its vault already deployed
///         and only completes what is missing (the record, the roles); and 23 vaults share one
///         implementation to verify, audit, and upgrade instead of 23.
///
/// @notice A redeploy supersedes the vault the address book records for the token, and that vault
///         keeps its `MINTER_ROLE`/`BURNER_ROLE` on the token until someone revokes them: through
///         its owner's upgrade authority that is a way to mint without any proof, and it is
///         invisible to the precompile registry, the one place an auditor would look. The script
///         therefore revokes both roles from the superseded vault when it manages the roles
///         inline and otherwise stops before deploying anything, with the exact `revokeRole`
///         commands in the failure message; it never leaves two vaults with mint authority
///         silently.
///
/// @dev The vault stays inert until the governance safe registers it on the precompile with
///      `setTokenConfig(token, vault, auditorKey)`; the script prints that call as the final
///      checklist item and never attempts it. It also warns when the precompile account has no
///      code on the target chain (a genesis without the account, before the fork injects it):
///      the vault refuses `shield`/`unshield` with `PrecompileNotLive` until then, so nothing can
///      be shielded yet. That refusal is not what makes an early role grant safe: every guard on
///      the mint path except the token's own `onlyRole(MINTER_ROLE)` lives in vault code the
///      owner can replace by upgrade, so from the grant onward the binding control is the
///      owner's key, which is why the owner check in `setUp` refuses anything but the governance
///      safe unless told otherwise.
///
/// @dev The checks after `vm.stopBroadcast()` read the vault and the token back rather than the
///      inputs that produced them, so a divergence in the simulation fails by name instead of
///      with a bare panic. Under `--broadcast` they still describe the simulation, not the
///      receipts: run with `--slow` so a failed transaction stops the sequence (the role grants
///      carry the simulated proxy address, and a reverted CREATE would not stop them at their own
///      nonces), and confirm real state afterwards with the `cast call` reads the script prints.
///      Every printed `cast send` carries `--chain`, which puts the chain id into the signed
///      transaction, so a command copied to another network's RPC is rejected by that node
///      instead of "succeeding" against an address with no code there.
///
/// @dev Neither of `initialize`'s own input guards is reachable from here: a zero or unset
///      `SHIELD_TOKEN` fails the "is not set" check in `setUp`, and an unset or zero
///      `SHIELD_VAULT_OWNER` means the governance safe. Every input check is a named `require` in
///      `setUp`, before `vm.startBroadcast()`, so a bad input fails the simulation by name and
///      nothing is sent.
///
/// @dev Env vars:
///      - `SHIELD_TOKEN`: the eXYZ `Stablecoin` proxy the vault shields; must be listed under
///        `eXYZs` in the resolved deployments file
///      - `SHIELD_VAULT_OWNER` (optional): the vault owner (gates pause/unpause and upgrades);
///        defaults to `Safe` and must equal it unless `SHIELD_ALLOW_NON_SAFE_OWNER=true`
///      - `SHIELD_ALLOW_NON_SAFE_OWNER` (optional, default `false`): devnet-only opt-out from the
///        owner check
///      - `SHIELD_GRANT_INLINE` (optional, default `false`): grant (and on a redeploy revoke) the
///        token roles inline; requires broadcasting with the token admin key
///
/// @dev The address book is written only by a `--broadcast` (or `--resume`) run: forge executes
///      the script in a plain `forge script` too, and a dry run that recorded its predicted
///      addresses would leave the next run nothing to supersede, so the vault that holds the
///      roles would keep them with no message. The write still happens in the broadcast run's
///      simulation, before its transactions land, which is why the revoke is the first
///      transaction of a redeploy: a `--slow` stop after it leaves the superseded vault without
///      roles and a re-run completes the rest, while a stop before it means the deployments
///      file must be restored (`git checkout`) before running again.
///
/// @dev The environment, the address-book path, and whether to write the book back are read
///      through `_config`, `_deploymentsPath`, and `_recording`, which are virtual so the test
///      suite can pin a configuration per test and write to a scratch copy of the address book
///      instead of touching the process-wide environment or the committed file.
///
/// @dev Usage: `SHIELD_TOKEN=0x... forge script script/DeployShieldVault.s.sol \
///      --rpc-url $TN_RPC_URL --private-key $DEPLOYER_PK -vvvv --slow --broadcast`
contract DeployShieldVault is Script {
    /// @notice The run configuration; see `_config` for the environment variables behind it.
    struct Config {
        /// @dev `SHIELD_TOKEN`.
        address token;
        /// @dev `SHIELD_VAULT_OWNER`; zero means "the governance safe".
        address owner;
        /// @dev `SHIELD_ALLOW_NON_SAFE_OWNER`.
        bool allowNonSafeOwner;
        /// @dev `SHIELD_GRANT_INLINE`.
        bool grantInline;
    }

    /// @dev CREATE2 salt of the implementation. `ShieldVault` compiles from source, so its initcode
    ///      (and with it this address) moves with any compiler or source change, and the proxies'
    ///      addresses follow the implementation's because their initcode embeds it. Redeploying
    ///      identical bytecode on a chain that already holds it lands on the same address and is
    ///      skipped rather than needing a bumped salt.
    bytes32 internal constant IMPL_SALT = bytes32(bytes("ShieldVault"));

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
    /// @notice Whether the run was asked to manage the token roles inline.
    bool public grantInline;

    /// @notice Populated by run(). Public so tests can read the deployed addresses back.
    ShieldVault public vaultImpl;
    ShieldVault public vault;
    /// @notice Whether the implementation already had code (recorded, or at its CREATE2 address).
    bool public implReused;
    /// @notice Whether the proxy already had code at its CREATE2 address (a re-run for the token).
    bool public vaultReused;
    /// @notice Whether run() granted the token roles itself (asked to, and the broadcaster
    ///         administers them).
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

        require(config.token != address(0), "DeployShieldVault: SHIELD_TOKEN is not set");
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
        require(
            config.token.code.length > 0,
            string.concat(
                "DeployShieldVault: SHIELD_TOKEN ", symbol, " has no code on chain ", vm.toString(block.chainid)
            )
        );
        token = Stablecoin(config.token);
        require(
            LibString.eq(token.symbol(), symbol),
            string.concat("DeployShieldVault: SHIELD_TOKEN is recorded as ", symbol, " but reports ", token.symbol())
        );
        previousVault = vm.parseJsonAddress(json, string.concat(".shieldVaults.", symbol));
        grantInline = config.grantInline;

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

        // one implementation per chain: the recorded one, else the CREATE2 address of the current
        // source, deployed below when nothing is there yet
        address impl = deployments.ShieldVaultImpl;
        address currentImpl = vm.computeCreate2Address(IMPL_SALT, keccak256(type(ShieldVault).creationCode));
        if (impl.code.length == 0) impl = currentImpl;
        implReused = impl.code.length > 0;
        vaultImpl = ShieldVault(impl);

        // the proxy is a pure function of (implementation, token, owner): a re-run for the token
        // lands on the same address and is skipped, and a dry run knows the address before
        // anything is broadcast
        bytes memory initCall = abi.encodeCall(ShieldVault.initialize, (address(token), owner));
        bytes32 vaultSalt = keccak256(abi.encodePacked("ShieldVault", address(token)));
        address predictedVault = vm.computeCreate2Address(
            vaultSalt, keccak256(abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initCall)))
        );
        vaultReused = predictedVault.code.length > 0;
        vault = ShieldVault(predictedVault);

        console2.log(implReused ? "ShieldVault implementation in use:" : "ShieldVault implementation to deploy:", impl);
        console2.log(
            vaultReused ? "ShieldVault proxy already deployed:" : "ShieldVault proxy to deploy:", predictedVault
        );
        if (implReused && impl != currentImpl) {
            console2.log(
                "WARNING: the implementation in use was not built from the current source; new vaults reuse it."
            );
            console2.log("         Roll new code with a UUPS upgrade, or zero ShieldVaultImpl in the address book.");
        }

        vm.startBroadcast();
        (, address broadcaster,) = vm.readCallers();

        // `grantRole`/`revokeRole` are gated on the role's admin role (DEFAULT_ADMIN_ROLE on
        // Stablecoin), so manage the roles inline only when asked to and the broadcaster holds
        // it, and otherwise leave the calls to the token admin: the roles live on the token, not
        // on the vault
        bool canManageRoles = grantInline && token.hasRole(token.getRoleAdmin(minterRole), broadcaster)
            && token.hasRole(token.getRoleAdmin(burnerRole), broadcaster);

        // a redeploy supersedes the recorded vault, whose roles nobody else is told to revoke:
        // revoke them here or stop before anything is deployed (a re-run for the same vault
        // supersedes nothing)
        bool supersedes = previousVault != address(0) && previousVault != predictedVault
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

        // the revoke goes first: the address book already names the new vault (written in this
        // run's simulation), so a stop after the revoke leaves nothing stranded and a stop before
        // it is the one case the operator must restore the file for
        if (supersedes && canManageRoles) {
            token.revokeRole(minterRole, previousVault);
            token.revokeRole(burnerRole, previousVault);
            rolesRevoked = true;
        }

        if (!implReused) {
            vaultImpl = new ShieldVault{ salt: IMPL_SALT }();
            require(
                address(vaultImpl) == impl, "DeployShieldVault: the implementation did not land at its CREATE2 address"
            );
        }
        if (!vaultReused) {
            vault = ShieldVault(address(new ERC1967Proxy{ salt: vaultSalt }(impl, initCall)));
            require(
                address(vault) == predictedVault, "DeployShieldVault: the proxy did not land at its CREATE2 address"
            );
        }

        if (canManageRoles) {
            if (!token.hasRole(minterRole, address(vault))) token.grantRole(minterRole, address(vault));
            if (!token.hasRole(burnerRole, address(vault))) token.grantRole(burnerRole, address(vault));
            rolesGranted = true;
        }

        vm.stopBroadcast();

        address precompile = vault.PRECOMPILE();
        precompileLive = precompile.code.length > 0;

        // verify what is on the chain, not the inputs that produced it
        require(address(vaultImpl).code.length > 0, "DeployShieldVault: the implementation has no code");
        require(address(vault).code.length > 0, "DeployShieldVault: the proxy has no code");
        require(
            vm.load(address(vault), ERC1967Utils.IMPLEMENTATION_SLOT) == bytes32(uint256(uint160(address(vaultImpl)))),
            "DeployShieldVault: the proxy does not point at the implementation"
        );
        require(address(vault.token()) == address(token), "DeployShieldVault: the vault is bound to another token");
        require(vault.owner() == owner, "DeployShieldVault: the vault has another owner");
        require(vault.pendingOwner() == address(0), "DeployShieldVault: the vault has a pending owner");
        require(!vault.paused(), "DeployShieldVault: the fresh vault is paused");
        if (rolesGranted) {
            require(
                token.hasRole(minterRole, address(vault)) && token.hasRole(burnerRole, address(vault)),
                "DeployShieldVault: the vault does not hold MINTER_ROLE and BURNER_ROLE after the grant"
            );
        }
        if (rolesRevoked) {
            require(
                !token.hasRole(minterRole, previousVault) && !token.hasRole(burnerRole, previousVault),
                "DeployShieldVault: the superseded vault still holds a role after the revoke"
            );
        }

        // record the implementation and the proxy (under the token's symbol) so the hand-offs
        // below read the address book; a dry run records nothing, so it cannot hide a
        // superseded vault from the broadcast that follows it
        bool recorded = _recording();
        if (recorded) {
            vm.writeJson(
                LibString.toHexString(uint256(uint160(address(vaultImpl))), 20), deploymentsPath, ".ShieldVaultImpl"
            );
            vm.writeJson(
                LibString.toHexString(uint256(uint160(address(vault))), 20),
                deploymentsPath,
                string.concat(".shieldVaults.", symbol)
            );
        }

        // logs
        console2.log(
            implReused ? "ShieldVault implementation reused:" : "ShieldVault implementation deployed at:", impl
        );
        console2.log(vaultReused ? "ShieldVault proxy found at:" : "ShieldVault proxy deployed at:", address(vault));
        console2.log("  token:", address(token), symbol);
        console2.log("  owner:", owner);
        if (recorded) {
            console2.log(
                string.concat("  recorded under ShieldVaultImpl and shieldVaults.", symbol, " in ", deploymentsPath)
            );
        } else {
            console2.log("  dry run: the address book is written only by a --broadcast run");
        }
        console2.log("Confirm the broadcast against chain state (the lines above describe the simulation):");
        console2.log(_vaultCheck("token()", address(token)));
        console2.log(_vaultCheck("owner()", owner));
        if (rolesRevoked) {
            console2.log("Revoked MINTER_ROLE and BURNER_ROLE on the token from the superseded vault", previousVault);
            console2.log(_roleCheck(minterRole, previousVault, false));
            console2.log(_roleCheck(burnerRole, previousVault, false));
        }
        if (rolesGranted) {
            console2.log("Granted MINTER_ROLE and BURNER_ROLE on the token to the vault as", broadcaster);
            console2.log(_roleCheck(minterRole, address(vault), true));
            console2.log(_roleCheck(burnerRole, address(vault), true));
        } else {
            if (grantInline) {
                console2.log(
                    "Broadcaster", broadcaster, "does not administer the token's roles; the token admin must run:"
                );
            } else {
                console2.log(
                    "The token admin must grant the roles (or rerun with SHIELD_GRANT_INLINE=true and the admin key):"
                );
            }
            console2.log(_roleCommand("grantRole", minterRole, address(vault)));
            console2.log(_roleCommand("grantRole", burnerRole, address(vault)));
            console2.log("and confirm:");
            console2.log(_roleCheck(minterRole, address(vault), true));
            console2.log(_roleCheck(burnerRole, address(vault), true));
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
            allowNonSafeOwner: vm.envOr("SHIELD_ALLOW_NON_SAFE_OWNER", false),
            grantInline: vm.envOr("SHIELD_GRANT_INLINE", false)
        });
    }

    /// @dev The chain's address book, resolved by chain id.
    function _deploymentsPath() internal view virtual returns (string memory) {
        return string.concat(vm.projectRoot(), DeploymentsResolver.relativePath());
    }

    /// @dev Whether this run writes the address book: only a `--broadcast` or `--resume` run does.
    function _recording() internal view virtual returns (bool) {
        return vm.isContext(VmSafe.ForgeContext.ScriptBroadcast) || vm.isContext(VmSafe.ForgeContext.ScriptResume);
    }

    /// @dev The `eXYZs` key whose address is `token_`, or the empty string when there is none.
    function _symbolOf(string memory json, address token_) internal pure returns (string memory) {
        string[] memory symbols = vm.parseJsonKeys(json, ".eXYZs");
        for (uint256 i; i < symbols.length; ++i) {
            if (vm.parseJsonAddress(json, string.concat(".eXYZs.", symbols[i])) == token_) return symbols[i];
        }
        return "";
    }

    /// @dev A copy-pasteable `cast send` calling `action(role, account)` on the token, pinned to
    ///      this chain by `--chain` (see the contract-level note).
    function _roleCommand(string memory action, bytes32 role, address account) internal view returns (string memory) {
        return string.concat(
            "  cast send --rpc-url $TN_RPC_URL --chain ",
            vm.toString(block.chainid),
            " --private-key $ADMIN_PK ",
            vm.toString(address(token)),
            ' "',
            action,
            '(bytes32,address)" ',
            vm.toString(role),
            " ",
            vm.toString(account)
        );
    }

    /// @dev The `cast call` confirming `hasRole(role, account)` on the token reads `expected`.
    ///      Against an address with no code the call returns nothing and fails to decode, which
    ///      is the signal a bare `cast send` to the wrong network never gives.
    function _roleCheck(bytes32 role, address account, bool expected) internal view returns (string memory) {
        return string.concat(
            "  cast call --rpc-url $TN_RPC_URL ",
            vm.toString(address(token)),
            ' "hasRole(bytes32,address)(bool)" ',
            vm.toString(role),
            " ",
            vm.toString(account),
            "   # must print ",
            expected ? "true" : "false"
        );
    }

    /// @dev The `cast call` confirming the vault's `getter` reads `expected`; a look-alike proxy
    ///      over the same implementation fails the owner read.
    function _vaultCheck(string memory getter, address expected) internal view returns (string memory) {
        return string.concat(
            "  cast call --rpc-url $TN_RPC_URL ",
            vm.toString(address(vault)),
            ' "',
            getter,
            '(address)"   # must print ',
            vm.toString(expected)
        );
    }
}
