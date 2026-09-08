# Scripts

## Genesis Precompile Config Generation

**`GenerateGenesisPrecompileConfig.s.sol`** generates `deployments/genesis/precompile-config.yaml`, which Telcoin Network protocol uses to instantiate contracts at genesis.

### What it does

Simulates deployment of the following contracts, captures their storage layout, and writes a YAML file with addresses, bytecode, and storage slots:

- **Safe singleton** - the Gnosis Safe implementation contract
- **SafeProxyFactory** - factory for creating Safe proxies
- **CompatibilityFallbackHandler** - default Safe fallback handler (EIP-1271 signature validation, token callbacks), pinned to the canonical Safe v1.4.1 address `0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99` so Safe tooling that defaults the fallback handler resolves it on TN
- **Governance Safe** - a 3-of-7 multisig proxy configured with hardcoded owner addresses and threshold, referencing the CompatibilityFallbackHandler
- **WTEL** - wrapped TEL (canonical WETH9 shape), genesis-assigned at the vanity address `0x00000000000000000000000000000000000037E1`. Live testnet and devnet predate this entry and keep their CREATE2 deployments until their next regenesis/reset
- **TEL supply allocation** - assigns the remaining TEL supply to `0xde1e7e`
- **EIP-2935 / EIP-4788** - system contracts for historic block hashes and beacon block roots
- **Multicall3** - deployed at `0xcA11bde05977b3631167028862bE2a173976CA11`

### When to run

Re-run this script **any time you change**:

- Governance safe owner addresses or threshold (`_setGovernanceSafeConfig()`)
- Safe contract dependencies (implementation, proxy factory, fallback handler)
- TEL supply constants (`telTotalSupply`, `governanceInitialBalance`)
- Addresses in `deployments/deployments-mainnet.json` that the script reads (e.g., `Safe`, `SafeImpl`, `SafeProxyFactory`, `CompatibilityFallbackHandler`)
- System contract bytecode (EIP-2935, EIP-4788)

### How to run

```bash
forge script script/GenerateGenesisPrecompileConfig.s.sol -vvvv
```

No RPC URL or private key is needed - it runs entirely locally. The output is written to `deployments/genesis/precompile-config.yaml`.

After running, review the diff to verify the changes are correct:

```bash
git diff deployments/genesis/precompile-config.yaml
```

---

## Shield Vault Deployment

**`DeployShieldVault.s.sol`** deploys a `ShieldVault` for one eXYZ stablecoin: the public-side contract that burns tokens on `shield` and mints them on `unshield` against the TN-SHIELD precompile.

### What it does

- Resolves the chain's deployments file by chain id (`deployments/DeploymentsResolver.sol`) and refuses any chain id the resolver does not map, so a stale `--rpc-url` cannot deploy against the wrong network
- Checks that `SHIELD_TOKEN` is one of the file's `eXYZs` entries and reports that entry's symbol on-chain; the `StablecoinImpl` address is refused by name, because it answers the role reads like a token but administers nothing, so a vault bound to it would deploy cleanly and stay inert for good
- Reuses the chain's `ShieldVault` implementation, recorded under `ShieldVaultImpl` in the deployments file, and deploys it via CREATE2 (salt `ShieldVault`) when there is none; its constructor locks it with `_disableInitializers`
- Deploys an `ERC1967Proxy` initialized with `initialize(token, owner)` via CREATE2, salted on the token, the owner being the governance safe unless explicitly overridden; a re-run for the same token finds the proxy already deployed and only completes what is missing
- Prints the token's `MINTER_ROLE` and `BURNER_ROLE` grants to the proxy for the token admin, or makes them itself when `SHIELD_GRANT_INLINE=true` and the broadcaster administers those roles on the token
- Records the implementation under `ShieldVaultImpl` and the proxy under `shieldVaults.<symbol>` in the deployments file
- Logs the implementation and proxy addresses and the remaining checklist
- Warns when the precompile account has no code on the target chain; the vault refuses `shield` and `unshield` with `PrecompileNotLive` until the TN-SHIELD fork injects it, so nothing can be shielded yet (what makes an early role grant safe is the owner check, not this refusal: every other guard on the mint path lives in vault code the owner can replace by upgrade)

One vault is deployed per token, so run the script once per stablecoin.

### Parameters

| Env var                       | Value                                                                                                                                                                                                                                            |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SHIELD_TOKEN`                | The eXYZ `Stablecoin` proxy the vault shields; must be listed under `eXYZs` in the resolved deployments file                                                                                                                                      |
| `SHIELD_VAULT_OWNER`          | Optional. The vault owner, which gates pause/unpause and upgrades. Defaults to the governance safe (`Safe` in the deployments file, `0x...07a0` on every network) and must equal it unless `SHIELD_ALLOW_NON_SAFE_OWNER` is set                    |
| `SHIELD_ALLOW_NON_SAFE_OWNER` | Optional, default `false`. Set to `true` to deploy with an owner other than the governance safe. Honoured on devnet only, enforced by chain id: a wrong owner is permanent, because ownership can never be renounced and only the owner can transfer it, and the owner's upgrade authority reaches the token's mint path |
| `SHIELD_GRANT_INLINE`         | Optional, default `false`. Set to `true` to grant the token roles (and, on a redeploy, revoke the superseded vault's) inline; the broadcaster must then hold the token's `DEFAULT_ADMIN_ROLE`                                                                                      |
| `SHIELD_SUPERSEDE`            | Required for a redeploy, refused otherwise. The vault recorded under `shieldVaults.<symbol>` that this run retires, exactly as the deployments file records it; any run whose vault address differs from the recorded one stops without it                                          |

The owner is set directly at initialization, with no acceptance step.
Later transfers are two-step (`transferOwnership`, then `acceptOwnership` by the new owner) and ownership can never be renounced.

### How to run

```bash
SHIELD_TOKEN=<stablecoin address> \
forge script script/DeployShieldVault.s.sol \
  --rpc-url $TN_RPC_URL \
  --private-key $DEPLOYER_PK \
  -vvvv --slow
```

Append `--broadcast` to send the transactions.
Without it forge only simulates, and the script then writes nothing, not even the address book, so a dry run before the broadcast is safe.
The address book is written during the simulation of a `--broadcast` (or `--resume`) run, before its transactions land; if a redeploy broadcast stops before its revoke has landed, restore the deployments file (`git checkout`) before running again, or the next run finds nothing to supersede.
The deployment needs no privilege, so use a plain deployer key.
The token's `DEFAULT_ADMIN_ROLE` key mints without limit and administers itself, and one vault is deployed per token, so exposing it for every run is a window that recurs 23 times; broadcast with it only when `SHIELD_GRANT_INLINE=true` is set on purpose, and otherwise hand the printed grants to whoever holds it.
Keep `--slow`: the role grants carry the proxy address computed in the simulation, and without it a reverted deployment would not stop them from being sent at their own nonces.

### After running

The vault is inert until two out-of-band steps complete, both printed by the script:

1. If the broadcaster did not administer the token's roles, the token admin grants `MINTER_ROLE` and `BURNER_ROLE` on the token to the proxy.
2. The governance safe registers the vault on the precompile with `setTokenConfig(token, vault, auditorKey)`; until then the precompile rejects the vault's `shield` and `unshield` calls.

The script's checks and logs describe forge's simulation, not the receipts, so confirm the real chain state before handing the address on.
The script prints the reads: `token()` and `owner()` on the proxy, and `hasRole` on the token for every role it granted, revoked, or left for the admin.
Every `cast send` it prints carries `--rpc-url` and `--chain`; the chain id goes into the signed transaction, so a command copied to another network's RPC is rejected by that node instead of appearing to succeed against an address that has no code there.

The implementation and proxy addresses are written to `ShieldVaultImpl` and `shieldVaults.<symbol>` in the resolved deployments file; commit that change with the deployment so both hand-offs read the address book rather than the terminal.

### Deterministic addresses

Both contracts go through the genesis-deployed CREATE2 deployer, so the vault address is a pure function of the implementation, the token, and the owner, and a run without `--broadcast` prints it before anything is sent.
That lets the governance safe collect its signatures on `setTokenConfig(token, vault, auditorKey)` in parallel with the deployment instead of after it, and gives every audit and verification one implementation to look at rather than one per token.

The implementation's address moves with any compiler or source change, and the proxies' addresses follow it because their initcode embeds it.
The script keeps using the recorded implementation while it has code, so all vaults on a chain share one, and warns when that implementation was not built from the current source.
Roll new code with a UUPS upgrade of the existing vaults; zero `ShieldVaultImpl` in the deployments file only if new vaults are meant to start on code the existing ones do not run.

### Redeploying

A redeploy is any run whose vault address differs from the one recorded under `shieldVaults.<symbol>`.
The address is a function of the recorded implementation, the token, and the owner, so a run becomes a redeploy not only on purpose (a recorded vault with a wrong owner, which nobody else can change) but also by drift: `ShieldVaultImpl` edited after a UUPS upgrade, or `SHIELD_VAULT_OWNER` omitted after an opted-in run.
Retiring the recorded vault is governance-visible, since the precompile registry points at it and `setTokenConfig` has to be redone, so the script refuses every redeploy unless `SHIELD_SUPERSEDE` names the recorded vault exactly; the refusal prints both vaults with their owners, and a `SHIELD_SUPERSEDE` that names nothing the run retires is refused too.
A redeploy also supersedes the recorded vault, which keeps its `MINTER_ROLE` and `BURNER_ROLE` on the token until someone revokes them.
Nothing else in the system points at it any more, so an unrevoked vault is mint authority that the precompile registry does not show.
Step zero of any redeploy is therefore the revoke:

- with `SHIELD_GRANT_INLINE=true` and the token admin broadcasting, the script revokes both roles from the recorded vault itself, as the first transaction of the run, before deploying and granting to the new one;
- otherwise it stops before deploying anything and prints the two `revokeRole` commands for the token admin; run them, then run the script again.

Only a recorded vault that still holds a role triggers this; one whose roles were already revoked is superseded silently.

---

## Testnet Scripts

All testnet scripts require `--rpc-url` and `--private-key` (or `--ledger`) to broadcast transactions.

### Management

| Script                                          | Purpose                                                                       |
| ----------------------------------------------- | ----------------------------------------------------------------------------- |
| `testnet/TestnetFundDeveloper.s.sol`            | Sends TEL and all 23 eXYZ stablecoins to a developer address                  |
| `testnet/TestnetGrantRole.s.sol`                | Grants `MINTER_ROLE` and `BURNER_ROLE` on all stablecoins to faucet addresses |
| `testnet/TestnetManageFaucet.s.sol`             | Enables or disables stablecoin faucet functionality on `StablecoinManager`    |
| `testnet/TestnetUpgradeStablecoinManager.s.sol` | Upgrades the `StablecoinManager` proxy to a new implementation                |

### Deployment

| Script                                                     | Purpose                                                                              |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `testnet/deploy/TestnetDeployTokens.s.sol`                 | Deploys the `Stablecoin` implementation and 23 eXYZ proxy instances via CREATE2      |
| `testnet/deploy/TestnetDeployStablecoinManager.s.sol`      | Deploys `StablecoinManager` implementation + ERC1967 proxy, initializes faucet roles |
| `testnet/deploy/TestnetDeployUniswapV2.s.sol`              | Deploys Uniswap V2 Factory, Router, and 45 trading pairs                             |
| `testnet/deploy/TestnetDeployGitAttestationRegistry.s.sol` | Deploys `GitAttestationRegistry` and initializes maintainer roles                    |

### Running testnet scripts

```bash
forge script script/testnet/<ScriptFile>.s.sol \
  --rpc-url $TN_RPC_URL \
  --private-key $ADMIN_PK \
  -vvvv
```

Append `--broadcast` to actually send transactions (without it, forge only simulates).

### Shared configuration

All scripts read contract addresses from a per-network deployments file, resolved by chain id via `deployments/DeploymentsResolver.sol`:

| Network | Chain id         | Deployments file                       | RPC shorthand (`--rpc-url <name>`)      |
| ------- | ---------------- | -------------------------------------- | --------------------------------------- |
| Testnet | `0x7e1` (2017)   | `deployments/deployments-testnet.json`  | `testnet` (node1.telcoin.network)        |
| Devnet  | `0x7e1d` (32285) | `deployments/deployments-devnet.json`   | `devnet` (node1.devnet.telcoin.network)  |
| Mainnet | TBD              | `deployments/deployments-mainnet.json`  | added once the chain id is finalized     |

Genesis-assigned addresses (Safe infrastructure, ConsensusRegistry, magic addresses) are identical across networks because all networks share the same genesis configuration. `deployments-mainnet.json` holds exactly those and nothing else, making it the genesis source of truth consumed by `GenerateGenesisPrecompileConfig`; non-genesis keys stay zeroed until contracts are actually deployed.

Devnet is reset frequently, so its file starts with only the genesis-assigned addresses plus canonical CREATE2 deployments like Permit2. Script-deployed addresses are zeroed after each reset and repopulated by the deploy scripts, which write their results back to the resolved file so subsequent scripts pick up the correct addresses. At the next reset, also set `WTEL` to its genesis vanity address `0x...37E1` (the current value is a pre-genesis CREATE2 deployment). Any other chain id (including local simulations and tests) falls back to the testnet file, preserving prior behavior.

The bash pipeline (`script/bash/deploy-testnet-infra.sh`, `script/bash/test-faucet-drips.sh`) applies the same chain-id rule; point `TN_RPC_URL` (or `RPC` for the faucet script) at a devnet node to run against devnet.
