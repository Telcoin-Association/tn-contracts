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

- Deploys the `ShieldVault` implementation (its constructor locks it with `_disableInitializers`)
- Deploys an `ERC1967Proxy` initialized with `initialize(token, owner)`
- Grants the token's `MINTER_ROLE` and `BURNER_ROLE` to the proxy when the broadcaster administers those roles on the token, and otherwise prints the two grant calls for the token admin
- Logs the implementation and proxy addresses and the remaining checklist

One vault is deployed per token, so run the script once per stablecoin.

### Parameters

| Env var              | Value                                                                                                                                  |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `SHIELD_TOKEN`       | The eXYZ `Stablecoin` proxy the vault shields                                                                                          |
| `SHIELD_VAULT_OWNER` | The vault owner, which gates pause/unpause and upgrades; intended to be the governance safe (`Safe` in the network's deployments file) |

### How to run

```bash
SHIELD_TOKEN=<stablecoin address> SHIELD_VAULT_OWNER=<governance safe> \
forge script script/DeployShieldVault.s.sol \
  --rpc-url $TN_RPC_URL \
  --private-key $ADMIN_PK \
  -vvvv
```

Append `--broadcast` to actually send transactions (without it, forge only simulates).

### After running

The vault is inert until two out-of-band steps complete, both printed by the script:

1. If the broadcaster did not administer the token's roles, the token admin grants `MINTER_ROLE` and `BURNER_ROLE` on the token to the proxy.
2. The governance safe registers the vault on the precompile with `setTokenConfig(token, vault, auditorKey)`; until then the precompile rejects the vault's `shield` and `unshield` calls.

The script does not write to the deployments file (there is no `ShieldVault` entry in it); record the logged proxy address wherever the token's deployment is tracked.

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
