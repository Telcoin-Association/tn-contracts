# Scripts

## Genesis Precompile Config Generation

**`GenerateGenesisPrecompileConfig.s.sol`** generates `deployments/genesis/precompile-config.yaml`, which Telcoin Network protocol uses to instantiate contracts at genesis.

### What it does

Writes every genesis account — 25 in total — to the YAML: addresses, nonces, balances, bytecode, and storage slots.

**Canonical Safe v1.4.1 suite** (13 contracts, byte-exact runtime bytes vendored under `deployments/genesis/canonical-bytecode/` — see its README for provenance and hashes), etched at the canonical cross-chain addresses:

- **Safe / SafeL2 singletons** - the L1 and event-emitting L2 implementation contracts, each with its constructor's `threshold = 1` storage replicated
- **SafeProxyFactory** - CREATE2 factory for Safe proxies; canonical bytes make counterfactual (multichain) Safe creations land at the same address on TN as on Ethereum/Sepolia/Base
- **CompatibilityFallbackHandler** - default Safe fallback handler (EIP-1271 signature validation, token callbacks), pinned to `0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99` so Safe tooling that defaults the fallback handler resolves it on TN
- **SafeToL2Setup** - setup-time delegatecall target that switches counterfactual Safes onto SafeL2 (`block.chainid != 1`)
- **MultiSend / MultiSendCallOnly / SignMessageLib / CreateCall / SimulateTxAccessor** - the delegatecall libraries of the v1.4.1 registry
- **SafeMigration / SafeToL2Migration** - singleton migration helpers, completing the full 12-contract v1.4.1 [safe-deployments](https://github.com/safe-global/safe-deployments/tree/main/src/assets/v1.4.1) registry
- **SafeSingletonFactory** - Safe's deterministic CREATE2 factory, so future canonical Safe contracts can be deployed permissionlessly at parity addresses; its deployer EOA (`0xE1CB04A0…3cBC37`) is included at nonce 1 to mark the presigned deployment tx as spent

**Governance and TEL**:

- **Governance Safe** - a 3-of-7 multisig proxy on the **SafeL2** singleton (so Safe Transaction Service can index it) with hardcoded owner addresses and threshold, referencing the CompatibilityFallbackHandler, funded with 10 TEL for gas. The rest of the TEL genesis allocation (validator stakes, issuance) happens in the node's genesis ceremony, not in this yaml
- **WTEL** - wrapped TEL (canonical WETH9 shape), genesis-assigned at the vanity address `0x00000000000000000000000000000000000037E1`. Live testnet and devnet predate this entry and keep their CREATE2 deployments until their next regenesis/reset
- **TEL precompile** - `0x…07e1` gets one byte of code (`0xfe`) so EXTCODESIZE checks pass before the native Rust handler takes over

**Deterministic-deployment infrastructure**, each with its deployer EOA at nonce 1 (presigned/keyless creation tx marked spent):

- **EIP-2935 / EIP-4788** - system contracts for historic block hashes and beacon block roots, plus their two deployer EOAs
- **Multicall3** - `0xcA11bde05977b3631167028862bE2a173976CA11`, plus its deployer EOA
- **Arachnid proxy** - the standard CREATE2 deterministic deployment proxy at `0x4e59b448…956C`, plus its keyless deployer EOA

### When to run

Re-run this script **any time you change**:

- Governance safe owner addresses or threshold (`_setGovernanceSafeConfig()`)
- Vendored canonical bytecode under `deployments/genesis/canonical-bytecode/` (the generator asserts each file's keccak256 before etching)
- Addresses in `deployments/deployments-mainnet.json` that the script reads (e.g., `Safe`, `SafeImpl`, `SafeProxyFactory`, `CompatibilityFallbackHandler`)
- System contract bytecode (EIP-2935, EIP-4788)
- The governance Safe's genesis balance (`governanceInitialBalance`)

### How to run

```bash
forge script script/GenerateGenesisPrecompileConfig.s.sol -vvvv
```

No RPC URL or private key is needed - it runs entirely locally. The output is written to `deployments/genesis/precompile-config.yaml`.

After running, review the diff to verify the changes are correct:

```bash
git diff deployments/genesis/precompile-config.yaml
```

CI regenerates the yaml and fails on any diff against the committed file
(`Check genesis precompile-config.yaml drift` in `.github/workflows/test.yml`),
so a generator change merged without re-running the script — or a hand-edit to
the yaml — cannot land silently.

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
