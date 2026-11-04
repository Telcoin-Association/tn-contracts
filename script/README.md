# Scripts

## Genesis Precompile Config Generation

**`GenerateGenesisPrecompileConfig.s.sol`** generates `deployments/genesis/precompile-config.yaml`, which Telcoin Network protocol uses to instantiate contracts at genesis.

### What it does

Writes every genesis account (54 in total) to the YAML: addresses, nonces, balances, bytecode, and storage slots.

**Canonical Safe v1.4.1 suite** (13 contracts, byte-exact runtime bytes vendored under `deployments/genesis/canonical-bytecode/` — see its README for provenance and hashes), etched at the canonical cross-chain addresses:

- **Safe / SafeL2 singletons** - the L1 and event-emitting L2 implementation contracts, each with its constructor's `threshold = 1` storage replicated
- **SafeProxyFactory** - CREATE2 factory for Safe proxies; canonical bytes make counterfactual (multichain) Safe creations land at the same address on TN as on Ethereum/Sepolia/Base
- **CompatibilityFallbackHandler** - default Safe fallback handler (EIP-1271 signature validation, token callbacks), pinned to `0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99` so Safe tooling that defaults the fallback handler resolves it on TN
- **SafeToL2Setup** - setup-time delegatecall target that switches counterfactual Safes onto SafeL2 (`block.chainid != 1`)
- **MultiSend / MultiSendCallOnly / SignMessageLib / CreateCall / SimulateTxAccessor** - the delegatecall libraries of the v1.4.1 registry
- **SafeMigration / SafeToL2Migration** - singleton migration helpers, completing the full 12-contract v1.4.1 [safe-deployments](https://github.com/safe-global/safe-deployments/tree/main/src/assets/v1.4.1) registry
- **SafeSingletonFactory** - Safe's deterministic CREATE2 factory, so future canonical Safe contracts can be deployed permissionlessly at parity addresses; its deployer EOA (`0xE1CB04A0…3cBC37`) is included at nonce 1 to mark the presigned deployment tx as spent

**Safe passkey module** (safe-modules `modules/passkey` v0.2.1, 5 contracts, byte-exact runtime bytes vendored in the same directory) - `SafeWebAuthnSignerFactory`, `SafeWebAuthnSignerSingleton`, `SafeWebAuthnSharedSigner` and the P-256 fallback verifiers `DaimoP256Verifier` and `FCLP256Verifier`, etched at their canonical addresses so a passkey (WebAuthn) Safe owner's counterfactual signer address is the same on TN as on Ethereum/Polygon/Base. None has storage. The factory is written at nonce 2, because its constructor `CREATE`d the singleton at nonce 1; the other four use nonce 1. Their deployers (the Safe Singleton Factory, the Arachnid proxy, and the passkey factory itself) are already in genesis, so no deployer EOA is added. `test/genesis/GenesisPasskeyParity.t.sol` proves the signer-address parity and runs WebAuthn verification through the Daimo fallback, since TN has no P-256 precompile.

**Other canonical infrastructure** (byte-exact Ethereum runtime bytes, one subdirectory of `deployments/genesis/canonical-bytecode/` per batch), etched so the addresses wallets, SDKs and bundlers hardcode work from block 0:

- **Safe v1.3.0 suite** (13 accounts) - both singletons at their canonical and eip155 addresses, each with `threshold = 1`, plus the proxy factory, fallback handler, MultiSend and MultiSendCallOnly (canonical and eip155), SignMessageLib, CreateCall and SimulateTxAccessor. The v1.3.0 proxy factories do not check that the singleton has code and anyone can deploy them, so a counterfactual v1.3.0 Safe address could be claimed on a chain where the singletons arrive later; in genesis they never arrive late. Real v1.3.0 Safes created on other chains (for example the Polygon Safe `0x583D596b…90B2`) land at the same address on TN
- **CreateX** - at `0xba5Ed099…ba5Ed`. After genesis it could arrive only through its author's presigned nonce-0 transaction (100 gwei gas price, a top-up to a third-party EOA), so it is etched and that deployer EOA (`0xeD456e05…F352b5`) is included at nonce 1 to mark the transaction spent
- **ERC-4337 EntryPoints v0.6, v0.7 and v0.8** with the SenderCreator each one's constructor creates. The EntryPoints are written at nonce 2 (their constructors `CREATE`d the SenderCreator at nonce 1); v0.6 and v0.7 carry their reentrancy guard's `NOT_ENTERED` in slot 2. v0.8 is the EIP-7702-aware version, and TN has EIP-7702 from genesis
- **Permit2** - the token-approval layer routers and aggregators expect at `0x000000000022D473…8BA3`
- **Safe 4337 module v0.3.0** - `Safe4337Module` and `SafeModuleSetup`, which with the v1.4.1 suite and EntryPoint v0.7 let a Safe act as an ERC-4337 account

EntryPoint v0.8 and Permit2 cache chain id 1 and Ethereum's EIP-712 domain separator in their bytes, and rebuild the separator from `block.chainid` on any other chain; genesis keeps the Ethereum bytes so `cast code` matches Ethereum. One test file per batch under `test/genesis/` pins every hash, checks the yaml entries, replays the original Ethereum creation code to confirm the etched storage and nonces, and runs each contract under the Adiri chain id, standing in for any chain other than Ethereum (a v1.3.0 Safe, user operations through all three EntryPoints and through a 4337 Safe, CREATE2/CREATE3 through CreateX, a Permit2 permit).

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

## Mainnet Post-Genesis Scripts

Scripts under `script/mainnet/deploy/` land the infrastructure that mainnet needs after
genesis and that genesis cannot carry, because its addresses and owner arguments are
specific to Telcoin Network. Each one does a single job and runs on its own:

| Script | Deploys | Depends on |
| ------ | ------- | ---------- |
| `MainnetDeployUniswapV2.s.sol` | UniswapV2Factory and UniswapV2Router02 (no pairs) | genesis WTEL |
| `MainnetDeployUniswapV3.s.sol` | UniswapV3Factory and the v3-periphery set (no pools) | genesis WTEL, Uniswap V2 |

The canonical cross-chain contracts (Safe v1.3.0, CreateX, the ERC-4337 EntryPoints,
Permit2, the Safe 4337 module) are in genesis, described above, so they need no script.

`MainnetDeployBase.sol` gives every script the same guarantees:

- **Mainnet only.** A script refuses to run until `DeploymentsResolver.MAINNET_CHAIN_ID`
  is set, then runs only against that chain. It reads `deployments-mainnet.json`
  directly; the resolver's fallback for unknown chain ids is the testnet file.
- **Idempotent.** Every contract lands at a deterministic address. A script predicts
  each address first and skips anything that already has code, so a re-run sends no
  transactions and a front-run with identical initcode changes nothing.
- **Canonical by construction.** The Uniswap contracts are deployed from the vendored
  bytecode under `external/uniswap/precompiles/`, with the V3 factory's creation code
  hash-checked before deployment and the V2 factory's runtime after, so V2 pairs and
  V3 pools derive from the canonical init code hashes.
- **No privileged deployer.** Owner-gated roles go to the genesis governance Safe
  inside the deploy itself: V2's `feeToSetter` is a constructor argument, and the V3
  factory is created by `script/utils/UniswapV3FactoryDeployer.sol`, which enables the 0.01%
  fee tier and hands ownership to governance in the same transaction. The
  broadcasting key only pays gas, so any funded account can run these scripts.
- **Records only real deployments.** The address book is written only with
  `--broadcast`; a dry run leaves it untouched.

### Running mainnet scripts

Dry-run first, then broadcast with `--slow` so each transaction is confirmed before the
next is sent:

```bash
forge script script/mainnet/deploy/<ScriptFile>.s.sol \
  --rpc-url $TN_MAINNET_RPC_URL \
  --private-key $DEPLOYER_PK \
  -vvvv            # dry run

forge script script/mainnet/deploy/<ScriptFile>.s.sol \
  --rpc-url $TN_MAINNET_RPC_URL \
  --private-key $DEPLOYER_PK \
  --broadcast --slow -vvvv
```

**Uniswap V3 needs V2 first.** SwapRouter02 routes across both and takes the V2
factory as a constructor argument.

`test/mainnet/MainnetDeploy.t.sol` runs every script against a replay of mainnet
genesis, each alone, then again to prove a re-run is a no-op, and checks the results
end to end (governance owns the V3 factory and V2's fee switch, and V2 pairs and V3
pools land at the canonical init code hash addresses).

### Not covered here

- **LayerZero TEL bridge.** `NativeBridge`, the Telcoin Network side of the TEL OFT
  mesh, is deployed and peered by the `tel-v3` bridge pipeline. It needs LayerZero's
  EndpointV2, message libraries, executor and DVNs live on Telcoin Network first, so
  it follows LayerZero's own deployment to the chain. On mainnet the bridge holds the
  native TEL that backs bridged supply, so funding its reserve is part of that rollout.

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

Genesis-assigned addresses (Safe infrastructure, ConsensusRegistry, magic addresses) are identical across networks because all networks share the same genesis configuration. `deployments-mainnet.json` is the genesis source of truth consumed by `GenerateGenesisPrecompileConfig`; its non-genesis keys stay zeroed until the mainnet scripts above actually deploy those contracts. The mainnet scripts address this file explicitly rather than through the resolver.

Devnet is reset frequently, so its file starts with only the genesis-assigned addresses plus canonical CREATE2 deployments like Permit2. Script-deployed addresses are zeroed after each reset and repopulated by the deploy scripts, which write their results back to the resolved file so subsequent scripts pick up the correct addresses. At the next reset, also set `WTEL` to its genesis vanity address `0x...37E1` (the current value is a pre-genesis CREATE2 deployment). Any other chain id (including local simulations and tests) falls back to the testnet file, preserving prior behavior.

The bash pipeline (`script/bash/deploy-testnet-infra.sh`, `script/bash/test-faucet-drips.sh`) applies the same chain-id rule; point `TN_RPC_URL` (or `RPC` for the faucet script) at a devnet node to run against devnet.
