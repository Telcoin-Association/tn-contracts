# Uniswap V3 pre-compiled bytecode

This directory holds the deploy-time bytecode for every V3 contract we
deploy via Arachnid CREATE2. The shape mirrors `external/uniswap/precompiles/`
for V2, which carries `UniswapV2FactoryBytecode.sol` and
`UniswapV2Router02Bytecode.sol` as `bytes constant` literals.

## Why bytecode files instead of source

V3 source is **Solidity 0.7.6**. `tn-contracts` pins `solc = "0.8.26"` with
`auto_detect_solc = false`. Compiling V3 source inline would either require
flipping `auto_detect_solc = true` (adds compilation cost to every build,
risks subtle ABI / storage drift) or maintaining a separate Foundry profile
just for V3. Shipping pre-compiled bytecode literals is the same approach
V2 uses today, keeps the build dependency footprint flat, and gives us
deterministic CREATE2 addresses across every deploy.

## Files this directory will hold

| File | Constant exported | Purpose |
|---|---|---|
| `UniswapV3FactoryBytecode.sol` | `UNISWAPV3FACTORY_BYTECODE` | Factory creation code |
| `NFTDescriptorBytecode.sol` | `NFTDESCRIPTOR_BYTECODE` | NFTDescriptor library |
| `NonfungibleTokenPositionDescriptorBytecode.sol` | `NONFUNGIBLE_TOKEN_POSITION_DESCRIPTOR_BYTECODE` | Position-NFT renderer |
| `NonfungiblePositionManagerBytecode.sol` | `NONFUNGIBLE_POSITION_MANAGER_BYTECODE` | Position-NFT mint / collect / burn |
| `SwapRouter02Bytecode.sol` | `SWAP_ROUTER_02_BYTECODE` | V2 + V3 router |
| `QuoterV2Bytecode.sol` | `QUOTER_V2_BYTECODE` | Off-chain quote helper |
| `TickLensBytecode.sol` | `TICK_LENS_BYTECODE` | Tick liquidity reader |

`TestnetDeployUniswapV3.s.sol` will import all seven and feed them through
the existing Arachnid CREATE2 deployer.

## Refresh recipe (canonical bytecode)

The bytecode in these files MUST match what Uniswap published on mainnet.
Init-code hashes are load-bearing: any indexer / front-end that knows the
canonical hash will not find pools deployed with a different one. Recipe:

1. **Pin the source release.** Use `@uniswap/v3-core@1.0.0` and
   `@uniswap/v3-periphery@1.4.4` from npm. These are the canonical mainnet
   versions. Do not use a release candidate or a fork; the SwapRouter02
   address derivation in particular hardcodes the Pool init-code hash.
2. **Match the optimizer settings.** Uniswap mainnet was compiled with
   Solidity 0.7.6, optimizer enabled, **800 runs** for v3-core (`Pool` and
   `Factory`) and **1_000_000 runs** for v3-periphery (NPM, SwapRouter02,
   QuoterV2, etc.). These settings are baked into Uniswap's
   `hardhat.config.ts` files in the published packages.
3. **Extract bytecode from the published artifacts.** Each Uniswap npm
   package ships `artifacts/contracts/<Name>.sol/<Name>.json` with a
   `bytecode` field. Copy the hex string (minus the `0x` prefix) into the
   matching `<Name>Bytecode.sol` constant in this directory.
4. **Verify the init-code hash.** For the Factory, the published Pool
   init-code hash is `0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54`
   (mainnet canonical). Confirm this in the Factory's bytecode dump or by
   recomputing `keccak256(creationCode)` after compile.
5. **Pin everything in commit messages.** Reference the npm tag, the
   compile recipe, and the init-code hash in the commit that lands the
   bytecode files. This is the single point where canonicality is verified;
   it MUST be reviewable from the commit alone.

## What happens until these files exist

`TestnetDeployUniswapV3.s.sol` reverts at `run()` with a clear message
pointing back here. The orchestrator script
(`script/bash/deploy-testnet-infra.sh`) gates the V3 step on the existence
of `UniswapV3FactoryBytecode.sol` in this directory and prints a
"Uniswap V3 bytecode not populated, deferring..." message instead of
running the script. So the V3 step is harmless on the foundation commit
and lights up automatically when the bytecode files land.

## Lineage

- `external/uniswap/precompiles/UniswapV2FactoryBytecode.sol` and
  `UniswapV2Router02Bytecode.sol` are the format template; mirror them.
- See `script/testnet/deploy/UNISWAP_V3_V4.md` for the broader deploy strategy
  and the collision-avoidance plan with the in-flight faucet branch.
