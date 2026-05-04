# Uniswap V3 + V4 on Telcoin Network

This document captures the deploy strategy, dependency policy, and on-chain
invariants for the V3 and V4 deployments on Adiri Testnet (chainId 2017).
It is the prose counterpart of the deploy scripts under
`script/testnet/deploy/TestnetDeployUniswapV3.s.sol` and
`TestnetDeployUniswapV4.s.sol`.

## Why both, and why now

V2 is already deployed and works for the base swap and LP cases, but it has
two structural limitations on this chain:

1. **Solidity 0.5.16 codesize guard.** `UniswapV2Pair` uses high-level
   `IERC20(token0).balanceOf(address(this))` calls inside `mint` / `burn` /
   `swap`. Solidity 0.4.22+ wraps every high-level external call with an
   `extcodesize > 0` guard. The TEL_MINT precompile at `0x07e1` has zero
   EVM bytecode by construction, so any V2 pool involving wTEL reverts at
   the codesize guard inside `Pair.mint` with no return data. The fix on the
   V2 side is to register a stub of EVM bytecode at the precompile (same
   trick used for the StablecoinManager TEL-mint path), but that is a
   chain-side change with its own coordination cost.
2. **No concentrated liquidity, no hooks.** V2's single-pool-per-pair model
   is fine for stable-stable, less fine for native TEL pairs where the
   price discovery is wider. V3's fee tiers and tick-range positions and
   V4's hooks both buy us functionality we want for the Telcoin Network
   swap experience.

V3 and V4 sidestep the codesize guard naturally - their pool / pool-manager
logic uses low-level `staticcall` for `balanceOf` and decodes the result
manually, so the extcodesize check the Solidity compiler injects on
high-level calls never fires. The precompile works against V3/V4 today,
without waiting on a chain-side bytecode-stub deploy.

## Solidity-version policy

| Layer | Source language | How we ship it |
|---|---|---|
| V2 (already deployed) | 0.5.16 / 0.6.6 | Pre-compiled bytecode literals under `external/uniswap/precompiles/` |
| V3 (this branch) | 0.7.6 | Pre-compiled bytecode literals under `external/uniswap/precompiles/v3/` |
| V4 (this branch) | 0.8.26 | Pre-compiled bytecode literals under `external/uniswap/precompiles/v4/` |
| Permit2 (this branch) | 0.8.17 | Pre-compiled bytecode literal under `external/uniswap/precompiles/v4/Permit2Bytecode.sol` |

`foundry.toml` pins `solc = "0.8.26"` and `auto_detect_solc = false`. We do
not change either. Every Uniswap layer therefore ships as deterministic
CREATE2 deployments of pre-compiled bytecode via Arachnid.

V4 *can* compile under 0.8.26 in principle, but Uniswap's own
`foundry.toml` for v4-periphery requires `via_ir = true` plus a
44_444_444 optimizer-runs target (with per-file overrides for
`PositionManager` and `PositionDescriptor` via `compilation_restrictions`).
Enabling `via_ir = true` at tn-contracts' project level crashes solc on
Windows; scoping `via_ir` to the v4 paths via Foundry's
`compilation_restrictions` errors with "Missing profile satisfying
settings restrictions" because the V4 deploy script's imports drag
type definitions across compile-unit boundaries that Foundry can't
reconcile under our pinned version. Treating V4 the way we treat V2
and V3 (CREATE2-deploy of pre-compiled bytecode) sidesteps the
compile-config problem entirely while preserving the canonical Uniswap
mainnet release behavior.

The bytecode files are extracted from canonical Uniswap sources via
`fetch-uniswap-v3-bytecode.sh` and `fetch-uniswap-v4-bytecode.sh`. The
V3 fetch pulls from npm (canonical 1.0.0 / 1.4.4 / 1.3.0 packages); the
V4 fetch builds `lib/v4-periphery` in place under its own `foundry.toml`
and pulls the resulting artifacts. Init-code hashes must match canonical
mainnet so any indexer or analytics tool that knows Uniswap pool address
derivation works against this chain unchanged.

## Deployment ordering

The V3 and V4 deploys slot into `script/bash/deploy-testnet-infra.sh` as
new steps after the existing V2 step. The orchestrator's `has_code` check
gives us free idempotency and re-runs are safe.

Step layout after this branch lands:

| # | Step | Script |
|---|---|---|
| 1 | Stablecoin tokens (23 eXYZ ERC20s) | `TestnetDeployTokens.s.sol` |
| 2 | StablecoinManager (faucet) | `TestnetDeployStablecoinManager.s.sol` |
| 3 | GitAttestationRegistry | `TestnetDeployGitAttestationRegistry.s.sol` |
| 4 | Uniswap V2 (factory + router + 45 pools) | `TestnetDeployUniswapV2.s.sol` |
| 5 | **Uniswap V3** (factory + periphery, no pools) | `TestnetDeployUniswapV3.s.sol` |
| 6 | **Uniswap V4** (Permit2 + PoolManager + periphery) | `TestnetDeployUniswapV4.s.sol` |
| 7 | Grant faucet roles | `TestnetGrantRole.s.sol` |

Run order **inside** `TestnetDeployUniswapV3.s.sol`:

1. `UniswapV3Factory` (deterministic via Arachnid).
2. `NFTDescriptor` library.
3. `NonfungibleTokenPositionDescriptor` (proxied to NFTDescriptor).
4. `NonfungiblePositionManager` (constructor: factory, wTEL, descriptor).
5. `SwapRouter02` (constructor: factory v2, factory v3, position manager, wTEL).
   We point factory v2 at the existing `uniswapV2.UniswapV2Factory` so the
   universal router can route across both V2 and V3 pools.
6. `QuoterV2` (constructor: factory, wTEL).
7. `TickLens`.

Run order **inside** `TestnetDeployUniswapV4.s.sol`:

1. **Permit2** - skip if already at the canonical address
   `0x000000000022D473030F116dDEE9F6B43aC78BA3`. Otherwise deploy via
   Arachnid with the canonical salt so the address matches every other
   chain. Permit2 ships as a bytecode literal under
   `external/uniswap/precompiles/v4/Permit2Bytecode.sol` because the
   canonical CREATE2 address is recipe-pinned to a specific compiled
   bytecode hash; recompiling the source under our 0.8.26 settings would
   shift the deterministic address off canonical.
2. `PoolManager` (singleton, constructor: protocol fee controller).
3. `PositionManager` (constructor: pool manager, permit2, wTEL, descriptor).
4. `V4Quoter` (constructor: pool manager). Off-chain price-impact /
   amount-out preview, mirrors V3 `QuoterV2`'s role.
5. `StateView` (constructor: pool manager). Read-only state accessor for
   slot0, liquidity, ticks, and positions; lets the swap UI fetch state
   without entering the PoolManager unlock pattern.

**UniversalRouter is intentionally NOT deployed here.** As of this
foundation commit, no tagged release of `Uniswap/universal-router`
includes V4 routing - the V4-aware build lives on a non-canonical
branch (`add-v4-routing` and similar). We defer UniversalRouter until
Uniswap tags a V4-aware release so we can pin against canonical mainnet
rather than a moving branch HEAD. The swap UI in the meantime composes
V4 swaps via direct `PoolManager.unlock` callbacks plus V4Quoter for
previews and StateView for state reads. UniversalRouter will land in a
later commit that adds it to `Deployments.sol` + `deployments.json` +
this script + the orchestrator.

V4 hook ecosystem is not deployed here - hooks are tenant-deployed.

## Pinning recipe (canonical Uniswap release versions)

| Repo | Pin | Why |
|---|---|---|
| `@uniswap/v3-core` | npm `1.0.0` | Canonical mainnet V3 core |
| `@uniswap/v3-periphery` | npm `1.4.4` | Canonical mainnet V3 periphery |
| `@uniswap/swap-router-contracts` | npm `1.3.0` | Canonical mainnet `SwapRouter02` |
| `Uniswap/v4-core` | tag `v4.0.0` (commit `e50237c43811bd9b526eff40f26772152a42daba`) | Canonical mainnet V4 core |
| `Uniswap/v4-periphery` | commit `9dafaaecc1e2e1e824eda9d941085f96517d827b` (no release tags exist; pinned to `main` HEAD as of 2026-05-03) | Best available canonical reference |
| `Uniswap/permit2` | tag `0x000000000022D473030F116dDEE9F6B43aC78BA3` (commit `cc306b601f172c51bc04334a109e98340456620b`) | Tag name IS the canonical universal address |
| `Uniswap/universal-router` | DEFERRED | No tagged release includes V4 yet |

The V3 + Permit2 pins ship as pre-compiled bytecode literals under
`external/uniswap/precompiles/`. The V4 pins ship as forge-installed
submodules under `lib/v4-core` and `lib/v4-periphery`, compiled inline
since their source language is 0.8.x.

## Orchestrator integration

Both new steps follow the existing `has_code` pattern:

```bash
if has_code ".uniswapV3.UniswapV3Factory"; then
    echo "[Step 5/7] Uniswap V3 already deployed, skipping..."
elif [[ ! -f "external/uniswap/precompiles/v3/UniswapV3FactoryBytecode.sol" ]]; then
    echo "[Step 5/7] Uniswap V3 bytecode not populated, deferring..."
else
    forge script script/testnet/deploy/TestnetDeployUniswapV3.s.sol ...
fi
```

The "deferred" branch lets the foundation commit ship without populated
V3 bytecode files. Once the bytecode files land in
`external/uniswap/precompiles/v3/`, the next orchestrator run picks up
where it left off. Same idea for V4 with a `lib/v4-core` directory check.

## Pool initialization

**Strategy: infra-only.** This deploy script registers the V3 / V4 contracts
and their addresses, but does **not** create initial pools or fee tiers.
Liquidity providers initialize pools via the swap UI or directly through
`NonfungiblePositionManager.mint` (V3, which lazy-creates pools at first
mint per fee tier) or `PoolManager.initialize` (V4).

This contrasts with V2's `TestnetDeployUniswapV2.s.sol`, which proactively
creates 45 pairs at deploy time. V2's flat `getPair(tokenA, tokenB)`
mapping makes the upfront seeding cheap and predictable. V3's
`(tokenA, tokenB, fee)` keyspace and V4's `PoolKey { tokens, fee, tickSpacing, hooks }`
keyspace explode the surface area enough that opinionated upfront seeding
would lock in fee-tier choices before liquidity providers tell us what they
actually want. Letting LPs initialize is also closer to how mainnet V3 / V4
operate.

For mainnet the strategy may flip: a small seeded set of canonical pools
(e.g. wTEL/eUSD at 500 bps, eUSD/eEUR at 100 bps) gives first-mover
liquidity providers a deterministic place to land.

## wTEL handling

Both V3 and V4 take `wTEL` (the `WETH9` constructor argument on V3
periphery, the `weth9` argument on V4 periphery) as the address that wraps
the chain's native token. We pass `magicAddresses.TEL_MINT_PRECOMPILE`
(`0x00000000000000000000000000000000000007e1`).

Operationally this means:
- V3 / V4 pools that include native TEL hold balances against the
  precompile address.
- The precompile must implement `balanceOf`, `transferFrom`, `approve`,
  `allowance`, and `decimals` (the IERC20 surface used by V3 pool /
  V4 PoolManager via `staticcall`).
- The precompile does NOT need a bytecode stub for V3 / V4 to function.
  It does still need one for V2 to function with native TEL pairs - so if
  we leave V2 in place after V3 / V4 ship, the bytecode stub is still
  worth landing for V2's sake.

## Precompile capability matrix (verified on Adiri 2026-05-04)

The TEL_MINT precompile at `0x07e1` was probed via `cast call` and
Multicall3-chained `eth_call` against the live chain. Findings:

| Method | Behavior | V3 / V4 implication |
|---|---|---|
| `name()` | returns `"Telcoin"` | Used by NFT descriptor, fine |
| `symbol()` | returns `"TEL"` | Used by NFT descriptor, fine |
| `decimals()` | returns `18` | Required by V3 NFT descriptor + V4 PositionDescriptor |
| `totalSupply()` | returns small number (~11e18 at probe time, not actual circulating) | Not consumed by V3 / V4 hot paths |
| `balanceOf(addr)` | returns `addr`'s **native** balance | "balance == native" semantics; users already have wTEL by holding TEL |
| `approve(spender, amount)` | returns true, **persists allowance** in precompile storage | OK |
| `allowance(owner, spender)` | reads back exactly what `approve` set | OK |
| `transferFrom(from, to, amount)` | **moves native balance** from `from` to `to`, decrements allowance | OK |
| `transfer(to, amount)` | moves native, no approval needed | OK |
| `deposit() payable` | **REVERTS with `PrecompileError`** | UI must NOT call wrap-in-flight paths |
| `withdraw(uint256)` | **REVERTS with `PrecompileError`** | UI must NOT call unwrap paths |

The deposit / withdraw reverts are the load-bearing constraint for the
swap UI design. Because the precompile uses "balance == native"
semantics, users implicitly have wTEL just by holding TEL - no wrap
step is needed or possible. Any V3 / V4 router code path that internally
calls `IWETH9.deposit{value:}` or `IWETH9.withdraw` will revert against
this precompile.

The integration test under `test/uniswap/V3IntegrationFork.t.sol` etches
a `MockTelMintPrecompile` at `0x07e1` whose `deposit` / `withdraw` DO
work, so don't read fork-test green as proof that wrap-in-flight paths
work on the real chain. The test's actual LP and swap operations do not
exercise deposit / withdraw, only `transferFrom` + `balanceOf`, so those
results are faithful to real-chain behavior.

### Forbidden V3 router calls on the swap UI side

The swap UI for V3 MUST avoid every router function that wraps or
unwraps in flight, since each calls `IWETH9.deposit` or
`IWETH9.withdraw` internally:

- `SwapRouter02.exactInputSingle{value: X}(...)` with native TEL input
- `SwapRouter02.exactInput{value: X}(...)` with native TEL input
- `SwapRouter02.unwrapWETH9(...)` and `unwrapWETH9WithFee(...)`
- `SwapRouter02.refundETH()`
- `NonfungiblePositionManager.createAndInitializePoolIfNecessary{value: X}(...)` with native TEL
- `NonfungiblePositionManager.mint{value: X}(...)` with native TEL leg
- `NonfungiblePositionManager.unwrapWETH9(...)` and `refundETH()`
- Any `multicall(...)` that bundles the above

### Permitted V3 calls

- `SwapRouter02.exactInputSingle(...)` and `exactInput(...)` without `value`
- `NonfungiblePositionManager.mint(MintParams { token0: wTEL, token1: eUSD, ... })` without `value`
- `NonfungiblePositionManager.increaseLiquidity(...)` without `value`
- `NonfungiblePositionManager.decreaseLiquidity(...)` and `collect(...)` (these don't touch IWETH9)
- `NonfungiblePositionManager.burn(...)`
- `QuoterV2.quoteExactInputSingle(...)` (off-chain quotes)

User flow becomes simpler than V2 - no wrap modal, no extra
transaction:
1. User calls `precompile.approve(router, amount)` once per token-pair-per-router
2. User calls `router.exactInputSingle({tokenIn: precompile, ...})` directly
3. Router pulls native via `transferFrom`, performs swap, returns the
   non-native side to the user

### V4 expectations

V4's `PoolManager.unlock` callback pattern uses low-level calls and the
PositionManager / V4Router intentionally don't have IWETH9 wrap helpers
(V4 prefers explicit Permit2 + token operations over wrap-in-flight),
so V4 should be similarly safe. The same caveats apply: avoid any path
that calls `deposit` or `withdraw` on the wTEL token.

## deployments.json schema

Pre-existing layout is preserved. New nested objects sit alongside
`uniswapV2`:

```jsonc
{
  // ... existing top-level keys unchanged ...
  "uniswapV2": { /* unchanged */ },
  "uniswapV3": {
    "NFTDescriptor": "0x...",
    "NonfungiblePositionManager": "0x...",
    "NonfungibleTokenPositionDescriptor": "0x...",
    "QuoterV2": "0x...",
    "SwapRouter02": "0x...",
    "TickLens": "0x...",
    "UniswapV3Factory": "0x..."
  },
  "uniswapV4": {
    "Permit2": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    "PoolManager": "0x...",
    "PositionManager": "0x...",
    "UniversalRouter": "0x..."
  }
}
```

`Deployments.sol` carries matching `UniswapV3` and `UniswapV4` structs.
Both struct files and the JSON keys are alphabetized with uppercase
identifiers first, per Foundry's `vm.parseJson` requirement.

## Operational notes

- **Init-code hash drift.** If we recompile the V3 bytecode files under
  different optimizer settings, the resulting pool init-code hash changes.
  That breaks `UniswapV3Factory.computeAddress` in any consumer (front-end,
  indexer, the SwapRouter02 itself) that hardcodes the canonical hash. The
  README under `external/uniswap/precompiles/v3/` pins the exact compile
  recipe to match mainnet. Treat it as a load-bearing constant.
- **Permit2 universality.** Permit2 is deployed at the same address on
  every chain because it's deployed via Arachnid with a fixed salt. We
  preserve that property. Any change here breaks compatibility with every
  off-chain tool that assumes `0x000000000022D473030F116dDEE9F6B43aC78BA3`.
- **UniversalRouter routing.** UniversalRouter takes a flag-encoded
  `commands` byte string. The front-end builds these commands per
  user-action; we don't need a chain-side change to add new command
  flavors, but we do need to keep the V2/V3 factory addresses passed at
  deploy time correct. Re-deploying any of those factories means
  re-deploying the UniversalRouter or routing breaks for that pool source.

## Open items (will land in follow-up commits)

- **Live deploy + writeback to `deployments.json`.** Both V3 and V4
  deploy scripts are structurally complete and should produce real
  addresses on first invocation. V3 has been sim'd against the Adiri
  fork (7 CREATE2 succeeded, ~17 TEL gas estimate) and against an
  etched-mock-precompile fork integration test (LP mint + swap pass).
  V4 has been sim'd against the Adiri fork (6 CREATE2 succeeded,
  ~14 TEL gas estimate). Live deploy is the next step.
- **V4 fork integration test.** A V4-specific counterpart to
  `test/uniswap/V3IntegrationFork.t.sol` would etch the mock precompile,
  run the V4 deploy logic, initialize a `PoolKey` for wTEL/eUSD via
  `PoolManager.initialize`, mint a position via `PositionManager`, and
  exercise a swap via `PoolManager.unlock`. Skipped from this commit
  to keep scope focused on the deploy plumbing.
- **Swap UI integration.** Tracked separately under `telcoin-network-swap`;
  see that repo's CHANGELOG for V3 / V4 routing, fee-tier picker,
  concentrated-liquidity UI, and the `/positions` page.

## Branch / merge strategy

This branch (`feature/uniswap-v3-v4`) is based off
`enhancement-tn-faucet-timing-update`, **not** off `master`. The faucet
branch is in flight and is expected to merge first. Branching off it means
we inherit the faucet branch's `Deployments.sol` and `deployments.json`
state (which reflects what's actually deployed on Adiri today), and our
diff is purely additive on top of that state.

**Expected merge order**: faucet branch -> master, then this branch ->
master via rebase.

**Collision surface vs faucet branch**:

| File | Faucet diff | Our diff | Resolution |
|---|---|---|---|
| `deployments/Deployments.sol` | Adds `MagicAddresses` struct + field | Adds `UniswapV3` / `UniswapV4` structs + fields, all alphabetically after `uniswapV2` | Disjoint lines, clean replay |
| `deployments/deployments.json` | Refreshes addresses, adds `magicAddresses` block | Adds `uniswapV3` / `uniswapV4` blocks after `uniswapV2` | Disjoint keys, clean replay |
| `script/bash/deploy-testnet-infra.sh` | Renumbers `X/6` -> `X/5`, drops Step 6 (TestnetManageFaucet) | Renumbers `X/5` -> `X/7`, adds Step 5 (V3) + Step 6 (V4) | Textually overlapping; the V3/V4 block is bracketed with `# BEGIN/END uniswap-v3-v4` markers so conflicts during rebase are obvious to resolve. Mechanical replay of the renumber works because master will have `X/5` after faucet lands. |
| `foundry.toml` | Updated | Untouched | No conflict |

**Rebase recipe** when faucet lands on master:

```
git fetch origin
git checkout feature/uniswap-v3-v4
git rebase origin/master
# resolve any orchestrator step-numbering conflicts inside the BEGIN/END block
git rebase --continue
```

If the faucet branch evolves further between this branch's foundation
commit and the faucet merge (e.g. additional orchestrator steps land),
the renumber portion of our diff may need a second pass. The
`# BEGIN/END uniswap-v3-v4` markers exist so that pass is mechanical.

## Lineage

- `script/testnet/deploy/TestnetDeployUniswapV2.s.sol` is the deploy-shape
  template this design mirrors (Arachnid CREATE2, deployments.json
  read-modify-write, struct-decoded config in setUp).
- `INVARIANTS.md` (and the per-repo equivalents in
  `telcoin-laboratories-contracts` and `telcoin-network-swap`) is the
  template for the operational rules section.
