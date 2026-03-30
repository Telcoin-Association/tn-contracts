# Code Review: worker-configs branch

Date: 2026-03-30
Scope: Rename `EpochGasTarget` → `WorkerConfigs` + refactor from single-value gas target to strategy-agnostic per-worker fee config store
Branch: `worker-configs`

## Summary

Clean refactor from a simple default+override gas target pattern to a strategy-aware per-worker config store. The code is well-structured with good NatSpec, proper access control, and solid test coverage (22/22 tests pass). No security vulnerabilities found. One confirmed integration bug (Makefile), one design-level concern around stale config reactivation, and several informational items.

| # | Title | Severity | Category | Status |
|---|-------|----------|----------|--------|
| 1 | Makefile missing WorkerConfigs artifact | Medium | Integration | Confirmed |
| 2 | Shrinking numWorkers leaves stale configs that silently reactivate on expand | Medium | State Manipulation | Design Decision |
| 3 | Constructor silent truncation if strategies.length > uint16 max | Low | Arithmetic | Partially Valid |
| 4 | No events emitted for initial constructor configs | Low | Events | Confirmed |
| 5 | setNumWorkers(0) allowed | Low | Access Control | Design Decision |
| 6 | Missing tests: setNumWorkers(0) and shrink-then-expand | Low | Testing | Confirmed |
| 7 | setNumWorkers gas scales linearly with worker count | Informational | Gas | Confirmed |
| 8 | No function to clear/delete a worker config | Informational | Code Quality | Design Decision |

## Findings

### 1. Makefile missing WorkerConfigs artifact
- **Severity**: Medium
- **Category**: Integration
- **Location**: `Makefile` — `update-artifacts` target
- **Description**: The `update-artifacts` Make target does not copy `WorkerConfigs.json`. Running `make update-artifacts` would not update this artifact.
- **Impact**: Downstream consumers (parent Rust repo) would not get updated artifacts when the standard build process is used.
- **Evaluation**: **Confirmed**. All other artifacts are listed; this one is missing.
- **Fix**:
```makefile
# Add after the last cp line in update-artifacts:
cp out/WorkerConfigs.sol/WorkerConfigs.json artifacts/
```

### 2. Shrinking numWorkers leaves stale configs that silently reactivate on expand
- **Severity**: Medium
- **Category**: State Manipulation
- **Location**: `src/consensus/WorkerConfigs.sol:50` — `setNumWorkers()`
- **Description**: When `setNumWorkers` shrinks (e.g., 5→3), workers 3 and 4 retain their configs in storage. A later expansion back to 5 passes the coverage check using those old configs without the owner explicitly re-setting them.
- **Impact**: Owner expands worker set and unknowingly reactivates outdated strategy/value pairs.
- **Evaluation**: **Design Decision with undocumented risk.** The invariants doc says "setWorkerConfig allows setting config for any workerId; setNumWorkers validates coverage" — the design intentionally separates config setting from worker count. However, the staleness reactivation risk is not documented. Governance must explicitly manage configs before expanding.
- **Recommendation**: Document in `invariants.md`: "Worker configs beyond the current numWorkers are preserved in storage and reactivate if numWorkers expands. Governance must review/update configs before expanding the worker set."

### 3. Constructor silent truncation if strategies.length > uint16 max
- **Severity**: Low
- **Category**: Arithmetic
- **Location**: `src/consensus/WorkerConfigs.sol:40`
- **Description**: `uint16 count = uint16(strategies.length)` silently truncates if the array exceeds 65535 elements. The loop would configure only `count` workers, not all entries.
- **Impact**: Practically unreachable due to gas limits (>65k SSTORE ops), but silent truncation is a correctness concern.
- **Evaluation**: **Partially Valid.** Unreachable in practice, but defensive programming suggests adding a bounds check.
- **Fix**:
```solidity
if (strategies.length > type(uint16).max) revert TooManyWorkers();
uint16 count = uint16(strategies.length);
```

### 4. No events emitted for initial constructor configs
- **Severity**: Low
- **Category**: Events
- **Location**: `src/consensus/WorkerConfigs.sol:43-46` — constructor loop
- **Description**: The constructor sets all worker configs but emits no `WorkerConfigUpdated` events. Off-chain indexers would miss initial configuration state.
- **Impact**: Indexers must read contract state directly or decode deployment tx input data. Constructor events are standard practice and the gas cost is negligible (~375 gas/event).
- **Evaluation**: **Confirmed** gap for indexer compatibility.
- **Fix**:
```solidity
for (uint16 i = 0; i < count; i++) {
    if (values[i] < MIN_GAS) revert ValueBelowMinGas(values[i]);
    _workerConfigs[i] = WorkerConfig({strategy: strategies[i], value: values[i]});
    emit WorkerConfigUpdated(i, strategies[i], values[i]);  // Add this
}
```

### 5. setNumWorkers(0) allowed
- **Severity**: Low
- **Category**: Access Control
- **Location**: `src/consensus/WorkerConfigs.sol:50` — `setNumWorkers()`
- **Description**: No minimum check prevents `setNumWorkers(0)`, which would leave the protocol with zero worker configurations.
- **Impact**: Governance mistake could disable all workers. Mitigated by `onlyOwner`. May be intentional for initialization or maintenance windows.
- **Evaluation**: **Design Decision.** Acceptable if protocol-side Rust code enforces worker count > 0 at usage time. Should be documented in invariants.
- **Recommendation**: Ensure at least 1 worker or else revert.

### 6. Missing tests: setNumWorkers(0) and shrink-then-expand
- **Severity**: Low
- **Category**: Testing
- **Location**: `test/consensus/WorkerConfigsTest.t.sol`
- **Description**: Two important state transition sequences lack test coverage:
  1. `setNumWorkers(0)` — zero-worker state not tested
  2. Shrink-then-expand — config persistence after shrinking not verified
- **Impact**: Undocumented behavior without test evidence of intent.
- **Evaluation**: **Confirmed.** These are the two most important missing test cases.
- **Suggested tests**:
```solidity
function test_setNumWorkers_zero() public {
    vm.prank(owner);
    wc.setNumWorkers(0);
    assertEq(wc.numWorkers(), 0);
}

function test_setNumWorkers_shrinkThenExpand() public {
    vm.prank(owner);
    wc.setNumWorkers(1);
    assertEq(wc.numWorkers(), 1);
    // Worker 1 still has old config — expansion should succeed
    vm.prank(owner);
    wc.setNumWorkers(2);
    assertEq(wc.numWorkers(), 2);
    (, uint64 v1) = wc.getWorkerConfig(1);
    assertEq(v1, 30_000_000);
}
```

### 7. setNumWorkers gas scales linearly with worker count
- **Severity**: Informational
- **Category**: Gas
- **Location**: `src/consensus/WorkerConfigs.sol:52`
- **Description**: The validation loop costs ~103 gas per worker (warm SLOAD + comparison). At 65535 workers, this is ~6.75M gas — within block limits but expensive. At realistic scales (10-100 workers), cost is 3k-12k gas, which is trivial.
- **Impact**: No practical concern for expected worker counts. O(n) validation cannot be eliminated without sacrificing the coverage invariant.
- **Evaluation**: **Informational.** No action needed for current scale.

### 8. No function to clear/delete a worker config
- **Severity**: Informational
- **Category**: Code Quality
- **Location**: `src/consensus/WorkerConfigs.sol`
- **Description**: The old `clearWorkerTargetGas` was removed with no replacement. Configs can only be overwritten, not deleted.
- **Impact**: None in practice. Configs beyond `numWorkers` are inert. Owner can overwrite with `(0, MIN_GAS)` if needed.
- **Evaluation**: **Design Decision.** Acceptable — no operational flow requires deletion.

## Security Summary

- **Access control**: All mutators correctly guarded with `onlyOwner`. Verified by tests.
- **Reentrancy**: No external calls, no ETH handling. Safe.
- **Invariant enforcement**: All 4 documented invariants properly enforced in code.
- **State transitions**: No path allows a worker with `value < MIN_GAS` in the active set (0..numWorkers-1).
- **Key space**: `uint16` mapping keys — no collision risk.

## Invariants Check

| Invariant | Enforced By | Tested |
|-----------|------------|--------|
| Every worker 0..numWorkers-1 has value >= MIN_GAS | `setNumWorkers()` loop (line 52-54), constructor (line 44) | Yes |
| setWorkerConfig allows any workerId; setNumWorkers validates coverage | `setWorkerConfig` has no upper bound; `setNumWorkers` validates range | Yes |
| strategy is raw uint8 stored without interpretation | No validation/transformation of strategy field | Yes |
| constructor atomically sets numWorkers and all configs | Constructor loop validates and stores atomically | Yes |

**Undocumented invariants to add**: stale config reactivation on expand, setNumWorkers(1) minimum, unset workers return (0,0).

## Artifact Compatibility

- **WorkerConfigs.json**: Exists, correct compilation target (`src/consensus/WorkerConfigs.sol`)
- **EpochGasTarget.json**: Properly deleted
- **Stale references**: Zero `EpochGasTarget`/`IEpochGasTarget` references remain in codebase
- **Deployments**: `Deployments.sol` and `deployments.json` correctly updated; address `0xfee0fee0fee0fee0fee0fee0fee0fee0fee0fee0` preserved
- **Makefile**: **Needs fix** — missing WorkerConfigs copy line
- **Parent repo**: No references to either artifact name found in `telcoin-network`

## Test Coverage Summary

- **Status**: 22/22 tests pass
- **Function coverage**: All public/external functions tested
- **Error path coverage**: All 4 custom errors tested
- **Event coverage**: Both events tested
- **Fuzz tests**: 2 fuzz tests with realistic bounds (value >= 7, count 1-20)
- **Gaps**: setNumWorkers(0), shrink-then-expand sequence, single-worker constructor, config overwrite, idempotent setNumWorkers

## NatSpec Coverage

- **Interface (IWorkerConfigs.sol)**: Complete. All functions, errors, events documented with @notice, @param, @return.
- **Implementation (WorkerConfigs.sol)**: Uses `@inheritdoc` correctly. Constructor has @param tags. Struct and state vars documented.
- **Minor gap**: `numWorkers()` view function in interface has only @notice, could use @dev for protocol context.

## Gas Optimization Opportunities

| Optimization | Savings | Severity |
|-------------|---------|----------|
| numWorkers (uint16) wastes a full slot; could pack with owner | ~2100 gas (one fewer cold SLOAD) | Low — not worth the complexity |
| WorkerConfig struct (9 bytes) uses full 32-byte slot in mapping | N/A — mapping entries always use full slots | N/A |
| setNumWorkers loop SLOADs cannot be cached further | N/A — each is a different mapping key | N/A |

No actionable gas optimizations for this contract.
