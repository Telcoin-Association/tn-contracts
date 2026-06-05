# ConsensusRegistry per-status sets: required telcoin-network changes

This document specifies the protocol-side (telcoin-network) changes needed to match the
`ConsensusRegistry` per-status `EnumerableSet` refactor. The contract change is intentionally
ABI-breaking; the protocol must be updated and committee-selection re-baselined before the new
contract is deployed.

## What changed in the contract

- `getValidators(ValidatorStatus status)` now returns `address[]` (the addresses in exactly that
  status's set), not `ValidatorInfo[]`. It reverts on `Undefined` and `Any`.
- The `Active` query no longer folds in `PendingActivation`/`PendingExit`. Each status is queried
  on its own. The committee-eligible pool is the union of the `{ PendingActivation, Active,
  PendingExit }` queries.
- New `getValidatorsInfo(ValidatorStatus status)` returns `ValidatorInfo[]` (full structs) for callers
  that still need them.
- `getEligibleValidatorCount()` returns the on-chain size of that eligible union (unchanged signature).
- `getCommitteeValidators(uint32 epoch)` and `getValidator(address)` are unchanged.

## Required Rust changes

### 1. ABI binding - `crates/tn-reth/src/system_calls.rs`
In the `sol!` block, change the `getValidators` return type and add `getValidatorsInfo`:

```solidity
// was: function getValidators(uint8 status) public view returns (ValidatorInfo[] memory);
function getValidators(uint8 status) public view returns (address[] memory);
function getValidatorsInfo(uint8 status) external view returns (ValidatorInfo[] memory);
```

`getCommitteeValidators`, `getValidator`, and the `ValidatorInfo`/`ValidatorStatus` types are unchanged.

### 2. Committee selection - `crates/tn-reth/src/evm/block.rs::shuffle_new_committee` (~L271)
Today this makes one `getValidators(Active)` call, decodes `Vec<ValidatorInfo>`, and partitions on
`currentStatus == PendingExit` to separate the backfill pool from the primary pool.

Replace with three addresses-only calls and use set membership in place of the `currentStatus` field:

- primary pool = `getValidators(PendingActivation)` concatenated with `getValidators(Active)`
- backfill pool = `getValidators(PendingExit)`

Then apply the existing seeded Fisher-Yates shuffle and committee-size logic to those address vectors.
No `ValidatorInfo` decode is needed for selection - it operates on addresses only. (If a future caller
needs the structs for a status, use `getValidatorsInfo`.)

This is a meaningful simplification: the protocol no longer reads `currentStatus` to reconstruct the
partition - the set the address came from is its status.

### 3. Determinism / re-baseline
Selection now shuffles a concatenation of three per-status address arrays rather than one combined array.
This remains deterministic across nodes (every node reads identical set state, and EnumerableSet's
iteration order is a deterministic function of that state), but the order differs from the previous
`tokenByIndex`-based order, so committee-selection golden tests must be regenerated. There is no
consensus-safety change: the on-chain `getEligibleValidatorCount()` (the union size, used by
`concludeEpoch`'s committee-size guard) and the off-chain candidate pool are both the union of the same
three eligible sets, so they cannot drift.

### 4. Genesis - `crates/tn-reth/src/lib.rs::create_consensus_registry_genesis_accounts`
No change expected. Genesis is built by replaying the Solidity constructor and capturing all written
storage slots; the constructor now also seeds the `Active` `EnumerableSet`, whose slots are captured by
the same generic mechanism. Action item: confirm the genesis builder records all constructor writes
rather than a hardcoded variable/slot list. If it enumerates known variables, add the `validatorSets`
mapping.

### 5. Unaffected paths
The BLS / committee construction path (`getCommitteeValidators(epoch)` in `epoch.rs`, and
`validators_for_epoch`) reads committees, not status sets, and is unchanged.

## Gas (informational)
On the contract side, the protocol's per-epoch `getValidators` read drops sharply because it returns
addresses instead of decoding `ValidatorInfo[]` (roughly an 88% reduction at ~128 validators); the
per-status set reads and the queue fetch in `concludeEpoch` shrink from O(totalSupply) to O(set). The
eligible count stays a cached single SLOAD (`eligibleValidatorCount`, maintained by `_setStatus`
alongside the sets), so the hot count path is unchanged. The only added cost is on the infrequent,
governance-gated transitions (stake/activate/exit do an extra set add/remove), negligible against the
recurring read savings.
