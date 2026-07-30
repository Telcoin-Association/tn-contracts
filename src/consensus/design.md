Consensus Registry

#### ConsensusNFT Whitelist

To join Telcoin Network as a validator, node operators first must be approved by Telcoin governance. Once approved, validators will be issued a `ConsensusNFT` serving as a permissioned validator whitelist. Only the contract owner, an address managed by Telcoin governance, can issue these NFTs via `ConsensusRegistry::mint()`

The ERC721 `tokenId` of each validator's token serves as their validator uid. TokenIDS can be reused after burned when a validator retires, but validator addresses can never be reused after exit.

# ConsensusRegistry Design

The `ConsensusRegistry` contract is a core component of the Telcoin Network, designed to manage the validator lifecycle, staking mechanisms, and historical epoch data.

## Validator Permissioning via ConsensusNFT

- **Governance Approval**: Validators are mobile network operators vetted through Telcoin governance, which mints a `ConsensusNFT` on the StakeManager to the validator's address.
- **Validator Representation**: Each validator is represented by a `ValidatorInfo` struct, optimized for storage efficiency.
- **NFT Characteristics**:
  - There are roughly 700 MNOs in the world, so the validator set will be small and current storage gas cost limits provide plenty of leeway before an update is required
  - Supports up to (type(uint24).max - 1) validators, with the maximum tokenID reserved as an `UNSTAKED` flag.
  - TokenIDs are generally minted in ascending order, but previously burned tokenIDs can be reminted to avoid gaps
  - ConsensusNFTs are non-transferable and do not yet implement `TokenURI`, which will be finalized during pilot and likely be a simple TEL logo svg.

## Consensus Mechanisms

### System Calls

The Telcoin Network leverages Bullshark and Narwhal protocols, enabling nodes to build blocks in parallel. Epochs are delineated by timestamps rather than block numbers.

At the epoch boundary, the protocol performs gasless system calls to the ConsensusRegistry to update its state with epoch, validator, and rewards information. System call logic is abstracted into the `SystemCallable` module.

- **Boundary sequence**: within the closing block the protocol makes three system calls in a fixed order - `applyIncentives(rewardInfos)`, then `applySlashes(slashes)`, then `concludeEpoch(newCommittee)`. The ordering is a security invariant: rewards are weighted by the versions active during the closing epoch on pre-slash collateral, slashes land on full old-version collateral, and only then does `concludeEpoch` settle the version queue from post-slash balances and rotate the epoch. Sequencing slashes before the conclude call also lets the protocol assemble `newCommittee` and read `nextCommitteeSize` after slash-to-zero ejections have landed, so the conclude call's committee checks can never revert against a stale pre-slash view and an ejected validator is never seated in a future committee.
  - *Rewards (`applyIncentives`)*: incremented per validator based on performance (consensus header count) and stake version weight. Entries naming sentinel addresses or retired validators are skipped rather than reverting, so a malformed entry cannot stall the boundary. Not yet enabled during the pilot; the protocol passes an empty array.
  - *Slashing (`applySlashes`)*: decrements validators' stakes as penalties; a slash to zero ejects and retires the validator. Sentinel and retired entries are skipped. Not yet enabled during the pilot; the protocol passes an empty array.
  - *Epoch conclusion (`concludeEpoch`)*: settles queued stake version changes, validates that the provided `newCommittee` length matches `nextCommitteeSize`, finalizes the previous epoch, updates the voting committee and validator set, and stores new epoch information. Validator committees are protocol-managed and stored historically and for future epochs using ring buffers.
  - *Refund delivery*: settlement refunds accrue as `claimRefund` credits rather than transfers, so the conclude call performs no external calls beyond the trusted Issuance consolidation and its gas cost is storage-bounded regardless of recipient behavior. User-initiated escrow returns (cancel, request overwrite) push through Issuance with a bounded gas stipend, falling back to the same credit on failure.

### Committee Size Configuration

- **Dynamic Committee Sizing**: The `nextCommitteeSize` variable allows governance to adjust committee sizes without protocol hard forks
- **Protocol Integration**: The protocol reads `nextCommitteeSize` directly from contract storage to determine how many validators to include in future committees passed to `concludeEpoch`
- **Safety Bounds**: Committee size is validated against the number of eligible validators to prevent invalid states

## Staking and Delegation

- **Configurable Stake Amounts**: Stake amounts are configurable to support iterative adjustments in early phases based on node operator feedback and protocol updates.
- **Stake Versions**: Records are kept of validators joining under different versions for accurate stake tracking and weighted reward calculation. Stake versions are set on a per-validator basis at stake time and may be changed in-place via `requestStakeVersionChange`. Changes are version-forward only; moving to an earlier version index is not supported (though a later version may carry a lower stake amount).
  - **Epoch-Boundary Version Queue**: For in-service validators (PendingActivation, Active), a version change request only enters a queue; the change is applied automatically inside `concludeEpoch` at an epoch boundary, after that boundary's slashes have landed. Validators have no control over settlement timing, so no request or settlement timing can move value ahead of a slash, and reward weights are stable within an epoch by construction (versions never change mid-epoch for in-service validators).
    - *Stake increase*: the caller sends the exact deficit as `msg.value`; it is escrowed inside the queue entry (never in the stake balance, so it is invisible to reward accounting) and becomes stake at the boundary flip. Increases settle at the first boundary after the request.
    - *Stake decrease*: no value moves at request time. The decrease settles once `STAKE_DECREASE_DELAY_EPOCHS` further boundaries have passed, covering slashes whose detection lags the offense. At settlement the surplus above `newStakeAmount` is refunded to the reward recipient from the post-slash balance; any slashed portion of the surplus is sent to Issuance for future epoch rewards.
    - *Same stake amount*: no value transfer occurs; the flip still waits for the boundary.
    - *Overwrite and cancel*: a repeat request overwrites the entry (returning any prior escrow to its funder and re-stamping the request epoch); `cancelStakeVersionChange` withdraws it. Escrow returns always go to the recorded funder, never to the reward recipient.
    - *Lifecycle*: retiring a validator (unstake, governance burn, or slash-to-zero) drops its queue entry and credits any escrow back to the funder via `claimRefund`; the escrow never became stake and is not confiscable.
  - **Immediate Lane for `Staked` Validators**: a `Staked` validator is not in service, is never a committee member, and can already reclaim its full stake at any time via `unstake`, so its version changes settle immediately in the request transaction.
  - **Delegation Version Tracking**: When a delegated validator's stake version changes, the `Delegation.validatorVersion` field is also updated to maintain consistency.
  - **Reward Interaction**: Validators with both accrued rewards and a pending slash should claim rewards before requesting a decrease. A stake-decreasing settlement on a partially slashed validator may zero claimable rewards since the balance is set to `newStakeAmount`. The recipient still receives the correct total ETH via the refund.
- **Issuance Contract**: Accepts TEL for rewards distribution, using TEL "burnt" for epoch rewards. For simplicity, the Issuance contract offloads accounting to the EVM native ledger.
- **Delegation**: DPOS is currently supported though expected to be used sparingly for delegators and validators with ongoing offchain relationships or agreements.
- **Delegation Rewards**: Delegators receive all stake rewards and the staked balance upon unstaking, so schemas for splitting stake rewards between validator and delegator are assumed to be agreed upon offchain by those parties and settled externally to the protocol

## Geographic Diversity

### Region Mapping

Validators are assigned a GSMA region identifier (`uint8 region`) on `ValidatorInfo`. The region value corresponds to GSMA's standard regional breakdown:

| Value | Region |
|-------|--------|
| 0 | Unspecified (default) |
| 1 | Sub-Saharan Africa |
| 2 | Middle East & North Africa |
| 3 | Greater China |
| 4 | Asia Pacific |
| 5 | Europe |
| 6 | CIS |
| 7 | Latin America & Caribbean |
| 8 | North America |

All uint8 values (0-255) are valid. Values 9-255 are available for future region assignments without requiring a contract upgrade.

### `setValidatorRegion`

Governance sets a validator's region via `setValidatorRegion(address, uint8)`, gated by `onlyOwner`. The region is stored on `ValidatorInfo` in the same storage slot as the other packed scalar fields (32 bytes total), adding zero additional gas cost.

### Region-Aware Committee Shuffle

The committee shuffle algorithm ensures geographic diversity:

1. Validators are separated into assigned (region 1-8) and unassigned (region 0) groups
2. Each region group is internally shuffled via Fisher-Yates for intra-region fairness
3. Region visit order is randomized
4. Round-robin selection cycles through regions, taking one validator per region per round
5. After round-robin exhausts assigned regions, remaining slots are filled from the unassigned pool
6. If still not full, additional assigned validators fill remaining seats

Validators with region 0 bypass diversity constraints entirely, preserving backwards compatibility. When all validators are region 0, the algorithm degrades to a standard Fisher-Yates shuffle.

> **Note**: The committee shuffle algorithm above is implemented in the Rust protocol client, not in Solidity. The ConsensusRegistry contract stores the region field and exposes `getValidators(Active)` for the protocol to apply the shuffle when building committees.

## Rewards and Issuance

- **Rewards Claiming**: Pull-only claim flow to avoid reverts during critical consensus logic.
- **Rewards Sourcing**: During the MNO pilot, consensus block rewards are funded by the TAO in a subsidized growth phase.
- **Balance Tracking** Validator balances use a uint256 ledger which represents outstanding balance in full, including both stake and any accrued rewards.
