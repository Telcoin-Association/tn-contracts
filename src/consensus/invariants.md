# ConsensusRegistry invariants

**consensus**

- consensus-related functions `concludeEpoch` `applyIncentives` `applySlashes` should only revert for undeniably invalid state to minimize interruption protocol operation
- concludeEpoch must be the final system call of the epoch, succeeding reward and slash system calls
- active validatort count and committee size must never reach 0 or more than the number of effectively active (active and pendingexit) validators in the new epoch.
- four latest epochs (current and three in past) are correctly stored
- future committees are stored up to two epochs into the future (next and subsequent)

**validators**

- BLS pubkeys must be unique and cannot be reused
- validator addresses must be unique and cannot be reused
- validator statuses are one directional; ie Active cannot revert to PendingActive, PendingExit cannot revert to Active, and so forth
- only staked validators can begin activation
- after self-activating, validators enter the pending activation queue and activate at the start of the next epoch
- pending activation and pending exit validators are also considered active since exit queue is updated before checking committee size
- exit from the pending exit queue is determined solely by the protocol, which determines a queued validator may exit by excluding it from the committee across 3 epochs
- unless forcibly burned, only Exited or Staked validators can unstake, ie: Exited to Retired, or Staked to Any (unstaking pre-activation bypasses activation)
- retired validator addresses can never rejoin
- validators are only eligible for rewards at the completion of their first full epoch
- unvariant: validator storage vector can eventually grow to exceed gas limits but this will be a good problem to have and storage can be optimized

**stake**

- initial validators' stakes are allocated to the ConsensusRegistry and decremented from InterchainTEL directly within the protocol on the rust side (thus not provided to the constructor)
- the only way to withdraw funds from the ConsensusRegistry and Issuance contract are during reward claim or full validator retirement using `unstake()` which sends stake + rewards
- stake configs must take effect in the next epoch, not current
- stake config versions are set on a per-validator basis at stake time
- rewards are weighted by validator version initial stake and the number of consensus headers for the epoch
- consensus burns must never push committees or validator set to invalid state
- consensus burned tokenIDs must not cause a revert for system called epoch actions
- consensus burns slash all the validator's remaining stake
- slashes are applied until the validator outstanding balance reaches 0,
- consensus burns and slashes-to-zero immediately retire the validator and eject it from all upcoming committees
- ConsensusRegistry only ever holds staked funds, including on behalf of the initial validator set at network genesis (rest to InterchainTEL)
- Issuance only ever holds epoch reward funds, less claims
- when unstaking, stake is sourced from the registry
- when claiming or unstaking, rewards are sourced from Issuance
- claims can revert if Issuance contract runs dry (eg TAO governance problem) but rewards ledger must continue being updated by applyIncentives or applySlahes
- all capital flows to the stake originator, ie the recipient for both stake and rewards is either a validator's delegator if one exists, or the validator itself if not

**protocol**

- protocol dictates committee based on `getValidators(Active)` and Fisher-Yates shuffle
- protocol enforces that maximum committee size is 32
