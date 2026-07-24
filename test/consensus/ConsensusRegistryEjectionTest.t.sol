// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { RewardInfo, Slash, IStakeManager } from "src/interfaces/IStakeManager.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";

/// Governance-ejection lifecycle coverage: `burn` and slash-to-zero forcibly remove a validator
/// from the current, next, and subsequent stored committees via swap-and-pop (`_eject`), shrinking
/// and reordering those arrays mid-epoch. These tests pin the full lifecycle around that mutation:
/// epoch conclusion over shrunken committees, ring-buffer consistency, stake confiscation to
/// Issuance, the retired-skip branches in `applyIncentives`/`applySlashes`, guard behavior, and the
/// exact post-ejection array order the Rust epoch-record producer performs ordered reads against.
contract ConsensusRegistryEjectionTest is ConsensusRegistryTestUtils {
    bytes32 internal constant VALIDATOR_SLASHED_TOPIC = keccak256("ValidatorSlashed((address,uint256))");

    function setUp() public {
        // target
        consensusRegistry = ConsensusRegistry(0x07E17e17E17e17E17e17E17E17E17e17e17E17e1);

        vm.startStateDiffRecording();
        StakeConfig memory stakeConfig_ = StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_);
        ConsensusRegistry tempRegistry =
            new ConsensusRegistry(stakeConfig_, initialValidators, initialBlsPubkeys, initialBLSPops, crOwner);
        Vm.AccountAccess[] memory records = vm.stopAndReturnStateDiff();
        bytes32[] memory slots = saveWrittenSlots(address(tempRegistry), records);
        copyContractState(address(tempRegistry), address(consensusRegistry), slots);

        // simulate protocol allocation of validators' initial stake
        registryGenesisBal = stakeAmount_ * initialValidators.length;
        vm.deal(address(consensusRegistry), registryGenesisBal);
        // set protocol system address
        sysAddress = consensusRegistry.SYSTEM_ADDRESS();

        vm.deal(validator5, stakeAmount_);

        // deal issuance contract max TEL supply to test reward distribution
        vm.deal(crOwner, epochIssuance_);
        vm.prank(crOwner);
        consensusRegistry.allocateIssuance{ value: epochIssuance_ }();
    }

    /*
     *   helpers
     */

    function _burn(address validatorAddress) internal {
        vm.prank(crOwner);
        consensusRegistry.burn(validatorAddress);
    }

    function _conclude(address[] memory futureCommittee) internal {
        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(futureCommittee);
    }

    /// @dev The three genesis survivors after removing `burned`, sorted for `concludeEpoch`.
    function _sortedSurvivors(address burned) internal view returns (address[] memory sorted) {
        sorted = new address[](3);
        uint256 counter;
        address[] memory genesis = _sortedGenesisCommittee();
        for (uint256 i; i < genesis.length; ++i) {
            if (genesis[i] != burned) sorted[counter++] = genesis[i];
        }
    }

    function _committeeOf(uint32 epoch) internal view returns (address[] memory) {
        return consensusRegistry.getEpochInfo(epoch).committee;
    }

    function _assertCommitteeEquals(uint32 epoch, address[] memory expected, string memory err) internal view {
        address[] memory actual = _committeeOf(epoch);
        assertEq(actual.length, expected.length, err);
        for (uint256 i; i < expected.length; ++i) {
            assertEq(actual[i], expected[i], err);
        }
    }

    /// @dev Asserts every epoch in `[fromEpoch, toEpoch]` excludes `who` and has `expectedLen` members.
    function _assertWindowExcludes(uint32 fromEpoch, uint32 toEpoch, address who, uint256 expectedLen) internal view {
        for (uint32 e = fromEpoch; e <= toEpoch; ++e) {
            assertEq(_committeeOf(e).length, expectedLen, "unexpected committee length in window");
            _assertCommitteeExcludes(e, who);
        }
    }

    /// @dev Positional zip pin: the address-committee and pubkey-committee getters must index the
    /// same underlying array, so `getCommitteeBlsPubkeys(e)[i]` is the pubkey of
    /// `getCommitteeValidators(e)[i]`. The Rust node zips these two reads positionally.
    function _assertCommitteeZipConsistent(uint32 epoch) internal view {
        ValidatorInfo[] memory infos = consensusRegistry.getCommitteeValidators(epoch);
        bytes[] memory pubkeys = consensusRegistry.getCommitteeBlsPubkeys(epoch);
        assertEq(infos.length, pubkeys.length, "committee getter length drift");
        for (uint256 i; i < infos.length; ++i) {
            assertEq(
                pubkeys[i],
                consensusRegistry.getBlsPubkey(infos[i].validatorAddress),
                "positional zip drift between committee getters"
            );
        }
    }

    function _countSlashedLogs(Vm.Log[] memory logs) internal pure returns (uint256 count) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == VALIDATOR_SLASHED_TOPIC) ++count;
        }
    }

    function _firstSlashedLog(Vm.Log[] memory logs) internal pure returns (Slash memory) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == VALIDATOR_SLASHED_TOPIC) {
                return abi.decode(logs[i].data, (Slash));
            }
        }
        revert("no ValidatorSlashed log found");
    }

    /*
     *   A. burn -> lifecycle
     */

    /// A1: the core liveness pin. A mid-epoch governance burn shrinks the current, next, and
    /// subsequent committees; the network must then conclude epochs indefinitely over the shrunken
    /// committees. Burn event order (NextCommitteeSizeUpdated -> ValidatorExited -> ValidatorRetired)
    /// is pinned because `_ejectFromCommittees` runs before `_exit`/`_retire` in `_consensusBurn`.
    function test_burn_thenConcludeEpoch_networkContinues() public {
        assertEq(consensusRegistry.getCurrentEpoch(), 0);
        assertEq(consensusRegistry.getNextCommitteeSize(), 4);

        // exact event order for the burn itself; genesis validators have activationEpoch 0 and
        // the burn happens in epoch 0, so exitEpoch is 0
        vm.expectEmit(true, true, true, true);
        emit NextCommitteeSizeUpdated(4, 3, 3);
        vm.expectEmit(true, true, true, true);
        emit ValidatorExited(ValidatorInfo(validator1, 0, 0, ValidatorStatus.Exited, false, 0, 0));
        vm.expectEmit(true, true, true, true);
        emit ValidatorRetired(ValidatorInfo(validator1, 0, 0, ValidatorStatus.Any, true, 0, 0));
        _burn(validator1);

        // the entire stored window (current + two futures) excludes the burned validator
        assertTrue(consensusRegistry.isRetired(validator1));
        assertEq(consensusRegistry.getEligibleValidatorCount(), 3);
        _assertWindowExcludes(0, 2, validator1, 3);
        _assertSetInvariant();

        // network continues: three epoch conclusions over the shrunken committee
        address[] memory survivors = _sortedSurvivors(validator1);
        for (uint32 i = 1; i <= 3; ++i) {
            vm.roll(block.number + 1);
            _conclude(survivors);
            assertEq(consensusRegistry.getCurrentEpoch(), i);
            // full queryable window (three past epochs through two future epochs) stays shrunken
            uint32 windowStart = i >= 3 ? i - 3 : 0;
            _assertWindowExcludes(windowStart, i + 2, validator1, 3);
            _assertSetInvariant();
        }
    }

    /// A1 variant: burn and concludeEpoch land in the same block (no roll in between), matching a
    /// governance burn that lands in an epoch's closing block right before the system calls.
    function test_burn_thenConcludeEpoch_sameBlock() public {
        _burn(validator1);
        _conclude(_sortedSurvivors(validator1));

        assertEq(consensusRegistry.getCurrentEpoch(), 1);
        _assertWindowExcludes(0, 3, validator1, 3);
        _assertSetInvariant();
    }

    /// A2: burning during epoch 0 mutates epochInfo[0] and futureEpochInfo[1..2], while the
    /// constructor-seeded copies in epochInfo[1..2] still hold the full genesis committee. Those
    /// stale copies must never leak: epoch reads for 1 and 2 route to futureEpochInfo until
    /// `_updateEpochInfo` overwrites epochInfo[1..2] from the mutated futureEpochInfo at conclusion.
    function test_burn_epochZero_ringBufferConsistency() public {
        _burn(validator1);

        // pre-conclusion reads for epochs 0-2 all reflect the ejection
        _assertWindowExcludes(0, 2, validator1, 3);

        // concluding overwrites the stale epochInfo[1] genesis copy from mutated futureEpochInfo[1]
        address[] memory survivors = _sortedSurvivors(validator1);
        _conclude(survivors);
        assertEq(consensusRegistry.getCurrentEpoch(), 1);
        assertEq(consensusRegistry.getCurrentEpochInfo().epochId, 1);
        _assertWindowExcludes(0, 3, validator1, 3);

        // and again for the stale epochInfo[2] copy
        _conclude(survivors);
        assertEq(consensusRegistry.getCurrentEpoch(), 2);
        assertEq(consensusRegistry.getCurrentEpochInfo().epochId, 2);
        _assertWindowExcludes(0, 4, validator1, 3);
    }

    /// A3: burn confiscates exactly the initial stake to Issuance and zeroes the registry ledger.
    function test_burn_confiscatesStakeToIssuance() public {
        uint256 issuanceBalBefore = issuance.balance;
        uint256 registryBalBefore = address(consensusRegistry).balance;
        (uint256 outstandingBefore, uint256 initialStake,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(outstandingBefore, stakeAmount_);
        assertEq(initialStake, stakeAmount_);

        _burn(validator1);

        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_, "issuance must receive confiscated stake");
        assertEq(address(consensusRegistry).balance, registryBalBefore - stakeAmount_);
        (uint256 outstandingAfter,, uint256 rewardsAfter) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(outstandingAfter, 0, "ledger must be zeroed");
        assertEq(rewardsAfter, 0);
        assertTrue(consensusRegistry.isRetired(validator1));
        assertEq(consensusRegistry.totalSupply(), 3);
    }

    /// A4: behavior tripwire. Burning a validator that already Exited honestly (but has not yet
    /// unstaked) confiscates its full stake to Issuance, even though the validator could otherwise
    /// have reclaimed it via `unstake`. If governance intends to expel without confiscation, it must
    /// let exited validators unstake instead of burning them.
    function test_burn_exitedValidator_confiscatesStake() public {
        // walk validator1 through the honest exit queue: PendingExit, then excluded from all
        // stored committees after three conclusions over survivor committees
        vm.prank(validator1);
        consensusRegistry.beginExit();

        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(3);

        address[] memory survivors = _sortedSurvivors(validator1);
        _conclude(survivors); // epoch 1: validator1 still in current/next committees -> stays queued
        _conclude(survivors); // epoch 2: still in current committee -> stays queued
        _conclude(survivors); // epoch 3: absent from current + both futures -> exits

        ValidatorInfo memory exited = consensusRegistry.getValidator(validator1);
        assertEq(uint8(exited.currentStatus), uint8(ValidatorStatus.Exited));
        assertEq(exited.exitEpoch, 3);
        assertFalse(consensusRegistry.isRetired(validator1));
        assertEq(consensusRegistry.getEligibleValidatorCount(), 3);

        // burning the exited-but-not-unstaked validator confiscates the stake it could have reclaimed
        uint256 issuanceBalBefore = issuance.balance;
        _burn(validator1);

        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_, "exited validator's stake confiscated");
        assertTrue(consensusRegistry.isRetired(validator1));
        (uint256 outstanding,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(outstanding, 0);
        _assertSetInvariant();
    }

    /// A5: burning a PendingExit committee member keeps the status sets in lockstep, and the normal
    /// exit queue still works for a different PendingExit validator over the mutated committees.
    function test_burn_pendingExit_thenQueueUpdate() public {
        // validator2 enters the exit queue, then governance burns it while PendingExit
        vm.prank(validator2);
        consensusRegistry.beginExit();
        _assertSetInvariant();

        _burn(validator2);
        assertTrue(consensusRegistry.isRetired(validator2));
        assertEq(consensusRegistry.getValidators(ValidatorStatus.PendingExit).length, 0);
        assertEq(consensusRegistry.getEligibleValidatorCount(), 3);
        assertEq(consensusRegistry.getNextCommitteeSize(), 3);
        _assertWindowExcludes(0, 2, validator2, 3);
        _assertSetInvariant();

        // a different validator exits via the queue, walked over the post-ejection committees
        vm.prank(validator3);
        consensusRegistry.beginExit();
        _assertSetInvariant();

        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(2);

        address[] memory pair = new address[](2);
        pair[0] = validator1;
        pair[1] = validator4;
        _sortAddresses(pair);

        _conclude(pair); // epoch 1: validator3 still in current (post-ejection) committee
        _conclude(pair); // epoch 2: still in current committee
        _assertSetInvariant();
        _conclude(pair); // epoch 3: absent everywhere -> exits via queue

        ValidatorInfo memory exited = consensusRegistry.getValidator(validator3);
        assertEq(uint8(exited.currentStatus), uint8(ValidatorStatus.Exited));
        assertEq(exited.exitEpoch, 3);
        assertFalse(consensusRegistry.isRetired(validator3), "queue exit must not retire");
        assertEq(consensusRegistry.getEligibleValidatorCount(), 2);
        _assertSetInvariant();
    }

    /// A6: past-epoch committee getters must keep working when a past committee contains a retired
    /// tombstone, and the address/pubkey getters must stay positionally zipped for past (full),
    /// current (shrunken), and future (shrunken) epochs.
    function test_getCommitteeGetters_pastEpochWithRetiredMember() public {
        // seat the ring buffer, then burn at epoch 2: epochs 0-1 keep the full genesis committee
        // (with the soon-to-be tombstone), epochs 2-4 are ejected in place
        _seatCommittees();
        assertEq(consensusRegistry.getCurrentEpoch(), 2);
        _burn(validator1);

        // past epochs retain the tombstoned member and stay readable
        for (uint32 e = 0; e <= 1; ++e) {
            address[] memory past = _committeeOf(e);
            assertEq(past.length, 4, "past committees must be untouched");
            ValidatorInfo[] memory infos = consensusRegistry.getCommitteeValidators(e);
            bool sawTombstone;
            for (uint256 i; i < infos.length; ++i) {
                if (infos[i].validatorAddress == validator1) {
                    sawTombstone = true;
                    assertTrue(infos[i].isRetired);
                }
            }
            assertTrue(sawTombstone, "tombstone member expected in past committee");
        }

        // shrunken current + future epochs exclude the tombstone
        _assertWindowExcludes(2, 4, validator1, 3);

        // the tombstone's pubkey stays resolvable, but it is no longer a validator
        bytes memory tombstoneKey = consensusRegistry.getBlsPubkey(validator1);
        assertEq(tombstoneKey.length, 96);
        assertFalse(consensusRegistry.isValidator(tombstoneKey));

        // positional zip pin across past/current/future shapes
        _assertCommitteeZipConsistent(0);
        _assertCommitteeZipConsistent(1);
        _assertCommitteeZipConsistent(2);
        _assertCommitteeZipConsistent(3);
        _assertCommitteeZipConsistent(4);
    }

    /*
     *   B. swap-and-pop order pin
     */

    /// B1: canary pinning `_eject`'s exact swap-and-pop order. The Rust epoch-record producer reads
    /// these arrays with order-sensitive comparisons, so a future "helpful" re-sort on ejection must
    /// fail this test loudly rather than silently changing the on-chain byte order.
    function test_eject_swapAndPop_exactOrderPinned() public {
        // genesis committees are in constructor push order [validator1..validator4]
        address[] memory pre = _committeeOf(0);
        assertEq(pre.length, 4);
        assertEq(pre[0], validator1);
        assertEq(pre[1], validator2);
        assertEq(pre[2], validator3);
        assertEq(pre[3], validator4);

        // ejecting index 0: last element swaps in, array pops -> [v4, v2, v3]
        _burn(pre[0]);
        address[] memory expectedAfterFirst = new address[](3);
        expectedAfterFirst[0] = pre[3];
        expectedAfterFirst[1] = pre[1];
        expectedAfterFirst[2] = pre[2];
        for (uint32 e = 0; e <= 2; ++e) {
            _assertCommitteeEquals(e, expectedAfterFirst, "first ejection must be exact swap-and-pop");
        }

        // ejecting the new index 0 (v4): [v3, v2]
        _burn(expectedAfterFirst[0]);
        address[] memory expectedAfterSecond = new address[](2);
        expectedAfterSecond[0] = pre[2];
        expectedAfterSecond[1] = pre[1];
        for (uint32 e = 0; e <= 2; ++e) {
            _assertCommitteeEquals(e, expectedAfterSecond, "second ejection must be exact swap-and-pop");
        }
    }

    /*
     *   C. applySlashes
     */

    /// C1: the ejection boundary is strict `>`: a validator survives while balance > slash amount,
    /// so slashing to exactly zero remaining (amount == balance) ejects.
    function test_applySlashes_exactBalanceBoundary() public {
        // slash all but 1 wei: balance (1M TEL) > amount (1M TEL - 1) -> ledger decrement only
        Slash[] memory nearTotal = new Slash[](1);
        nearTotal[0] = Slash(validator1, stakeAmount_ - 1);
        vm.expectEmit(true, true, true, true);
        emit ValidatorSlashed(Slash(validator1, stakeAmount_ - 1));
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(nearTotal);

        (uint256 outstanding,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(outstanding, 1, "1 wei must survive the near-total slash");
        assertFalse(consensusRegistry.isRetired(validator1));
        assertEq(uint8(consensusRegistry.getValidator(validator1).currentStatus), uint8(ValidatorStatus.Active));
        assertEq(consensusRegistry.getEligibleValidatorCount(), 4);
        assertEq(_committeeOf(0).length, 4);

        // one more wei: balance (1) > amount (1) is false -> ejection; the full initial stake
        // consolidates on Issuance, covering the previously slashed remainder
        uint256 issuanceBalBefore = issuance.balance;
        Slash[] memory finalWei = new Slash[](1);
        finalWei[0] = Slash(validator1, 1);
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(finalWei);

        assertTrue(consensusRegistry.isRetired(validator1));
        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_, "the full initial stake consolidates");
        assertEq(consensusRegistry.getEligibleValidatorCount(), 3);
        assertEq(consensusRegistry.getNextCommitteeSize(), 3);
        _assertWindowExcludes(0, 2, validator1, 3);
        _assertSetInvariant();
    }

    /// C2: retired validators are skipped inside a slash batch; exactly one ValidatorSlashed fires.
    function test_applySlashes_skipsRetiredInBatch() public {
        _burn(validator1);

        Slash[] memory slashes = new Slash[](2);
        slashes[0] = Slash(validator1, 100); // retired: skipped, no event
        slashes[1] = Slash(validator2, 100);

        vm.recordLogs();
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(_countSlashedLogs(logs), 1, "exactly one ValidatorSlashed expected");
        Slash memory emitted = _firstSlashedLog(logs);
        assertEq(emitted.validatorAddress, validator2);
        assertEq(emitted.amount, 100);

        (uint256 outstanding1,,) = consensusRegistry.getBalanceBreakdown(validator1);
        (uint256 outstanding2,,) = consensusRegistry.getBalanceBreakdown(validator2);
        assertEq(outstanding1, 0, "retired ledger must stay zeroed");
        assertEq(outstanding2, stakeAmount_ - 100);
    }

    /// C3: a batch slashing the same validator twice ejects on the first entry and hits the
    /// retired-skip on the second, within one call.
    function test_applySlashes_doubleSlashSameValidatorInBatch() public {
        Slash[] memory slashes = new Slash[](2);
        slashes[0] = Slash(validator2, stakeAmount_); // amount == balance -> ejects
        slashes[1] = Slash(validator2, 1); // now retired -> skipped

        vm.recordLogs();
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(_countSlashedLogs(logs), 1, "second entry must hit the retired skip");
        Slash memory emitted = _firstSlashedLog(logs);
        assertEq(emitted.validatorAddress, validator2);
        assertEq(emitted.amount, stakeAmount_);

        assertTrue(consensusRegistry.isRetired(validator2));
        assertEq(consensusRegistry.getEligibleValidatorCount(), 3);
        _assertWindowExcludes(0, 2, validator2, 3);
        _assertSetInvariant();
    }

    /// C4: confiscation split for a slashed-to-zero validator holding rewards. Only
    /// min(outstanding, initialStake) moves to Issuance; the reward portion is confiscated purely on
    /// the ledger (those funds already sit on Issuance).
    function test_applySlashes_confiscationSplitWithRewards() public {
        // give validator2 the full epoch issuance as rewards
        RewardInfo[] memory rewards = new RewardInfo[](1);
        rewards[0] = RewardInfo(validator2, 100);
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewards);

        (uint256 outstanding,, uint256 rewardAmount) = consensusRegistry.getBalanceBreakdown(validator2);
        assertEq(outstanding, stakeAmount_ + epochIssuance_);
        assertEq(rewardAmount, epochIssuance_);

        // slash the exact outstanding balance -> ejection; Issuance receives exactly the initial
        // stake, NOT stake + rewards
        uint256 issuanceBalBefore = issuance.balance;
        uint256 registryBalBefore = address(consensusRegistry).balance;
        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator2, outstanding);
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);

        assertTrue(consensusRegistry.isRetired(validator2));
        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_, "exactly min(outstanding, initialStake) moves");
        assertEq(address(consensusRegistry).balance, registryBalBefore - stakeAmount_);
        (uint256 outstandingAfter,, uint256 rewardsAfter) = consensusRegistry.getBalanceBreakdown(validator2);
        assertEq(outstandingAfter, 0);
        assertEq(rewardsAfter, 0, "reward claim wiped with the ledger");
    }

    /*
     *   D. applyIncentives with retired validators
     */

    /// D1: a retired rewardee contributes zero weight, so its share is redistributed to live
    /// validators and rounding dust accrues to undistributedIssuance.
    function test_applyIncentives_skipsRetired_weightsRedistributed() public {
        _burn(validator1);
        assertEq(consensusRegistry.undistributedIssuance(), 0);

        RewardInfo[] memory rewards = new RewardInfo[](4);
        rewards[0] = RewardInfo(validator1, 1); // retired: skipped
        rewards[1] = RewardInfo(validator2, 1);
        rewards[2] = RewardInfo(validator3, 1);
        rewards[3] = RewardInfo(validator4, 5);

        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewards);

        // weights count live validators only: totalWeight = stake * (1 + 1 + 5)
        uint256 total = epochIssuance_;
        uint256 totalWeight = stakeAmount_ * 7;
        uint256 expected2 = (total * (stakeAmount_ * 1)) / totalWeight;
        uint256 expected3 = (total * (stakeAmount_ * 1)) / totalWeight;
        uint256 expected4 = (total * (stakeAmount_ * 5)) / totalWeight;

        (uint256 outstanding1,,) = consensusRegistry.getBalanceBreakdown(validator1);
        (uint256 outstanding2,,) = consensusRegistry.getBalanceBreakdown(validator2);
        (uint256 outstanding3,,) = consensusRegistry.getBalanceBreakdown(validator3);
        (uint256 outstanding4,,) = consensusRegistry.getBalanceBreakdown(validator4);
        assertEq(outstanding1, 0, "retired validator must not accrue rewards");
        assertEq(outstanding2, stakeAmount_ + expected2);
        assertEq(outstanding3, stakeAmount_ + expected3);
        assertEq(outstanding4, stakeAmount_ + expected4);

        // redistribution pin: validator2's live share (1/7 of issuance) exceeds what it would have
        // received had the retired validator's weight still counted (1/8)
        assertGt(expected2, (total * (stakeAmount_ * 1)) / (stakeAmount_ * 8));

        uint256 dust = total - (expected2 + expected3 + expected4);
        assertGt(dust, 0, "chosen weights must produce rounding dust");
        assertEq(consensusRegistry.undistributedIssuance(), dust, "dust must roll into undistributedIssuance");
    }

    /// D2: when every weighted rewardee is retired (or has zero headers), totalWeight is zero and
    /// applyIncentives returns early: the epoch's issuance is NOT rolled into undistributedIssuance
    /// on this path, and no balances move.
    function test_applyIncentives_allRetiredRewardees_earlyReturn() public {
        _burn(validator1);

        RewardInfo[] memory rewards = new RewardInfo[](2);
        rewards[0] = RewardInfo(validator1, 100); // retired: zero weight
        rewards[1] = RewardInfo(validator2, 0); // zero headers: zero weight

        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewards);

        assertEq(consensusRegistry.undistributedIssuance(), 0, "early return must not roll issuance into dust");
        (uint256 outstanding2,,) = consensusRegistry.getBalanceBreakdown(validator2);
        assertEq(outstanding2, stakeAmount_, "no rewards distributed on early return");
    }

    /// D3: the exact closing-block system-call sequence (applyIncentives -> applySlashes ->
    /// concludeEpoch) succeeds in one block after a mid-epoch burn. Foundry twin of the e2e
    /// current-committee ejection test's epoch boundary.
    function test_applyIncentives_thenConclude_fullClosingBlockSequence() public {
        _burn(validator1);

        vm.startPrank(sysAddress);

        // incentives: the retired leader is skipped, live validators split the epoch issuance
        RewardInfo[] memory rewards = new RewardInfo[](4);
        rewards[0] = RewardInfo(validator1, 3); // retired: skipped
        rewards[1] = RewardInfo(validator2, 1);
        rewards[2] = RewardInfo(validator3, 1);
        rewards[3] = RewardInfo(validator4, 1);
        consensusRegistry.applyIncentives(rewards);

        // slashes: a survivable penalty against a live validator
        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator4, 1000);
        consensusRegistry.applySlashes(slashes);

        // conclude over the shrunken committee
        consensusRegistry.concludeEpoch(_sortedSurvivors(validator1));
        vm.stopPrank();

        assertEq(consensusRegistry.getCurrentEpoch(), 1);
        _assertWindowExcludes(0, 3, validator1, 3);

        uint256 share = epochIssuance_ / 3;
        (uint256 outstanding1,,) = consensusRegistry.getBalanceBreakdown(validator1);
        (uint256 outstanding2,,) = consensusRegistry.getBalanceBreakdown(validator2);
        (uint256 outstanding4,,) = consensusRegistry.getBalanceBreakdown(validator4);
        assertEq(outstanding1, 0);
        assertEq(outstanding2, stakeAmount_ + share);
        assertEq(outstanding4, stakeAmount_ + share - 1000);
        _assertSetInvariant();
    }

    /*
     *   E. guards
     */

    /// E1: a second burn of the same validator reverts with the retired sentinel status.
    function test_burn_revertsOnDoubleBurn() public {
        _burn(validator1);

        vm.expectRevert(abi.encodeWithSelector(InvalidStatus.selector, ValidatorStatus.Any));
        vm.prank(crOwner);
        consensusRegistry.burn(validator1);
    }

    /// E2: burning down to the last eligible validator reverts atomically. nextCommitteeSize
    /// auto-decrements stepwise (3 -> 2 -> 1) on the way down; the burn that would empty the
    /// committee reverts InvalidCommitteeSize(0, 0) leaving the final validator fully intact.
    function test_burn_toLastEligible_revertsAtomically() public {
        vm.expectEmit(true, true, true, true);
        emit NextCommitteeSizeUpdated(4, 3, 3);
        _burn(validator1);
        assertEq(consensusRegistry.getNextCommitteeSize(), 3);

        vm.expectEmit(true, true, true, true);
        emit NextCommitteeSizeUpdated(3, 2, 2);
        _burn(validator2);
        assertEq(consensusRegistry.getNextCommitteeSize(), 2);

        vm.expectEmit(true, true, true, true);
        emit NextCommitteeSizeUpdated(2, 1, 1);
        _burn(validator3);
        assertEq(consensusRegistry.getNextCommitteeSize(), 1);
        assertEq(_committeeOf(0).length, 1);
        assertEq(_committeeOf(0)[0], validator4);

        // the final burn would empty the committee: whole call reverts
        uint256 issuanceBalBefore = issuance.balance;
        vm.expectRevert(abi.encodeWithSelector(InvalidCommitteeSize.selector, 0, 0));
        vm.prank(crOwner);
        consensusRegistry.burn(validator4);

        // atomicity: validator4 untouched
        assertFalse(consensusRegistry.isRetired(validator4));
        assertEq(uint8(consensusRegistry.getValidator(validator4).currentStatus), uint8(ValidatorStatus.Active));
        (uint256 outstanding,,) = consensusRegistry.getBalanceBreakdown(validator4);
        assertEq(outstanding, stakeAmount_);
        assertEq(consensusRegistry.getEligibleValidatorCount(), 1);
        assertEq(consensusRegistry.getNextCommitteeSize(), 1);
        assertEq(_committeeOf(0).length, 1);
        assertEq(consensusRegistry.totalSupply(), 1);
        assertEq(issuance.balance, issuanceBalBefore, "failed burn must not move funds");
        _assertSetInvariant();
    }

    /// E3: burning a PendingActivation validator that was never seated in any committee is a
    /// committee no-op: the eligible count decrements and stake is confiscated, but the stored
    /// committees and nextCommitteeSize are untouched.
    function test_burn_pendingActivationNeverSeated() public {
        _addFifthValidator();
        assertEq(consensusRegistry.getEligibleValidatorCount(), 5);
        assertEq(consensusRegistry.getNextCommitteeSize(), 4);

        address[] memory snapshot0 = _committeeOf(0);
        address[] memory snapshot1 = _committeeOf(1);
        address[] memory snapshot2 = _committeeOf(2);

        uint256 issuanceBalBefore = issuance.balance;
        _burn(validator5);

        assertTrue(consensusRegistry.isRetired(validator5));
        assertEq(consensusRegistry.getEligibleValidatorCount(), 4);
        assertEq(consensusRegistry.getNextCommitteeSize(), 4, "no auto-decrement when size still fits");
        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_, "staked-but-unseated stake confiscated");
        _assertCommitteeEquals(0, snapshot0, "current committee must be untouched");
        _assertCommitteeEquals(1, snapshot1, "next committee must be untouched");
        _assertCommitteeEquals(2, snapshot2, "subsequent committee must be untouched");
        _assertSetInvariant();
    }

    /// E4: burn is the governance escape hatch and works while the registry is paused.
    function test_burn_worksWhilePaused() public {
        vm.prank(crOwner);
        consensusRegistry.pause();
        assertTrue(consensusRegistry.paused());

        _burn(validator1);

        assertTrue(consensusRegistry.isRetired(validator1));
        _assertWindowExcludes(0, 2, validator1, 3);
        _assertSetInvariant();
    }

    /// E5: an applySlashes batch that would empty the network reverts as a whole: the first three
    /// ejections are rolled back together with the fourth's InvalidCommitteeSize(0, 0). Matters for
    /// a future Rust slash producer: a batch is all-or-nothing.
    function test_applySlashes_batchEmptyingNetworkRevertsAtomically() public {
        uint256 issuanceBalBefore = issuance.balance;

        Slash[] memory slashes = new Slash[](4);
        slashes[0] = Slash(validator1, stakeAmount_);
        slashes[1] = Slash(validator2, stakeAmount_);
        slashes[2] = Slash(validator3, stakeAmount_);
        slashes[3] = Slash(validator4, stakeAmount_);

        vm.expectRevert(abi.encodeWithSelector(InvalidCommitteeSize.selector, 0, 0));
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);

        // all-or-nothing: every validator remains Active, funded, and seated
        address[4] memory genesis = [validator1, validator2, validator3, validator4];
        for (uint256 i; i < genesis.length; ++i) {
            assertFalse(consensusRegistry.isRetired(genesis[i]));
            assertEq(uint8(consensusRegistry.getValidator(genesis[i]).currentStatus), uint8(ValidatorStatus.Active));
            (uint256 outstanding,,) = consensusRegistry.getBalanceBreakdown(genesis[i]);
            assertEq(outstanding, stakeAmount_);
        }
        assertEq(consensusRegistry.getEligibleValidatorCount(), 4);
        assertEq(consensusRegistry.getNextCommitteeSize(), 4);
        assertEq(_committeeOf(0).length, 4);
        assertEq(issuance.balance, issuanceBalBefore, "reverted batch must not move funds");
        _assertSetInvariant();
    }

    /*
     *   F. future-committee-only ejection
     */

    /// F1: burning a validator seated only in the subsequent committee leaves the current and next
    /// committees byte-identical, shrinks only the subsequent one, and fires the 5 -> 4
    /// auto-decrement (eligible drops below nextCommitteeSize). Complements the Rust e2e
    /// future-only test, whose committee size stays put because its size never exceeded eligible.
    function test_burn_futureCommitteeOnly_currentUnaffected() public {
        // seat validator5 only in the subsequent committee: activate it, widen the committee to 5,
        // and conclude once so the epoch-3 committee (the only one containing validator5) is stored
        _addFifthValidator();
        vm.expectEmit(true, true, true, true);
        emit NextCommitteeSizeUpdated(4, 5, 5);
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(5);

        address[] memory allFive = new address[](5);
        allFive[0] = validator1;
        allFive[1] = validator2;
        allFive[2] = validator3;
        allFive[3] = validator4;
        allFive[4] = validator5;
        _sortAddresses(allFive);
        _conclude(allFive);

        assertEq(consensusRegistry.getCurrentEpoch(), 1);
        assertEq(uint8(consensusRegistry.getValidator(validator5).currentStatus), uint8(ValidatorStatus.Active));
        _assertCommitteeExcludes(1, validator5);
        _assertCommitteeExcludes(2, validator5);
        _assertCommitteeEquals(3, allFive, "validator5 must be seated in the subsequent committee");

        address[] memory snapshotCurrent = _committeeOf(1);
        address[] memory snapshotNext = _committeeOf(2);

        // burn fires the auto-decrement: eligible drops to 4 while nextCommitteeSize was 5
        vm.expectEmit(true, true, true, true);
        emit NextCommitteeSizeUpdated(5, 4, 4);
        _burn(validator5);

        assertTrue(consensusRegistry.isRetired(validator5));
        assertEq(consensusRegistry.getEligibleValidatorCount(), 4);
        assertEq(consensusRegistry.getNextCommitteeSize(), 4);
        _assertCommitteeEquals(1, snapshotCurrent, "current committee must be byte-identical");
        _assertCommitteeEquals(2, snapshotNext, "next committee must be byte-identical");
        assertEq(_committeeOf(3).length, 4, "subsequent committee must shrink");
        _assertCommitteeExcludes(3, validator5);
        _assertSetInvariant();

        // the network continues over the adjusted size
        _conclude(_sortedGenesisCommittee());
        assertEq(consensusRegistry.getCurrentEpoch(), 2);
        _assertSetInvariant();
    }
}
