// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { IConsensusRegistry } from "src/interfaces/IConsensusRegistry.sol";
import { SystemCallable } from "src/consensus/SystemCallable.sol";
import { StakeManager } from "src/consensus/StakeManager.sol";
import { Slash, RewardInfo, IStakeManager } from "src/interfaces/IStakeManager.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";

/// @dev Fuzz test module separated into new file with extra setup to avoid `OutOfGas`
contract ConsensusRegistryTestFuzz is ConsensusRegistryTestUtils {
    function setUp() public {
        // target
        consensusRegistry = ConsensusRegistry(0x07E17e17E17e17E17e17E17E17E17e17e17E17e1);

        vm.startStateDiffRecording();
        StakeConfig memory stakeConfig_ = StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_);
        ConsensusRegistry tempRegistry = new ConsensusRegistry(stakeConfig_, initialValidators, initialBLSPops, crOwner);
        Vm.AccountAccess[] memory records = vm.stopAndReturnStateDiff();
        bytes32[] memory slots = saveWrittenSlots(address(tempRegistry), records);
        copyContractState(address(tempRegistry), address(consensusRegistry), slots);

        // simulate protocol allocation of validators' initial stake
        registryGenesisBal = stakeAmount_ * initialValidators.length;
        vm.deal(address(consensusRegistry), registryGenesisBal);
        // set protocol system address
        sysAddress = consensusRegistry.SYSTEM_ADDRESS();

        // deal issuance contract max TEL supply to test reward distribution
        vm.deal(crOwner, epochIssuance_);
        vm.prank(crOwner);
        consensusRegistry.allocateIssuance{ value: epochIssuance_ }();
    }

    function testFuzz_mintBurn(uint24 numValidators) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 700));

        _fuzz_mint(numValidators);
        uint256 supplyBefore = consensusRegistry.totalSupply();

        // leave enough validators for the committee to stay intact
        uint32 currentEpoch = consensusRegistry.getCurrentEpoch();
        address[] memory currentCommittee = consensusRegistry.getEpochInfo(currentEpoch).committee;
        assertEq(consensusRegistry.getNextCommitteeSize(), currentCommittee.length);
        uint256[] memory burnedIds = _fuzz_burn(numValidators, currentCommittee);

        // asserts
        assertEq(consensusRegistry.totalSupply(), supplyBefore - burnedIds.length);
        uint256 numActive = numValidators >= burnedIds.length ? numValidators - burnedIds.length : 2;
        assertLe(consensusRegistry.getNextCommitteeSize(), numActive);
        assertEq(consensusRegistry.getValidators(ValidatorStatus.Active).length, numActive);
        assertEq(consensusRegistry.getCommitteeValidators(currentEpoch).length, numActive);
        for (uint256 i; i < burnedIds.length; ++i) {
            uint256 tokenId = burnedIds[i];

            // recreate validator
            address burned = _addressFromPrivateKey(tokenId);

            assertTrue(consensusRegistry.isRetired(burned));
            assertEq(consensusRegistry.balanceOf(burned), 0);

            vm.expectRevert();
            consensusRegistry.ownerOf(tokenId);
            // remint can't be done with same addresses
            vm.expectRevert();
            consensusRegistry.mint(burned);
        }
    }

    function testFuzz_mintStakeBurn(uint24 numValidators) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 400));

        uint256 issuanceBalanceBefore = consensusRegistry.issuance().balance;

        _fuzz_mint(numValidators);
        uint256 supplyBefore = consensusRegistry.totalSupply();

        _fuzz_stake(numValidators, stakeAmount_);
        _fuzz_activate(numValidators);
        uint256 numActive = consensusRegistry.getValidators(ValidatorStatus.Active).length;

        // leave enough validators for the committee to stay intact
        uint32 currentEpoch = consensusRegistry.getCurrentEpoch();
        address[] memory currentCommittee = consensusRegistry.getEpochInfo(currentEpoch).committee;
        assertEq(consensusRegistry.getNextCommitteeSize(), currentCommittee.length);
        uint256[] memory burnedIds = _fuzz_burn(numValidators, currentCommittee);

        // asserts
        assertEq(consensusRegistry.totalSupply(), supplyBefore - burnedIds.length);
        uint256 numActiveAfter = numActive >= burnedIds.length ? numActive - burnedIds.length : 2;
        assertLe(consensusRegistry.getNextCommitteeSize(), numActiveAfter);
        assertEq(consensusRegistry.getValidators(ValidatorStatus.Active).length, numActiveAfter);
        assertEq(consensusRegistry.getCommitteeValidators(currentEpoch).length, numActiveAfter);
        uint256 expectedIssuanceBalanceAfter = issuanceBalanceBefore + stakeAmount_ * burnedIds.length;
        assertEq(consensusRegistry.issuance().balance, expectedIssuanceBalanceAfter);
        for (uint256 i; i < burnedIds.length; ++i) {
            uint256 tokenId = burnedIds[i];

            // recreate validator
            address burned = _addressFromPrivateKey(tokenId);

            assertTrue(consensusRegistry.isRetired(burned));
            assertEq(consensusRegistry.balanceOf(burned), 0);

            vm.expectRevert();
            consensusRegistry.ownerOf(tokenId);
        }
    }

    function testFuzz_concludeEpoch_success(uint24 numValidators) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 750));

        uint256 numActive = consensusRegistry.getValidators(ValidatorStatus.Active).length + numValidators;

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);
        _fuzz_activate(numValidators);

        // identify committee size, conclude an epoch to reach activation epoch, then create a committee
        uint256 committeeSize = _fuzz_computeCommitteeSize(numActive, numValidators);

        // update nextCommitteeSize to match the next committee
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(committeeSize));

        // conclude epoch to reach activationEpoch for validators entered in stake & activate loop
        vm.startPrank(sysAddress);
        address[] memory tokenIdCommittee = _createTokenIdCommittee(committeeSize);
        consensusRegistry.concludeEpoch(tokenIdCommittee);
        address[] memory futureCommittee = _fuzz_createFutureCommittee(numActive, committeeSize);

        // set the subsequent epoch committee by concluding epoch
        EpochInfo memory epochInfo = consensusRegistry.getCurrentEpochInfo();
        uint32 newEpoch = consensusRegistry.getCurrentEpoch() + 1;
        address[] memory newCommittee = consensusRegistry.getEpochInfo(newEpoch).committee;
        vm.expectEmit(true, true, true, true);
        emit IConsensusRegistry
            .NewEpoch(IConsensusRegistry.EpochInfo(
                newCommittee,
                epochInfo.epochIssuance,
                uint64(block.number + 1),
                newEpoch,
                epochInfo.epochDuration,
                epochInfo.stakeVersion
            ));
        consensusRegistry.concludeEpoch(futureCommittee);

        // asserts
        uint256 numActiveAfter = consensusRegistry.getValidators(ValidatorStatus.Active).length;
        assertEq(numActiveAfter, numActive);
        uint32 returnedEpoch = consensusRegistry.getCurrentEpoch();
        assertEq(returnedEpoch, newEpoch);
        address[] memory currentCommittee = consensusRegistry.getEpochInfo(newEpoch).committee;
        for (uint256 i; i < currentCommittee.length; ++i) {
            assertEq(currentCommittee[i], initialValidators[i].validatorAddress);
        }
        address[] memory nextCommittee = consensusRegistry.getEpochInfo(newEpoch + 1).committee;
        for (uint256 i; i < nextCommittee.length; ++i) {
            assertEq(nextCommittee[i], tokenIdCommittee[i]);
        }
        address[] memory subsequentCommittee = consensusRegistry.getEpochInfo(newEpoch + 2).committee;
        for (uint256 i; i < subsequentCommittee.length; ++i) {
            assertEq(subsequentCommittee[i], futureCommittee[i]);
        }
    }

    function testFuzz_concludeEpoch_invalidCommitteeSize(uint24 numValidators) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 750));

        // read next committee size from state
        uint16 nextCommitteeSize = consensusRegistry.getNextCommitteeSize();
        uint256 numActive = consensusRegistry.getValidators(ValidatorStatus.Active).length + numValidators;
        uint256 wrongCommitteeSize = _fuzz_computeCommitteeSize(numActive, numValidators);

        // ensure wrongCommitteeSize is different from nextCommitteeSize
        vm.assume(wrongCommitteeSize != nextCommitteeSize);

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);
        _fuzz_activate(numValidators);

        // Try to conclude epoch with wrong size (different from nextCommitteeSize)
        address[] memory wrongSizeCommittee = _createTokenIdCommittee(wrongCommitteeSize);

        // Should revert with InvalidCommitteeSize
        vm.prank(sysAddress);
        vm.expectRevert(abi.encodeWithSelector(InvalidCommitteeSize.selector, nextCommitteeSize, wrongCommitteeSize));
        consensusRegistry.concludeEpoch(wrongSizeCommittee);

        // Now fix it and verify it works
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(wrongCommitteeSize));

        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(wrongSizeCommittee);
    }

    function testFuzz_applyIncentives(uint24 numValidators, uint24 numRewardees) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 800));
        numRewardees = uint24(bound(uint256(numRewardees), 1, numValidators));

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);

        vm.startPrank(sysAddress);
        // apply incentives
        (RewardInfo[] memory rewardInfos, uint256[] memory expectedRewards) = _fuzz_createRewardInfos(numRewardees);
        consensusRegistry.applyIncentives(rewardInfos);
        vm.stopPrank();

        // assert rewards were incremented for each specified validator
        for (uint256 i; i < expectedRewards.length; ++i) {
            uint256 updatedRewards = consensusRegistry.getRewards(rewardInfos[i].validatorAddress);
            assertEq(updatedRewards, expectedRewards[i]);
        }
    }

    function test_applyIncentives_dustRollover() public {
        // arithmetic with 7 validators to guarantee a remainder
        uint24 numValidators = 7;
        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);

        vm.startPrank(sysAddress);

        (RewardInfo[] memory rewardInfos,) = _fuzz_createRewardInfos(numValidators);

        // override randomness with 'consensusHeaderCount == 1` to ensure every validator has equal weight
        for (uint256 i; i < rewardInfos.length; ++i) {
            rewardInfos[i].consensusHeaderCount = 1;
        }

        // simulate 3 cycles to prove that dust is accumulating and clearing.
        uint256 knownDust;
        for (uint256 epoch = 1; epoch <= 3; ++epoch) {
            uint256 totalAvailable = epochIssuance_ + knownDust;
            uint256 expectedRewardPerValidator = totalAvailable / numValidators;
            uint256 expectedRemainder = totalAvailable - (expectedRewardPerValidator * numValidators);

            if (expectedRemainder == 0) {
                revert("Test Setup Failed: Divisor produced zero remainder.");
            }

            consensusRegistry.applyIncentives(rewardInfos);
            uint256 storedDust = consensusRegistry.undistributedIssuance();
            assertEq(storedDust, expectedRemainder, "Undistributed issuance (dust) does not match expected remainder");

            knownDust = storedDust;
        }

        vm.stopPrank();
    }

    function testFuzz_claimStakeRewards(uint24 numValidators, uint24 numRewardees) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 800));
        numRewardees = uint24(bound(uint256(numRewardees), 1, numValidators));

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);

        vm.startPrank(sysAddress);
        // apply incentives
        (RewardInfo[] memory rewardInfos, uint256[] memory expectedRewards) = _fuzz_createRewardInfos(numRewardees);
        consensusRegistry.applyIncentives(rewardInfos);
        vm.stopPrank();

        // claim rewards and assert
        for (uint256 i; i < expectedRewards.length; ++i) {
            // capture initial validator balance
            address validator = rewardInfos[i].validatorAddress;
            uint256 initialBalance = validator.balance;
            assertEq(initialBalance, 0);

            uint256 expectedReward = expectedRewards[i];
            bool willRevert = expectedReward < minWithdrawAmount_;
            if (willRevert) {
                expectedReward = 0;
                vm.expectRevert();
            } else {
                vm.expectEmit(true, true, true, true);
                emit IConsensusRegistry.RewardsClaimed(validator, expectedReward);
            }
            vm.prank(validator);
            consensusRegistry.claimStakeRewards(validator);

            // check balance after claiming
            if (willRevert) {
                assertEq(validator.balance, initialBalance);
            } else {
                assertEq(validator.balance, initialBalance + expectedReward);
            }
        }
    }

    function testFuzz_upgradeStakeVersion_increase(uint24 numValidators, uint24 stakeMultiplier) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 400));
        stakeMultiplier = uint24(bound(uint256(stakeMultiplier), 2, 10));

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);
        _fuzz_activate(numValidators);

        uint256 newStakeAmount = stakeAmount_ * stakeMultiplier;
        uint8 newVersion = _fuzz_upgradeGlobalStakeVersion(newStakeAmount);

        uint256 registryBalBefore = address(consensusRegistry).balance;

        _fuzz_upgradeValidatorStakeVersions(numValidators, newVersion, newStakeAmount, stakeAmount_);

        // assertions
        uint256 deficit = newStakeAmount - stakeAmount_;
        assertEq(address(consensusRegistry).balance, registryBalBefore + deficit * numValidators);

        for (uint256 i; i < numValidators; ++i) {
            address v = _addressFromPrivateKey(i + 5);
            ValidatorInfo memory info = consensusRegistry.getValidator(v);
            assertEq(info.stakeVersion, newVersion);

            (uint256 bal,,) = consensusRegistry.getBalanceBreakdown(v);
            assertEq(bal, newStakeAmount);
        }
    }

    function testFuzz_upgradeStakeVersion_decrease(uint24 numValidators, uint256 slashBps, uint256 newStakeRatio) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 400));
        slashBps = bound(slashBps, 0, 9999);
        newStakeRatio = bound(newStakeRatio, 1, 99);

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);
        _fuzz_activate(numValidators);

        // apply slashes
        uint256 slashAmount = stakeAmount_ * slashBps / 10000;
        if (slashAmount > 0) {
            Slash[] memory slashes = new Slash[](numValidators);
            for (uint256 i; i < numValidators; ++i) {
                address v = _addressFromPrivateKey(i + 5);
                slashes[i] = Slash(v, slashAmount);
            }
            vm.prank(sysAddress);
            consensusRegistry.applySlashes(slashes);
        }

        // create lower version
        uint256 newStakeAmount = stakeAmount_ * newStakeRatio / 100;
        // skip if newStakeAmount is 0 (would be degenerate)
        vm.assume(newStakeAmount > 0);
        uint8 newVersion = _fuzz_upgradeGlobalStakeVersion(newStakeAmount);

        // upgrade each validator individually to verify refund tiers
        for (uint256 i; i < numValidators; ++i) {
            address v = _addressFromPrivateKey(i + 5);

            // skip validators that were ejected (balance reached 0 via slash)
            if (consensusRegistry.isRetired(v)) continue;

            (uint256 currentBalance,,) = consensusRegistry.getBalanceBreakdown(v);
            uint256 recipientBalBefore = v.balance;

            uint256 expectedRefund;
            if (currentBalance >= stakeAmount_) {
                // not slashed: full surplus refund
                expectedRefund = stakeAmount_ - newStakeAmount;
            } else if (currentBalance > newStakeAmount) {
                // partially slashed: partial refund
                expectedRefund = currentBalance - newStakeAmount;
            }
            // else: slashed below new stake, no refund

            vm.prank(v);
            consensusRegistry.upgradeValidatorStakeVersion(v, newVersion);

            ValidatorInfo memory info = consensusRegistry.getValidator(v);
            assertEq(info.stakeVersion, newVersion);

            if (expectedRefund > 0) {
                // refund goes through Issuance.distributeStakeReward, which sends to recipient (v)
                assertEq(v.balance, recipientBalBefore + expectedRefund);
            }

            (uint256 newBal,,) = consensusRegistry.getBalanceBreakdown(v);
            if (currentBalance >= stakeAmount_) {
                assertEq(newBal, newStakeAmount);
            } else if (currentBalance > newStakeAmount) {
                assertEq(newBal, newStakeAmount);
            } else {
                // slashed below new stake: balance unchanged
                assertEq(newBal, currentBalance);
            }
        }
    }

    function testFuzz_upgradeStakeVersion_multiVersion(uint24 numValidators, uint8 numVersions) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 200));
        numVersions = uint8(bound(uint256(numVersions), 2, 10));

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);
        _fuzz_activate(numValidators);

        // create N versions with increasing stake
        uint8[] memory versionIds = new uint8[](numVersions);
        uint256[] memory stakeAmounts = new uint256[](numVersions);
        for (uint256 v; v < numVersions; ++v) {
            uint256 newStake = stakeAmount_ * (v + 2); // 2x, 3x, 4x, ...
            versionIds[v] = _fuzz_upgradeGlobalStakeVersion(newStake);
            stakeAmounts[v] = newStake;
        }

        uint8 finalVersion = versionIds[numVersions - 1];
        uint256 finalStake = stakeAmounts[numVersions - 1];
        uint256 deficit = finalStake - stakeAmount_;

        // each validator jumps from v0 directly to final version
        for (uint256 i; i < numValidators; ++i) {
            address v = _addressFromPrivateKey(i + 5);
            vm.deal(v, deficit);
            vm.prank(v);
            consensusRegistry.upgradeValidatorStakeVersion{value: deficit}(v, finalVersion);

            ValidatorInfo memory info = consensusRegistry.getValidator(v);
            assertEq(info.stakeVersion, finalVersion);

            (uint256 bal,,) = consensusRegistry.getBalanceBreakdown(v);
            assertEq(bal, finalStake);
        }

        // verify upgrading to an intermediate (now-lower) version reverts
        if (numVersions > 1) {
            uint8 intermediateVersion = versionIds[0];
            address testValidator = _addressFromPrivateKey(5);
            vm.prank(testValidator);
            vm.expectRevert(abi.encodeWithSelector(InvalidStakeVersion.selector, finalVersion, intermediateVersion));
            consensusRegistry.upgradeValidatorStakeVersion(testValidator, intermediateVersion);
        }
    }

    function testFuzz_upgradeStakeVersion_rewardsPreserved(uint24 numValidators, uint24 numRewardees) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 200));
        numRewardees = uint24(bound(uint256(numRewardees), 1, numValidators));

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);
        _fuzz_activate(numValidators);

        // apply initial incentives to accrue some rewards
        RewardInfo[] memory rewardInfos = new RewardInfo[](numRewardees);
        for (uint256 i; i < numRewardees; ++i) {
            // use fuzzed validators (secret 5+), give each 1 consensus header for simplicity
            rewardInfos[i] = RewardInfo(_addressFromPrivateKey(i + 5), 1);
        }

        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewardInfos);

        // record pre-upgrade rewards
        uint256[] memory rewardsBefore = new uint256[](numRewardees);
        for (uint256 i; i < numRewardees; ++i) {
            rewardsBefore[i] = consensusRegistry.getRewards(rewardInfos[i].validatorAddress);
        }

        // create new version with higher stake and upgrade first half
        uint256 newStakeAmount = stakeAmount_ * 2;
        uint8 newVersion = _fuzz_upgradeGlobalStakeVersion(newStakeAmount);

        uint24 halfValidators = numRewardees / 2;
        // upgrade first half only
        for (uint256 i; i < halfValidators; ++i) {
            address v = _addressFromPrivateKey(i + 5);
            uint256 deficit = newStakeAmount - stakeAmount_;
            vm.deal(v, deficit);
            vm.prank(v);
            consensusRegistry.upgradeValidatorStakeVersion{value: deficit}(v, newVersion);
        }

        // verify pre-upgrade rewards are preserved (balance includes stake + rewards)
        for (uint256 i; i < numRewardees; ++i) {
            uint256 rewardsAfter = consensusRegistry.getRewards(rewardInfos[i].validatorAddress);
            assertEq(rewardsAfter, rewardsBefore[i], "Rewards should be preserved after version upgrade");
        }

        // allocate more issuance for next round
        vm.deal(crOwner, epochIssuance_);
        vm.prank(crOwner);
        consensusRegistry.allocateIssuance{value: epochIssuance_}();

        // apply incentives again - now mixed versions should use different weights
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewardInfos);

        // verify mixed-version weighting: upgraded validators should earn more
        if (halfValidators > 0 && numRewardees > halfValidators) {
            // upgraded validator (version newVersion, weight = newStakeAmount * 1)
            uint256 upgradedNewRewards = consensusRegistry.getRewards(_addressFromPrivateKey(5)) - rewardsBefore[0];
            // non-upgraded validator (version 0, weight = stakeAmount_ * 1)
            uint256 nonUpgradedNewRewards = consensusRegistry.getRewards(_addressFromPrivateKey(halfValidators + 5)) - rewardsBefore[halfValidators];

            // upgraded validators have 2x the stake weight, so should earn ~2x the rewards
            // use >= since integer division may cause slight variance
            assertGe(upgradedNewRewards, nonUpgradedNewRewards, "Upgraded validators should earn >= non-upgraded");
        }
    }

    function testFuzz_upgradeStakeVersion_concludeEpoch(uint24 numValidators) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 200));

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);
        _fuzz_activate(numValidators);

        uint256 numActive = consensusRegistry.getValidators(ValidatorStatus.Active).length;

        // upgrade half to new version
        uint256 newStakeAmount = stakeAmount_ * 3;
        uint8 newVersion = _fuzz_upgradeGlobalStakeVersion(newStakeAmount);

        uint24 halfValidators = numValidators / 2;
        if (halfValidators > 0) {
            uint256 deficit = newStakeAmount - stakeAmount_;
            for (uint256 i; i < halfValidators; ++i) {
                address v = _addressFromPrivateKey(i + 5);
                vm.deal(v, deficit);
                vm.prank(v);
                consensusRegistry.upgradeValidatorStakeVersion{value: deficit}(v, newVersion);
            }
        }

        // conclude epoch - setup committee size and committee
        uint256 committeeSize = _fuzz_computeCommitteeSize(numActive, numValidators);
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(committeeSize));

        // first conclude to handle pending activations
        address[] memory tokenIdCommittee = _createTokenIdCommittee(committeeSize);
        vm.startPrank(sysAddress);
        consensusRegistry.concludeEpoch(tokenIdCommittee);

        // create future committee and conclude again
        address[] memory futureCommittee = _fuzz_createFutureCommittee(numActive, committeeSize);
        consensusRegistry.concludeEpoch(futureCommittee);
        vm.stopPrank();

        // assertions
        // epoch transition succeeded (no revert)
        uint32 currentEpoch = consensusRegistry.getCurrentEpoch();
        EpochInfo memory epochInfo = consensusRegistry.getCurrentEpochInfo();

        // EpochInfo.stakeVersion reflects global version, not individual
        assertEq(epochInfo.stakeVersion, newVersion, "Epoch stakeVersion should reflect global version");

        // all validators remain Active
        uint256 numActiveAfter = consensusRegistry.getValidators(ValidatorStatus.Active).length;
        assertEq(numActiveAfter, numActive, "All validators should remain active after epoch transition");

        // verify mixed versions in validator set
        if (halfValidators > 0) {
            // upgraded validator
            ValidatorInfo memory upgraded = consensusRegistry.getValidator(_addressFromPrivateKey(5));
            assertEq(upgraded.stakeVersion, newVersion);
            assertEq(uint8(upgraded.currentStatus), uint8(ValidatorStatus.Active));

            // non-upgraded validator (last fuzzed)
            address lastValidator = _addressFromPrivateKey(numValidators + 4);
            ValidatorInfo memory nonUpgraded = consensusRegistry.getValidator(lastValidator);
            assertEq(nonUpgraded.stakeVersion, 0);
            assertEq(uint8(nonUpgraded.currentStatus), uint8(ValidatorStatus.Active));
        }

        // committee membership unaffected by version differences
        // futureCommittee was placed at currentEpoch + 2 by the second concludeEpoch
        address[] memory committeeMembers = consensusRegistry.getEpochInfo(currentEpoch + 2).committee;
        assertEq(committeeMembers.length, committeeSize, "Committee size should be correct");
    }

    function testFuzz_upgradeStakeVersion_invalidInputs(uint24 numValidators, uint256 wrongMsgValue, uint8 invalidVersion) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 100));

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);
        _fuzz_activate(numValidators);

        uint256 newStakeAmount = stakeAmount_ * 2;
        uint8 newVersion = _fuzz_upgradeGlobalStakeVersion(newStakeAmount);
        uint256 deficit = newStakeAmount - stakeAmount_;

        address testValidator = _addressFromPrivateKey(5);

        // Sub-test A: Wrong msg.value on increase
        wrongMsgValue = bound(wrongMsgValue, 0, type(uint128).max);
        vm.assume(wrongMsgValue != deficit);
        vm.deal(testValidator, wrongMsgValue);
        vm.prank(testValidator);
        vm.expectRevert(abi.encodeWithSelector(InvalidStakeAmount.selector, wrongMsgValue));
        consensusRegistry.upgradeValidatorStakeVersion{value: wrongMsgValue}(testValidator, newVersion);

        // Sub-test B: Non-zero msg.value on decrease
        uint256 lowerStake = stakeAmount_ / 2;
        uint8 lowerVersion = _fuzz_upgradeGlobalStakeVersion(lowerStake);
        vm.deal(testValidator, 1 ether);
        vm.prank(testValidator);
        vm.expectRevert(abi.encodeWithSelector(InvalidStakeAmount.selector, 1 ether));
        consensusRegistry.upgradeValidatorStakeVersion{value: 1 ether}(testValidator, lowerVersion);

        // Sub-test C: targetVersion <= currentVersion (version 0, same as current)
        vm.prank(testValidator);
        vm.expectRevert(abi.encodeWithSelector(InvalidStakeVersion.selector, uint8(0), uint8(0)));
        consensusRegistry.upgradeValidatorStakeVersion(testValidator, 0);

        // Sub-test D: targetVersion > stakeVersion (too high)
        uint8 tooHigh = uint8(bound(uint256(invalidVersion), lowerVersion + 1, type(uint8).max));
        vm.prank(testValidator);
        vm.expectRevert(abi.encodeWithSelector(InvalidStakeVersion.selector, uint8(0), tooHigh));
        consensusRegistry.upgradeValidatorStakeVersion(testValidator, tooHigh);

        // Sub-test E: PendingExit status
        // Use an initial genesis validator (already Active) since fuzzed validators are PendingActivation
        // beginExit checks numActive > committeeSize; with 4 initial + numValidators fuzzed, we have enough
        {
            address exitValidator = validator1; // genesis validator, already Active
            vm.prank(exitValidator);
            consensusRegistry.beginExit();

            vm.prank(exitValidator);
            vm.expectRevert(abi.encodeWithSelector(InvalidStatus.selector, ValidatorStatus.PendingExit));
            consensusRegistry.upgradeValidatorStakeVersion(exitValidator, newVersion);
        }

        // Sub-test F: Unauthorized caller
        address unauthorized = address(0xdead);
        vm.prank(unauthorized);
        vm.expectRevert(abi.encodeWithSelector(NotRecipient.selector, testValidator));
        consensusRegistry.upgradeValidatorStakeVersion(testValidator, newVersion);
    }
}
