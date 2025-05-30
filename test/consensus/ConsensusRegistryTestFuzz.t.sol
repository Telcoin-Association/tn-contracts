// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { IConsensusRegistry } from "src/interfaces/IConsensusRegistry.sol";
import { SystemCallable } from "src/consensus/SystemCallable.sol";
import { StakeManager } from "src/consensus/StakeManager.sol";
import { Slash, RewardInfo, IStakeManager } from "src/interfaces/IStakeManager.sol";
import { InterchainTEL } from "src/InterchainTEL.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";

/// @dev Fuzz test module separated into new file with extra setup to avoid `OutOfGas`
contract ConsensusRegistryTestFuzz is ConsensusRegistryTestUtils {
    function setUp() public {
        StakeConfig memory stakeConfig_ = StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_);
        consensusRegistry = new ConsensusRegistry(stakeConfig_, initialValidators, crOwner);

        sysAddress = consensusRegistry.SYSTEM_ADDRESS();

        // deal issuance contract max TEL supply to test reward distribution
        vm.deal(crOwner, epochIssuance_);
        vm.prank(crOwner);
        consensusRegistry.allocateIssuance{ value: epochIssuance_ }();
    }

    function testFuzz_mintBurn(uint24 numValidators) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 645));

        _fuzz_mint(numValidators);
        vm.deal(address(consensusRegistry), stakeAmount_ * (numValidators + 5)); // provide funds
        uint256 supplyBefore = consensusRegistry.totalSupply();

        // leave enough validators for the committee to stay intact
        uint32 currentEpoch = consensusRegistry.getCurrentEpoch();
        address[] memory currentCommittee = consensusRegistry.getEpochInfo(currentEpoch).committee;
        uint256[] memory burnedIds = _fuzz_burn(numValidators, currentCommittee);

        // asserts
        assertEq(consensusRegistry.totalSupply(), supplyBefore - burnedIds.length);
        for (uint256 i; i < burnedIds.length; ++i) {
            uint256 tokenId = burnedIds[i];

            // recreate validator
            address burned = _createRandomAddress(tokenId);

            assertTrue(consensusRegistry.isRetired(tokenId));
            assertEq(consensusRegistry.balanceOf(burned), 0);

            vm.expectRevert();
            consensusRegistry.ownerOf(tokenId);
            vm.expectRevert();
            consensusRegistry.getValidatorTokenId(burned);
            vm.expectRevert();
            consensusRegistry.getValidatorByTokenId(tokenId);
        }

        // remint can't be done with same addresses
        vm.expectRevert();
        consensusRegistry.mint(_createRandomAddress(1), 1);

        // remint with new addresses
        for (uint256 i; i < numValidators; ++i) {
            // account for initial validators
            uint256 tokenId = i + 5;
            uint256 uniqueSeed = tokenId + numValidators;
            address newValidator = _createRandomAddress(uniqueSeed);

            // deal `stakeAmount` funds and prank governance NFT mint to `newValidator`
            vm.deal(newValidator, stakeAmount_);
            vm.prank(crOwner);
            consensusRegistry.mint(newValidator, tokenId);
        }
    }

    function testFuzz_concludeEpoch(uint24 numValidators) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 2000));

        uint256 numActive = consensusRegistry.getValidators(ValidatorStatus.Active).length + numValidators;

        _fuzz_mint(numValidators);
        _fuzz_stake(numValidators, stakeAmount_);
        _fuzz_activate(numValidators);

        // identify committee size, conclude an epoch to reach activation epoch, then create a committee
        uint256 committeeSize = _fuzz_computeCommitteeSize(numActive, numValidators);
        // conclude epoch to reach activationEpoch for validators entered in stake & activate loop
        vm.startPrank(sysAddress);
        address[] memory zeroCommittee = new address[](committeeSize);
        consensusRegistry.concludeEpoch(zeroCommittee);
        address[] memory newCommittee = _fuzz_createNewCommittee(numActive, committeeSize);

        // set the subsequent epoch committee by concluding epoch
        uint32 duration = consensusRegistry.getCurrentEpochInfo().epochDuration;
        vm.expectEmit(true, true, true, true);
        emit IConsensusRegistry.NewEpoch(IConsensusRegistry.EpochInfo(newCommittee, uint64(block.number + 1), duration));
        consensusRegistry.concludeEpoch(newCommittee);

        // asserts
        uint256 numActiveAfter = consensusRegistry.getValidators(ValidatorStatus.Active).length;
        assertEq(numActiveAfter, numActive);
        uint32 newEpoch = consensusRegistry.getCurrentEpoch();
        address[] memory currentCommittee = consensusRegistry.getEpochInfo(newEpoch).committee;
        for (uint256 i; i < currentCommittee.length; ++i) {
            assertEq(currentCommittee[i], initialValidators[i].validatorAddress);
        }
        address[] memory nextCommittee = consensusRegistry.getEpochInfo(newEpoch + 1).committee;
        for (uint256 i; i < nextCommittee.length; ++i) {
            assertEq(nextCommittee[i], zeroCommittee[i]);
        }
        address[] memory subsequentCommittee = consensusRegistry.getEpochInfo(newEpoch + 2).committee;
        for (uint256 i; i < subsequentCommittee.length; ++i) {
            assertEq(subsequentCommittee[i], newCommittee[i]);
        }
    }

    function testFuzz_applyIncentives(uint24 numValidators, uint24 numRewardees) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 1050));
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

    function testFuzz_claimStakeRewards(uint24 numValidators, uint24 numRewardees) public {
        numValidators = uint24(bound(uint256(numValidators), 1, 2000));
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
}
