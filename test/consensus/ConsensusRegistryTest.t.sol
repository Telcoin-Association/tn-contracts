// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { IConsensusRegistry } from "src/consensus/IConsensusRegistry.sol";
import { SystemCallable } from "src/consensus/SystemCallable.sol";
import { StakeManager } from "src/consensus/StakeManager.sol";
import { StakeInfo, IStakeManager } from "src/consensus/IStakeManager.sol";
import { RWTEL } from "src/RWTEL.sol";

contract ConsensusRegistryTest is Test {
    ConsensusRegistry public consensusRegistryImpl;
    ConsensusRegistry public consensusRegistry;
    RWTEL public rwTEL;

    address public owner = address(0x1);
    address public validator0 = address(0x2);
    IConsensusRegistry.ValidatorInfo[] initialValidators; // contains validator0 only
    address public validator1 = address(0x42);
    address public sysAddress;

    bytes public blsPubkey =
        hex"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456";
    bytes public blsSig =
        hex"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    bytes32 public ed25519Pubkey = bytes32(hex"1234567890123456789012345678901234567890123456789012345678901234");

    uint256 public telMaxSupply = 100_000_000_000 ether;
    uint256 public stakeAmount = 1_000_000 ether;
    uint256 public minWithdrawAmount = 10_000 ether;

    function setUp() public {
        // set RWTEL address (its bytecode is written after deploying ConsensusRegistry)
        rwTEL = RWTEL(address(0x7e1));

        // provide an initial validator as the network will launch with at least one validator
        initialValidators.push(
            IConsensusRegistry.ValidatorInfo(
                _createRandomBlsPubkey(stakeAmount),
                keccak256(abi.encode(stakeAmount)),
                validator0,
                uint32(0),
                uint32(0),
                uint16(1),
                bytes4(0),
                IConsensusRegistry.ValidatorStatus.Active
            )
        );
        consensusRegistryImpl = new ConsensusRegistry();
        consensusRegistry = ConsensusRegistry(payable(address(new ERC1967Proxy(address(consensusRegistryImpl), ""))));
        consensusRegistry.initialize(address(rwTEL), stakeAmount, minWithdrawAmount, initialValidators, owner);

        sysAddress = consensusRegistry.SYSTEM_ADDRESS();

        vm.deal(validator1, 100_000_000 ether);

        // deploy an RWTEL module and then use its bytecode to etch on a fixed address (use create2 in prod)
        RWTEL tmp =
            new RWTEL(address(consensusRegistry), address(0xbeef), "test", "TEST", 0, address(0x0), address(0x0), 0);
        vm.etch(address(rwTEL), address(tmp).code);
        // deal RWTEL max TEL supply to test reward distribution
        vm.deal(address(rwTEL), telMaxSupply);
    }

    // Test for successful staking
    function test_stake() public {
        // Check event emission
        uint32 activationEpoch = uint32(2);
        uint16 expectedIndex = uint16(2);
        vm.expectEmit(true, true, true, true);
        emit IConsensusRegistry.ValidatorPendingActivation(
            IConsensusRegistry.ValidatorInfo(
                blsPubkey,
                ed25519Pubkey,
                validator1,
                activationEpoch,
                uint32(0),
                expectedIndex,
                bytes4(0),
                IConsensusRegistry.ValidatorStatus.PendingActivation
            )
        );
        vm.prank(validator1);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, blsSig, ed25519Pubkey);

        // Check validator information
        IConsensusRegistry.ValidatorInfo[] memory validators =
            consensusRegistry.getValidators(IConsensusRegistry.ValidatorStatus.PendingActivation);
        assertEq(validators.length, 1);
        assertEq(validators[0].ecdsaPubkey, validator1);
        assertEq(validators[0].blsPubkey, blsPubkey);
        assertEq(validators[0].ed25519Pubkey, ed25519Pubkey);
        assertEq(validators[0].activationEpoch, activationEpoch);
        assertEq(validators[0].exitEpoch, uint32(0));
        assertEq(validators[0].unused, bytes4(0));
        assertEq(validators[0].validatorIndex, expectedIndex);
        assertEq(uint8(validators[0].currentStatus), uint8(IConsensusRegistry.ValidatorStatus.PendingActivation));

        // Finalize epoch twice to reach validator1 activationEpoch
        vm.startPrank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        // use 2 member array for committee now that there are 2 active
        consensusRegistry.finalizePreviousEpoch(new address[](2), new StakeInfo[](0));
        vm.stopPrank();

        // Check validator information
        IConsensusRegistry.ValidatorInfo[] memory activeValidators =
            consensusRegistry.getValidators(IConsensusRegistry.ValidatorStatus.Active);
        assertEq(activeValidators.length, 2);
        assertEq(activeValidators[0].ecdsaPubkey, validator0);
        assertEq(activeValidators[1].ecdsaPubkey, validator1);
        assertEq(uint8(activeValidators[1].currentStatus), uint8(IConsensusRegistry.ValidatorStatus.Active));
    }

    function testRevert_stake_inblsPubkeyLength() public {
        vm.prank(validator1);
        vm.expectRevert(IConsensusRegistry.InvalidBLSPubkey.selector);
        consensusRegistry.stake{ value: stakeAmount }("", blsSig, ed25519Pubkey);
    }

    function testRevert_stake_invalidBlsSigLength() public {
        vm.prank(validator1);
        vm.expectRevert(IConsensusRegistry.InvalidProof.selector);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, "", ed25519Pubkey);
    }

    // Test for incorrect stake amount
    function testRevert_stake_invalidStakeAmount() public {
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.InvalidStakeAmount.selector, 0));
        consensusRegistry.stake{ value: 0 }(blsPubkey, blsSig, ed25519Pubkey);
    }

    function test_exit() public {
        // First stake
        vm.prank(validator1);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, blsSig, ed25519Pubkey);

        // Finalize epoch to twice reach activation epoch
        vm.startPrank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        consensusRegistry.finalizePreviousEpoch(new address[](2), new StakeInfo[](0));
        vm.stopPrank();

        // Check event emission
        uint32 activationEpoch = uint32(2);
        uint32 exitEpoch = uint32(4);
        uint16 expectedIndex = 2;
        vm.expectEmit(true, true, true, true);
        emit IConsensusRegistry.ValidatorPendingExit(
            IConsensusRegistry.ValidatorInfo(
                blsPubkey,
                ed25519Pubkey,
                validator1,
                activationEpoch,
                exitEpoch,
                expectedIndex,
                bytes4(0),
                IConsensusRegistry.ValidatorStatus.PendingExit
            )
        );
        // Exit
        vm.prank(validator1);
        consensusRegistry.exit();

        // Check validator information is pending exit
        IConsensusRegistry.ValidatorInfo[] memory pendingExitValidators =
            consensusRegistry.getValidators(IConsensusRegistry.ValidatorStatus.PendingExit);
        assertEq(pendingExitValidators.length, 1);
        assertEq(pendingExitValidators[0].ecdsaPubkey, validator1);
        assertEq(uint8(pendingExitValidators[0].currentStatus), uint8(IConsensusRegistry.ValidatorStatus.PendingExit));

        // Finalize epoch twice to reach exit epoch
        vm.startPrank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        vm.stopPrank();

        // Check validator information is exited
        IConsensusRegistry.ValidatorInfo[] memory exitValidators =
            consensusRegistry.getValidators(IConsensusRegistry.ValidatorStatus.Exited);
        assertEq(exitValidators.length, 1);
        assertEq(exitValidators[0].ecdsaPubkey, validator1);
        assertEq(uint8(exitValidators[0].currentStatus), uint8(IConsensusRegistry.ValidatorStatus.Exited));
    }

    function test_exit_rejoin() public {
        // First stake
        vm.prank(validator1);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, blsSig, ed25519Pubkey);

        // Finalize epoch to twice reach activation epoch
        vm.startPrank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        consensusRegistry.finalizePreviousEpoch(new address[](2), new StakeInfo[](0));
        vm.stopPrank();

        // Exit
        vm.prank(validator1);
        consensusRegistry.exit();

        // Finalize epoch twice to reach exit epoch
        vm.startPrank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        vm.stopPrank();

        // Check event emission
        uint32 newActivationEpoch = consensusRegistry.getCurrentEpoch() + 2;
        uint32 exitEpoch = uint32(4);
        uint16 expectedIndex = 2;
        vm.expectEmit(true, true, true, true);
        emit IConsensusRegistry.ValidatorPendingActivation(
            IConsensusRegistry.ValidatorInfo(
                blsPubkey,
                ed25519Pubkey,
                validator1,
                newActivationEpoch,
                exitEpoch,
                expectedIndex,
                bytes4(0),
                IConsensusRegistry.ValidatorStatus.PendingActivation
            )
        );
        // Re-stake after exit
        vm.prank(validator1);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, blsSig, ed25519Pubkey);

        // Check validator information
        IConsensusRegistry.ValidatorInfo[] memory validators =
            consensusRegistry.getValidators(IConsensusRegistry.ValidatorStatus.PendingActivation);
        assertEq(validators.length, 1);
        assertEq(validators[0].ecdsaPubkey, validator1);
        assertEq(uint8(validators[0].currentStatus), uint8(IConsensusRegistry.ValidatorStatus.PendingActivation));
    }

    // Test for exit by a non-validator
    function testRevert_exit_nonValidator() public {
        address nonValidator = address(0x3);

        vm.prank(nonValidator);
        vm.expectRevert(abi.encodeWithSelector(IConsensusRegistry.NotValidator.selector, nonValidator));
        consensusRegistry.exit();
    }

    // Test for exit by a validator who is not active
    function testRevert_exit_notActive() public {
        // First stake
        vm.prank(validator1);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, blsSig, ed25519Pubkey);

        // Attempt to exit without being active
        vm.prank(validator1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IConsensusRegistry.InvalidStatus.selector, IConsensusRegistry.ValidatorStatus.PendingActivation
            )
        );
        consensusRegistry.exit();
    }

    function test_unstake() public {
        // First stake
        vm.prank(validator1);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, blsSig, ed25519Pubkey);

        // Finalize epoch to process stake
        vm.prank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));

        // Finalize epoch again to reach validator1 activationEpoch
        vm.prank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](2), new StakeInfo[](0));

        // Check validator information
        IConsensusRegistry.ValidatorInfo[] memory validators =
            consensusRegistry.getValidators(IConsensusRegistry.ValidatorStatus.Active);
        assertEq(validators.length, 2);
        assertEq(validators[0].ecdsaPubkey, validator0);
        assertEq(validators[1].ecdsaPubkey, validator1);
        assertEq(uint8(validators[1].currentStatus), uint8(IConsensusRegistry.ValidatorStatus.Active));

        // Exit
        vm.prank(validator1);
        consensusRegistry.exit();

        // Check validator information
        IConsensusRegistry.ValidatorInfo[] memory pendingExitValidators =
            consensusRegistry.getValidators(IConsensusRegistry.ValidatorStatus.PendingExit);
        assertEq(pendingExitValidators.length, 1);
        assertEq(pendingExitValidators[0].ecdsaPubkey, validator1);
        assertEq(uint8(pendingExitValidators[0].currentStatus), uint8(IConsensusRegistry.ValidatorStatus.PendingExit));

        // Finalize epoch twice to process exit
        vm.startPrank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        vm.stopPrank();

        // Check validator information
        IConsensusRegistry.ValidatorInfo[] memory exitedValidators =
            consensusRegistry.getValidators(IConsensusRegistry.ValidatorStatus.Exited);
        assertEq(exitedValidators.length, 1);
        assertEq(exitedValidators[0].ecdsaPubkey, validator1);
        assertEq(uint8(exitedValidators[0].currentStatus), uint8(IConsensusRegistry.ValidatorStatus.Exited));

        // Capture pre-exit balance
        uint256 initialBalance = validator1.balance;

        // Check event emission
        vm.expectEmit(true, true, true, true);
        emit IConsensusRegistry.RewardsClaimed(validator1, stakeAmount);
        // Unstake
        vm.prank(validator1);
        consensusRegistry.unstake();

        // Check balance after unstake
        uint256 finalBalance = validator1.balance;
        assertEq(finalBalance, initialBalance + stakeAmount);
    }

    // Test for unstake by a non-validator
    function testRevert_unstake_nonValidator() public {
        address nonValidator = address(0x3);

        vm.prank(nonValidator);
        vm.expectRevert(abi.encodeWithSelector(IConsensusRegistry.NotValidator.selector, nonValidator));
        consensusRegistry.unstake();
    }

    // Test for unstake by a validator who has not exited
    function testRevert_unstake_notExited() public {
        // First stake
        vm.prank(validator1);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, blsSig, ed25519Pubkey);

        // Attempt to unstake without exiting
        vm.prank(validator1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IConsensusRegistry.InvalidStatus.selector, IConsensusRegistry.ValidatorStatus.PendingActivation
            )
        );
        consensusRegistry.unstake();
    }

    // Test for successful claim of staking rewards
    function testFuzz_claimStakeRewards(uint240 fuzzedRewards) public {
        fuzzedRewards = uint240(bound(uint256(fuzzedRewards), minWithdrawAmount, telMaxSupply));

        // First stake
        vm.prank(validator1);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, blsSig, ed25519Pubkey);

        // Capture initial rewards info
        uint256 initialRewards = consensusRegistry.getRewards(validator1);

        // Finalize epoch twice to reach validator1 activationEpoch
        vm.startPrank(sysAddress);
        (, uint256 numActiveValidators) =
            consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        // use 2 member array for committee now that there are 2 active
        consensusRegistry.finalizePreviousEpoch(new address[](numActiveValidators + 1), new StakeInfo[](0));

        // Simulate earning rewards by finalizing an epoch with a `StakeInfo` for validator1
        uint16 validator1Index = 2;
        StakeInfo[] memory validator1Rewards = new StakeInfo[](1);
        validator1Rewards[0] = StakeInfo(validator1Index, fuzzedRewards);
        consensusRegistry.finalizePreviousEpoch(new address[](2), validator1Rewards);
        vm.stopPrank();

        // Check rewards were incremented
        uint256 updatedRewards = consensusRegistry.getRewards(validator1);
        assertEq(updatedRewards, initialRewards + fuzzedRewards);

        // Capture initial validator balance
        uint256 initialBalance = validator1.balance;

        // Check event emission and claim rewards
        vm.expectEmit(true, true, true, true);
        emit IConsensusRegistry.RewardsClaimed(validator1, fuzzedRewards);
        vm.prank(validator1);
        consensusRegistry.claimStakeRewards();

        // Check balance after claiming
        uint256 updatedBalance = validator1.balance;
        assertEq(updatedBalance, initialBalance + fuzzedRewards);
    }

    // Test for claim by a non-validator
    function testRevert_claimStakeRewards_nonValidator() public {
        address nonValidator = address(0x3);
        vm.deal(nonValidator, 10 ether);

        vm.prank(nonValidator);
        vm.expectRevert(abi.encodeWithSelector(IConsensusRegistry.NotValidator.selector, nonValidator));
        consensusRegistry.claimStakeRewards();
    }

    // Test for claim by a validator with insufficient rewards
    function testRevert_claimStakeRewards_insufficientRewards() public {
        // First stake
        vm.prank(validator1);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, blsSig, ed25519Pubkey);

        // Finalize epoch twice to reach validator1 activationEpoch
        vm.startPrank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        // use 2 member array for committee now that there are 2 active
        consensusRegistry.finalizePreviousEpoch(new address[](2), new StakeInfo[](0));

        // earn too little rewards for withdrawal
        uint240 notEnoughRewards = uint240(minWithdrawAmount - 1);
        uint16 validator1Index = 2;
        StakeInfo[] memory validator1Rewards = new StakeInfo[](1);
        validator1Rewards[0] = StakeInfo(validator1Index, notEnoughRewards);
        consensusRegistry.finalizePreviousEpoch(new address[](2), validator1Rewards);
        vm.stopPrank();

        // Attempt to claim rewards
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.InsufficientRewards.selector, notEnoughRewards));
        consensusRegistry.claimStakeRewards();
    }

    function test_finalizePreviousEpoch_updatesEpochInfo() public {
        // Initialize test data
        address[] memory newCommittee = new address[](1);
        newCommittee[0] = address(0x69);

        uint32 initialEpoch = consensusRegistry.getCurrentEpoch();
        assertEq(initialEpoch, 0);

        // Call the function
        vm.prank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(newCommittee, new StakeInfo[](0));

        // Fetch current epoch and verify it has incremented
        uint32 currentEpoch = consensusRegistry.getCurrentEpoch();
        assertEq(currentEpoch, initialEpoch + 1);

        // Verify new epoch information
        IConsensusRegistry.EpochInfo memory epochInfo = consensusRegistry.getEpochInfo(currentEpoch);
        assertEq(epochInfo.blockHeight, block.number);
        for (uint256 i; i < epochInfo.committee.length; ++i) {
            assertEq(epochInfo.committee[i], newCommittee[i]);
        }
    }

    function test_finalizePreviousEpoch_activatesValidators() public {
        // enter validator in PendingActivation state
        vm.prank(validator1);
        consensusRegistry.stake{ value: stakeAmount }(blsPubkey, new bytes(96), ed25519Pubkey);

        // Fast forward epochs to reach activatino epoch
        vm.startPrank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        consensusRegistry.finalizePreviousEpoch(new address[](2), new StakeInfo[](0));
        vm.stopPrank();

        // check validator1 activated
        IConsensusRegistry.ValidatorInfo[] memory validators =
            consensusRegistry.getValidators(IConsensusRegistry.ValidatorStatus.Active);
        assertEq(validators.length, 2);
        assertEq(validators[0].ecdsaPubkey, validator0);
        assertEq(validators[1].ecdsaPubkey, validator1);
        uint16 returnedIndex = consensusRegistry.getValidatorIndex(validator1);
        assertEq(returnedIndex, 2);
        IConsensusRegistry.ValidatorInfo memory returnedVal = consensusRegistry.getValidatorByIndex(returnedIndex);
        assertEq(returnedVal.ecdsaPubkey, validator1);
    }

    function testFuzz_finalizePreviousEpoch(
        uint16 numValidators,
        uint240 fuzzedRewards
    )
        public
    {
        numValidators = uint16(bound(uint256(numValidators), 4, 8000)); // fuzz up to 8k validators
        fuzzedRewards = uint240(bound(uint256(fuzzedRewards), minWithdrawAmount, telMaxSupply));

        // exit existing validator0 which was activated in constructor to clean up calculations
        vm.prank(validator0);
        consensusRegistry.exit();
        // Finalize epoch once to reach `PendingExit` for `validator0`
        vm.prank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));

        numValidators = 2000;
        fuzzedRewards = uint240(minWithdrawAmount);

        // activate validators using `stake()` and construct `newCommittee` array as pseudorandom subset (1/3) of all validators
        uint256 committeeSize = uint256(numValidators) * 10_000 / 3 / 10_000 + 1; // address precision loss
        address[] memory newCommittee = new address[](committeeSize);
        uint256 committeeCounter;
        for (uint256 i; i < numValidators; ++i) {
            // create random new validator keys
            bytes memory newBLSPubkey = _createRandomBlsPubkey(i);
            bytes memory newBLSSig = _createRandomBlsSig(i);
            bytes32 newED25519Pubkey = _createRandomED25519Pubkey(i);
            address newValidator = address(uint160(uint256(keccak256(abi.encode(i)))));

            vm.deal(newValidator, stakeAmount);
            vm.prank(newValidator);
            consensusRegistry.stake{ value: stakeAmount }(newBLSPubkey, newBLSSig, newED25519Pubkey);

            // assert initial rewards info is 0
            uint256 initialRewards = consensusRegistry.getRewards(newValidator);
            assertEq(initialRewards, 0);

            // conditionally push validator address to array (deterministic but random enough for tests)
            if (uint256(keccak256(abi.encode(i))) % 2 == 0) {
                // if the `newCommittee` array has been populated, continue
                if (committeeCounter == newCommittee.length) continue;

                newCommittee[committeeCounter] = newValidator;
                committeeCounter++;
            }
        }

        // Finalize epoch twice to reach activationEpoch for validators entered in the `stake()` loop
        vm.startPrank(sysAddress);
        consensusRegistry.finalizePreviousEpoch(new address[](1), new StakeInfo[](0));
        // use 2 member array for committee now that there are 2 active
        consensusRegistry.finalizePreviousEpoch(newCommittee, new StakeInfo[](0));

        uint256 numRecipients = newCommittee.length; // all committee members receive rewards
        uint240 rewardPerValidator = uint240(fuzzedRewards / numRecipients);
        // construct `committeeRewards` array to compensate voting committee equally (total `fuzzedRewards` divided
        // across committee)
        StakeInfo[] memory committeeRewards = new StakeInfo[](numRecipients);
        for (uint256 i; i < newCommittee.length; ++i) {
            uint16 recipientIndex = consensusRegistry.getValidatorIndex(newCommittee[i]);
            committeeRewards[i] = StakeInfo(recipientIndex, rewardPerValidator);
        }

        // Expect the event
        vm.expectEmit(true, true, true, true);
        emit IConsensusRegistry.NewEpoch(IConsensusRegistry.EpochInfo(newCommittee, uint64(block.number)));
        // increment rewards by finalizing an epoch with a `StakeInfo` for constructed committee (new committee not
        // relevant)
        consensusRegistry.finalizePreviousEpoch(newCommittee, committeeRewards);
        vm.stopPrank();

        // Check rewards were incremented for each committee member
        for (uint256 i; i < newCommittee.length; ++i) {
            uint16 index = consensusRegistry.getValidatorIndex(newCommittee[i]);
            address committeeMember = consensusRegistry.getValidatorByIndex(index).ecdsaPubkey;
            uint256 updatedRewards = consensusRegistry.getRewards(committeeMember);
            assertEq(updatedRewards, rewardPerValidator);
        }
    }

    // Attempt to call without sysAddress should revert
    function testRevert_finalizePreviousEpoch_OnlySystemCall() public {
        vm.expectRevert(abi.encodeWithSelector(SystemCallable.OnlySystemCall.selector, address(this)));
        consensusRegistry.finalizePreviousEpoch(new address[](0), new StakeInfo[](0));
    }

    function _createRandomBlsPubkey(uint256 seed) internal pure returns (bytes memory) {
        bytes32 seedHash = keccak256(abi.encode(seed));
        return abi.encodePacked(seedHash, bytes16(keccak256(abi.encode(seedHash))));
    }

    function _createRandomBlsSig(uint256 seed) internal pure returns (bytes memory) {
        bytes32 seedHash = keccak256(abi.encode(seed));
        return abi.encodePacked(seedHash, keccak256(abi.encode(seedHash)), bytes32(0));
    }

    function _createRandomED25519Pubkey(uint256 seed) internal pure returns (bytes32) {
        return keccak256(abi.encode(seed));
    }
}
