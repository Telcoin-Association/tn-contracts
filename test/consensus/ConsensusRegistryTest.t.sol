// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { SystemCallable } from "src/consensus/SystemCallable.sol";
import { StakeManager } from "src/consensus/StakeManager.sol";
import { Slash, IStakeManager } from "src/interfaces/IStakeManager.sol";
import { InterchainTEL } from "src/InterchainTEL.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";
import { BlsG1 } from "../../src/consensus/BlsG1.sol";

contract ConsensusRegistryTest is ConsensusRegistryTestUtils {
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

        vm.deal(validator5, stakeAmount_);

        // deal issuance contract max TEL supply to test reward distribution
        vm.deal(crOwner, epochIssuance_);
        vm.prank(crOwner);
        consensusRegistry.allocateIssuance{ value: epochIssuance_ }();
    }

    function test_setUp() public view {
        assertEq(consensusRegistry.getCurrentEpoch(), 0);
        ValidatorInfo[] memory active = consensusRegistry.getValidators(ValidatorStatus.Active);
        for (uint256 i; i < 3; ++i) {
            assertEq(active[i].validatorAddress, initialValidators[i].validatorAddress);
            assertEq(
                consensusRegistry.getValidator(initialValidators[i].validatorAddress).validatorAddress,
                active[i].validatorAddress
            );
            assertFalse(consensusRegistry.isRetired(initialValidators[i].validatorAddress));
            assertTrue(consensusRegistry.isValidator(initialValidators[i].blsPubkey));

            EpochInfo memory info = consensusRegistry.getEpochInfo(uint32(i));
            for (uint256 j; j < 4; ++j) {
                assertEq(info.committee[j], initialValidators[j].validatorAddress);
                (uint256 balance,,) = consensusRegistry.getBalanceBreakdown(initialValidators[j].validatorAddress);
                assertEq(balance, stakeAmount_);
            }
        }

        address missing = consensusRegistry.SYSTEM_ADDRESS();
        assertFalse(consensusRegistry.isRetired(missing));

        ValidatorInfo[] memory committee = consensusRegistry.getCommitteeValidators(0);
        for (uint256 i; i < committee.length; ++i) {
            assertEq(committee[i].validatorAddress, initialValidators[i].validatorAddress);
        }
        assertEq(consensusRegistry.totalSupply(), 4);
        assertEq(consensusRegistry.getCurrentStakeVersion(), 0);
        assertEq(consensusRegistry.stakeConfig(0).stakeAmount, stakeAmount_);
        assertEq(consensusRegistry.stakeConfig(0).minWithdrawAmount, minWithdrawAmount_);
    }

    function test_stake() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        assertEq(consensusRegistry.getValidators(ValidatorStatus.Staked).length, 0);

        // assert not validator
        assertFalse(consensusRegistry.isValidator(validator5BlsPubkey));

        // validator signs proof of possession message
        bytes memory message = consensusRegistry.proofOfPossessionMessage(validator5BlsPubkey, validator5);
        bytes memory validator5BlsSig =
            eip2537PointG1ToUncompressed(_blsEIP2537SignatureFromSecret(validator5Secret, message));

        // Check event emission
        bytes memory dummyPubkey = _blsDummyPubkeyFromSecret(validator5Secret);
        vm.expectEmit(true, true, true, true);
        emit ValidatorStaked(ValidatorInfo(
                dummyPubkey, validator5, PENDING_EPOCH, uint32(0), ValidatorStatus.Staked, false, false, uint8(0)
            ));
        vm.prank(validator5);
        consensusRegistry.stake{ value: stakeAmount_ }(
            dummyPubkey, BlsG1.ProofOfPossession(validator5BlsPubkey, validator5BlsSig)
        );

        // Check validator information
        ValidatorInfo[] memory validators = consensusRegistry.getValidators(ValidatorStatus.Staked);
        assertEq(validators.length, 1);
        assertEq(validators[0].validatorAddress, validator5);
        assertEq(validators[0].blsPubkey, dummyPubkey);
        assertEq(validators[0].activationEpoch, PENDING_EPOCH);
        assertEq(validators[0].exitEpoch, uint32(0));
        assertEq(validators[0].isRetired, false);
        assertEq(validators[0].isDelegated, false);
        assertEq(validators[0].stakeVersion, uint8(0));
        assertEq(uint8(validators[0].currentStatus), uint8(ValidatorStatus.Staked));

        // assert is validator
        assertTrue(consensusRegistry.isValidator(dummyPubkey));
    }

    function test_delegateStake() public {
        vm.prank(crOwner);
        uint256 validator5PrivateKey = 5;
        validator5 = vm.addr(validator5PrivateKey);
        address delegator = _addressFromPrivateKey(42);
        vm.deal(delegator, stakeAmount_);

        consensusRegistry.mint(validator5);

        // validator signs delegation
        bytes memory dummyPubkey = _blsDummyPubkeyFromSecret(validator5Secret);
        bytes32 structHash = consensusRegistry.delegationDigest(dummyPubkey, validator5, delegator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator5PrivateKey, structHash);
        bytes memory validatorSig = abi.encodePacked(r, s, v);

        // validator signs proof of possession message
        bytes memory message = consensusRegistry.proofOfPossessionMessage(validator5BlsPubkey, validator5);
        bytes memory validator5BlsSig =
            eip2537PointG1ToUncompressed(_blsEIP2537SignatureFromSecret(validator5Secret, message));

        // Check event emission
        bool isDelegate = true;
        vm.expectEmit(true, true, true, true);
        emit ValidatorStaked(ValidatorInfo(
                dummyPubkey, validator5, PENDING_EPOCH, uint32(0), ValidatorStatus.Staked, false, isDelegate, uint8(0)
            ));

        vm.prank(delegator);
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            dummyPubkey, BlsG1.ProofOfPossession(validator5BlsPubkey, validator5BlsSig), validator5, validatorSig
        );

        // Check validator information
        ValidatorInfo[] memory validators = consensusRegistry.getValidators(ValidatorStatus.Staked);
        assertEq(validators.length, 1);
        assertEq(validators[0].validatorAddress, validator5);
        assertEq(validators[0].blsPubkey, dummyPubkey);
        assertEq(validators[0].activationEpoch, PENDING_EPOCH);
        assertEq(validators[0].exitEpoch, uint32(0));
        assertEq(validators[0].isRetired, false);
        assertEq(validators[0].isDelegated, true);
        assertEq(validators[0].stakeVersion, uint8(0));
        assertEq(uint8(validators[0].currentStatus), uint8(ValidatorStatus.Staked));
    }

    function test_burnValidatorBeforeStake() public {
        vm.startPrank(crOwner);
        consensusRegistry.mint(validator5);
        // validator5 AFKs after being whitelisted and never stakes + activates, so burn
        consensusRegistry.burn(validator5);
        vm.stopPrank();

        assertEq(address(consensusRegistry).balance, registryGenesisBal);
    }

    function test_activate() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        // validator signs proof of possession message
        bytes memory message = consensusRegistry.proofOfPossessionMessage(validator5BlsPubkey, validator5);
        bytes memory validator5BlsSig =
            eip2537PointG1ToUncompressed(_blsEIP2537SignatureFromSecret(validator5Secret, message));
        bytes memory dummyPubkey = _blsDummyPubkeyFromSecret(validator5Secret);

        // expect revert - not enough active validators
        vm.expectRevert(abi.encodeWithSelector(InvalidCommitteeSize.selector, 4, 5));
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(5);

        vm.prank(validator5);
        consensusRegistry.stake{ value: stakeAmount_ }(
            dummyPubkey, BlsG1.ProofOfPossession(validator5BlsPubkey, validator5BlsSig)
        );

        // activate and conclude epoch to reach validator5 activationEpoch
        uint256 numActiveBefore = consensusRegistry.getValidators(ValidatorStatus.Active).length;
        vm.prank(validator5);
        consensusRegistry.activate();

        ValidatorInfo[] memory activeValidators = consensusRegistry.getValidators(ValidatorStatus.Active);
        assertEq(activeValidators.length, numActiveBefore + 1);

        uint32 activationEpoch = consensusRegistry.getCurrentEpoch() + 1;

        // update committee size
        vm.expectEmit();
        emit NextCommitteeSizeUpdated(4, 5, 5);
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(activeValidators.length));

        vm.expectEmit(true, true, true, true);
        emit ValidatorActivated(ValidatorInfo(
                dummyPubkey, validator5, activationEpoch, uint32(0), ValidatorStatus.Active, false, false, uint8(0)
            ));
        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(activeValidators.length));

        // Check validator information
        assertEq(activeValidators[0].validatorAddress, validator1);
        assertEq(activeValidators[1].validatorAddress, validator2);
        assertEq(activeValidators[2].validatorAddress, validator3);
        assertEq(activeValidators[3].validatorAddress, validator4);
        assertEq(activeValidators[4].validatorAddress, validator5);
        for (uint256 i; i < activeValidators.length - 1; ++i) {
            assertEq(uint8(activeValidators[i].currentStatus), uint8(ValidatorStatus.Active));
        }
        assertEq(uint8(activeValidators[4].currentStatus), uint8(ValidatorStatus.PendingActivation));
    }

    function testRevert_stake_invalidPoint() public {
        vm.prank(validator5);
        // providing identity reverts with actual=256, expected=256
        vm.expectRevert(abi.encodeWithSelector(BlsG1.InvalidPoint.selector, 256, 256));
        consensusRegistry.stake{ value: stakeAmount_ }(
            new bytes(96), BlsG1.ProofOfPossession(new bytes(192), new bytes(128))
        );
    }

    // Test for incorrect stake amount
    function testRevert_stake_invalidStakeAmount() public {
        // validator signs proof of possession message
        bytes memory message = consensusRegistry.proofOfPossessionMessage(validator5BlsPubkey, validator5);
        bytes memory validator5BlsSig =
            eip2537PointG1ToUncompressed(_blsEIP2537SignatureFromSecret(validator5Secret, message));

        bytes memory dummyPubkey = _blsDummyPubkeyFromSecret(validator5Secret);
        vm.startPrank(validator5);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.InvalidStakeAmount.selector, 0));
        consensusRegistry.stake{ value: 0 }(dummyPubkey, BlsG1.ProofOfPossession(validator5BlsPubkey, validator5BlsSig));
        vm.stopPrank();
    }

    function test_beginExit() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        // starting committee size
        uint256 numActiveBefore = consensusRegistry.getValidators(ValidatorStatus.Active).length;

        // validator signs proof of possession message
        bytes memory message = consensusRegistry.proofOfPossessionMessage(validator5BlsPubkey, validator5);
        bytes memory validator5BlsSig =
            eip2537PointG1ToUncompressed(_blsEIP2537SignatureFromSecret(validator5Secret, message));
        bytes memory dummyPubkey = _blsDummyPubkeyFromSecret(validator5Secret);
        vm.prank(validator5);
        consensusRegistry.stake{ value: stakeAmount_ }(
            dummyPubkey, BlsG1.ProofOfPossession(validator5BlsPubkey, validator5BlsSig)
        );

        // activate and conclude epoch to reach validator5 activationEpoch
        vm.prank(validator5);
        consensusRegistry.activate();

        uint32 activationEpoch = consensusRegistry.getCurrentEpoch() + 1;
        uint256 numActiveAfter = consensusRegistry.getValidators(ValidatorStatus.Active).length;

        address[] memory nextCommittee = _createTokenIdCommittee(numActiveAfter);

        // conclude epoch fails if nextCommitteeSize doesn't match arg length
        vm.prank(sysAddress);
        vm.expectRevert(abi.encodeWithSelector(InvalidCommitteeSize.selector, numActiveBefore, numActiveAfter));
        consensusRegistry.concludeEpoch(nextCommittee);

        // update nextCommitteeSize and conclude epoch
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(numActiveAfter));
        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(nextCommittee);

        assertEq(consensusRegistry.getValidators(ValidatorStatus.PendingExit).length, 0);

        // Check event emission
        vm.expectEmit(true, true, true, true);
        emit ValidatorPendingExit(ValidatorInfo(
                dummyPubkey,
                validator5,
                activationEpoch,
                PENDING_EPOCH,
                ValidatorStatus.PendingExit,
                false,
                false,
                uint8(0)
            ));
        // begin exit
        vm.prank(validator5);
        consensusRegistry.beginExit();

        // Check validator information is pending exit
        ValidatorInfo[] memory pendingExitValidators = consensusRegistry.getValidators(ValidatorStatus.PendingExit);
        assertEq(pendingExitValidators.length, 1);
        assertEq(pendingExitValidators[0].validatorAddress, validator5);
        assertEq(uint8(pendingExitValidators[0].currentStatus), uint8(ValidatorStatus.PendingExit));

        // set next committee back to 4
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(numActiveBefore));

        // Finalize epoch twice to reach exit epoch
        vm.startPrank(sysAddress);
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(numActiveBefore));
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(numActiveBefore));
        vm.stopPrank();

        assertEq(consensusRegistry.getValidators(ValidatorStatus.PendingExit).length, 0);
        assertEq(consensusRegistry.getValidators(ValidatorStatus.Active).length, numActiveBefore);

        // Check validator information is exited
        ValidatorInfo[] memory exitValidators = consensusRegistry.getValidators(ValidatorStatus.Exited);
        assertEq(exitValidators.length, 1);
        assertEq(exitValidators[0].validatorAddress, validator5);
        assertEq(uint8(exitValidators[0].currentStatus), uint8(ValidatorStatus.Exited));
    }

    // Test for exit by a non-validator
    function testRevert_beginExit_nonValidator() public {
        address nonValidator = address(0x3);

        vm.prank(nonValidator);
        vm.expectRevert(abi.encodeWithSelector(InvalidTokenId.selector, _getTokenId(nonValidator)));
        consensusRegistry.beginExit();
    }

    // Test for exit by a validator who is not active
    function testRevert_beginExit_notActive() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        // validator signs proof of possession message
        bytes memory message = consensusRegistry.proofOfPossessionMessage(validator5BlsPubkey, validator5);
        bytes memory validator5BlsSig =
            eip2537PointG1ToUncompressed(_blsEIP2537SignatureFromSecret(validator5Secret, message));

        vm.startPrank(validator5);
        consensusRegistry.stake{ value: stakeAmount_ }(
            _blsDummyPubkeyFromSecret(validator5Secret), BlsG1.ProofOfPossession(validator5BlsPubkey, validator5BlsSig)
        );

        // Attempt to exit without being active
        vm.expectRevert(abi.encodeWithSelector(InvalidStatus.selector, ValidatorStatus.Staked));
        consensusRegistry.beginExit();
        vm.stopPrank();
    }

    function test_unstake_exited() public {
        uint256 numActive = consensusRegistry.getValidators(ValidatorStatus.Active).length;

        vm.deal(address(consensusRegistry), stakeAmount_ * numActive);

        // validator becomes `PendingExit` status which is still committee eligible
        vm.prank(validator1);
        consensusRegistry.beginExit();
        assertEq(numActive, consensusRegistry.getValidators(ValidatorStatus.Active).length);

        // validators pending exit are only exited after elapsing 3 epochs without committee service
        vm.startPrank(sysAddress);
        address[] memory makeValidator1Wait = _createTokenIdCommittee(numActive);
        makeValidator1Wait[makeValidator1Wait.length - 1] = validator1;
        consensusRegistry.concludeEpoch(makeValidator1Wait);

        // conclude epoch twice with placeholder committee to simulate protocol-determined exit
        address[] memory tokenIdCommittee = _createTokenIdCommittee(numActive);
        consensusRegistry.concludeEpoch(tokenIdCommittee);
        consensusRegistry.concludeEpoch(tokenIdCommittee);
        vm.stopPrank();

        // set nextCommitteeSize
        uint256 activeAfterExit = numActive - 1;
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(activeAfterExit));

        // exit occurs on third epoch without validator5 in committee
        uint32 expectedExitEpoch = uint32(consensusRegistry.getCurrentEpoch() + 1);
        vm.expectEmit(true, true, true, true);
        emit ValidatorExited(ValidatorInfo(
                _blsDummyPubkeyFromSecret(1), // recreate validator1 blsPubkey
                validator1,
                uint32(0),
                expectedExitEpoch,
                ValidatorStatus.Exited,
                false,
                false,
                uint8(0)
            ));

        vm.startPrank(sysAddress);
        address[] memory afterExitCommittee = _createTokenIdCommittee(activeAfterExit);
        consensusRegistry.concludeEpoch(afterExitCommittee);

        uint256 initialBalance = validator1.balance;
        assertEq(initialBalance, 0);

        // conclude one additional epoch to reach unstake eligibility epoch
        consensusRegistry.concludeEpoch(afterExitCommittee);
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit RewardsClaimed(validator1, stakeAmount_);
        vm.prank(validator1);
        consensusRegistry.unstake(validator1);

        // validator1 earned 4 epochs' rewards, split between 4 validators
        uint256 finalBalance = validator1.balance;
        assertEq(finalBalance, stakeAmount_);
    }

    function test_unstake_staked() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        // validator signs proof of possession message
        bytes memory message = consensusRegistry.proofOfPossessionMessage(validator5BlsPubkey, validator5);
        bytes memory validator5BlsSig =
            eip2537PointG1ToUncompressed(_blsEIP2537SignatureFromSecret(validator5Secret, message));

        // stake stake but never activate
        vm.startPrank(validator5);
        consensusRegistry.stake{ value: stakeAmount_ }(
            _blsDummyPubkeyFromSecret(validator5Secret), BlsG1.ProofOfPossession(validator5BlsPubkey, validator5BlsSig)
        );

        uint256 initialBalance = validator5.balance;
        assertEq(initialBalance, 0);

        // unstake to abort activation
        vm.expectEmit(true, true, true, true);
        emit RewardsClaimed(validator5, stakeAmount_);
        consensusRegistry.unstake(validator5);

        vm.stopPrank();

        // validator5 should have reclaimed their stake
        uint256 finalBalance = validator5.balance;
        assertEq(finalBalance, stakeAmount_);
    }

    // Test for unstake by a non-validator
    function testRevert_unstake_nonValidator() public {
        address nonValidator = address(0x3);

        vm.prank(crOwner);
        consensusRegistry.mint(nonValidator);

        vm.prank(nonValidator);
        vm.expectRevert();
        consensusRegistry.unstake(nonValidator);
    }

    // Test for unstake by a validator who has not exited
    function testRevert_unstake_notStakedOrExited() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        // validator signs proof of possession message
        bytes memory message = consensusRegistry.proofOfPossessionMessage(validator5BlsPubkey, validator5);
        bytes memory validator5BlsSig =
            eip2537PointG1ToUncompressed(_blsEIP2537SignatureFromSecret(validator5Secret, message));
        bytes memory dummyPubkey = _blsDummyPubkeyFromSecret(validator5Secret);

        // stake and activate
        vm.startPrank(validator5);
        consensusRegistry.stake{ value: stakeAmount_ }(
            dummyPubkey, BlsG1.ProofOfPossession(validator5BlsPubkey, validator5BlsSig)
        );
        consensusRegistry.activate();

        // Attempt to unstake without exiting
        bytes memory err = abi.encodeWithSelector(
            IneligibleUnstake.selector,
            ValidatorInfo(dummyPubkey, validator5, 1, 0, ValidatorStatus.PendingActivation, false, false, 0)
        );
        vm.expectRevert(err);
        consensusRegistry.unstake(validator5);

        vm.stopPrank();
    }

    // Test for claim by a non-validator
    function testRevert_claimStakeRewards_nonValidator() public {
        address nonValidator = address(0x3);
        vm.deal(nonValidator, 10 ether);

        vm.prank(nonValidator);
        vm.expectRevert(abi.encodeWithSelector(InvalidTokenId.selector, _getTokenId(nonValidator)));
        consensusRegistry.claimStakeRewards(nonValidator);
    }

    // Test for claim by a validator with insufficient rewards
    function testRevert_claimStakeRewards_insufficientRewards() public {
        // Attempt to claim rewards without applying incentives
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.InsufficientRewards.selector, 0));
        consensusRegistry.claimStakeRewards(validator1);
    }

    function test_concludeEpoch_updatesEpochInfo() public {
        // Initialize test data
        address[] memory newCommittee = new address[](4);
        newCommittee[0] = address(0x69);
        newCommittee[1] = address(0x70);
        newCommittee[2] = address(0x71);
        newCommittee[3] = address(0x72);

        uint32 initialEpoch = consensusRegistry.getCurrentEpoch();
        assertEq(initialEpoch, 0);

        // nextCommitteeSize should be 4 from constructor
        assertEq(consensusRegistry.getNextCommitteeSize(), 4);

        // Call the function
        vm.startPrank(sysAddress);
        consensusRegistry.concludeEpoch(newCommittee);
        consensusRegistry.concludeEpoch(newCommittee);
        vm.stopPrank();

        // Fetch current epoch and verify it has incremented
        uint32 currentEpoch = consensusRegistry.getCurrentEpoch();
        assertEq(currentEpoch, initialEpoch + 2);

        // Verify future epoch information
        EpochInfo memory epochInfo = consensusRegistry.getEpochInfo(currentEpoch + 2);
        assertEq(epochInfo.blockHeight, 0);
        for (uint256 i; i < epochInfo.committee.length; ++i) {
            assertEq(epochInfo.committee[i], newCommittee[i]);
        }
    }

    // Attempt to call without sysAddress should revert
    function testRevert_concludeEpoch_OnlySystemCall() public {
        vm.expectRevert(abi.encodeWithSelector(SystemCallable.OnlySystemCall.selector, address(this)));
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(4));
    }

    function test_burnAutoAdjustsCommitteeSize() public {
        // Setup: Set nextCommitteeSize to current active count
        uint256 numActive = consensusRegistry.getValidators(ValidatorStatus.Active).length;
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(numActive));

        // Burn a validator that's in committees
        vm.expectEmit();
        emit NextCommitteeSizeUpdated(uint16(numActive), uint16(numActive - 1), numActive - 1);
        vm.prank(crOwner);
        consensusRegistry.burn(validator1);

        // Verify nextCommitteeSize was auto-adjusted
        assertEq(consensusRegistry.getNextCommitteeSize(), numActive - 1);
    }

    function test_ejectFromCommittees_doubleSubtractionBug() public {
        // explicitly set committee size to match current active count
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(4);

        // advance to establish the committees
        vm.startPrank(sysAddress);
        address[] memory committee4 = new address[](4);
        committee4[0] = validator1;
        committee4[1] = validator2;
        committee4[2] = validator3;
        committee4[3] = validator4;
        _sortAddresses(committee4);

        consensusRegistry.concludeEpoch(committee4);
        consensusRegistry.concludeEpoch(committee4);
        vm.stopPrank();

        // burn validator1 who is in the current, next, and subsequent committees
        // this will trigger _ejectFromCommittees where the validator is found and ejected

        vm.prank(crOwner);
        consensusRegistry.burn(validator1);

        // check the committee was actually modified
        address[] memory currentCommittee = consensusRegistry.getCurrentEpochInfo().committee;

        // committee should have 3 members after burning validator 1
        assertEq(currentCommittee.length, 3);

        // validator1 should not be in the committee
        for (uint256 i = 0; i < currentCommittee.length; i++) {
            assertTrue(currentCommittee[i] != validator1);
        }
    }

    function test_slash_triggersEjection_correctSizeCheck() public {
        // test that slashing to 0 balance (which triggers _consensusburn and _ejectfromcommittees)
        // correctly handles committee size

        // setup slash that reduces balance to 0
        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator1, stakeAmount_ + 1); // slash more than balance

        // this should trigger _consensusBurn -> _ejectFromCommittees
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);

        // verify validator was ejected and committee size adjusted
        ValidatorInfo[] memory activeValidators = consensusRegistry.getValidators(ValidatorStatus.Active);
        assertEq(activeValidators.length, 3); // 4 initial - 1 slashed
        assertTrue(consensusRegistry.isRetired(validator1));

        // committee size should auto-adjust
        assertEq(consensusRegistry.getNextCommitteeSize(), 3);
    }
}
