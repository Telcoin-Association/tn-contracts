// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { SystemCallable } from "src/consensus/SystemCallable.sol";
import { StakeManager } from "src/consensus/StakeManager.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { RewardInfo, Slash, IStakeManager } from "src/interfaces/IStakeManager.sol";
import { IConsensusRegistry } from "src/interfaces/IConsensusRegistry.sol";
import { Issuance } from "src/consensus/Issuance.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";

contract ConsensusRegistryTest is ConsensusRegistryTestUtils {
    function setUp() public {
        // target
        consensusRegistry = ConsensusRegistry(0x07E17e17E17e17E17e17E17E17E17e17e17E17e1);

        vm.startStateDiffRecording();
        StakeConfig memory stakeConfig_ = StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_);
        ConsensusRegistry tempRegistry = new ConsensusRegistry(stakeConfig_, initialValidators, initialBlsPubkeys, initialBLSPops, crOwner);
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
        ValidatorInfo[] memory active = consensusRegistry.getValidatorsInfo(ValidatorStatus.Active);
        for (uint256 i; i < 3; ++i) {
            assertEq(active[i].validatorAddress, initialValidators[i].validatorAddress);
            assertEq(
                consensusRegistry.getValidator(initialValidators[i].validatorAddress).validatorAddress,
                active[i].validatorAddress
            );
            assertFalse(consensusRegistry.isRetired(initialValidators[i].validatorAddress));
            assertTrue(consensusRegistry.isValidator(consensusRegistry.getBlsPubkey(initialValidators[i].validatorAddress)));

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

    function test_getBlsPubkey_revertsForZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.BlsPubkeyNotFound.selector, address(0)));
        consensusRegistry.getBlsPubkey(address(0));
    }

    function test_getBlsPubkey_revertsForUnregisteredAddress() public {
        address unknown = address(0xdead);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.BlsPubkeyNotFound.selector, unknown));
        consensusRegistry.getBlsPubkey(unknown);
    }

    function test_setValidatorRegion() public {
        // region defaults to 0
        ValidatorInfo memory info = consensusRegistry.getValidator(validator1);
        assertEq(info.region, 0);

        // owner sets region
        vm.expectEmit(true, true, true, true);
        emit ValidatorRegionUpdated(validator1, 5);
        vm.prank(crOwner);
        consensusRegistry.setValidatorRegion(validator1, 5);

        info = consensusRegistry.getValidator(validator1);
        assertEq(info.region, 5);

        // update to different region
        vm.prank(crOwner);
        consensusRegistry.setValidatorRegion(validator1, 8);
        info = consensusRegistry.getValidator(validator1);
        assertEq(info.region, 8);

        // reset to unspecified
        vm.prank(crOwner);
        consensusRegistry.setValidatorRegion(validator1, 0);
        info = consensusRegistry.getValidator(validator1);
        assertEq(info.region, 0);
    }

    function test_setValidatorRegion_revert_notOwner() public {
        vm.expectRevert();
        vm.prank(validator1);
        consensusRegistry.setValidatorRegion(validator1, 5);
    }

    function test_setValidatorRegion_revert_noNFT() public {
        vm.expectRevert();
        vm.prank(crOwner);
        consensusRegistry.setValidatorRegion(address(0xdead), 5);
    }

    function test_setValidatorRegion_stakedValidator() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        vm.prank(validator5);
        consensusRegistry.stake{
            value: stakeAmount_
        }(validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig));

        assertEq(uint8(consensusRegistry.getValidator(validator5).currentStatus), uint8(ValidatorStatus.Staked));

        vm.expectEmit(true, true, true, true);
        emit ValidatorRegionUpdated(validator5, 3);
        vm.prank(crOwner);
        consensusRegistry.setValidatorRegion(validator5, 3);
        assertEq(consensusRegistry.getValidator(validator5).region, 3);
    }

    function test_stake_preservesRegionSetBeforeStake() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        // region assigned while the validator is minted but not yet staked
        vm.prank(crOwner);
        consensusRegistry.setValidatorRegion(validator5, 7);
        assertEq(consensusRegistry.getValidator(validator5).region, 7);

        vm.prank(validator5);
        consensusRegistry.stake{ value: stakeAmount_ }(
            validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig)
        );

        assertEq(uint8(consensusRegistry.getValidator(validator5).currentStatus), uint8(ValidatorStatus.Staked));
        assertEq(consensusRegistry.getValidator(validator5).region, 7);
    }

    function test_constructor_revertsOnZeroEpochDuration() public {
        StakeConfig memory badConfig = StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, 0);
        vm.expectRevert(abi.encodeWithSelector(IConsensusRegistry.InvalidDuration.selector, uint32(0)));
        new ConsensusRegistry(badConfig, initialValidators, initialBlsPubkeys, initialBLSPops, crOwner);
    }

    function test_setValidatorRegion_pendingActivationValidator() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        vm.prank(validator5);
        consensusRegistry.stake{
            value: stakeAmount_
        }(validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig));

        vm.prank(validator5);
        consensusRegistry.activate();

        assertEq(uint8(consensusRegistry.getValidator(validator5).currentStatus), uint8(ValidatorStatus.PendingActivation));

        vm.expectEmit(true, true, true, true);
        emit ValidatorRegionUpdated(validator5, 4);
        vm.prank(crOwner);
        consensusRegistry.setValidatorRegion(validator5, 4);
        assertEq(consensusRegistry.getValidator(validator5).region, 4);
    }

    function test_setValidatorRegion_pendingExitValidator() public {
        // validator1 is Active from genesis
        vm.prank(validator1);
        consensusRegistry.beginExit();

        assertEq(uint8(consensusRegistry.getValidator(validator1).currentStatus), uint8(ValidatorStatus.PendingExit));

        vm.expectEmit(true, true, true, true);
        emit ValidatorRegionUpdated(validator1, 6);
        vm.prank(crOwner);
        consensusRegistry.setValidatorRegion(validator1, 6);
        assertEq(consensusRegistry.getValidator(validator1).region, 6);
    }

    function test_setValidatorRegion_exitedValidator() public {
        uint256 numActive = consensusRegistry.getEligibleValidatorCount();

        // validator1 begins exit
        vm.prank(validator1);
        consensusRegistry.beginExit();

        // conclude 3 epochs without validator1 in committee to reach Exited
        vm.startPrank(sysAddress);
        address[] memory makeValidator1Wait = _createTokenIdCommittee(numActive);
        makeValidator1Wait[makeValidator1Wait.length - 1] = validator1;
        consensusRegistry.concludeEpoch(makeValidator1Wait);

        address[] memory tokenIdCommittee = _createTokenIdCommittee(numActive);
        consensusRegistry.concludeEpoch(tokenIdCommittee);
        consensusRegistry.concludeEpoch(tokenIdCommittee);
        vm.stopPrank();

        uint256 activeAfterExit = numActive - 1;
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(activeAfterExit));

        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(activeAfterExit));

        assertEq(uint8(consensusRegistry.getValidator(validator1).currentStatus), uint8(ValidatorStatus.Exited));

        vm.expectEmit(true, true, true, true);
        emit ValidatorRegionUpdated(validator1, 7);
        vm.prank(crOwner);
        consensusRegistry.setValidatorRegion(validator1, 7);
        assertEq(consensusRegistry.getValidator(validator1).region, 7);
    }

    function test_setValidatorRegion_maxUint8() public {
        vm.expectEmit(true, true, true, true);
        emit ValidatorRegionUpdated(validator1, 255);
        vm.prank(crOwner);
        consensusRegistry.setValidatorRegion(validator1, 255);
        assertEq(consensusRegistry.getValidator(validator1).region, 255);
    }

    function test_stake() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        assertEq(consensusRegistry.getValidators(ValidatorStatus.Staked).length, 0);

        // assert not validator
        assertFalse(consensusRegistry.isValidator(validator5BlsPubkey));

        // Check event emission
        vm.expectEmit(true, true, true, true);
        emit ValidatorStaked(ValidatorInfo(
                validator5, PENDING_EPOCH, uint32(0), ValidatorStatus.Staked, false, uint8(0), uint8(0)
            ));
        vm.prank(validator5);
        consensusRegistry.stake{
            value: stakeAmount_
        }(validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig));

        // Check validator information
        ValidatorInfo[] memory validators = consensusRegistry.getValidatorsInfo(ValidatorStatus.Staked);
        assertEq(validators.length, 1);
        assertEq(validators[0].validatorAddress, validator5);
        assertEq(consensusRegistry.getBlsPubkey(validator5), validator5BlsPubkey);
        assertEq(validators[0].activationEpoch, PENDING_EPOCH);
        assertEq(validators[0].exitEpoch, uint32(0));
        assertEq(validators[0].isRetired, false);
        assertEq(validators[0].stakeVersion, uint8(0));
        assertEq(uint8(validators[0].currentStatus), uint8(ValidatorStatus.Staked));

        // assert is validator
        assertTrue(consensusRegistry.isValidator(validator5BlsPubkey));
    }

    function test_delegateStake() public {
        vm.prank(crOwner);
        uint256 validator5PrivateKey = 5;
        validator5 = vm.addr(validator5PrivateKey);
        address delegator = _addressFromPrivateKey(42);
        vm.deal(delegator, stakeAmount_);

        consensusRegistry.mint(validator5);

        // validator signs delegation
        bytes32 structHash = consensusRegistry.delegationDigest(validator5BlsPubkey, validator5, delegator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator5PrivateKey, structHash);
        bytes memory validatorSig = abi.encodePacked(r, s, v);

        // Check event emission
        vm.expectEmit(true, true, true, true);
        emit ValidatorStaked(ValidatorInfo(
                validator5, PENDING_EPOCH, uint32(0), ValidatorStatus.Staked, false, uint8(0), uint8(0)
            ));

        vm.prank(delegator);
        consensusRegistry.delegateStake{
            value: stakeAmount_
        }(validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig), validator5, validatorSig);

        // Check validator information
        ValidatorInfo[] memory validators = consensusRegistry.getValidatorsInfo(ValidatorStatus.Staked);
        assertEq(validators.length, 1);
        assertEq(validators[0].validatorAddress, validator5);
        assertEq(consensusRegistry.getBlsPubkey(validator5), validator5BlsPubkey);
        assertEq(validators[0].activationEpoch, PENDING_EPOCH);
        assertEq(validators[0].exitEpoch, uint32(0));
        assertEq(validators[0].isRetired, false);
        assertTrue(consensusRegistry.isDelegated(validator5));
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

        // expect revert - not enough active validators
        vm.expectRevert(abi.encodeWithSelector(InvalidCommitteeSize.selector, 4, 5));
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(5);

        vm.prank(validator5);
        consensusRegistry.stake{
            value: stakeAmount_
        }(validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig));

        // activate validator5 -> PendingActivation (committee-eligible next epoch, but not in the Active set)
        uint256 numEligibleBefore = consensusRegistry.getEligibleValidatorCount();
        vm.prank(validator5);
        consensusRegistry.activate();

        // per-status: the Active set is unchanged; validator5 joins the eligible pool as PendingActivation
        ValidatorInfo[] memory activeValidators = consensusRegistry.getValidatorsInfo(ValidatorStatus.Active);
        ValidatorInfo[] memory pendingActivation = consensusRegistry.getValidatorsInfo(ValidatorStatus.PendingActivation);
        uint256 numEligible = consensusRegistry.getEligibleValidatorCount();
        assertEq(numEligible, numEligibleBefore + 1);
        assertEq(activeValidators.length, numEligibleBefore);
        assertEq(pendingActivation.length, 1);

        uint32 activationEpoch = consensusRegistry.getCurrentEpoch() + 1;

        // update committee size to the full eligible pool
        vm.expectEmit();
        emit NextCommitteeSizeUpdated(4, 5, 5);
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(numEligible));

        vm.expectEmit(true, true, true, true);
        emit ValidatorActivated(ValidatorInfo(
                validator5, activationEpoch, uint32(0), ValidatorStatus.Active, false, uint8(0), uint8(0)
            ));
        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(numEligible));

        // Active set holds the genesis validators in order; validator5 is the lone PendingActivation
        assertEq(activeValidators[0].validatorAddress, validator1);
        assertEq(activeValidators[1].validatorAddress, validator2);
        assertEq(activeValidators[2].validatorAddress, validator3);
        assertEq(activeValidators[3].validatorAddress, validator4);
        for (uint256 i; i < activeValidators.length; ++i) {
            assertEq(uint8(activeValidators[i].currentStatus), uint8(ValidatorStatus.Active));
        }
        assertEq(pendingActivation[0].validatorAddress, validator5);
        assertEq(uint8(pendingActivation[0].currentStatus), uint8(ValidatorStatus.PendingActivation));
    }

    function testRevert_stake_invalidPoint() public {
        vm.prank(validator5);
        // an all-zero compressed pubkey is rejected by the registry's compressed-key flag check
        vm.expectRevert(IStakeManager.InvalidBLSPubkey.selector);
        consensusRegistry.stake{
            value: stakeAmount_
        }(new bytes(96), IStakeManager.ProofOfPossession(new bytes(48)));
    }

    /// @notice EXP-001 regression: a key and its y-sign-flipped negation (same x) cannot both register.
    function testRevert_stake_negationDoubleRegistration() public {
        // A registers compress(PK) (y-sign flag 0)
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);
        bytes memory compressedPK = _blsDummyPubkeyFromSecret(validator5Secret);
        vm.prank(validator5);
        consensusRegistry.stake{ value: stakeAmount_ }(compressedPK, IStakeManager.ProofOfPossession(validator5BlsSig));

        // B attempts to register the SAME key with the y-sign flag flipped (same x, different bytes)
        address attackerB = _addressFromPrivateKey(99);
        vm.deal(attackerB, stakeAmount_);
        vm.prank(crOwner);
        consensusRegistry.mint(attackerB);
        bytes memory compressedNegPK = new bytes(96);
        for (uint256 i; i < 96; ++i) {
            compressedNegPK[i] = compressedPK[i];
        }
        compressedNegPK[0] = compressedNegPK[0] ^ bytes1(0x20); // flip blst y-sign flag

        // x-keyed deduplication collapses the negation variant and rejects it
        vm.prank(attackerB);
        vm.expectRevert(DuplicateBLSPubkey.selector);
        consensusRegistry.stake{ value: stakeAmount_ }(compressedNegPK, IStakeManager.ProofOfPossession(_blsDummySigFromSecret(99)));
    }

    /// @notice A stored compressed key with a malformed compression/infinity flag is rejected by the
    /// registry's compressed-key flag check.
    function testRevert_stake_malformedCompressedFlags() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);
        bytes memory compressed = _blsDummyPubkeyFromSecret(validator5Secret);

        // infinity flag set -> off-chain blst decodes to the identity point
        bytes memory infinityFlagged = new bytes(96);
        for (uint256 i; i < 96; ++i) {
            infinityFlagged[i] = compressed[i];
        }
        infinityFlagged[0] = infinityFlagged[0] | bytes1(0x40);
        vm.prank(validator5);
        vm.expectRevert(IStakeManager.InvalidBLSPubkey.selector);
        consensusRegistry.stake{ value: stakeAmount_ }(infinityFlagged, IStakeManager.ProofOfPossession(validator5BlsSig));

        // compression flag cleared -> off-chain blst fails to decode
        bytes memory uncompressedFlagged = new bytes(96);
        for (uint256 i; i < 96; ++i) {
            uncompressedFlagged[i] = compressed[i];
        }
        uncompressedFlagged[0] = uncompressedFlagged[0] & bytes1(0x7f);
        vm.prank(validator5);
        vm.expectRevert(IStakeManager.InvalidBLSPubkey.selector);
        consensusRegistry.stake{ value: stakeAmount_ }(
            uncompressedFlagged, IStakeManager.ProofOfPossession(validator5BlsSig)
        );
    }

    /// @notice A wrong-length signature makes the mock precompile return false, so the registry
    /// reverts InvalidProofOfPossession.
    function testRevert_stake_wrongLengthSignature() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        vm.prank(validator5);
        vm.expectRevert(
            abi.encodeWithSelector(IStakeManager.InvalidProofOfPossession.selector, IStakeManager.ProofOfPossession(new bytes(47)))
        );
        consensusRegistry.stake{ value: stakeAmount_ }(validator5BlsPubkey, IStakeManager.ProofOfPossession(new bytes(47)));
    }

    /// @notice An empty committee reverts cleanly (InvalidCommitteeSize), not an `_enforceSorting` panic.
    function testRevert_concludeEpoch_emptyCommittee() public {
        address[] memory empty = new address[](0);
        uint16 size = consensusRegistry.getNextCommitteeSize();
        vm.prank(sysAddress);
        vm.expectRevert(abi.encodeWithSelector(InvalidCommitteeSize.selector, uint256(size), uint256(0)));
        consensusRegistry.concludeEpoch(empty);
    }

    /// @notice eligibleValidatorCount tracks exits from the committee-eligible set (entries/+1 and the
    /// full lifecycle are covered by the invariant hooks in the fuzz suite).
    function test_eligibleValidatorCount_burnDecrements() public {
        // genesis: 4 Active validators are committee-eligible
        assertEq(consensusRegistry.getEligibleValidatorCount(), 4);
        _assertSetInvariant();

        // governance burn of an Active (eligible) validator -> exit + retire: -1
        vm.prank(crOwner);
        consensusRegistry.burn(validator1);
        assertEq(consensusRegistry.getEligibleValidatorCount(), 3);
        _assertSetInvariant();
    }



    // Test for incorrect stake amount
    function testRevert_stake_invalidStakeAmount() public {
        vm.startPrank(validator5);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.InvalidStakeAmount.selector, 0));
        consensusRegistry.stake{ value: 0 }(validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig));
        vm.stopPrank();
    }

    function test_beginExit() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        // starting committee size
        uint256 numActiveBefore = consensusRegistry.getEligibleValidatorCount();

        vm.prank(validator5);
        consensusRegistry.stake{
            value: stakeAmount_
        }(validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig));

        // activate and conclude epoch to reach validator5 activationEpoch
        vm.prank(validator5);
        consensusRegistry.activate();

        uint32 activationEpoch = consensusRegistry.getCurrentEpoch() + 1;
        uint256 numActiveAfter = consensusRegistry.getEligibleValidatorCount();

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
                validator5,
                activationEpoch,
                PENDING_EPOCH,
                ValidatorStatus.PendingExit,
                false,
                uint8(0),
                uint8(0)
            ));
        // begin exit
        vm.prank(validator5);
        consensusRegistry.beginExit();

        // Check validator information is pending exit
        ValidatorInfo[] memory pendingExitValidators = consensusRegistry.getValidatorsInfo(ValidatorStatus.PendingExit);
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
        assertEq(consensusRegistry.getEligibleValidatorCount(), numActiveBefore);

        // Check validator information is exited
        ValidatorInfo[] memory exitValidators = consensusRegistry.getValidatorsInfo(ValidatorStatus.Exited);
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

        vm.startPrank(validator5);
        consensusRegistry.stake{
            value: stakeAmount_
        }(validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig));

        // Attempt to exit without being active
        vm.expectRevert(abi.encodeWithSelector(InvalidStatus.selector, ValidatorStatus.Staked));
        consensusRegistry.beginExit();
        vm.stopPrank();
    }

    function test_unstake_exited() public {
        uint256 numActive = consensusRegistry.getEligibleValidatorCount();

        vm.deal(address(consensusRegistry), stakeAmount_ * numActive);

        // validator becomes `PendingExit` status which is still committee eligible
        vm.prank(validator1);
        consensusRegistry.beginExit();
        assertEq(numActive, consensusRegistry.getEligibleValidatorCount());

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
        bytes memory validator1Pubkey = _blsDummyPubkeyFromSecret(1); // recreate validator1 blsPubkey
        vm.expectEmit(true, true, true, true);
        emit ValidatorExited(ValidatorInfo(
                validator1,
                uint32(0),
                expectedExitEpoch,
                ValidatorStatus.Exited,
                false,
                uint8(0),
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
        consensusRegistry.unstake(validator1, false);

        // validator1 earned 4 epochs' rewards, split between 4 validators
        uint256 finalBalance = validator1.balance;
        assertEq(finalBalance, stakeAmount_);
    }

    function test_unstake_staked() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        // stake stake but never activate
        vm.startPrank(validator5);
        consensusRegistry.stake{
            value: stakeAmount_
        }(validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig));

        uint256 initialBalance = validator5.balance;
        assertEq(initialBalance, 0);

        // unstake to abort activation
        vm.expectEmit(true, true, true, true);
        emit RewardsClaimed(validator5, stakeAmount_);
        consensusRegistry.unstake(validator5, false);

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
        consensusRegistry.unstake(nonValidator, false);
    }

    // Test for unstake by a validator who has not exited
    function testRevert_unstake_notStakedOrExited() public {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        // stake and activate
        vm.startPrank(validator5);
        consensusRegistry.stake{
            value: stakeAmount_
        }(validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig));
        consensusRegistry.activate();

        // Attempt to unstake without exiting
        bytes memory err = abi.encodeWithSelector(
            IneligibleUnstake.selector,
            ValidatorInfo(validator5, 1, 0, ValidatorStatus.PendingActivation, false, 0, 0)
        );
        vm.expectRevert(err);
        consensusRegistry.unstake(validator5, false);

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
        uint256 numActive = consensusRegistry.getEligibleValidatorCount();
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
        ValidatorInfo[] memory activeValidators = consensusRegistry.getValidatorsInfo(ValidatorStatus.Active);
        assertEq(activeValidators.length, 3); // 4 initial - 1 slashed
        assertTrue(consensusRegistry.isRetired(validator1));

        // committee size should auto-adjust
        assertEq(consensusRegistry.getNextCommitteeSize(), 3);
    }

    /*
     *   upgradeValidatorStakeVersion
     */

    function test_upgradeValidatorStakeVersion_increaseStake() public {
        // Create a new stake version with higher stake
        uint256 newStakeAmt = 2_000_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        // validator1 is Active with version 0
        uint256 deficit = newStakeAmt - stakeAmount_;
        vm.deal(validator1, deficit);

        vm.expectEmit(true, true, true, true);
        emit ValidatorStakeVersionUpgraded(validator1, 0, newVersion, stakeAmount_, newStakeAmt);

        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion{value: deficit}(validator1, newVersion);

        // Verify state
        ValidatorInfo memory info = consensusRegistry.getValidator(validator1);
        assertEq(info.stakeVersion, newVersion);
        (uint256 balance, uint256 stakeAmt,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balance, newStakeAmt);
        assertEq(stakeAmt, newStakeAmt);
    }

    function test_upgradeValidatorStakeVersion_decreaseStake() public {
        // Create a new stake version with lower stake
        uint256 newStakeAmt = 500_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 recipientBalBefore = validator1.balance;

        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);

        // Verify state
        ValidatorInfo memory info = consensusRegistry.getValidator(validator1);
        assertEq(info.stakeVersion, newVersion);
        (uint256 balance, uint256 stakeAmt,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balance, newStakeAmt);
        assertEq(stakeAmt, newStakeAmt);
        // surplus refunded to validator1 (who is the recipient since no delegator)
        uint256 surplus = stakeAmount_ - newStakeAmt;
        assertEq(validator1.balance, recipientBalBefore + surplus);
    }

    function test_upgradeValidatorStakeVersion_sameStake() public {
        // Create a new version with same stake amount
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(stakeAmount_, minWithdrawAmount_ * 2, epochIssuance_, epochDuration_)
        );

        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);

        ValidatorInfo memory info = consensusRegistry.getValidator(validator1);
        assertEq(info.stakeVersion, newVersion);
        (uint256 balance,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balance, stakeAmount_);
    }

    function test_upgradeValidatorStakeVersion_stakedStatus() public {
        // Mint and stake validator5 (Staked status, not yet activated)
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        vm.prank(validator5);
        consensusRegistry.stake{value: stakeAmount_}(
            validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig)
        );

        // Create new version with higher stake
        uint256 newStakeAmt = 2_000_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 deficit = newStakeAmt - stakeAmount_;
        vm.deal(validator5, deficit);

        vm.prank(validator5);
        consensusRegistry.upgradeValidatorStakeVersion{value: deficit}(validator5, newVersion);

        ValidatorInfo memory info = consensusRegistry.getValidator(validator5);
        assertEq(info.stakeVersion, newVersion);
        assertEq(uint8(info.currentStatus), uint8(ValidatorStatus.Staked));
    }

    function test_upgradeValidatorStakeVersion_delegated() public {
        // Setup delegated validator5
        vm.prank(crOwner);
        uint256 validator5PrivateKey = 5;
        validator5 = vm.addr(validator5PrivateKey);
        address delegator = _addressFromPrivateKey(42);
        vm.deal(delegator, stakeAmount_);

        consensusRegistry.mint(validator5);

        bytes32 structHash = consensusRegistry.delegationDigest(validator5BlsPubkey, validator5, delegator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator5PrivateKey, structHash);
        bytes memory validatorSig = abi.encodePacked(r, s, v);

        vm.prank(delegator);
        consensusRegistry.delegateStake{value: stakeAmount_}(
            validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig), validator5, validatorSig
        );

        // Create new version with lower stake
        uint256 newStakeAmt = 500_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 delegatorBalBefore = delegator.balance;

        // Delegator calls upgrade (they are the recipient)
        vm.prank(delegator);
        consensusRegistry.upgradeValidatorStakeVersion(validator5, newVersion);

        // Verify delegation record updated
        ValidatorInfo memory info = consensusRegistry.getValidator(validator5);
        assertEq(info.stakeVersion, newVersion);

        // Surplus refunded to delegator (the recipient)
        uint256 surplus = stakeAmount_ - newStakeAmt;
        assertEq(delegator.balance, delegatorBalBefore + surplus);
    }

    function test_upgradeValidatorStakeVersion_preservesRewards() public {
        // First conclude an epoch and apply incentives so validator1 has rewards
        address[] memory committee = new address[](4);
        committee[0] = validator1;
        committee[1] = validator2;
        committee[2] = validator3;
        committee[3] = validator4;
        _sortAddresses(committee);

        vm.prank(sysAddress);
        RewardInfo[] memory rewards = new RewardInfo[](4);
        rewards[0] = RewardInfo(validator1, 10);
        rewards[1] = RewardInfo(validator2, 10);
        rewards[2] = RewardInfo(validator3, 10);
        rewards[3] = RewardInfo(validator4, 10);
        consensusRegistry.applyIncentives(rewards);

        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(committee);

        // Record validator1's rewards before upgrade
        uint256 rewardsBefore = consensusRegistry.getRewards(validator1);
        assertTrue(rewardsBefore > 0);

        // Create new version with higher stake
        uint256 newStakeAmt = 2_000_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 deficit = newStakeAmt - stakeAmount_;
        vm.deal(validator1, deficit);

        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion{value: deficit}(validator1, newVersion);

        // Rewards should be preserved
        uint256 rewardsAfter = consensusRegistry.getRewards(validator1);
        assertEq(rewardsAfter, rewardsBefore);
    }

    function test_upgradeValidatorStakeVersion_slashedDecrease() public {
        // Slash validator1 partially (lose 200k of 1M stake)
        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator1, 200_000e18);
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);

        // validator1 balance is now 800k, stakeAmount is 1M
        (uint256 balBefore,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balBefore, 800_000e18);

        // Create new version with 600k stake
        uint256 newStakeAmt = 600_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 recipientBalBefore = validator1.balance;

        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);

        // Partial refund: balance(800k) - newStakeAmt(600k) = 200k refund (not full 400k surplus)
        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, newStakeAmt);
        assertEq(validator1.balance, recipientBalBefore + 200_000e18);
    }

    function testRevert_upgradeValidatorStakeVersion_wrongMsgValue() public {
        uint256 newStakeAmt = 2_000_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        // Send wrong amount (too much)
        uint256 wrongAmount = newStakeAmt;
        vm.deal(validator1, wrongAmount);

        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.InvalidStakeAmount.selector, wrongAmount));
        consensusRegistry.upgradeValidatorStakeVersion{value: wrongAmount}(validator1, newVersion);
    }

    function testRevert_upgradeValidatorStakeVersion_invalidVersion() public {
        // Target version <= current (0)
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.InvalidStakeVersion.selector, uint8(0), uint8(0)));
        consensusRegistry.upgradeValidatorStakeVersion(validator1, 0);

        // Target version > global stakeVersion
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.InvalidStakeVersion.selector, uint8(0), uint8(5)));
        consensusRegistry.upgradeValidatorStakeVersion(validator1, 5);
    }

    function testRevert_upgradeValidatorStakeVersion_pendingExit() public {
        // Put validator1 in PendingExit
        vm.prank(validator1);
        consensusRegistry.beginExit();

        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(InvalidStatus.selector, ValidatorStatus.PendingExit));
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);
    }

    function testRevert_upgradeValidatorStakeVersion_notRecipient() public {
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        address unauthorized = address(0xdead);
        vm.prank(unauthorized);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.NotRecipient.selector, validator1));
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);
    }

    function test_upgradeValidatorStakeVersion_strandedFundsFixVerification() public {
        // Slash validator1 partially (200k of 1M stake)
        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator1, 200_000e18);
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);

        // validator1 balance is now 800k
        (uint256 balBefore,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balBefore, 800_000e18);

        // Create new version with 600k stake, downgrade
        uint256 newStakeAmt = 600_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 recipientBalBefore = validator1.balance;
        uint256 issuanceBalBefore = issuance.balance;
        uint256 registryBalBefore = address(consensusRegistry).balance;

        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);

        // Verify balance = newStakeAmount (600k)
        (uint256 balAfter, uint256 stakeAmt,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, newStakeAmt);
        assertEq(stakeAmt, newStakeAmt);

        // Recipient gets refund: 800k - 600k = 200k
        uint256 refundAmount = 200_000e18;
        assertEq(validator1.balance, recipientBalBefore + refundAmount);

        // Confiscated amount (1M - 800k = 200k) sent to Issuance
        uint256 confiscatedAmount = 200_000e18;
        assertEq(issuance.balance, issuanceBalBefore + confiscatedAmount);

        // ConsensusRegistry balance decreased by full surplus (refund + confiscated = 400k)
        uint256 fullSurplus = stakeAmount_ - newStakeAmt; // 1M - 600k = 400k
        assertEq(address(consensusRegistry).balance, registryBalBefore - fullSurplus);
    }

    function test_upgradeValidatorStakeVersion_slashRewardsDowngrade() public {
        // Apply incentives so validator1 earns rewards
        address[] memory committee = new address[](4);
        committee[0] = validator1;
        committee[1] = validator2;
        committee[2] = validator3;
        committee[3] = validator4;
        _sortAddresses(committee);

        RewardInfo[] memory rewards = new RewardInfo[](4);
        rewards[0] = RewardInfo(validator1, 10);
        rewards[1] = RewardInfo(validator2, 10);
        rewards[2] = RewardInfo(validator3, 10);
        rewards[3] = RewardInfo(validator4, 10);
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewards);
        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(committee);

        // Record rewards earned
        uint256 rewardsBefore = consensusRegistry.getRewards(validator1);
        assertTrue(rewardsBefore > 0);

        // Slash validator1 partially (200k)
        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator1, 200_000e18);
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);

        // Balance after slash = stakeAmount + rewards - 200k
        (uint256 balAfterSlash,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfterSlash, stakeAmount_ + rewardsBefore - 200_000e18);

        // Create new version with 600k stake, downgrade
        uint256 newStakeAmt = 600_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 recipientBalBefore = validator1.balance;

        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);

        // Balance after = newStakeAmount (600k)
        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, newStakeAmt);

        // getRewards() = 0 (rewards zeroed - this is expected/documented behavior)
        // After version change, rewards = balance - newStakeAmount = 600k - 600k = 0
        uint256 rewardsAfter = consensusRegistry.getRewards(validator1);
        assertEq(rewardsAfter, 0);

        // Recipient gets correct refund (balanceAfterSlash - newStakeAmt)
        uint256 expectedRefund = balAfterSlash - newStakeAmt;
        assertEq(validator1.balance, recipientBalBefore + expectedRefund);
    }

    function test_upgradeValidatorStakeVersion_decreasePreservesRewardsNoSlash() public {
        // Apply incentives so validator1 earns rewards
        address[] memory committee = new address[](4);
        committee[0] = validator1;
        committee[1] = validator2;
        committee[2] = validator3;
        committee[3] = validator4;
        _sortAddresses(committee);

        RewardInfo[] memory rewards = new RewardInfo[](4);
        rewards[0] = RewardInfo(validator1, 10);
        rewards[1] = RewardInfo(validator2, 10);
        rewards[2] = RewardInfo(validator3, 10);
        rewards[3] = RewardInfo(validator4, 10);
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewards);
        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(committee);

        uint256 rewardsBefore = consensusRegistry.getRewards(validator1);
        assertTrue(rewardsBefore > 0);

        // Create new version with 500k stake, downgrade (NO slash)
        uint256 newStakeAmt = 500_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 recipientBalBefore = validator1.balance;

        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);

        // Balance after = newStakeAmount + rewardsBefore (rewards preserved)
        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, newStakeAmt + rewardsBefore);

        // getRewards() = rewardsBefore (unchanged)
        uint256 rewardsAfter = consensusRegistry.getRewards(validator1);
        assertEq(rewardsAfter, rewardsBefore);

        // Recipient gets exact surplus (oldStake - newStake = 500k)
        uint256 surplus = stakeAmount_ - newStakeAmt;
        assertEq(validator1.balance, recipientBalBefore + surplus);
    }

    function test_upgradeValidatorStakeVersion_upgradeThenClaimRewards() public {
        // Upgrade validator1 to higher version (2M stake)
        uint256 newStakeAmt = 2_000_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 deficit = newStakeAmt - stakeAmount_;
        vm.deal(validator1, deficit);
        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion{value: deficit}(validator1, newVersion);

        // Allocate issuance and apply incentives, conclude epoch
        vm.deal(crOwner, epochIssuance_);
        vm.prank(crOwner);
        consensusRegistry.allocateIssuance{value: epochIssuance_}();

        address[] memory committee = new address[](4);
        committee[0] = validator1;
        committee[1] = validator2;
        committee[2] = validator3;
        committee[3] = validator4;
        _sortAddresses(committee);

        RewardInfo[] memory rewards = new RewardInfo[](4);
        rewards[0] = RewardInfo(validator1, 10);
        rewards[1] = RewardInfo(validator2, 10);
        rewards[2] = RewardInfo(validator3, 10);
        rewards[3] = RewardInfo(validator4, 10);
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewards);
        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(committee);

        // Verify rewards earned > 0
        uint256 rewardsEarned = consensusRegistry.getRewards(validator1);
        assertTrue(rewardsEarned > 0);

        // Claim rewards via claimStakeRewards
        uint256 balBefore = validator1.balance;
        vm.prank(validator1);
        consensusRegistry.claimStakeRewards(validator1);

        // Verify claim succeeded, rewards zeroed, balance back to newStakeAmount
        uint256 rewardsAfterClaim = consensusRegistry.getRewards(validator1);
        assertEq(rewardsAfterClaim, 0);
        assertEq(validator1.balance, balBefore + rewardsEarned);

        (uint256 contractBal,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(contractBal, newStakeAmt);
    }

    function test_upgradeValidatorStakeVersion_upgradeThenSlash() public {
        // Upgrade validator1 to higher version (2M stake)
        uint256 newStakeAmt = 2_000_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 deficit = newStakeAmt - stakeAmount_;
        vm.deal(validator1, deficit);
        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion{value: deficit}(validator1, newVersion);

        // Slash 500k
        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator1, 500_000e18);
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);

        // Verify balance = 2M - 500k = 1.5M
        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, 1_500_000e18);

        // Verify status still Active, version unchanged
        ValidatorInfo memory info = consensusRegistry.getValidator(validator1);
        assertEq(uint8(info.currentStatus), uint8(ValidatorStatus.Active));
        assertEq(info.stakeVersion, newVersion);

        // Verify rewards = 0 (slashed below stake)
        uint256 rewardsAfter = consensusRegistry.getRewards(validator1);
        assertEq(rewardsAfter, 0);
    }

    function testRevert_upgradeValidatorStakeVersion_paused() public {
        // Create new version
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        // Pause contract via crOwner
        vm.prank(crOwner);
        consensusRegistry.pause();

        // Try upgrade - expect revert with EnforcedPause
        vm.prank(validator1);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);

        // Unpause, verify upgrade succeeds
        vm.prank(crOwner);
        consensusRegistry.unpause();

        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);

        ValidatorInfo memory info = consensusRegistry.getValidator(validator1);
        assertEq(info.stakeVersion, newVersion);
    }

    function test_upgradeValidatorStakeVersion_zeroStakeVersion() public {
        // Create version with stakeAmount = 0
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(0, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        uint256 recipientBalBefore = validator1.balance;

        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion(validator1, newVersion);

        // Verify: full stake refunded, balance = 0
        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, 0);
        assertEq(validator1.balance, recipientBalBefore + stakeAmount_);
    }

    function test_upgradeValidatorStakeVersion_sequentialUpgrades() public {
        // Create v1 (1.5M) and v2 (2M)
        uint256 v1StakeAmt = 1_500_000e18;
        uint256 v2StakeAmt = 2_000_000e18;

        vm.startPrank(crOwner);
        uint8 v1 = consensusRegistry.upgradeStakeVersion(
            StakeConfig(v1StakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );
        uint8 v2 = consensusRegistry.upgradeStakeVersion(
            StakeConfig(v2StakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );
        vm.stopPrank();

        // Upgrade v0 -> v1
        uint256 deficit1 = v1StakeAmt - stakeAmount_;
        vm.deal(validator1, deficit1);
        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion{value: deficit1}(validator1, v1);

        // Verify state after v0 -> v1
        ValidatorInfo memory info1 = consensusRegistry.getValidator(validator1);
        assertEq(info1.stakeVersion, v1);
        (uint256 bal1, uint256 stakeAmt1,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(bal1, v1StakeAmt);
        assertEq(stakeAmt1, v1StakeAmt);

        // Upgrade v1 -> v2
        uint256 deficit2 = v2StakeAmt - v1StakeAmt;
        vm.deal(validator1, deficit2);
        vm.prank(validator1);
        consensusRegistry.upgradeValidatorStakeVersion{value: deficit2}(validator1, v2);

        // Verify state after v1 -> v2
        ValidatorInfo memory info2 = consensusRegistry.getValidator(validator1);
        assertEq(info2.stakeVersion, v2);
        (uint256 bal2, uint256 stakeAmt2,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(bal2, v2StakeAmt);
        assertEq(stakeAmt2, v2StakeAmt);

        // Check total balance equals v2 stake amount
        assertEq(bal2, v2StakeAmt);
    }

    function test_stakeVersionGetters_divergeForPendingVersion() public {
        uint256 newStakeAmt = 2_000_000e18;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmt, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );

        // mid-epoch the epoch-active version is unchanged, while the config getter already
        // returns the newly authored configuration that activates at the next epoch start
        assertEq(consensusRegistry.getCurrentStakeVersion(), 0);
        assertEq(consensusRegistry.getCurrentStakeConfig().stakeAmount, newStakeAmt);

        // at the next epoch start the authored version is stamped in and the getters agree
        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(4));
        assertEq(consensusRegistry.getCurrentStakeVersion(), newVersion);
        assertEq(consensusRegistry.getCurrentStakeConfig().stakeAmount, newStakeAmt);
        assertEq(
            consensusRegistry.getCurrentStakeConfig().stakeAmount,
            consensusRegistry.stakeConfig(consensusRegistry.getCurrentStakeVersion()).stakeAmount
        );
    }

    function test_getEpochInfo_futureEpochProjection() public {
        // advance two epochs so both future ring buffer slots have been rewritten
        vm.startPrank(sysAddress);
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(4));
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(4));
        vm.stopPrank();

        uint32 current = consensusRegistry.getCurrentEpoch();
        for (uint32 ahead = 1; ahead <= 2; ++ahead) {
            EpochInfo memory info = consensusRegistry.getEpochInfo(current + ahead);
            // committee and epoch id are known for future epochs
            assertEq(info.epochId, current + ahead);
            assertEq(info.committee.length, 4);
            // config fields project the latest authored configuration (still genesis here)
            assertEq(info.epochIssuance, epochIssuance_);
            assertEq(uint256(info.epochDuration), uint256(epochDuration_));
            assertEq(uint256(info.stakeVersion), 0);
            // block height is unknowable for future epochs
            assertEq(uint256(info.blockHeight), 0);
        }

        // authoring a new version mid-epoch updates the projection immediately
        uint256 newIssuance = epochIssuance_ * 2;
        uint32 newDuration = epochDuration_ + 1;
        vm.prank(crOwner);
        uint8 newVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(2_000_000e18, minWithdrawAmount_, newIssuance, newDuration)
        );

        for (uint32 ahead = 1; ahead <= 2; ++ahead) {
            EpochInfo memory info = consensusRegistry.getEpochInfo(current + ahead);
            assertEq(info.epochId, current + ahead);
            assertEq(info.committee.length, 4);
            assertEq(info.epochIssuance, newIssuance);
            assertEq(uint256(info.epochDuration), uint256(newDuration));
            assertEq(uint256(info.stakeVersion), uint256(newVersion));
            assertEq(uint256(info.blockHeight), 0);
        }
    }

    function test_delegatedValidator_voluntaryExit_clearedDelegation() public {
        // --- setup delegation for validator5 ---
        uint256 validator5PrivateKey = 5;
        validator5 = vm.addr(validator5PrivateKey);
        address delegator = _addressFromPrivateKey(42);
        vm.deal(delegator, stakeAmount_);

        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        bytes32 structHash = consensusRegistry.delegationDigest(validator5BlsPubkey, validator5, delegator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator5PrivateKey, structHash);
        bytes memory validatorSig = abi.encodePacked(r, s, v);

        vm.prank(delegator);
        consensusRegistry.delegateStake{value: stakeAmount_}(
            validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig), validator5, validatorSig
        );
        assertTrue(consensusRegistry.isDelegated(validator5));

        // --- activate validator and conclude epoch ---
        vm.prank(validator5);
        consensusRegistry.activate();

        uint256 numActiveAfter = consensusRegistry.getEligibleValidatorCount();
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(numActiveAfter));
        vm.prank(sysAddress);
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(numActiveAfter));

        // --- begin exit ---
        vm.prank(validator5);
        consensusRegistry.beginExit();

        // conclude 2 epochs without validator5 in committee to reach Exited
        uint256 numActiveBefore = numActiveAfter - 1;
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(numActiveBefore));
        vm.startPrank(sysAddress);
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(numActiveBefore));
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(numActiveBefore));

        // conclude 1 more epoch for unstake eligibility
        consensusRegistry.concludeEpoch(_createTokenIdCommittee(numActiveBefore));
        vm.stopPrank();

        // --- delegator unstakes ---
        vm.deal(address(consensusRegistry), stakeAmount_);
        vm.prank(delegator);
        consensusRegistry.unstake(validator5, false);

        // delegation must be cleared
        assertFalse(consensusRegistry.isDelegated(validator5));
    }

    function test_delegatedValidator_burn_clearedDelegation() public {
        // --- setup delegation for validator5 ---
        uint256 validator5PrivateKey = 5;
        validator5 = vm.addr(validator5PrivateKey);
        address delegator = _addressFromPrivateKey(42);
        vm.deal(delegator, stakeAmount_);

        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        bytes32 structHash = consensusRegistry.delegationDigest(validator5BlsPubkey, validator5, delegator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator5PrivateKey, structHash);
        bytes memory validatorSig = abi.encodePacked(r, s, v);

        vm.prank(delegator);
        consensusRegistry.delegateStake{value: stakeAmount_}(
            validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig), validator5, validatorSig
        );
        assertTrue(consensusRegistry.isDelegated(validator5));

        // --- owner burns the staked delegated validator ---
        vm.prank(crOwner);
        consensusRegistry.burn(validator5);

        // delegation must be cleared
        assertFalse(consensusRegistry.isDelegated(validator5));
    }

    /*
     *   slashed-stake top-ups
     */

    /// @dev Partially slashes genesis `validator1` via system call
    function _slashValidator1(uint256 amount) internal {
        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator1, amount);
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);
    }

    /// @dev Exits genesis `validator1` through the pending-exit queue and elapses one further
    /// epoch so it becomes unstake-eligible
    function _exitValidator1ToUnstakeEligibility() internal {
        uint256 numActive = consensusRegistry.getEligibleValidatorCount();

        vm.prank(validator1);
        consensusRegistry.beginExit();

        // validator1 serves in the genesis committees for the first epochs, so conclude past them
        vm.startPrank(sysAddress);
        address[] memory waitCommittee = _createTokenIdCommittee(numActive);
        waitCommittee[waitCommittee.length - 1] = validator1;
        consensusRegistry.concludeEpoch(waitCommittee);
        address[] memory tokenIdCommittee = _createTokenIdCommittee(numActive);
        consensusRegistry.concludeEpoch(tokenIdCommittee);
        consensusRegistry.concludeEpoch(tokenIdCommittee);
        vm.stopPrank();

        uint256 activeAfterExit = numActive - 1;
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(activeAfterExit));

        // exit resolves on the next epoch conclusion; one further epoch reaches unstake eligibility
        vm.startPrank(sysAddress);
        address[] memory afterExitCommittee = _createTokenIdCommittee(activeAfterExit);
        consensusRegistry.concludeEpoch(afterExitCommittee);
        consensusRegistry.concludeEpoch(afterExitCommittee);
        vm.stopPrank();
    }

    function test_applyIncentives_slashedValidatorWeightReduced() public {
        // slash validator1 to half its stake; equal header counts should now yield unequal rewards
        uint256 slashAmt = stakeAmount_ / 2;
        _slashValidator1(slashAmt);

        RewardInfo[] memory rewardInfos = new RewardInfo[](2);
        rewardInfos[0] = RewardInfo(validator1, 10);
        rewardInfos[1] = RewardInfo(validator2, 10);
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewardInfos);

        // validator1's weight derives from its reduced balance, validator2's from its full stake
        uint256 slashedWeight = (stakeAmount_ - slashAmt) * 10;
        uint256 fullWeight = stakeAmount_ * 10;
        uint256 totalWeight = slashedWeight + fullWeight;
        uint256 expected1 = epochIssuance_ * slashedWeight / totalWeight;
        uint256 expected2 = epochIssuance_ * fullWeight / totalWeight;

        (uint256 bal1,,) = consensusRegistry.getBalanceBreakdown(validator1);
        (uint256 bal2,,) = consensusRegistry.getBalanceBreakdown(validator2);
        assertEq(bal1, stakeAmount_ - slashAmt + expected1);
        assertEq(bal2, stakeAmount_ + expected2);
        assertEq(consensusRegistry.getRewards(validator2), expected2);
    }

    function test_applyIncentives_rewardsDoNotIncreaseWeight() public {
        // validator1 accrues rewards, pushing its balance above the stake amount
        RewardInfo[] memory firstRound = new RewardInfo[](1);
        firstRound[0] = RewardInfo(validator1, 10);
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(firstRound);
        uint256 firstRoundRewards = consensusRegistry.getRewards(validator1);
        assertEq(firstRoundRewards, epochIssuance_);

        // second round: equal header counts for validator1 and validator2 yield equal rewards
        // because weight is capped at the version's stake amount
        RewardInfo[] memory secondRound = new RewardInfo[](2);
        secondRound[0] = RewardInfo(validator1, 10);
        secondRound[1] = RewardInfo(validator2, 10);
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(secondRound);

        assertEq(consensusRegistry.getRewards(validator1), firstRoundRewards + epochIssuance_ / 2);
        assertEq(consensusRegistry.getRewards(validator2), epochIssuance_ / 2);
    }

    function test_topUpSlashedStake_validatorSelf() public {
        uint256 slashAmt = 200_000e18;
        _slashValidator1(slashAmt);

        uint256 registryBalBefore = address(consensusRegistry).balance;
        uint256 issuanceBalBefore = issuance.balance;

        vm.deal(validator1, slashAmt);
        vm.expectEmit(true, true, true, true);
        emit ValidatorStakeToppedUp(validator1, slashAmt);
        vm.prank(validator1);
        consensusRegistry.topUpSlashedStake{ value: slashAmt }(validator1);

        // the balance ledger is restored to the full stake amount
        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, stakeAmount_);

        // the top-up value consolidates on Issuance; the registry retains its stake-backed native
        assertEq(issuance.balance, issuanceBalBefore + slashAmt);
        assertEq(address(consensusRegistry).balance, registryBalBefore);
    }

    function test_topUpSlashedStake_ownerWhenAuthorityRequired() public {
        uint256 slashAmt = 150_000e18;
        _slashValidator1(slashAmt);

        vm.prank(crOwner);
        consensusRegistry.setTopUpAuthorityRequired(true);

        vm.deal(crOwner, slashAmt);
        vm.prank(crOwner);
        consensusRegistry.topUpSlashedStake{ value: slashAmt }(validator1);

        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, stakeAmount_);
    }

    function test_topUpSlashedStake_delegator() public {
        // setup delegation for validator5
        uint256 validator5PrivateKey = 5;
        validator5 = vm.addr(validator5PrivateKey);
        address delegator = _addressFromPrivateKey(42);
        vm.deal(delegator, stakeAmount_);

        vm.prank(crOwner);
        consensusRegistry.mint(validator5);

        bytes32 structHash = consensusRegistry.delegationDigest(validator5BlsPubkey, validator5, delegator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator5PrivateKey, structHash);
        bytes memory validatorSig = abi.encodePacked(r, s, v);

        vm.prank(delegator);
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig), validator5, validatorSig
        );

        // slash the staked validator5, then its delegator restores the stake
        uint256 slashAmt = 100_000e18;
        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator5, slashAmt);
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);

        vm.deal(delegator, slashAmt);
        vm.prank(delegator);
        consensusRegistry.topUpSlashedStake{ value: slashAmt }(validator5);

        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator5);
        assertEq(balAfter, stakeAmount_);
    }

    function test_topUpSlashedStake_thenUnstake_noOrphanedFunds() public {
        uint256 slashAmt = 200_000e18;
        _slashValidator1(slashAmt);

        // top up, restoring the ledger; the deficit consolidates on Issuance
        vm.deal(validator1, slashAmt);
        vm.prank(validator1);
        consensusRegistry.topUpSlashedStake{ value: slashAmt }(validator1);

        _exitValidator1ToUnstakeEligibility();

        uint256 registryBalBefore = address(consensusRegistry).balance;
        uint256 issuanceBalBefore = issuance.balance;

        vm.prank(validator1);
        consensusRegistry.unstake(validator1, false);

        // the full stake returns and no native TEL is left stranded on the registry
        assertEq(validator1.balance, stakeAmount_);
        assertEq(address(consensusRegistry).balance, registryBalBefore - stakeAmount_);
        assertEq(issuance.balance, issuanceBalBefore);
    }

    function testRevert_topUpSlashedStake_authorityRequired() public {
        uint256 slashAmt = 100_000e18;
        _slashValidator1(slashAmt);

        vm.prank(crOwner);
        consensusRegistry.setTopUpAuthorityRequired(true);

        vm.deal(validator1, slashAmt);
        vm.prank(validator1);
        vm.expectRevert(TopUpAuthorityRequired.selector);
        consensusRegistry.topUpSlashedStake{ value: slashAmt }(validator1);
    }

    function testRevert_topUpSlashedStake_notRecipient() public {
        uint256 slashAmt = 100_000e18;
        _slashValidator1(slashAmt);

        address thirdParty = address(0xbeef);
        vm.deal(thirdParty, slashAmt);
        vm.prank(thirdParty);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.NotRecipient.selector, validator1));
        consensusRegistry.topUpSlashedStake{ value: slashAmt }(validator1);
    }

    function testRevert_topUpSlashedStake_notSlashed() public {
        vm.deal(validator1, 1);
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(StakeNotSlashed.selector, validator1, stakeAmount_, uint8(0)));
        consensusRegistry.topUpSlashedStake{ value: 1 }(validator1);
    }

    function testRevert_topUpSlashedStake_wrongValue() public {
        uint256 slashAmt = 100_000e18;
        _slashValidator1(slashAmt);

        uint256 wrongValue = slashAmt - 1;
        vm.deal(validator1, wrongValue);
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(InvalidDeficitAmount.selector, validator1, wrongValue, uint8(0)));
        consensusRegistry.topUpSlashedStake{ value: wrongValue }(validator1);
    }

    function testRevert_topUpSlashedStake_invalidStatus() public {
        uint256 slashAmt = 100_000e18;
        _slashValidator1(slashAmt);

        // pending-exit validators may not top up
        vm.prank(validator1);
        consensusRegistry.beginExit();

        vm.deal(validator1, slashAmt);
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(InvalidStatus.selector, ValidatorStatus.PendingExit));
        consensusRegistry.topUpSlashedStake{ value: slashAmt }(validator1);
    }

    function testRevert_topUpSlashedStake_unknownValidator() public {
        address unknown = address(0xabc);
        vm.deal(unknown, 1 ether);
        vm.prank(unknown);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.InvalidTokenId.selector, _getTokenId(unknown)));
        consensusRegistry.topUpSlashedStake{ value: 1 ether }(unknown);
    }

    function testRevert_topUpSlashedStake_paused() public {
        uint256 slashAmt = 100_000e18;
        _slashValidator1(slashAmt);

        vm.prank(crOwner);
        consensusRegistry.pause();

        vm.deal(validator1, slashAmt);
        vm.prank(validator1);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        consensusRegistry.topUpSlashedStake{ value: slashAmt }(validator1);
    }

    function test_setTopUpAuthorityRequired() public {
        assertFalse(consensusRegistry.topUpAuthorityRequired());

        vm.expectEmit(true, true, true, true);
        emit TopUpAuthorityRequirementUpdated(true);
        vm.prank(crOwner);
        consensusRegistry.setTopUpAuthorityRequired(true);
        assertTrue(consensusRegistry.topUpAuthorityRequired());

        vm.prank(crOwner);
        consensusRegistry.setTopUpAuthorityRequired(false);
        assertFalse(consensusRegistry.topUpAuthorityRequired());
    }

    function testRevert_setTopUpAuthorityRequired_notOwner() public {
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, validator1));
        consensusRegistry.setTopUpAuthorityRequired(true);
    }

    /*
     *   issuanceWithdrawal
     */

    function test_issuanceWithdrawal() public {
        uint256 amount = 10_000e18;
        uint256 issuanceBalBefore = issuance.balance;
        uint256 ownerBalBefore = crOwner.balance;

        vm.prank(crOwner);
        consensusRegistry.issuanceWithdrawal(amount);

        assertEq(issuance.balance, issuanceBalBefore - amount);
        assertEq(crOwner.balance, ownerBalBefore + amount);
    }

    function testRevert_issuanceWithdrawal_notOwner() public {
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, validator1));
        consensusRegistry.issuanceWithdrawal(1);
    }

    function testRevert_issuanceWithdrawal_insufficientBalance() public {
        uint256 available = issuance.balance;
        vm.prank(crOwner);
        vm.expectRevert(abi.encodeWithSelector(Issuance.InsufficientBalance.selector, available, available + 1));
        consensusRegistry.issuanceWithdrawal(available + 1);
    }

    function testRevert_issuanceWithdraw_onlyStakeManager() public {
        vm.prank(crOwner);
        vm.expectRevert(abi.encodeWithSelector(Issuance.OnlyStakeManager.selector, address(consensusRegistry)));
        Issuance(issuance).withdraw(1, crOwner);
    }

    /*
     *   slashing settlement
     */

    function test_applySlashes_partial_consolidatesAtUnstake() public {
        uint256 slashAmt = 200_000e18;
        uint256 registryBalBefore = address(consensusRegistry).balance;
        uint256 issuanceBalBefore = issuance.balance;

        vm.expectEmit(true, true, true, true);
        emit ValidatorSlashed(Slash(validator1, slashAmt));
        _slashValidator1(slashAmt);

        // a partial slash decrements only the balance ledger; no native TEL moves until settlement
        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, stakeAmount_ - slashAmt);
        assertEq(address(consensusRegistry).balance, registryBalBefore);
        assertEq(issuance.balance, issuanceBalBefore);

        // on unstake the slashed remainder consolidates on Issuance and the reduced stake returns
        _exitValidator1ToUnstakeEligibility();
        vm.prank(validator1);
        consensusRegistry.unstake(validator1, false);

        assertEq(validator1.balance, stakeAmount_ - slashAmt);
        assertEq(issuance.balance, issuanceBalBefore + slashAmt);
        assertEq(address(consensusRegistry).balance, registryBalBefore - stakeAmount_);
    }

    function test_applySlashes_fullSlash_consolidatesFullStake() public {
        uint256 registryBalBefore = address(consensusRegistry).balance;
        uint256 issuanceBalBefore = issuance.balance;

        // a slash consuming the whole balance ejects the validator and confiscates its full stake
        _slashValidator1(stakeAmount_);

        assertTrue(consensusRegistry.isRetired(validator1));
        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, 0);
        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_);
        assertEq(address(consensusRegistry).balance, registryBalBefore - stakeAmount_);
    }

    function test_applySlashes_partialThenFull_noOrphanedFunds() public {
        _slashValidator1(200_000e18);

        uint256 registryBalBefore = address(consensusRegistry).balance;
        uint256 issuanceBalBefore = issuance.balance;

        // the second slash consumes the whole remaining balance, triggering ejection via burn
        _slashValidator1(800_000e18);

        assertTrue(consensusRegistry.isRetired(validator1));
        // the full original stake consolidates on Issuance, including the earlier slashed portion
        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_);
        assertEq(address(consensusRegistry).balance, registryBalBefore - stakeAmount_);
    }

    function test_burn_slashedValidator_noOrphanedFunds() public {
        uint256 slashAmt = 200_000e18;
        _slashValidator1(slashAmt);

        uint256 registryBalBefore = address(consensusRegistry).balance;
        uint256 issuanceBalBefore = issuance.balance;

        // governance ejection confiscates the full stake-backed native, including the slashed portion
        vm.prank(crOwner);
        consensusRegistry.burn(validator1);

        assertTrue(consensusRegistry.isRetired(validator1));
        (uint256 balAfter,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(balAfter, 0);
        assertEq(validator1.balance, 0);
        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_);
        assertEq(address(consensusRegistry).balance, registryBalBefore - stakeAmount_);
    }

    /*
     *   reward-shortfall unstaking
     */

    function test_unstake_acceptRewardShortfall_paysFullRewardsWhenFunded() public {
        // validator1 accrues rewards
        RewardInfo[] memory rewardInfos = new RewardInfo[](1);
        rewardInfos[0] = RewardInfo(validator1, 10);
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewardInfos);
        uint256 accrued = consensusRegistry.getRewards(validator1);
        assertGt(accrued, 0);

        _exitValidator1ToUnstakeEligibility();

        uint256 issuanceBalBefore = issuance.balance;

        // with a funded reward pool a shortfall-accepting unstake is identical to a normal unstake:
        // nothing payable is ever forfeited
        vm.expectEmit(true, true, true, true);
        emit RewardsClaimed(validator1, stakeAmount_ + accrued);
        vm.prank(validator1);
        consensusRegistry.unstake(validator1, true);

        assertEq(validator1.balance, stakeAmount_ + accrued);
        assertTrue(consensusRegistry.isRetired(validator1));
        assertEq(issuance.balance, issuanceBalBefore - accrued);
    }

    function test_unstake_acceptRewardShortfall_insufficientIssuanceBalance() public {
        // validator1 accrues rewards
        RewardInfo[] memory rewardInfos = new RewardInfo[](1);
        rewardInfos[0] = RewardInfo(validator1, 10);
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewardInfos);
        uint256 accrued = consensusRegistry.getRewards(validator1);
        assertGt(accrued, 0);

        _exitValidator1ToUnstakeEligibility();

        // empty the reward pool so accrued rewards can no longer be paid out
        vm.deal(issuance, 0);

        // a normal unstake cannot cover the rewards owed and reverts
        vm.prank(validator1);
        vm.expectRevert(
            abi.encodeWithSelector(Issuance.InsufficientBalance.selector, stakeAmount_, stakeAmount_ + accrued)
        );
        consensusRegistry.unstake(validator1, false);

        // the shortfall-accepting path still returns the stake, forfeiting only the unpayable rewards
        vm.expectEmit(true, true, true, true);
        emit RewardsClaimed(validator1, stakeAmount_);
        vm.prank(validator1);
        consensusRegistry.unstake(validator1, true);
        assertEq(validator1.balance, stakeAmount_);
        assertEq(issuance.balance, 0);
    }

    function test_unstake_acceptRewardShortfall_partialShortfall() public {
        // validator1 accrues rewards
        RewardInfo[] memory rewardInfos = new RewardInfo[](1);
        rewardInfos[0] = RewardInfo(validator1, 10);
        vm.prank(sysAddress);
        consensusRegistry.applyIncentives(rewardInfos);
        uint256 accrued = consensusRegistry.getRewards(validator1);
        assertGt(accrued, 1);

        _exitValidator1ToUnstakeEligibility();

        // leave the reward pool able to cover only part of the accrued rewards
        uint256 payableRewards = accrued / 2;
        vm.deal(issuance, payableRewards);

        // a normal unstake still reverts on the shortfall
        vm.prank(validator1);
        vm.expectRevert(
            abi.encodeWithSelector(
                Issuance.InsufficientBalance.selector, payableRewards + stakeAmount_, stakeAmount_ + accrued
            )
        );
        consensusRegistry.unstake(validator1, false);

        // the shortfall-accepting path pays the stake plus the payable portion, forfeiting only the shortfall
        vm.expectEmit(true, true, true, true);
        emit RewardsClaimed(validator1, stakeAmount_ + payableRewards);
        vm.prank(validator1);
        consensusRegistry.unstake(validator1, true);

        assertEq(validator1.balance, stakeAmount_ + payableRewards);
        assertEq(issuance.balance, 0);
        assertTrue(consensusRegistry.isRetired(validator1));
    }
}
