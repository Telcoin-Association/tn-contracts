// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { SlotDerivation } from "@openzeppelin/contracts/utils/SlotDerivation.sol";
import { TransientSlot } from "@openzeppelin/contracts/utils/TransientSlot.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { ReentrancyGuard } from "solady/utils/ReentrancyGuard.sol";
import { RewardInfo, Slash, IStakeManager } from "../interfaces/IStakeManager.sol";
import { StakeManager } from "./StakeManager.sol";
import { IConsensusRegistry } from "../interfaces/IConsensusRegistry.sol";
import { SystemCallable } from "./SystemCallable.sol";
import { Issuance } from "./Issuance.sol";
import { IBlsG1, BLS_G1_ADDRESS } from "../interfaces/IBlsG1.sol";

/**
 * @title ConsensusRegistry
 * @author Telcoin Association
 * @author Huwonk
 * @notice A Telcoin Contract
 *
 * @notice This contract manages consensus validator external keys, staking, and committees
 * @dev This contract should be deployed to a predefined system address for use with system calls
 */
contract ConsensusRegistry is StakeManager, Pausable, Ownable, ReentrancyGuard, SystemCallable, IConsensusRegistry {
    using EnumerableSet for EnumerableSet.AddressSet;
    using SlotDerivation for bytes32;
    using TransientSlot for bytes32;
    using TransientSlot for TransientSlot.BooleanSlot;

    uint32 internal currentEpoch;
    uint8 internal epochPointer;
    uint16 internal nextCommitteeSize;
    uint256 public undistributedIssuance;
    mapping(address => ValidatorInfo) public validators;
    mapping(bytes32 => address) private blsPubkeyHashToValidator;
    EpochInfo[4] public epochInfo;
    EpochInfo[4] public futureEpochInfo;
    mapping(address => bytes) private blsPubkeys;
    /// @dev Per-status index of validators, keyed by `ValidatorStatus`. `_setStatus` is the single point
    /// that mutates membership, keeping each set in lockstep with `validators[addr].currentStatus`. Only
    /// real statuses get members; `Undefined` and `Any` never do. Retiring removes a validator from its set
    /// (it should not appear in any status query, exactly as the old scan skipped `isRetired`), but its
    /// `validators[addr]` record is retained as a tombstone (`isRetired = true`) that blocks re-joining.
    /// Replaces the old O(n) `tokenByIndex` scan: per-status queries are now O(set).
    mapping(uint8 => EnumerableSet.AddressSet) private validatorSets;
    /// @dev Cached size of the committee-eligible union `{ PendingActivation, Active, PendingExit }`, kept
    /// in sync by `_setStatus` so the hot count path (`concludeEpoch` et al.) stays a single SLOAD rather
    /// than three set-length reads. Invariant-tested against the eligible set sizes.
    uint256 internal eligibleValidatorCount;

    /// @dev Signals a validator's pending status until activation/exit to correctly apply incentives
    uint32 internal constant PENDING_EPOCH = type(uint32).max;

    /// @dev Namespace for the per-epoch transient committee-membership set (see `_markCommitteeMembers`)
    bytes32 private constant _COMMITTEE_TSET = keccak256("ConsensusRegistry.committeeMembership.v1");

    // Proof-of-possession verification is delegated to the native precompile at `BLS_G1_ADDRESS`
    // (see `IBlsG1.blsVerify`), which reuses the protocol's `blst` signing path.

    /**
     *
     *   consensus
     *
     */

    /// @inheritdoc IConsensusRegistry
    function concludeEpoch(address[] calldata futureCommittee) external override onlySystemCall {
        // ensure future committee is sorted
        _enforceSorting(futureCommittee);

        // ensure future committee is the correct length
        if (futureCommittee.length != nextCommitteeSize) {
            revert InvalidCommitteeSize(nextCommitteeSize, futureCommittee.length);
        }

        // update epoch ring buffer info, validator queue
        (uint32 newEpoch, uint256 issuance, uint32 duration, address[] memory newCommittee) =
            _updateEpochInfo(futureCommittee);
        _updateValidatorQueue(futureCommittee, newEpoch);

        // assert future epoch committee is valid against total now eligible
        _checkCommitteeSize(_eligibleValidatorCount(), futureCommittee.length);

        emit NewEpoch(EpochInfo(newCommittee, issuance, uint64(block.number + 1), newEpoch, duration, stakeVersion));
    }

    /// @inheritdoc IConsensusRegistry
    function applyIncentives(RewardInfo[] calldata rewardInfos) public override onlySystemCall {
        // identify total & individual weight factoring in stake & consensus headers
        uint256 totalWeight;
        uint256[] memory weights = new uint256[](rewardInfos.length);
        for (uint256 i; i < rewardInfos.length; ++i) {
            RewardInfo calldata reward = rewardInfos[i];
            if (reward.consensusHeaderCount == 0) continue;

            // signed consensus header means validator is whitelisted, staked, & active
            // unless validator was forcibly retired & ejected via burn: skip
            if (isRetired(reward.validatorAddress)) continue;

            uint8 rewardeeVersion = validators[reward.validatorAddress].stakeVersion;
            // derive validator's weight using initial stake for stability
            uint256 stakeAmount = versions[rewardeeVersion].stakeAmount;
            uint256 weight = stakeAmount * reward.consensusHeaderCount;

            totalWeight += weight;
            weights[i] = weight;
        }

        if (totalWeight == 0) return;

        // get epoch issuance amount and incorporate dust from the previous epoch
        uint256 epochIssuance = getCurrentEpochInfo().epochIssuance;
        uint256 totalAvailableToDistribute = epochIssuance + undistributedIssuance;

        // derive and apply validator's weighted share of epoch issuance
        uint256 amountDistributed;
        for (uint256 i; i < rewardInfos.length; ++i) {
            // will be 0 if `epochIssuance` is too small or `totalWeight` too large (many validators and/or headers)
            uint256 rewardAmount = (totalAvailableToDistribute * weights[i]) / totalWeight;

            if (rewardAmount > 0) {
                balances[rewardInfos[i].validatorAddress] += rewardAmount;
                amountDistributed += rewardAmount;
            }
        }

        // roll over any remaining dust to the next epoch
        undistributedIssuance = totalAvailableToDistribute - amountDistributed;
    }

    /// @inheritdoc IConsensusRegistry
    function applySlashes(Slash[] calldata slashes) external override onlySystemCall {
        for (uint256 i; i < slashes.length; ++i) {
            Slash calldata slash = slashes[i];
            // signed consensus header means validator is whitelisted, staked, & active
            // unless validator was forcibly retired & ejected via burn: skip
            if (isRetired(slash.validatorAddress)) continue;

            if (balances[slash.validatorAddress] > slash.amount) {
                balances[slash.validatorAddress] -= slash.amount;
            } else {
                // eject validators whose balance would reach 0
                _consensusBurn(slash.validatorAddress);
            }

            emit ValidatorSlashed(slash);
        }
    }

    /// @notice One-time back-fill of the per-status validator sets, the cached eligible count, and the
    /// BLS pubkey reverse index for an in-place upgrade from a deployment that predates them.
    /// @dev The storage layout is a clean append (the sets were appended after the pre-existing
    /// variables), so `validators[*]` and the ConsensusNFTs survive the code swap untouched; only
    /// `validatorSets` / `eligibleValidatorCount` start empty and must be rebuilt before the new read
    /// paths (`getValidators` / `getValidatorsInfo` / `concludeEpoch`) work. Walks the ConsensusNFT
    /// enumeration and re-derives each set from `currentStatus` (the preserved source of truth),
    /// mirroring `_setStatus`: retired, `Undefined`, and `Any` validators carry no set and are skipped.
    /// Idempotent - set adds dedupe and the count is recomputed from scratch - so a redundant call (or
    /// a call against a freshly seeded genesis) is a no-op. System-gated so the protocol invokes it
    /// once during the fork that swaps in this implementation.
    function migrateValidatorSets() external onlySystemCall {
        uint256 supply = totalSupply();
        uint256 eligible;
        for (uint256 i; i < supply; ++i) {
            address validatorAddress = ownerOf(tokenByIndex(i));

            // key the BLS reverse index by `_blsKeyId` so `isValidator` and `_spendBLSPubkey` resolve
            // this validator and enforce dedup; clear the pubkey-hash-keyed slot
            bytes memory blsPubkey = blsPubkeys[validatorAddress];
            if (blsPubkey.length == 96) {
                delete blsPubkeyHashToValidator[keccak256(blsPubkey)];
                blsPubkeyHashToValidator[_blsKeyId(blsPubkey)] = validatorAddress;
            }

            ValidatorInfo storage validator = validators[validatorAddress];
            if (validator.isRetired) continue;

            ValidatorStatus status = validator.currentStatus;
            if (status == ValidatorStatus.Undefined || status == ValidatorStatus.Any) continue;

            validatorSets[uint8(status)].add(validatorAddress);
            if (_eligibleForCommitteeNextEpoch(status)) ++eligible;
        }

        eligibleValidatorCount = eligible;
        emit ValidatorSetsMigrated(eligible);
    }

    /// @inheritdoc IConsensusRegistry
    function setValidatorRegion(address validatorAddress, uint8 region) external onlyOwner {
        _checkConsensusNFTOwner(validatorAddress);
        validators[validatorAddress].region = region;
        emit ValidatorRegionUpdated(validatorAddress, region);
    }

    /// @inheritdoc IConsensusRegistry
    function setNextCommitteeSize(uint16 newSize) external onlyOwner {
        if (newSize == 0) {
            revert InvalidCommitteeSize(epochInfo[epochPointer].committee.length, 0);
        }

        // Validate against current eligible validators
        uint256 eligible = _eligibleValidatorCount();
        if (newSize > eligible) {
            revert InvalidCommitteeSize(eligible, uint256(newSize));
        }

        uint16 oldSize = nextCommitteeSize;
        nextCommitteeSize = newSize;

        emit NextCommitteeSizeUpdated(oldSize, newSize, eligible);
    }

    /// @inheritdoc IConsensusRegistry
    function getNextCommitteeSize() external view returns (uint16) {
        return nextCommitteeSize;
    }

    /// @notice Number of committee-eligible validators: the unretired `{ PendingActivation, Active,
    /// PendingExit }` set. Derived O(1) from the per-status set sizes.
    function getEligibleValidatorCount() external view returns (uint256) {
        return _eligibleValidatorCount();
    }

    /// @dev Internal committee-eligible count, callable from the hot status paths. Returns the cached
    /// `eligibleValidatorCount` (a single SLOAD); the protocol obtains the eligible address pool by
    /// unioning the `{ PendingActivation, Active, PendingExit }` `getValidators` queries off-chain.
    function _eligibleValidatorCount() internal view returns (uint256) {
        return eligibleValidatorCount;
    }

    /// @inheritdoc IStakeManager
    function getCurrentStakeVersion() public view override returns (uint8) {
        return getCurrentEpochInfo().stakeVersion;
    }

    /// @inheritdoc IConsensusRegistry
    function getCurrentEpoch() public view returns (uint32) {
        return currentEpoch;
    }

    /// @inheritdoc IConsensusRegistry
    function getCurrentEpochInfo() public view returns (EpochInfo memory) {
        return _getRecentEpochInfo(currentEpoch, currentEpoch, epochPointer);
    }

    /// @inheritdoc IConsensusRegistry
    function getEpochInfo(uint32 epoch) public view returns (EpochInfo memory) {
        uint32 current = currentEpoch;
        if (epoch > current + 2 || (current >= 3 && epoch < current - 3)) {
            revert InvalidEpoch(epoch);
        }

        uint8 currentPointer = epochPointer;
        if (epoch > current) {
            return _getFutureEpochInfo(epoch, current, currentPointer);
        } else {
            return _getRecentEpochInfo(epoch, current, currentPointer);
        }
    }

    /// @inheritdoc IConsensusRegistry
    function getValidators(ValidatorStatus status) public view returns (address[] memory) {
        _checkQueryableStatus(status);

        return _getValidators(status);
    }

    /// @inheritdoc IConsensusRegistry
    function getValidatorsInfo(ValidatorStatus status) public view returns (ValidatorInfo[] memory) {
        _checkQueryableStatus(status);

        address[] memory addrs = _getValidators(status);
        ValidatorInfo[] memory infos = new ValidatorInfo[](addrs.length);
        for (uint256 i; i < addrs.length; ++i) {
            infos[i] = validators[addrs[i]];
        }

        return infos;
    }

    /// @inheritdoc IConsensusRegistry
    function getCommitteeValidators(uint32 epoch) public view returns (ValidatorInfo[] memory) {
        address[] memory committee = getEpochInfo(epoch).committee;
        ValidatorInfo[] memory committeeValidators = new ValidatorInfo[](committee.length);
        for (uint256 i; i < committeeValidators.length; ++i) {
            committeeValidators[i] = getValidator(committee[i]);
        }

        return committeeValidators;
    }

    /// @inheritdoc IConsensusRegistry
    function getBlsPubkey(address validatorAddress) public view returns (bytes memory) {
        bytes memory pubkey = blsPubkeys[validatorAddress];
        if (pubkey.length == 0) revert BlsPubkeyNotFound(validatorAddress);
        return pubkey;
    }

    /// @inheritdoc IConsensusRegistry
    function getCommitteeBlsPubkeys(uint32 epoch) public view returns (bytes[] memory) {
        address[] memory committee = getEpochInfo(epoch).committee;
        bytes[] memory pubkeys = new bytes[](committee.length);
        for (uint256 i; i < pubkeys.length; ++i) {
            pubkeys[i] = blsPubkeys[committee[i]];
        }

        return pubkeys;
    }

    /// @inheritdoc IConsensusRegistry
    function getValidator(address validatorAddress) public view returns (ValidatorInfo memory) {
        ValidatorInfo storage info = validators[validatorAddress];
        // if the queried validator is retired it is confirmed to have existed
        if (!info.isRetired) {
            // else validate input
            _checkConsensusNFTOwner(validatorAddress);
        }

        return info;
    }

    /// @inheritdoc IConsensusRegistry
    function isValidator(bytes calldata blsPubkey) public view returns (bool) {
        // validate bls pubkey format (must be 96 bytes)
        if (blsPubkey.length != 96) return false;

        // get the canonical (x-coordinate) key id and check if this pubkey was ever used
        bytes32 blsPubkeyHash = _blsKeyId(blsPubkey);
        address validatorAddress = blsPubkeyHashToValidator[blsPubkeyHash];

        // if no validator address found, return false
        if (validatorAddress == address(0)) return false;

        // check if validator is retired
        // this also checks if the nft still exists (not burned)
        if (isRetired(validatorAddress)) return false;

        return true;
    }

    /// @inheritdoc IConsensusRegistry
    function isDelegated(address validatorAddress) external view returns (bool) {
        return _isDelegated(validatorAddress);
    }

    /// @inheritdoc IConsensusRegistry
    function isRetired(address validatorAddress) public view returns (bool) {
        if (_exists(_getTokenId(validatorAddress))) {
            // validator exists but has not yet retired
            return false;
        } else if (validators[validatorAddress].currentStatus == ValidatorStatus.Undefined) {
            // validator doesn't exist but never existed in the first place
            return false;
        }

        return validators[validatorAddress].isRetired;
    }

    /// @inheritdoc StakeManager
    function getRewards(address validatorAddress) public view override returns (uint256) {
        uint8 stakeVersion = validators[validatorAddress].stakeVersion;
        uint256 initialStake = versions[stakeVersion].stakeAmount;

        return _getRewards(validatorAddress, initialStake);
    }

    /// @inheritdoc StakeManager
    function getBalanceBreakdown(address validatorAddress) public view override returns (uint256, uint256, uint256) {
        uint8 validatorVersion = validators[validatorAddress].stakeVersion;
        uint256 initialStakeAmount = versions[validatorVersion].stakeAmount;
        uint256 rewards = _getRewards(validatorAddress, initialStakeAmount);
        uint256 outstandingBalance = balances[validatorAddress];

        return (outstandingBalance, initialStakeAmount, rewards);
    }

    /// @inheritdoc IStakeManager
    function delegationDigest(
        bytes memory blsPubkey,
        address validatorAddress,
        address delegator
    )
        external
        view
        override
        returns (bytes32)
    {
        _checkConsensusNFTOwner(validatorAddress);
        // `_blsKeyId` mloads a fixed 96 bytes; guard the length for parity with `isValidator` and
        // `_verifyProofOfPossession` so off-chain integrators get a clean revert on a malformed key
        if (blsPubkey.length != 96) revert InvalidBLSPubkey();
        uint8 stakeVersion = getCurrentEpochInfo().stakeVersion;
        uint64 nonce = delegations[validatorAddress].nonce;
        bytes32 blsPubkeyHash = _blsKeyId(blsPubkey);
        bytes32 structHash =
            keccak256(abi.encode(DELEGATION_TYPEHASH, blsPubkeyHash, validatorAddress, delegator, stakeVersion, nonce));

        return _hashTypedData(structHash);
    }

    /**
     *
     *   validators
     *
     */

    /// @inheritdoc StakeManager
    function stake(
        bytes calldata blsPubkey,
        ProofOfPossession memory proofOfPossession
    )
        external
        payable
        override
        whenNotPaused
    {
        // verify the BLS signature proves caller's ownership of the BLS secret key
        _verifyProofOfPossession(proofOfPossession, msg.sender, blsPubkey);

        // require caller is known & whitelisted, having been issued a ConsensusNFT by governance
        uint8 validatorVersion = getCurrentEpochInfo().stakeVersion;
        uint256 stakeAmt = _checkStakeValue(msg.value, validatorVersion);
        _checkConsensusNFTOwner(msg.sender);
        // require validator has not yet staked
        _checkValidatorStatus(msg.sender, ValidatorStatus.Undefined);

        // enter validator in activation queue
        _recordStaked(blsPubkey, msg.sender, validatorVersion, stakeAmt);
    }

    /// @inheritdoc StakeManager
    function delegateStake(
        bytes calldata blsPubkey,
        ProofOfPossession memory proofOfPossession,
        address validatorAddress,
        bytes calldata validatorEIP712Signature
    )
        external
        payable
        override
        whenNotPaused
    {
        // verify the delegate has obtained validator's BLS signature proving ownership of the BLS secret key
        bytes32 blsPubkeyHash = _verifyProofOfPossession(proofOfPossession, validatorAddress, blsPubkey);

        // require `validatorAddress` is known & whitelisted, having been issued a ConsensusNFT by governance
        uint8 validatorVersion = getCurrentEpochInfo().stakeVersion;
        uint256 stakeAmt = _checkStakeValue(msg.value, validatorVersion);
        _checkConsensusNFTOwner(validatorAddress);

        // require validator status is `Undefined`
        _checkValidatorStatus(validatorAddress, ValidatorStatus.Undefined);
        uint64 nonce = delegations[validatorAddress].nonce;

        // governance may utilize white-glove onboarding or offchain agreements
        if (msg.sender != owner()) {
            bytes32 structHash = keccak256(
                abi.encode(DELEGATION_TYPEHASH, blsPubkeyHash, validatorAddress, msg.sender, validatorVersion, nonce)
            );
            bytes32 digest = _hashTypedData(structHash);
            if (!SignatureCheckerLib.isValidSignatureNowCalldata(validatorAddress, digest, validatorEIP712Signature)) {
                revert NotValidator(validatorAddress);
            }
        }

        delegations[validatorAddress] =
            Delegation(blsPubkeyHash, validatorAddress, msg.sender, validatorVersion, nonce + 1);
        _recordStaked(blsPubkey, validatorAddress, validatorVersion, stakeAmt);
    }

    /// @inheritdoc IConsensusRegistry
    function activate() external override whenNotPaused {
        // require caller is whitelisted, having been issued a ConsensusNFT by governance
        _checkConsensusNFTOwner(msg.sender);

        // require caller status is `Staked`
        _checkValidatorStatus(msg.sender, ValidatorStatus.Staked);

        ValidatorInfo storage validator = validators[msg.sender];
        // begin validator activation, completing automatically next epoch
        _beginActivation(validator, currentEpoch);
    }

    /// @dev Shared access control for stake-originator operations (claim / unstake / version upgrade):
    /// requires `validatorAddress` holds a ConsensusNFT and the caller is the validator or its delegator
    /// (the stake/reward recipient). Returns the recipient so callers route funds without re-deriving it.
    function _checkStakeOriginator(address validatorAddress) private view returns (address recipient) {
        _checkConsensusNFTOwner(validatorAddress);
        recipient = _getRecipient(validatorAddress);
        if (msg.sender != validatorAddress && msg.sender != recipient) revert NotRecipient(recipient);
    }

    /// @inheritdoc StakeManager
    function claimStakeRewards(address validatorAddress) external override whenNotPaused nonReentrant {
        address recipient = _checkStakeOriginator(validatorAddress);
        uint8 validatorVersion = validators[validatorAddress].stakeVersion;
        uint256 rewards = _claimStakeRewards(validatorAddress, recipient, validatorVersion);

        emit RewardsClaimed(recipient, rewards);
    }

    /// @inheritdoc IStakeManager
    function upgradeValidatorStakeVersion(
        address validatorAddress,
        uint8 targetVersion
    )
        external
        payable
        override
        whenNotPaused
        nonReentrant
    {
        // 1. Access control: the validator or its delegator may act
        address recipient = _checkStakeOriginator(validatorAddress);

        // 2. Status check: only Staked, PendingActivation, or Active
        ValidatorInfo storage validator = validators[validatorAddress];
        ValidatorStatus status = validator.currentStatus;
        if (
            status != ValidatorStatus.Staked && status != ValidatorStatus.PendingActivation
                && status != ValidatorStatus.Active
        ) {
            revert InvalidStatus(status);
        }

        // 3. Version validation: must be strictly newer, within bounds
        uint8 oldVersion = validator.stakeVersion;
        if (targetVersion <= oldVersion || targetVersion > stakeVersion) {
            revert InvalidStakeVersion(oldVersion, targetVersion);
        }

        // 4. Compute stake difference
        uint256 oldStakeAmount = versions[oldVersion].stakeAmount;
        uint256 newStakeAmount = versions[targetVersion].stakeAmount;

        // 5. Balance adjustment
        if (newStakeAmount > oldStakeAmount) {
            // Stake increase: caller must send exact deficit
            uint256 deficit = newStakeAmount - oldStakeAmount;
            if (msg.value != deficit) revert InvalidStakeAmount(msg.value);
            balances[validatorAddress] += deficit;
        } else if (newStakeAmount < oldStakeAmount) {
            // Stake decrease: refund surplus to recipient
            if (msg.value != 0) revert InvalidStakeAmount(msg.value);
            uint256 surplus = oldStakeAmount - newStakeAmount;
            uint256 currentBalance = balances[validatorAddress];
            uint256 refundAmount;
            if (currentBalance >= oldStakeAmount) {
                // Not slashed: full surplus refund
                refundAmount = surplus;
            } else if (currentBalance > newStakeAmount) {
                // Partially slashed: partial refund down to newStakeAmount
                refundAmount = currentBalance - newStakeAmount;
            }
            // else: slashed below new stake amount, no refund

            if (refundAmount > 0) {
                balances[validatorAddress] -= refundAmount;
                // Route through Issuance (same pattern as _unstake)
                Issuance(issuance).distributeStakeReward{ value: refundAmount }(recipient, 0);
            }

            // consolidate confiscated slash remainder on Issuance (same as _unstake pattern)
            uint256 confiscatedAmount = surplus - refundAmount;
            if (confiscatedAmount > 0) {
                (bool r,) = issuance.call{ value: confiscatedAmount }("");
                // this is believed to be impossible
                if (!r) revert IssuanceTransferFailed();
            }
        } else {
            // Same stake amount: just a metadata update
            if (msg.value != 0) revert InvalidStakeAmount(msg.value);
        }

        // 6. Update state
        validator.stakeVersion = targetVersion;
        if (_isDelegated(validatorAddress)) {
            delegations[validatorAddress].validatorVersion = targetVersion;
        }

        emit ValidatorStakeVersionUpgraded(validatorAddress, oldVersion, targetVersion, oldStakeAmount, newStakeAmount);
    }

    /// @inheritdoc IConsensusRegistry
    function beginExit() external override whenNotPaused {
        // require caller is whitelisted, having been issued a ConsensusNFT by governance
        _checkConsensusNFTOwner(msg.sender);

        // disallow filling up the exit queue
        uint256 numActive = _eligibleValidatorCount();
        uint256 committeeSize = epochInfo[epochPointer].committee.length;
        _checkCommitteeSize(numActive, committeeSize);

        // require caller status is `Active` and `currentEpoch >= activationEpoch`
        _checkValidatorStatus(msg.sender, ValidatorStatus.Active);
        ValidatorInfo storage validator = validators[msg.sender];
        uint32 current = currentEpoch;
        if (current < validator.activationEpoch) {
            revert InvalidEpoch(current);
        }

        // enter validator in pending exit queue
        _beginExit(validator);
    }

    /// @inheritdoc StakeManager
    function unstake(address validatorAddress) external override whenNotPaused nonReentrant {
        // require validator holds a ConsensusNFT and the caller is the validator or its delegator
        address recipient = _checkStakeOriginator(validatorAddress);

        ValidatorInfo storage validator = validators[validatorAddress];
        // stake originator can only reclaim stake pre-activation or one epoch after exiting
        if (!_eligibleForUnstake(validator)) revert IneligibleUnstake(validator);

        // permanently retire the validator and burn the ConsensusNFT
        _retire(validator);

        // return stake and send any outstanding rewards
        uint256 stakeAndRewards = _unstake(validatorAddress, recipient);

        emit RewardsClaimed(recipient, stakeAndRewards);
    }

    /**
     *
     *   ERC721
     *
     */

    /// @inheritdoc StakeManager
    function mint(address validatorAddress) external override onlyOwner {
        // validators may only possess one token and `validatorAddress` cannot be reused
        if (balanceOf(validatorAddress) != 0 || isRetired(validatorAddress)) {
            revert AlreadyDefined(validatorAddress);
        }

        // issue the ConsensusNFT
        _mint(validatorAddress, _getTokenId(validatorAddress));
    }

    /// @inheritdoc StakeManager
    function burn(address validatorAddress) external override onlyOwner {
        if (isRetired(validatorAddress)) revert InvalidStatus(ValidatorStatus.Any);
        // require validatorAddress is whitelisted, having been issued a ConsensusNFT by governance
        _checkConsensusNFTOwner(validatorAddress);

        if (validators[validatorAddress].currentStatus == ValidatorStatus.Undefined) {
            // immediately remove validators that were whitelisted but never staked (without setting epochs)
            _retire(validators[validatorAddress]);
            _burn(_getTokenId(validatorAddress));
        } else {
            // validators that have staked are exited, retired, and then unstaked
            _consensusBurn(validatorAddress);
        }
    }

    /// @inheritdoc StakeManager
    function allocateIssuance() external payable override onlyOwner {
        (bool r,) = issuance.call{ value: msg.value }("");
        // this is believed to be impossible
        if (!r) revert IssuanceTransferFailed();
    }

    /**
     *
     *   internals
     *
     */

    /// @notice Thrown when the BLS precompile staticcall fails or returns an unexpected payload
    error LowLevelCallFailure(bytes err);

    /// @dev The serialized telcoin proof-of-possession intent prefix (`scope=0, version=0, app=0`),
    /// which domain-separates PoP messages from other BLS signatures. Mirrors
    /// `Intent::telcoin(IntentScope::ProofOfPossession)` in tn-types; the off-chain
    /// `pop_message_layout_is_onchain_constructible` test pins it to `0x000000`.
    bytes3 private constant POP_INTENT_PREFIX = 0x000000;

    /// @notice Builds the proof-of-possession message a validator signs: the 3-byte intent prefix, the
    /// 96-byte compressed `pubkey`, and the 20-byte `validatorAddress`.
    /// @dev Constructed entirely on-chain from the compressed key and the raw address (no
    /// decompression), so it reproduces byte-for-byte the message tn-types signs off-chain in
    /// `construct_proof_of_possession_message`.
    function proofOfPossessionMessage(
        bytes memory pubkey,
        address validatorAddress
    )
        internal
        pure
        returns (bytes memory)
    {
        // Self-contained length gate: `abi.encodePacked` of a dynamic `pubkey` between fixed-size
        // fields is only unambiguous when `pubkey` has a fixed length, so enforce the 96-byte
        // compressed G2 form here rather than relying on every caller to pre-check it.
        if (pubkey.length != 96) revert InvalidBLSPubkey();
        return abi.encodePacked(POP_INTENT_PREFIX, pubkey, validatorAddress);
    }

    /// @param g1Pop The Proof Of Possession generated by a validator
    /// @param validatorAddress The validator's execution address
    /// @param blsPubkey The compressed 96-byte representation of `validatorAddress`s G2 BLS pubkey
    /// @notice This contract does not perform any (un)compression on `blsPubkey` due to EVM constraints
    function _verifyProofOfPossession(
        ProofOfPossession memory g1Pop,
        address validatorAddress,
        bytes memory blsPubkey
    )
        internal
        virtual
        returns (bytes32)
    {
        if (blsPubkey.length != 96) revert InvalidBLSPubkey();

        // The stored consensus key is blst's compressed G2 form: byte 0's top bit (0x80) is the
        // compression flag and the next (0x40) the infinity flag. The x-coordinate binding below masks
        // all three flag bits, so on its own it would accept a key whose x matches the proven key but
        // whose flags are malformed - e.g. the infinity flag set, which off-chain blst decodes to the
        // identity point, or the compression flag cleared, which fails to decode. Either yields a
        // committee member the consensus layer cannot process. Require compression set and infinity
        // clear so the stored key is a well-formed, non-identity point. The sign flag (0x20) is left
        // free: a wrong sign only disables this validator's own signatures, which BFT already tolerates.
        uint8 flags = uint8(blsPubkey[0]);
        if (flags & 0x80 == 0 || flags & 0x40 != 0) revert InvalidBLSPubkey();

        // Build the proof-of-possession message (intent || compressed pubkey || address) and verify
        // the signature over it through the native BLS precompile at `BLS_G1_ADDRESS`. The
        // message binds the exact `blsPubkey` stored below, so the binding is structural and
        // cryptographic - a proof for a different key cannot pass, and no separate x-coordinate
        // alignment check is needed to defeat rogue-key registration.
        bytes memory popMessage = proofOfPossessionMessage(blsPubkey, validatorAddress);
        // Low-level staticcall (not a typed `IBlsG1(...)` call) so Solidity does not emit its
        // EXTCODESIZE guard: the precompile is dispatched by the EVM at `BLS_G1_ADDRESS` and need not
        // carry on-chain bytecode. This mirrors the protocol's precompile-call convention (see also
        // `StablecoinManager`). A failed call or any non-32-byte return reverts, so an absent
        // precompile cannot decode as `false` and silently pass an unverified signature.
        (bool ok, bytes memory result) = BLS_G1_ADDRESS.staticcall(
            abi.encodeWithSelector(IBlsG1.blsVerify.selector, g1Pop.signature, blsPubkey, popMessage)
        );
        if (!ok || result.length != 32) revert LowLevelCallFailure(result);
        if (!abi.decode(result, (bool))) revert InvalidProofOfPossession(g1Pop);

        // prevent duplicate compressed pubkeys
        return _spendBLSPubkey(blsPubkey, validatorAddress);
    }

    /// @notice Spends `blsPubkey`. Must be an externally validated G2 point in 96-byte compressed form
    function _spendBLSPubkey(bytes memory blsPubkey, address validatorAddress) private returns (bytes32 blsPubkeyHash) {
        blsPubkeyHash = _blsKeyId(blsPubkey);
        if (blsPubkeyHashToValidator[blsPubkeyHash] != address(0)) revert DuplicateBLSPubkey();
        blsPubkeyHashToValidator[blsPubkeyHash] = validatorAddress;

        return blsPubkeyHash;
    }

    /// @notice Canonical identifier for a 96-byte compressed BLS G2 key: the keccak of its x-coordinate.
    /// @dev blst's compressed form is `x.c1 || x.c0` with 3 flag bits (compression/infinity/sign) in the
    /// top bits of byte 0. Keying deduplication on the x-coordinate (flag bits cleared) collapses a key and
    /// its y-sign negation - which share an x - into one id, enforcing one keypair per validator set. Two
    /// distinct valid G2 points share an x only if they are negations of each other, so honest distinct
    /// validators never collide. Caller must pass a 96-byte key (enforced upstream).
    function _blsKeyId(bytes memory compressed) internal pure returns (bytes32 id) {
        assembly {
            let ptr := add(compressed, 0x20)
            // hash the 96-byte x with the 3 flag bits cleared in the most-significant byte of word 0
            let scratch := mload(0x40)
            mstore(scratch, and(mload(ptr), 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))
            mstore(add(scratch, 0x20), mload(add(ptr, 0x20)))
            mstore(add(scratch, 0x40), mload(add(ptr, 0x40)))
            id := keccak256(scratch, 0x60)
        }
    }

    /// @notice Enters a validator into the activation queue upon receiving stake
    /// @dev Stores the new validator in the `validators` vector
    function _recordStaked(
        bytes calldata blsPubkey,
        address validatorAddress,
        uint8 stakeVersion,
        uint256 stakeAmt
    )
        internal
    {
        // record the validator as `Undefined`, then transition to `Staked` through `_setStatus` so the
        // `Staked` set add happens in the one place that maintains membership (the address is already set)
        validators[validatorAddress] = ValidatorInfo(
            validatorAddress, PENDING_EPOCH, uint32(0), ValidatorStatus.Undefined, false, stakeVersion, uint8(0)
        );
        ValidatorInfo storage newValidator = validators[validatorAddress];
        _setStatus(newValidator, ValidatorStatus.Staked);
        blsPubkeys[validatorAddress] = blsPubkey;
        balances[validatorAddress] = stakeAmt;

        emit ValidatorStaked(newValidator);
    }

    /// @dev Sets the next epoch as activation timestamp for epoch completeness wrt incentives
    function _beginActivation(ValidatorInfo storage validator, uint32 epoch) internal {
        validator.activationEpoch = epoch + 1;
        _setStatus(validator, ValidatorStatus.PendingActivation);

        emit ValidatorPendingActivation(validator);
    }

    /// @dev Activates a validator
    /// @dev Performed by protocol system call at commencement of validator's first full epoch
    function _activate(ValidatorInfo storage validator) internal {
        _setStatus(validator, ValidatorStatus.Active);

        emit ValidatorActivated(validator);
    }

    /// @notice Enters a validator into the exit queue
    /// @dev Finalized by the protocol when the validator is no longer required for committees
    function _beginExit(ValidatorInfo storage validator) internal {
        _setStatus(validator, ValidatorStatus.PendingExit);
        validator.exitEpoch = PENDING_EPOCH;

        emit ValidatorPendingExit(validator);
    }

    /// @notice Exits a validator from the network,
    /// @dev Only invoked via protocol client system call to `concludeEpoch()` or governance ejection
    /// @dev Once exited, the validator may unstake to reclaim their stake and rewards
    function _exit(ValidatorInfo storage validator, uint32 epoch) internal {
        _setStatus(validator, ValidatorStatus.Exited);
        validator.exitEpoch = epoch;

        emit ValidatorExited(validator);
    }

    /// @notice Permanently retires validator from the network
    /// @dev Ensures an validator cannot rejoin after exiting + unstaking or after governance ejection
    /// @dev Rejoining must be done by restarting validator onboarding process with new keys and tokenId
    function _retire(ValidatorInfo storage validator) internal {
        // `Any` has no set, so this just removes the validator from its current set (e.g. a governance
        // burn of an active validator, or the normal Exited -> retired flow)
        _setStatus(validator, ValidatorStatus.Any);
        validator.isRetired = true;

        emit ValidatorRetired(validator);
    }

    /// @dev The single point that mutates per-status set membership and the cached eligible count. Removes
    /// the validator from its old status set and adds it to the new one, keeping the sets in lockstep with
    /// `currentStatus`. `Undefined` and `Any` carry no set (the latter is the retired sentinel), so they are
    /// skipped on add; `remove` is a safe no-op when the validator was not a member. The committee-eligible
    /// count is adjusted by the change in eligibility across the transition. The address must already be set.
    function _setStatus(ValidatorInfo storage validator, ValidatorStatus newStatus) private {
        address addr = validator.validatorAddress;
        ValidatorStatus oldStatus = validator.currentStatus;

        validatorSets[uint8(oldStatus)].remove(addr);
        if (newStatus != ValidatorStatus.Undefined && newStatus != ValidatorStatus.Any) {
            validatorSets[uint8(newStatus)].add(addr);
        }

        bool wasEligible = _eligibleForCommitteeNextEpoch(oldStatus);
        bool nowEligible = _eligibleForCommitteeNextEpoch(newStatus);
        if (wasEligible && !nowEligible) {
            --eligibleValidatorCount;
        } else if (!wasEligible && nowEligible) {
            ++eligibleValidatorCount;
        }

        validator.currentStatus = newStatus;
    }

    /// @notice Performs activation and/or exit for validators pending in queue where applicable
    /// @dev Validators initiate activation, gaining `PendingActivation` status which resolves to
    /// `Active` at the end of the current epoch. Since they could time activation initiation
    /// with the epoch boundary, they are ineligible for rewards until completing a full epoch
    /// @dev Protocol determines exit eligibility via voter committee assignments across 3 epochs
    function _updateValidatorQueue(address[] calldata futureCommittee, uint32 current) internal {
        // snapshot to memory first: `_activate`/`_exit` mutate the live sets as we iterate
        address[] memory pendingActivation = _getValidators(ValidatorStatus.PendingActivation);
        for (uint256 i; i < pendingActivation.length; ++i) {
            ValidatorInfo storage activateValidator = validators[pendingActivation[i]];

            _activate(activateValidator);
        }

        address[] memory pendingExit = _getValidators(ValidatorStatus.PendingExit);
        uint8 currentEpochPointer = epochPointer;
        uint8 nextEpochPointer = (currentEpochPointer + 1) % 4;
        // Mark everyone serving on the current, next, or subsequent committee into a transient (EIP-1153)
        // set keyed to this epoch, then test each pending-exit validator in O(1) rather than rescanning
        // three committees (up to 100 each) per validator. The transient slots auto-clear at end of tx.
        bytes32 committeeSet = keccak256(abi.encodePacked(_COMMITTEE_TSET, current));
        _markCommitteeMembers(epochInfo[currentEpochPointer].committee, committeeSet);
        _markCommitteeMembers(futureEpochInfo[nextEpochPointer].committee, committeeSet);
        _markCommitteeMembers(futureCommittee, committeeSet);
        for (uint256 i; i < pendingExit.length; ++i) {
            address validatorAddress = pendingExit[i];
            // the protocol exits a queued validator by excluding it from all upcoming committees
            if (_isCommitteeMember(validatorAddress, committeeSet)) continue;
            _exit(validators[validatorAddress], current);
        }
    }

    /// @notice Forcibly eject a validator from the current, next, and subsequent committees
    /// @dev Intended for sparing use; only reverts if burning results in empty committee
    function _ejectFromCommittees(address validatorAddress, uint256 numEligible) internal {
        uint32 current = currentEpoch;
        uint8 currentEpochPointer = epochPointer;
        address[] storage currentCommittee = _getRecentEpochInfo(current, current, currentEpochPointer).committee;
        _eject(currentCommittee, validatorAddress);
        uint256 committeeSize = currentCommittee.length;
        _checkCommitteeSize(numEligible, committeeSize);

        uint32 nextEpoch = current + 1;
        address[] storage nextCommittee = _getFutureEpochInfo(nextEpoch, current, currentEpochPointer).committee;
        _eject(nextCommittee, validatorAddress);
        committeeSize = nextCommittee.length;
        _checkCommitteeSize(numEligible, committeeSize);

        uint32 subsequentEpoch = current + 2;
        address[] storage subsequentCommittee =
        _getFutureEpochInfo(subsequentEpoch, current, currentEpochPointer).committee;
        _eject(subsequentCommittee, validatorAddress);
        committeeSize = subsequentCommittee.length;
        _checkCommitteeSize(numEligible, committeeSize);

        // only decrement the nextCommitteeSize if the number of eligible validators drops below
        if (nextCommitteeSize > numEligible) {
            uint16 oldSize = nextCommitteeSize;
            nextCommitteeSize = uint16(numEligible);
            emit NextCommitteeSizeUpdated(oldSize, nextCommitteeSize, numEligible);
        }
    }

    function _eject(address[] storage committee, address validatorAddress) internal returns (bool) {
        uint256 len = committee.length;
        for (uint256 i; i < len; ++i) {
            if (committee[i] == validatorAddress) {
                committee[i] = committee[len - 1];
                committee.pop();

                return true;
            }
        }
        return false;
    }

    /// @dev Invoked either as part of a governance-initiated burn or a validator's final slash to 0
    /// @notice Burns or final slashes confiscate the validator's remaining stake held by this contract
    /// by sending it to the Issuance contract to be repurposed for future reward distribution
    function _consensusBurn(address validatorAddress) internal {
        ValidatorInfo storage validator = validators[validatorAddress];
        ValidatorStatus status = validator.currentStatus;
        // reverts if decremented committee size after ejection reaches 0, preventing network halt
        uint256 numEligible = _eligibleValidatorCount();
        // if validator being ejected is committee-eligible, ejection will decrement `numEligible`
        if (_eligibleForCommitteeNextEpoch(status)) {
            numEligible = numEligible - 1;
        }
        _ejectFromCommittees(validatorAddress, numEligible);

        // settle ledgers
        (uint256 outstandingBalance, uint256 initialStakeAmt,) = getBalanceBreakdown(validatorAddress);
        // rewards are already held on Issuance contract, so wiping registry's balance ledger effectively confiscates
        // them
        balances[validatorAddress] = 0;
        // confiscate outstanding stake balance by consolidating it on the Issuance contract
        uint256 confiscatedStake = outstandingBalance < initialStakeAmt ? outstandingBalance : initialStakeAmt;
        (bool r,) = issuance.call{ value: confiscatedStake }("");
        // this is believed to be impossible
        if (!r) revert IssuanceTransferFailed();

        // exit, retire, and unstake + burn validator immediately
        _exit(validator, currentEpoch);
        _retire(validator);
        address recipient = _getRecipient(validatorAddress);
        _unstake(validatorAddress, recipient);
    }

    /// @dev Stores the number of blocks finalized in previous epoch and the voter committee for the new epoch
    function _updateEpochInfo(address[] memory futureCommittee)
        internal
        returns (uint32, uint256, uint32, address[] memory)
    {
        // cache epoch ring buffer's pointers in memory
        uint8 prevEpochPointer = epochPointer;
        uint8 newEpochPointer = (prevEpochPointer + 1) % 4;

        // update new current epoch info
        epochPointer = newEpochPointer;
        uint32 newEpoch = ++currentEpoch;
        address[] storage newCommittee = futureEpochInfo[newEpochPointer].committee;
        StakeConfig memory newStakeConfig = getCurrentStakeConfig();
        epochInfo[newEpochPointer] = EpochInfo(
            newCommittee,
            newStakeConfig.epochIssuance,
            uint64(block.number) + 1,
            newEpoch,
            newStakeConfig.epochDuration,
            stakeVersion
        );

        // update future epoch info
        uint8 twoEpochsInFuturePointer = (newEpochPointer + 2) % 4;
        futureEpochInfo[twoEpochsInFuturePointer].committee = futureCommittee;
        futureEpochInfo[twoEpochsInFuturePointer].epochId = newEpoch + 2;

        return (newEpoch, newStakeConfig.epochIssuance, newStakeConfig.epochDuration, newCommittee);
    }

    /// @dev Fetch info for a future epoch; two epochs into future are stored
    /// @notice Block height is not known for future epochs, so it will be 0
    function _getFutureEpochInfo(
        uint32 future,
        uint32 current,
        uint8 currentPointer
    )
        internal
        view
        returns (EpochInfo storage)
    {
        uint8 futurePointer = (uint8(future - current) + currentPointer) % 4;
        EpochInfo storage info = futureEpochInfo[futurePointer];
        if (info.epochId != future) revert InvalidEpoch(future);

        return info;
    }

    /// @dev Fetch info for a current or past epoch; four latest are stored (current and three in past)
    function _getRecentEpochInfo(
        uint32 recent,
        uint32 current,
        uint8 currentPointer
    )
        internal
        view
        returns (EpochInfo storage)
    {
        // identify diff from pointer
        uint8 pointerDiff = uint8(current - recent);
        // prevent underflow by adding 4 (will be modulo'd away)
        uint8 pointer = (4 + currentPointer - pointerDiff) % 4;

        EpochInfo storage info = epochInfo[pointer];
        if (info.epochId != recent) revert InvalidEpoch(recent);

        return info;
    }

    function _enforceSorting(address[] calldata futureCommittee) internal pure {
        // iterate from index 1 comparing each element to its predecessor; this avoids the `length - 1`
        // underflow on an empty committee (which `concludeEpoch`'s length check then rejects cleanly)
        for (uint256 i = 1; i < futureCommittee.length; ++i) {
            if (futureCommittee[i - 1] >= futureCommittee[i]) revert CommitteeRequirement(futureCommittee[i - 1]);
        }
    }

    /// @dev Checks current committee size against total eligible for committee service in next epoch
    /// @notice Prevents the network from reaching invalid committee state
    function _checkCommitteeSize(uint256 activeOrPending, uint256 committeeSize) internal pure {
        if (activeOrPending == 0 || committeeSize == 0 || committeeSize > activeOrPending) {
            revert InvalidCommitteeSize(activeOrPending, committeeSize);
        }
    }

    /// @dev Reverts if the provided validator's status doesn't match the provided `requiredStatus`
    function _checkValidatorStatus(address validatorAddress, ValidatorStatus requiredStatus) private view {
        ValidatorStatus status = validators[validatorAddress].currentStatus;
        if (status != requiredStatus) revert InvalidStatus(status);
    }

    /// @dev Marks each address in `committee` into the transient (EIP-1153) `committeeSet` for O(1)
    /// membership tests in `_updateValidatorQueue`. `committeeSet` is keyed to the concluding epoch, so
    /// distinct epochs never collide, and transient slots auto-clear at end of transaction. Uses
    /// OpenZeppelin's audited SlotDerivation + TransientSlot rather than raw assembly; solc cannot
    /// express this natively because the `transient` keyword only supports value types, not mappings.
    function _markCommitteeMembers(address[] memory committee, bytes32 committeeSet) private {
        for (uint256 i; i < committee.length; ++i) {
            committeeSet.deriveMapping(committee[i]).asBoolean().tstore(true);
        }
    }

    /// @dev True if `validatorAddress` was marked into the transient `committeeSet`.
    function _isCommitteeMember(address validatorAddress, bytes32 committeeSet) private view returns (bool) {
        return committeeSet.deriveMapping(validatorAddress).asBoolean().tload();
    }

    /// @dev Active and pending activation/exit validators are eligible for committee service in next epoch
    function _eligibleForCommitteeNextEpoch(ValidatorStatus status) internal pure returns (bool) {
        return (status == ValidatorStatus.Active || status == ValidatorStatus.PendingExit
                || status == ValidatorStatus.PendingActivation);
    }

    /// @dev Returns true for `Staked` or `Exited` validators that have elapsed one full epoch since exit
    function _eligibleForUnstake(ValidatorInfo storage validator) internal view returns (bool) {
        ValidatorStatus status = validator.currentStatus;
        if (status == ValidatorStatus.Staked) return true;

        uint32 eligibleEpoch = validator.exitEpoch + 1;
        if (status == ValidatorStatus.Exited && currentEpoch >= eligibleEpoch) {
            return true;
        }

        return false;
    }

    /// @notice Returns the validators in `status`'s set, in the set's current (deterministic) order.
    /// @dev Per-status only: unlike the former scan, an `Active` query no longer folds in pending
    /// activation/exit. The protocol reconstructs the committee-eligible pool by unioning the
    /// `{ PendingActivation, Active, PendingExit }` queries off-chain.
    function _getValidators(ValidatorStatus status) internal view returns (address[] memory) {
        return validatorSets[uint8(status)].values();
    }

    /// @dev Status queries are defined only for statuses that maintain a set. `Undefined` and `Any`
    /// have no members (`Any` is the retired sentinel), so they revert rather than return an empty array.
    function _checkQueryableStatus(ValidatorStatus status) internal pure {
        if (status == ValidatorStatus.Undefined || status == ValidatorStatus.Any) {
            revert InvalidStatus(status);
        }
    }

    /**
     *
     *   pausability
     *
     */

    /// @dev Emergency function to pause validator and stake management
    /// @notice Does not pause system callable or ConsensusNFT fns. Only accessible by `owner`
    function pause() external onlyOwner {
        _pause();
    }

    /// @dev Emergency function to unpause validator and stake management
    /// @notice Does not affect system callable or ConsensusNFT fns. Only accessible by `owner`
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     *
     *   configuration
     *
     */

    /// @param initialValidators_ The initial validator set running Telcoin Network; these validators will
    /// comprise the voter committee for the first three epochs, ie `epochInfo[0:2]`
    /// @dev Stake for `initialValidators_` is allocated directly to the ConsensusRegistry balance and
    /// decremented directly from the TEL precompile within the protocol on the rust side
    /// @dev Only governance delegation is enabled at genesis
    constructor(
        StakeConfig memory genesisConfig_,
        ValidatorInfo[] memory initialValidators_,
        bytes[] memory blsPubkeys_,
        ProofOfPossession[] memory proofsOfPossession,
        address owner_
    )
        Ownable(owner_)
        StakeManager("ConsensusNFT", "CNFT")
    {
        if (
            initialValidators_.length == 0 || initialValidators_.length != blsPubkeys_.length
                || initialValidators_.length != proofsOfPossession.length
        ) {
            revert GenesisArityMismatch();
        }

        // set stake storage configs
        versions[0] = genesisConfig_;

        // set nextCommitteeSize based on current committee
        // NOTE: committees are expected to always be < 100
        nextCommitteeSize = uint16(initialValidators_.length);

        // set first three epochs with genesis config
        for (uint256 j; j <= 2; ++j) {
            EpochInfo storage epoch = epochInfo[j];
            epoch.epochId = uint32(j);
            epoch.epochDuration = genesisConfig_.epochDuration;
            epoch.epochIssuance = genesisConfig_.epochIssuance;

            EpochInfo storage futureEpoch = futureEpochInfo[j];
            futureEpoch.epochId = uint32(j);
            futureEpoch.epochDuration = genesisConfig_.epochDuration;
            futureEpoch.epochIssuance = genesisConfig_.epochIssuance;
        }

        // set initial validators
        for (uint256 i; i < initialValidators_.length; ++i) {
            ValidatorInfo memory currentValidator = initialValidators_[i];
            bytes32 blsPubkeyHash =
                _verifyProofOfPossession(proofsOfPossession[i], currentValidator.validatorAddress, blsPubkeys_[i]);

            // assert `validatorIndex` struct members match expected value
            if (currentValidator.validatorAddress == address(0x0)) {
                revert InvalidValidatorAddress();
            }
            if (currentValidator.activationEpoch != uint32(0)) {
                revert InvalidEpoch(currentValidator.activationEpoch);
            }
            if (currentValidator.exitEpoch != uint32(0)) {
                revert InvalidEpoch(currentValidator.exitEpoch);
            }
            if (currentValidator.currentStatus != ValidatorStatus.Active) {
                revert InvalidStatus(currentValidator.currentStatus);
            }
            if (currentValidator.isRetired != false) {
                revert InvalidStatus(ValidatorStatus.Exited);
            }
            if (currentValidator.stakeVersion != 0) {
                revert InvalidStakeAmount(currentValidator.stakeVersion);
            }

            // first three epochs use initial validators as committee
            for (uint256 j; j <= 2; ++j) {
                epochInfo[j].committee.push(currentValidator.validatorAddress);
                futureEpochInfo[j].committee.push(currentValidator.validatorAddress);
            }

            blsPubkeys[currentValidator.validatorAddress] = blsPubkeys_[i];
            validators[currentValidator.validatorAddress] = currentValidator;
            // seed the `Active` set (every genesis validator is Active, hence committee-eligible)
            validatorSets[uint8(ValidatorStatus.Active)].add(currentValidator.validatorAddress);
            balances[currentValidator.validatorAddress] = genesisConfig_.stakeAmount;
            blsPubkeyHashToValidator[blsPubkeyHash] = currentValidator.validatorAddress;
            _mint(currentValidator.validatorAddress, _getTokenId(currentValidator.validatorAddress));

            emit ValidatorActivated(currentValidator);
        }

        // every genesis validator is Active, hence committee-eligible
        eligibleValidatorCount = initialValidators_.length;
    }

    /// @inheritdoc IStakeManager
    function upgradeStakeVersion(StakeConfig calldata newConfig)
        external
        override
        onlyOwner
        whenNotPaused
        returns (uint8)
    {
        if (newConfig.epochDuration == 0) revert InvalidDuration(newConfig.epochDuration);

        uint8 newVersion = ++stakeVersion;
        versions[newVersion] = newConfig;

        return newVersion;
    }
}
