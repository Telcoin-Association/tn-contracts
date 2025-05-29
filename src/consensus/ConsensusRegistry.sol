// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { ReentrancyGuard } from "solady/utils/ReentrancyGuard.sol";
import { RewardInfo, Slash, IStakeManager } from "../interfaces/IStakeManager.sol";
import { StakeManager } from "./StakeManager.sol";
import { IConsensusRegistry } from "../interfaces/IConsensusRegistry.sol";
import { SystemCallable } from "./SystemCallable.sol";
import { Issuance } from "./Issuance.sol";

/**
 * @title ConsensusRegistry
 * @author Telcoin Association
 * @notice A Telcoin Contract
 *
 * @notice This contract manages consensus validator external keys, staking, and committees
 * @dev This contract should be deployed to a predefined system address for use with system calls
 */
contract ConsensusRegistry is StakeManager, Pausable, Ownable, ReentrancyGuard, SystemCallable, IConsensusRegistry {
    uint32 internal currentEpoch;
    uint8 internal epochPointer;
    EpochInfo[4] public epochInfo;
    EpochInfo[4] public futureEpochInfo;
    mapping(address => ValidatorInfo) public validators;
    mapping(bytes32 => bool) private usedBLSPubkeys;

    /// @dev Signals a validator's pending status until activation/exit to correctly apply incentives
    uint32 internal constant PENDING_EPOCH = type(uint32).max;

    /**
     *
     *   consensus
     *
     */

    /// @inheritdoc IConsensusRegistry
    function concludeEpoch(address[] calldata futureCommittee) external override onlySystemCall {
        // ensure future committee is sorted
        _enforceSorting(futureCommittee);

        // update epoch ring buffer info, validator queue
        (uint32 newEpoch, uint256 issuance, uint32 duration, address[] memory newCommittee) =
            _updateEpochInfo(futureCommittee);
        _updateValidatorQueue(futureCommittee, newEpoch);

        // assert future epoch committee is valid against total now eligible
        ValidatorInfo[] memory newActive = _getValidators(ValidatorStatus.Active);
        _checkCommitteeSize(newActive.length, futureCommittee.length);

        emit NewEpoch(EpochInfo(newCommittee, issuance, uint64(block.number + 1), duration, stakeVersion));
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

        // derive and apply validator's weighted share of epoch issuance
        uint256 epochIssuance = getCurrentEpochInfo().epochIssuance;
        for (uint256 i; i < rewardInfos.length; ++i) {
            // will be 0 if `epochIssuance` is too small or `totalWeight` too large (many validators and/or headers)
            uint256 rewardAmount = (epochIssuance * weights[i]) / totalWeight;
            balances[rewardInfos[i].validatorAddress] += rewardAmount;
        }
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
    function getValidators(ValidatorStatus status) public view returns (ValidatorInfo[] memory) {
        if (status == ValidatorStatus.Undefined) revert InvalidStatus(status);

        return _getValidators(status);
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
    function getValidator(address validatorAddress) public view returns (ValidatorInfo memory) {
        _checkConsensusNFTOwner(validatorAddress);

        return validators[validatorAddress];
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
        uint8 stakeVersion = getCurrentEpochInfo().stakeVersion;
        uint64 nonce = delegations[validatorAddress].nonce;
        bytes32 blsPubkeyHash = keccak256(blsPubkey);
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
    function stake(bytes calldata blsPubkey) external payable override whenNotPaused {
        if (blsPubkey.length != 96) revert InvalidBLSPubkey();

        // require caller is known & whitelisted, having been issued a ConsensusNFT by governance
        uint8 validatorVersion = getCurrentEpochInfo().stakeVersion;
        uint256 stakeAmt = _checkStakeValue(msg.value, validatorVersion);
        _checkConsensusNFTOwner(msg.sender);
        // require validator has not yet staked
        _checkValidatorStatus(msg.sender, ValidatorStatus.Undefined);

        // enter validator in activation queue
        _recordStaked(blsPubkey, msg.sender, false, validatorVersion, stakeAmt);
    }

    /// @inheritdoc StakeManager
    function delegateStake(
        bytes calldata blsPubkey,
        address validatorAddress,
        bytes calldata validatorSig
    )
        external
        payable
        override
        whenNotPaused
    {
        if (blsPubkey.length != 96) revert InvalidBLSPubkey();

        // require caller is known & whitelisted, having been issued a ConsensusNFT by governance
        uint8 validatorVersion = getCurrentEpochInfo().stakeVersion;
        uint256 stakeAmt = _checkStakeValue(msg.value, validatorVersion);
        _checkConsensusNFTOwner(validatorAddress);

        // require validator status is `Undefined`
        _checkValidatorStatus(validatorAddress, ValidatorStatus.Undefined);
        uint64 nonce = delegations[validatorAddress].nonce;
        bytes32 blsPubkeyHash = keccak256(blsPubkey);

        // governance may utilize white-glove onboarding or offchain agreements
        if (msg.sender != owner()) {
            bytes32 structHash = keccak256(
                abi.encode(DELEGATION_TYPEHASH, blsPubkeyHash, validatorAddress, msg.sender, validatorVersion, nonce)
            );
            bytes32 digest = _hashTypedData(structHash);
            if (!SignatureCheckerLib.isValidSignatureNowCalldata(validatorAddress, digest, validatorSig)) {
                revert NotValidator(validatorAddress);
            }
        }

        delegations[validatorAddress] =
            Delegation(blsPubkeyHash, msg.sender, validatorAddress, validatorVersion, nonce + 1);
        _recordStaked(blsPubkey, validatorAddress, true, validatorVersion, stakeAmt);
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

    /// @inheritdoc StakeManager
    function claimStakeRewards(address validatorAddress) external override whenNotPaused nonReentrant {
        // require validator is whitelisted, having been issued a ConsensusNFT by governance
        _checkConsensusNFTOwner(validatorAddress);
        uint8 validatorVersion = validators[validatorAddress].stakeVersion;

        // require caller is either the validator or its delegator
        address recipient = _getRecipient(validatorAddress);
        if (msg.sender != validatorAddress && msg.sender != recipient) revert NotRecipient(recipient);
        uint256 rewards = _claimStakeRewards(validatorAddress, recipient, validatorVersion);

        emit RewardsClaimed(recipient, rewards);
    }

    /// @inheritdoc IConsensusRegistry
    function beginExit() external override whenNotPaused {
        // require caller is whitelisted, having been issued a ConsensusNFT by governance
        _checkConsensusNFTOwner(msg.sender);

        // disallow filling up the exit queue
        uint256 numActive = _getValidators(ValidatorStatus.Active).length;
        uint256 committeeSize = epochInfo[epochPointer].committee.length;
        _checkCommitteeSize(numActive, committeeSize);

        // require caller status is `Active` and `currentEpoch >= activationEpoch`
        _checkValidatorStatus(msg.sender, ValidatorStatus.Active);
        ValidatorInfo storage validator = validators[msg.sender];
        uint32 current = currentEpoch;
        if (current < validators[msg.sender].activationEpoch) {
            revert InvalidEpoch(current);
        }

        // enter validator in pending exit queue
        _beginExit(validator);
    }

    /// @inheritdoc StakeManager
    function unstake(address validatorAddress) external override whenNotPaused nonReentrant {
        // require validator is whitelisted, having been issued a ConsensusNFT by governance
        _checkConsensusNFTOwner(validatorAddress);

        // require caller is either the validator or its delegator
        address recipient = _getRecipient(validatorAddress);
        if (msg.sender != validatorAddress && msg.sender != recipient) revert NotRecipient(recipient);

        // stake originator can only reclaim stake pre-activation or after exiting
        ValidatorStatus status = validators[validatorAddress].currentStatus;
        if (status != ValidatorStatus.Staked && status != ValidatorStatus.Exited) revert InvalidStatus(status);

        // permanently retire the validator and burn the ConsensusNFT
        ValidatorInfo storage validator = validators[validatorAddress];
        _retire(validator);

        // return stake and send any outstanding rewards
        uint256 stakeAndRewards = _unstake(validatorAddress, recipient, validator.stakeVersion);

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

        _consensusBurn(validatorAddress);
    }

    /// @inheritdoc StakeManager
    function allocateIssuance() external payable override onlyOwner {
        (bool r,) = issuance.call{ value: msg.value }("");
        require(r, "Impossible condition");
    }

    /**
     *
     *   internals
     *
     */

    /// @notice Enters a validator into the activation queue upon receiving stake
    /// @dev Stores the new validator in the `validators` vector
    function _recordStaked(
        bytes calldata blsPubkey,
        address validatorAddress,
        bool isDelegated,
        uint8 stakeVersion,
        uint256 stakeAmt
    )
        internal
    {
        bytes32 blsPubkeyHash = keccak256(blsPubkey);
        if (usedBLSPubkeys[blsPubkeyHash]) revert DuplicateBLSPubkey();
        usedBLSPubkeys[blsPubkeyHash] = true;

        ValidatorInfo memory newValidator = ValidatorInfo(
            blsPubkey,
            validatorAddress,
            PENDING_EPOCH,
            uint32(0),
            ValidatorStatus.Staked,
            false,
            isDelegated,
            stakeVersion
        );
        validators[validatorAddress] = newValidator;
        balances[validatorAddress] = stakeAmt;

        emit ValidatorStaked(newValidator);
    }

    /// @dev Sets the next epoch as activation timestamp for epoch completeness wrt incentives
    function _beginActivation(ValidatorInfo storage validator, uint32 epoch) internal {
        validator.activationEpoch = epoch + 1;
        validator.currentStatus = ValidatorStatus.PendingActivation;

        emit ValidatorPendingActivation(validator);
    }

    /// @dev Activates a validator
    /// @dev Performed by protocol system call at commencement of validator's first full epoch
    function _activate(ValidatorInfo storage validator) internal {
        validator.currentStatus = ValidatorStatus.Active;

        emit ValidatorActivated(validator);
    }

    /// @notice Enters a validator into the exit queue
    /// @dev Finalized by the protocol when the validator is no longer required for committees
    function _beginExit(ValidatorInfo storage validator) internal {
        validator.currentStatus = ValidatorStatus.PendingExit;
        validator.exitEpoch = PENDING_EPOCH;

        emit ValidatorPendingExit(validator);
    }

    /// @notice Exits a validator from the network,
    /// @dev Only invoked via protocol client system call to `concludeEpoch()` or governance ejection
    /// @dev Once exited, the validator may unstake to reclaim their stake and rewards
    function _exit(ValidatorInfo storage validator, uint32 epoch) internal {
        validator.currentStatus = ValidatorStatus.Exited;
        validator.exitEpoch = epoch;

        emit ValidatorExited(validator);
    }

    /// @notice Permanently retires validator from the network
    /// @dev Ensures an validator cannot rejoin after exiting + unstaking or after governance ejection
    /// @dev Rejoining must be done by restarting validator onboarding process with new keys and tokenId
    function _retire(ValidatorInfo storage validator) internal {
        validator.currentStatus = ValidatorStatus.Any;
        validator.isRetired = true;

        emit ValidatorRetired(validator);
    }

    /// @notice Performs activation and/or exit for validators pending in queue where applicable
    /// @dev Validators initiate activation, gaining `PendingActivation` status which resolves to
    /// `Active` at the end of the current epoch. Since they could time activation initiation
    /// with the epoch boundary, they are ineligible for rewards until completing a full epoch
    /// @dev Protocol determines exit eligibility via voter committee assignments across 3 epochs
    function _updateValidatorQueue(address[] calldata futureCommittee, uint32 current) internal {
        ValidatorInfo[] memory pendingActivation = _getValidators(ValidatorStatus.PendingActivation);
        for (uint256 i; i < pendingActivation.length; ++i) {
            ValidatorInfo storage activateValidator = validators[pendingActivation[i].validatorAddress];

            _activate(activateValidator);
        }

        ValidatorInfo[] memory pendingExit = _getValidators(ValidatorStatus.PendingExit);
        uint8 currentEpochPointer = epochPointer;
        uint8 nextEpochPointer = (currentEpochPointer + 1) % 4;
        address[] memory currentCommittee = epochInfo[currentEpochPointer].committee;
        address[] memory nextCommittee = futureEpochInfo[nextEpochPointer].committee;
        for (uint256 i; i < pendingExit.length; ++i) {
            // skip if validator is in current or either future committee
            address validatorAddress = pendingExit[i].validatorAddress;
            if (
                _isCommitteeMember(validatorAddress, currentCommittee)
                    || _isCommitteeMember(validatorAddress, nextCommittee)
                    || _isCommitteeMember(validatorAddress, futureCommittee)
            ) continue;

            ValidatorInfo storage exitValidator = validators[validatorAddress];
            _exit(exitValidator, current);
        }
    }

    /// @notice Forcibly eject a validator from the current, next, and subsequent committees
    /// @dev Intended for sparing use; only reverts if burning results in empty committee
    function _ejectFromCommittees(address validatorAddress, uint256 numEligible) internal {
        uint32 current = currentEpoch;
        uint8 currentEpochPointer = epochPointer;
        address[] storage currentCommittee = _getRecentEpochInfo(current, current, currentEpochPointer).committee;
        bool ejected = _eject(currentCommittee, validatorAddress);
        uint256 committeeSize = ejected ? currentCommittee.length - 1 : currentCommittee.length;
        _checkCommitteeSize(numEligible, committeeSize);

        uint32 nextEpoch = current + 1;
        address[] storage nextCommittee = _getFutureEpochInfo(nextEpoch, current, currentEpochPointer).committee;
        ejected = _eject(nextCommittee, validatorAddress);
        committeeSize = ejected ? nextCommittee.length - 1 : nextCommittee.length;
        _checkCommitteeSize(numEligible, committeeSize);

        uint32 subsequentEpoch = current + 2;
        address[] storage subsequentCommittee =
            _getFutureEpochInfo(subsequentEpoch, current, currentEpochPointer).committee;
        ejected = _eject(subsequentCommittee, validatorAddress);
        committeeSize = ejected ? subsequentCommittee.length - 1 : subsequentCommittee.length;
        _checkCommitteeSize(numEligible, committeeSize);
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

    function _consensusBurn(address validatorAddress) internal {
        balances[validatorAddress] = 0;

        ValidatorInfo storage validator = validators[validatorAddress];
        ValidatorStatus status = validator.currentStatus;
        // reverts if decremented committee size after ejection reaches 0, preventing network halt
        uint256 numEligible = _getValidators(ValidatorStatus.Active).length;
        // if validator being ejected is committee-eligible, ejection will decrement `numEligible`
        if (_eligibleForCommitteeNextEpoch(status)) {
            numEligible = numEligible - 1;
        }
        _ejectFromCommittees(validatorAddress, numEligible);

        // exit, retire, and unstake + burn validator immediately
        _exit(validator, currentEpoch);
        _retire(validator);
        address recipient = _getRecipient(validatorAddress);
        _unstake(validatorAddress, recipient, validator.stakeVersion);
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
        address[] storage newCommittee = futureEpochInfo[newEpochPointer].committee;
        StakeConfig memory newStakeConfig = getCurrentStakeConfig();
        epochInfo[newEpochPointer] = EpochInfo(
            newCommittee,
            newStakeConfig.epochIssuance,
            uint64(block.number) + 1,
            newStakeConfig.epochDuration,
            stakeVersion
        );
        epochPointer = newEpochPointer;
        uint32 newEpoch = ++currentEpoch;

        // update future epoch info
        uint8 twoEpochsInFuturePointer = (newEpochPointer + 2) % 4;
        futureEpochInfo[twoEpochsInFuturePointer].committee = futureCommittee;

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
        return futureEpochInfo[futurePointer];
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
        // identify diff from pointer, preventing underflow by adding 4 (will be modulo'd away)
        uint8 pointerDiff = uint8(4 + current - recent);
        uint8 pointer = (currentPointer + pointerDiff) % 4;
        return epochInfo[pointer];
    }

    function _enforceSorting(address[] calldata futureCommittee) internal pure {
        for (uint256 i; i < futureCommittee.length - 1; ++i) {
            if (futureCommittee[i] >= futureCommittee[i + 1]) revert CommitteeRequirement(futureCommittee[i]);
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

    /// @dev Returns whether given `validatorAddress` is a member of the given committee
    function _isCommitteeMember(address validatorAddress, address[] memory committee) internal pure returns (bool) {
        // cache len to memory
        uint256 committeeLen = committee.length;
        for (uint256 i; i < committeeLen; ++i) {
            // terminate if `validatorAddress` is a member of committee
            if (committee[i] == validatorAddress) return true;
        }

        return false;
    }

    /// @dev Active and pending activation/exit validators are eligible for committee service in next epoch
    function _eligibleForCommitteeNextEpoch(ValidatorStatus status) internal pure returns (bool) {
        return (
            status == ValidatorStatus.Active || status == ValidatorStatus.PendingExit
                || status == ValidatorStatus.PendingActivation
        );
    }

    /// @notice `Active` queries also include validators pending activation or exit
    /// Because they are eligible for voter committee service in the next epoch
    /// @dev There are ~1000 total MNOs in the world so `SLOAD` loops should not run out of gas
    /// @dev Room for storage optimization (SSTORE2 etc) to hold more validators
    function _getValidators(ValidatorStatus status) internal view returns (ValidatorInfo[] memory) {
        ValidatorInfo[] memory validatorsMatched = new ValidatorInfo[]((totalSupply()));
        uint256 numMatches;

        for (uint256 i; i < validatorsMatched.length; ++i) {
            address validatorAddress = _getAddress(tokenByIndex(i));
            ValidatorInfo storage current = validators[validatorAddress];
            if (current.isRetired) continue;

            // queries for `Any` status include all unretired validators
            bool matchFound = status == ValidatorStatus.Any;
            if (!matchFound) {
                // mem cache to save SLOADs
                ValidatorStatus currentStatus = current.currentStatus;

                // include pending activation/exit due to committee service eligibility in next epoch
                if (status == ValidatorStatus.Active) {
                    matchFound = _eligibleForCommitteeNextEpoch(currentStatus);
                } else {
                    // all other queries return only exact matches
                    matchFound = currentStatus == status;
                }
            }

            if (matchFound) {
                validatorsMatched[numMatches++] = current;
            }
        }

        // trim and return array
        assembly {
            mstore(validatorsMatched, numMatches)
        }

        return validatorsMatched;
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
    /// decremented directly from InterchainTEL within the protocol on the rust side
    /// @dev Only governance delegation is enabled at genesis
    constructor(
        StakeConfig memory genesisConfig_,
        ValidatorInfo[] memory initialValidators_,
        address owner_
    )
        Ownable(owner_)
        StakeManager("ConsensusNFT", "CNFT")
    {
        if (initialValidators_.length == 0 || initialValidators_.length > type(uint24).max) {
            revert GenesisArityMismatch();
        }

        // deploy Issuance contract and set stake storage configs
        issuance = payable(new Issuance(address(this)));
        versions[0] = genesisConfig_;

        for (uint256 j; j <= 2; ++j) {
            EpochInfo storage epoch = epochInfo[j];
            epoch.epochDuration = genesisConfig_.epochDuration;
            epoch.epochIssuance = genesisConfig_.epochIssuance;
        }

        for (uint256 i; i < initialValidators_.length; ++i) {
            ValidatorInfo memory currentValidator = initialValidators_[i];

            // assert `validatorIndex` struct members match expected value
            if (currentValidator.blsPubkey.length != 96) {
                revert InvalidBLSPubkey();
            }
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
            if (currentValidator.isDelegated == true) {
                // at genesis, only governance delegations are enabled
                delegations[currentValidator.validatorAddress] = Delegation(
                    keccak256(currentValidator.blsPubkey),
                    currentValidator.validatorAddress,
                    owner_,
                    uint8(0),
                    uint64(1)
                );
            }
            if (currentValidator.stakeVersion != 0) {
                revert InvalidStakeAmount(currentValidator.stakeVersion);
            }

            // first three epochs use initial validators as committee
            for (uint256 j; j <= 2; ++j) {
                epochInfo[j].committee.push(currentValidator.validatorAddress);
                futureEpochInfo[j].committee.push(currentValidator.validatorAddress);
            }

            validators[currentValidator.validatorAddress] = currentValidator;
            balances[currentValidator.validatorAddress] = genesisConfig_.stakeAmount;
            _mint(currentValidator.validatorAddress, _getTokenId(currentValidator.validatorAddress));

            emit ValidatorActivated(currentValidator);
        }
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
