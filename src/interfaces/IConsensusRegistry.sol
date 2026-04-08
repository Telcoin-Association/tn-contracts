// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { RewardInfo, Slash } from "./IStakeManager.sol";

/**
 * @title ConsensusRegistry Interface
 * @author Telcoin Association
 * @notice A Telcoin Contract
 *
 * @notice This contract provides the interface for the Telcoin ConsensusRegistry smart contract
 * @dev This contract should be deployed to a predefined system address for use with system calls
 */
interface IConsensusRegistry {
    /// @dev Packed struct storing each validator's onchain info
    struct ValidatorInfo {
        /// @notice Uncompressed BLS12-381 G2 public key in 256-byte EIP-2537 encoding
        bytes blsPubkey;
        /// @notice The validator's execution-layer address; doubles as its ConsensusNFT tokenId
        address validatorAddress;
        /// @notice Epoch at which this validator became or will become active
        uint32 activationEpoch;
        /// @notice Epoch at which this validator exited; 0 until exit begins, type(uint32).max while pending
        uint32 exitEpoch;
        /// @notice The validator's current lifecycle status
        ValidatorStatus currentStatus;
        /// @notice Once true, this validator address can never rejoin the network
        bool isRetired;
        /// @notice Index into the `versions` mapping identifying this validator's StakeConfig
        uint8 stakeVersion;
        /// @notice The geographic region assigned to the validator by governance (0=unspecified, 1-255 available)
        uint8 region;
    }

    /// @dev Stores each epoch's validator committee and starting block height
    /// @dev Used in two parallel ring buffers offset 2 to store past & future epochs
    struct EpochInfo {
        /// @notice Ordered set of validator addresses selected for this epoch's voting committee
        address[] committee;
        /// @notice Total TEL distributed as staking rewards during this epoch
        uint256 epochIssuance;
        /// @notice The L2 block number at which this epoch started; 0 for future epochs not yet begun
        uint64 blockHeight;
        /// @notice Sequential identifier for this epoch
        uint32 epochId;
        /// @notice Duration of this epoch in L2 blocks
        uint32 epochDuration;
        /// @notice The global StakeConfig version that was active when this epoch started
        uint8 stakeVersion;
    }

    /// @notice Thrown during genesis initialization when a validator has address(0)
    error InvalidValidatorAddress();
    /// @notice Thrown during genesis when initialValidators is empty or its length mismatches proofsOfPossession
    error GenesisArityMismatch();
    /// @notice Thrown when a BLS public key has already been registered to another validator
    error DuplicateBLSPubkey();
    /// @notice Thrown when a committee size is zero or exceeds the number of eligible validators
    /// @param minCommitteeSize The minimum acceptable committee size
    /// @param providedCommitteeSize The committee size that was rejected
    error InvalidCommitteeSize(uint256 minCommitteeSize, uint256 providedCommitteeSize);
    /// @notice Thrown when the committee array is not sorted in strictly ascending address order
    /// @param validatorAddress The address at which the sort invariant was violated
    error CommitteeRequirement(address validatorAddress);
    /// @notice Thrown when a delegated-stake EIP-712 signature fails verification
    /// @param validatorAddress The validator whose signature was invalid
    error NotValidator(address validatorAddress);
    /// @notice Thrown when minting a ConsensusNFT for an address that already holds one or is retired
    /// @param validatorAddress The address that was already defined
    error AlreadyDefined(address validatorAddress);
    /// @notice Thrown when a validator's current status does not match the required status for the operation
    /// @param status The validator's actual status that caused the revert
    error InvalidStatus(ValidatorStatus status);
    /// @notice Thrown when a queried epoch is outside the stored range or genesis epoch values are nonzero
    /// @param epoch The epoch number that was rejected
    error InvalidEpoch(uint32 epoch);
    /// @notice Thrown in upgradeStakeVersion when the new epoch duration is zero
    /// @param duration The invalid duration value
    error InvalidDuration(uint32 duration);
    /// @notice Thrown when a validator attempts to unstake but is ineligible
    /// @dev Validators may unstake only if Staked (pre-activation) or Exited with at least one full epoch elapsed
    /// @param validator The full ValidatorInfo of the ineligible validator
    error IneligibleUnstake(ValidatorInfo validator);

    /// @notice Emitted when a validator first stakes, entering the Staked lifecycle state
    /// @param validator The newly staked validator's info
    event ValidatorStaked(ValidatorInfo validator);
    /// @notice Emitted when a staked validator self-activates, entering the activation queue
    /// @dev Activation completes automatically at the start of the next epoch
    /// @param validator The validator entering PendingActivation status
    event ValidatorPendingActivation(ValidatorInfo validator);
    /// @notice Emitted when a validator's activation resolves at epoch conclusion or at genesis
    /// @param validator The newly activated validator's info
    event ValidatorActivated(ValidatorInfo validator);
    /// @notice Emitted when an active validator requests exit, entering the exit queue
    /// @dev Exit completes when the validator is no longer required in any future committee
    /// @param validator The validator entering PendingExit status
    event ValidatorPendingExit(ValidatorInfo validator);
    /// @notice Emitted when a pending-exit validator is removed from the active set by the protocol
    /// @param validator The exited validator's info
    event ValidatorExited(ValidatorInfo validator);
    /// @notice Emitted when a validator is permanently retired and its address can never rejoin
    /// @param validator The retired validator's info
    event ValidatorRetired(ValidatorInfo validator);
    /// @notice Emitted for each slash applied to a validator's outstanding balance
    /// @dev If the slash reduces the balance to zero, the validator is forcibly ejected and retired
    /// @param slash The slash details including validator address and penalty amount
    event ValidatorSlashed(Slash slash);
    /// @notice Emitted at epoch conclusion when a new epoch begins
    /// @param epoch The new epoch's full configuration including committee and block height
    event NewEpoch(EpochInfo epoch);
    /// @notice Emitted when governance updates a validator's geographic region assignment
    /// @param validatorAddress The validator whose region was updated
    /// @param region The new geographic region identifier
    event ValidatorRegionUpdated(address indexed validatorAddress, uint8 region);
    /// @notice Emitted when a stake originator claims accrued rewards or unstakes
    /// @param claimant The address that received the funds (validator or its delegator)
    /// @param rewards The amount of TEL claimed
    event RewardsClaimed(address indexed claimant, uint256 rewards);
    /// @notice Emitted when a validator's stake version is upgraded in-place
    /// @param validatorAddress The validator whose stake version was upgraded
    /// @param oldVersion The validator's previous stake version
    /// @param newVersion The validator's new stake version
    /// @param oldStakeAmount The stakeAmount associated with the old version
    /// @param newStakeAmount The stakeAmount associated with the new version
    event ValidatorStakeVersionUpgraded(
        address indexed validatorAddress,
        uint8 oldVersion,
        uint8 newVersion,
        uint256 oldStakeAmount,
        uint256 newStakeAmount
    );
    /// @notice Emitted when governance or the protocol adjusts the next epoch's committee size
    /// @param oldSize The previous nextCommitteeSize value
    /// @param newSize The updated nextCommitteeSize value
    /// @param numActiveValidators The current count of committee-eligible validators
    event NextCommitteeSizeUpdated(uint16 oldSize, uint16 newSize, uint256 numActiveValidators);

    /// @dev Validators marked `Active || PendingActivation || PendingExit` are still operational
    /// and thus eligible for committees. Queriable via `getValidators(Active)` status
    /// @param Staked Marks validators who have staked but have not yet entered activation queue
    /// @param PendingActivation Marks staked and operational validators in the activation queue,
    /// which automatically resolves to `Active` at the start of the next epoch
    /// @param Active Marks validators who are indefinitely operational and not in activation/exit queue
    /// @param PendingExit Marks validators in the exit queue. They are still eligible for committees,
    /// remaining staked and operational while awaiting automatic exit initiated by the protocol
    /// @param Exited Marks validators exited by the protocol client but have not yet unstaked
    /// @param Any Marks permanently retired validators, which offer little reason to be queried
    /// thus querying `getValidators(Any)` instead returns all unretired validators
    enum ValidatorStatus {
        Undefined,
        Staked,
        PendingActivation,
        Active,
        PendingExit,
        Exited,
        Any
    }

    /// @notice Voting Validator Committee changes at the end every epoch via syscall
    /// @dev Accepts the committee of voting validators for 2 epochs in the future
    /// @param newCommittee The future validator committee for `$.currentEpoch + 3`
    function concludeEpoch(address[] calldata newCommittee) external;

    /// @dev The network's epoch issuance distribution method, rewarding stake originators
    /// based on initial stake and on the validator's performance (consensus header count)
    /// @notice Stake originators are either a delegator if one exists, or the validator itself
    /// @notice Called just before concluding the current epoch
    /// @notice Not yet enabled during pilot, but scaffolding is included here.
    /// For the time being, system calls to this fn can provide empty calldata arrays
    function applyIncentives(RewardInfo[] calldata rewardInfos) external;

    /// @dev The network's slashing mechanism, which penalizes validators for misbehaving
    /// @notice Called just before concluding the current epoch
    /// @notice Not yet enabled during pilot, but scaffolding is included here.
    /// For the time being, system calls to this fn can provide empty calldata arrays
    function applySlashes(Slash[] calldata slashes) external;

    /// @dev Self-activation function for validators, gaining `PendingActivation` status and setting
    /// next epoch as activation epoch to ensure rewards eligibility only after completing a full epoch
    /// @notice Caller must own a ConsensusNFT and be `Staked` status, ie staked or delegated
    function activate() external;

    /// @dev Issues an exit request for a validator to be retired from the `Active` validator set
    /// @notice Reverts if the exit queue is full, ie if active validator count would drop too low
    function beginExit() external;

    /// @notice Sets the GSMA region identifier for a validator. Only callable by governance (owner).
    /// @param validatorAddress The address of the validator to update
    /// @param region The GSMA region identifier (uint8; 0=unspecified, 1-8=GSMA regions)
    function setValidatorRegion(address validatorAddress, uint8 region) external;

    /// @notice Set the internal value for the nextCommitteeSize.
    /// @dev This is managed off-chain and read by the protocol to shuffle n-validators for `concludeEpoch` call.
    /// @notice Reverts if the newSize is larger than the number of active/pending validators.
    function setNextCommitteeSize(uint16 newSize) external;

    /// @notice Returns the next committee size
    function getNextCommitteeSize() external view returns (uint16);

    /// @dev Returns the current epoch
    function getCurrentEpoch() external view returns (uint32);

    /// @dev Returns the current epoch's committee and block height
    function getCurrentEpochInfo() external view returns (EpochInfo memory);

    /// @dev Returns information about the provided epoch. Only four latest & two future epochs are stored
    /// @notice When querying for future epochs, `blockHeight` will be 0 as they are not yet known
    function getEpochInfo(uint32 epoch) external view returns (EpochInfo memory);

    /// @dev Returns an array of unretired validators matching the provided status
    /// @param `Any` queries return all unretired validators where `status != Any`
    /// @param `Active` queries also include validators pending activation or exit since all three
    /// remain eligible for committee service in the next epoch
    function getValidators(ValidatorStatus status) external view returns (ValidatorInfo[] memory);

    /// @dev Fetches the committee for a given epoch
    function getCommitteeValidators(uint32 epoch) external view returns (ValidatorInfo[] memory);

    /// @dev Fetches the `ValidatorInfo` for a given `validatorAddress == ConsensusNFT tokenId`
    function getValidator(address validatorAddress) external view returns (ValidatorInfo memory);

    /// @dev Check if a BLS public key corresponds to an active validator
    /// @param blsPubkey The compressed 96-byte BLS public key to check
    /// @return bool True if the validator exists and is not retired, false otherwise
    function isValidator(bytes calldata blsPubkey) external view returns (bool);

    /// @dev Returns whether a validator's stake was delegated (ie has a delegator)
    function isDelegated(address validatorAddress) external view returns (bool);

    /// @dev Returns whether a validator is exited && unstaked, ie "retired"
    /// @notice After retiring, a validator's `tokenId == validatorAddress` cannot be reused
    function isRetired(address validatorAddress) external view returns (bool);

    /// @dev Returns the BLS12-381 proof of possession message for given params
    /// @param blsPubkeyUncompressed Must provide the 192-byte uncompressed bls pubkey
    function proofOfPossessionMessage(
        bytes calldata blsPubkeyUncompressed,
        address validatorAddress
    )
        external
        view
        returns (bytes memory);
}
