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
        bytes blsPubkey; // using uncompressed 96 byte BLS public keys
        address validatorAddress;
        uint32 activationEpoch;
        uint32 exitEpoch;
        ValidatorStatus currentStatus;
        bool isRetired;
        bool isDelegated;
        uint8 stakeVersion;
    }

    /// @dev Stores each epoch's validator committee and starting block height
    /// @dev Used in two parallel ring buffers offset 2 to store past & future epochs
    struct EpochInfo {
        address[] committee;
        uint256 epochIssuance;
        uint64 blockHeight;
        uint32 epochDuration;
        uint8 stakeVersion;
    }

    error LowLevelCallFailure();
    error InvalidBLSPubkey();
    error InvalidValidatorAddress();
    error InvalidProof();
    error GenesisArityMismatch();
    error DuplicateBLSPubkey();
    error InvalidCommitteeSize(uint256 minCommitteeSize, uint256 providedCommitteeSize);
    error CommitteeRequirement(address validatorAddress);
    error NotValidator(address validatorAddress);
    error AlreadyDefined(address validatorAddress);
    error InvalidStatus(ValidatorStatus status);
    error InvalidEpoch(uint32 epoch);
    error InvalidDuration(uint32 duration);

    event ValidatorStaked(ValidatorInfo validator);
    event ValidatorPendingActivation(ValidatorInfo validator);
    event ValidatorActivated(ValidatorInfo validator);
    event ValidatorPendingExit(ValidatorInfo validator);
    event ValidatorExited(ValidatorInfo validator);
    event ValidatorRetired(ValidatorInfo validator);
    event ValidatorSlashed(Slash slash);
    event NewEpoch(EpochInfo epoch);
    event RewardsClaimed(address claimant, uint256 rewards);

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

    /// @dev Returns whether a validator is exited && unstaked, ie "retired"
    /// @notice After retiring, a validator's `tokenId == validatorAddress` cannot be reused
    function isRetired(address validatorAddress) external view returns (bool);
}
