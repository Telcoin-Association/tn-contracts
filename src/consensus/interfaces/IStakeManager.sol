// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

/**
 * @title IStakeManager
 * @author Telcoin Association
 * @notice A Telcoin Contract
 *
 * @notice This interface declares the ConsensusRegistry's staking API and data structures
 * @dev Implemented within StakeManager.sol, which is inherited by the ConsensusRegistry
 */
struct StakeInfo {
    uint24 validatorIndex;
    uint240 stakingRewards;
}

interface IStakeManager {
    /// @custom:storage-location erc7201:telcoin.storage.StakeManager
    struct StakeManagerStorage {
        address rwTEL;
        uint256 stakeAmount;
        uint256 minWithdrawAmount;
        mapping(address => StakeInfo) stakeInfo;
    }

    error InvalidStakeAmount(uint256 stakeAmount);
    error InsufficientRewards(uint256 withdrawAmount);
    error NotTransferable();
    error RequiresConsensusNFT();

    /// @dev Accepts the stake amount of native TEL and issues an activation request for the caller (validator)
    /// @notice Caller must already have been issued a `ConsensusNFT` by Telcoin governance
    function stake(
        bytes calldata blsPubkey,
        bytes calldata blsSig,
        bytes32 ed25519Pubkey
    ) external payable;

    /// @dev Increments the claimable rewards for each validator
    /// @notice May only be called by the client via system call, at the start of a new epoch
    /// @param stakingRewardInfos Staking reward info defining which validators to reward
    /// and how much each rewardee earned for the current epoch
    function incrementRewards(StakeInfo[] calldata stakingRewardInfos) external;

    /// @dev Used for validators to claim their staking rewards for validating the network
    /// @notice Rewards are incremented every epoch via syscall in `concludeEpoch()`
    function claimStakeRewards() external;

    /// @dev Returns previously staked funds and accrued rewards, if any, to the calling validator
    /// @notice May only be called after fully exiting
    function unstake() external;

    /// @dev Fetches the claimable rewards accrued for a given validator address
    /// @notice Does not include the original stake amount and cannot be claimed until surpassing `minWithdrawAmount`
    /// @return claimableRewards The validator's claimable rewards, not including the validator's stake
    function getRewards(
        address ecdsaPubkey
    ) external view returns (uint240 claimableRewards);
}
