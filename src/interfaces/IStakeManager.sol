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

/// @notice Struct used by storage ledger to record outstanding validator balances
/// @dev Links balances to ConsensusNFTs to enable DPoS & permanent validator retirement
/// @dev Updated via rewards and slashes
struct StakeInfo {
    uint24 tokenId;
    uint232 balance;
}

/// @notice Protocol info for system calls to split the epoch issuance amount
/// between validators based on how many consensus headers they produced
/// @notice Not enabled during MNO pilot
struct RewardInfo {
    address validatorAddress;
    uint232 consensusHeaderCount;
}

/// @notice Slash information for system calls to decrement outstanding validator balances
/// @notice Not enabled during MNO pilot
struct Slash {
    address validatorAddress;
    uint232 amount;
}

interface IStakeManager {
    /// @notice New StakeConfig versions take effect in the next epoch
    /// ie they are set for each epoch at its start
    struct StakeConfig {
        uint232 stakeAmount;
        uint232 minWithdrawAmount;
        uint232 epochIssuance;
        uint32 epochDuration;
    }

    struct Delegation {
        bytes32 blsPubkeyHash;
        address delegator;
        uint24 tokenId;
        uint8 validatorVersion;
        uint64 nonce;
    }

    error InvalidTokenId(uint256 tokenId);
    error InvalidStakeAmount(uint256 stakeAmount);
    error InsufficientRewards(uint256 withdrawAmount);
    error NotDelegator(address notDelegator);
    error NotTransferable();
    error RequiresConsensusNFT();
    error InvalidSupply();

    /// @dev Accepts the native TEL stake amount from the calling validator, enabling later self-activation
    /// @notice Caller must already have been issued a `ConsensusNFT` by Telcoin governance
    function stake(bytes calldata blsPubkey) external payable;

    /// @dev Accepts delegated stake from a non-validator caller authorized by a validator's EIP712 signature
    /// @notice `validatorAddress` must be a validator already in possession of a `ConsensusNFT`
    function delegateStake(
        bytes calldata blsPubkey,
        address validatorAddress,
        bytes calldata validatorSig
    )
        external
        payable;

    /// @dev Used by rewardees to claim staking rewards
    function claimStakeRewards(address ecdaPubkey) external;

    /// @dev Returns previously staked funds in addition to accrued rewards, if any, to the staker
    /// @notice May only be called after fully exiting
    /// @notice `StakeInfo::tokenId` will be set to `UNSTAKED` so the validator address cannot be reused
    function unstake(address validatorAddress) external;

    /// @notice Returns the delegation digest that a validator should sign to accept a delegation
    /// @return _ EIP-712 typed struct hash used to enable delegated proof of stake
    function delegationDigest(
        bytes memory blsPubkey,
        address validatorAddress,
        address delegator
    )
        external
        view
        returns (bytes32);

    /// @dev Returns the current total supply of minted ConsensusNFTs
    function totalSupply() external view returns (uint24);

    /// @dev Fetches the claimable rewards accrued for a given validator address
    /// @return _ The validator's claimable rewards, not including the validator's stake
    function getRewards(address validatorAddress) external view returns (uint232);

    /// @dev Fetches the StakeManager's issuance contract address
    function issuance() external view returns (address payable);

    /// @dev Returns staking information for the given address
    function getStakeInfo(address validatorAddress) external view returns (StakeInfo memory);

    /// @dev Returns the current version
    function stakeVersion() external view returns (uint8);

    /// @dev Returns the queried stake configuration
    function stakeConfig(uint8 version) external view returns (StakeConfig memory);

    /// @dev Returns the current stake configuration
    function getCurrentStakeConfig() external view returns (StakeConfig memory);

    /// @dev Permissioned function to upgrade stake, withdrawal, and consensus block reward configurations
    /// @notice The new version takes effect in the next epoch
    function upgradeStakeVersion(StakeConfig calldata newVersion) external returns (uint8);

    /// @dev Permissioned function to allocate TEL for epoch issuance, ie consensus block rewards
    /// @notice Allocated TEL cannot be recovered; it is effectively burned cryptographically
    /// The only way received TEL can be re-minted is as staking issuance rewards
    /// @notice Only governance may burn TEL in this manner
    function allocateIssuance() external payable;
}
