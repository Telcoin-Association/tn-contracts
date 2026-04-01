// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { BlsG1 } from "../consensus/BlsG1.sol";

/**
 * @title IStakeManager
 * @author Telcoin Association
 * @notice A Telcoin Contract
 *
 * @notice This interface declares the ConsensusRegistry's staking API and data structures
 * @dev Implemented within StakeManager.sol, which is inherited by the ConsensusRegistry
 */

/// @notice Protocol info for system calls to split the epoch issuance amount
/// between validators based on how many consensus headers they produced
/// @notice Not enabled during MNO pilot
struct RewardInfo {
    address validatorAddress;
    uint256 consensusHeaderCount;
}

/// @notice Slash information for system calls to decrement outstanding validator balances
/// @notice Not enabled during MNO pilot
struct Slash {
    address validatorAddress;
    uint256 amount;
}

interface IStakeManager {
    /// @notice New StakeConfig versions take effect in the next epoch
    /// ie they are set for each epoch at its start
    struct StakeConfig {
        /// @notice Required native TEL stake amount per validator for this version
        uint256 stakeAmount;
        /// @notice Minimum accrued reward threshold required to claim; prevents dust withdrawals
        uint256 minWithdrawAmount;
        /// @notice Total TEL distributed across all validators as rewards per epoch
        uint256 epochIssuance;
        /// @notice Duration of each epoch in L2 blocks
        uint32 epochDuration;
    }

    /// @notice Stores delegation state for a validator whose stake was provided by a third party
    struct Delegation {
        /// @notice keccak256 hash of the validator's 96-byte compressed BLS public key
        bytes32 blsPubkeyHash;
        /// @notice The validator address this delegation is bound to
        address validatorAddress;
        /// @notice The third-party address that provided the stake and receives rewards
        address delegator;
        /// @notice The StakeConfig version at the time of delegation; updated on version upgrade
        uint8 validatorVersion;
        /// @notice Monotonically increasing counter to prevent EIP-712 signature replay
        uint64 nonce;
    }

    /// @notice Thrown when BLS proof-of-possession signature verification fails
    /// @param proof The proof of possession that failed verification
    /// @param message The signed message that was expected
    error InvalidProofOfPossession(BlsG1.ProofOfPossession proof, bytes message);
    /// @notice Thrown when a token ID is zero, exceeds type(uint160).max, or does not exist
    /// @param tokenId The invalid token ID
    error InvalidTokenId(uint256 tokenId);
    /// @notice Thrown when msg.value does not match the required stake amount for the operation
    /// @param stakeAmount The invalid stake value that was provided
    error InvalidStakeAmount(uint256 stakeAmount);
    /// @notice Thrown when claimable rewards are zero or below the version's minWithdrawAmount
    /// @param withdrawAmount The reward amount that was insufficient
    error InsufficientRewards(uint256 withdrawAmount);
    /// @notice Thrown when the caller is neither the validator nor its delegator
    /// @param recipient The expected reward recipient (delegator if delegated, else the validator)
    error NotRecipient(address recipient);
    /// @notice Thrown on transfer, approve, or setApprovalForAll because ConsensusNFTs are soulbound
    error NotTransferable();
    /// @notice Thrown when the provided address does not own the expected ConsensusNFT
    error RequiresConsensusNFT();
    /// @notice Thrown when unstaking would reduce ConsensusNFT totalSupply to zero
    error InvalidSupply();
    /// @notice Thrown when a stake version upgrade targets an invalid version
    /// @dev Target version must be strictly greater than current and not exceed global `stakeVersion`
    /// @param currentVersion The validator's current stake version
    /// @param targetVersion The requested target version that was rejected
    error InvalidStakeVersion(uint8 currentVersion, uint8 targetVersion);

    /// @dev Accepts the native TEL stake amount from the calling validator, enabling later self-activation
    /// @notice Caller must already have been issued a `ConsensusNFT` by Telcoin governance
    /// @notice Ensuring `uncompressedPubkey` corresponds to `ValidatorInfo::blsPubkey` is better
    /// performed externally in Rust by the protocol due to EIP2537 precompile & EVM limitations
    /// so this contract does not perform any (un)compression checks
    function stake(
        bytes calldata blsPubkey,
        BlsG1.ProofOfPossession calldata proofOfPossession
    )
        external
        payable;

    /// @dev Accepts delegated stake from a non-validator caller authorized by a validator's EIP712 signature
    /// @notice `validatorAddress` must be a validator already in possession of a `ConsensusNFT`
    /// @notice Ensuring `uncompressedPubkey` corresponds to `ValidatorInfo::blsPubkey` is better
    /// performed externally in Rust by the protocol due to EIP2537 precompile & EVM limitations
    /// so this contract does not perform any (un)compression checks
    function delegateStake(
        bytes calldata blsPubkey,
        BlsG1.ProofOfPossession calldata proofOfPossession,
        address validatorAddress,
        bytes calldata validatorSig
    )
        external
        payable;

    /// @dev Used by rewardees to claim staking rewards
    function claimStakeRewards(address ecdaPubkey) external;

    /// @dev Returns previously staked funds in addition to accrued rewards, if any, to the staker
    /// @notice May be used to reverse validator onboarding pre-activation or permanently retire after full exit
    /// @notice Once unstaked and retired, validator addresses cannot be reused
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

    /// @dev Fetches the claimable rewards accrued for a given validator address
    /// @return _ The validator's claimable rewards, not including the validator's stake
    function getRewards(address validatorAddress) external view returns (uint256);

    /// @dev Fetches the StakeManager's issuance contract address
    function issuance() external view returns (address payable);

    /// @dev Returns staking information for the given address
    function getBalanceBreakdown(address validatorAddress) external view returns (uint256, uint256, uint256);

    /// @dev Returns the current version
    function getCurrentStakeVersion() external view returns (uint8);

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

    /// @dev Allows a staked validator (or its delegator) to upgrade their stake version in-place.
    /// Only callable for validators with status Staked, PendingActivation, or Active.
    /// @param validatorAddress The validator whose stake version should be upgraded
    /// @param targetVersion The new stake version to upgrade to (must be strictly greater than current)
    /// @notice If the new version requires more stake, `msg.value` must equal the exact deficit
    /// @notice If the new version requires less stake, the surplus is refunded to the reward recipient.
    /// For partially slashed validators, only the balance above `newStakeAmount` is refunded.
    /// @notice If a validator has been slashed and has accrued rewards, upgrading to a lower
    /// `stakeAmount` may zero claimable rewards since rewards are derived as `balance - stakeAmount`.
    /// The recipient still receives the correct total ETH via the refund. Validators should claim
    /// rewards before upgrading if they have both accrued rewards and pending slashes.
    function upgradeValidatorStakeVersion(address validatorAddress, uint8 targetVersion) external payable;
}
