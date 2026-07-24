// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

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

    /// @notice A stake version change requested by an in-service validator, queued for automatic
    /// settlement inside `concludeEpoch` at an epoch boundary, after that boundary's slashes land
    struct PendingStakeVersionChange {
        /// @notice The version to adopt at settlement; 0 is the no-pending sentinel
        /// (valid targets are always >= 1 since they must exceed the validator's current version)
        uint8 targetVersion;
        /// @notice The epoch the change was requested in; stake decreases settle only once
        /// `STAKE_DECREASE_DELAY_EPOCHS` further boundaries have passed
        uint32 requestEpoch;
        /// @notice The address that paid the escrow; escrow returns go here, never to the recipient
        address funder;
        /// @notice The exact stake deficit held for a stake-increasing change; zero otherwise.
        /// Held here rather than in `balances` so it is invisible to reward accounting until the flip
        uint256 escrow;
    }

    /// @notice Represents a validator's compressed BLS12-381 proof of possession.
    /// @param signature A 48-byte compressed G1 point: the PoP over the protocol's PoP message.
    /// @dev The proven public key is the separate 96-byte compressed `blsPubkey` passed to stake and
    /// genesis; the precompile verifies `signature` against it, so no pubkey is carried here.
    struct ProofOfPossession {
        bytes signature;
    }

    /// @notice Thrown when BLS proof-of-possession signature verification fails
    /// @param proof The proof of possession that failed verification
    error InvalidProofOfPossession(ProofOfPossession proof);
    /// @notice Thrown when a registered BLS public key is not a well-formed 96-byte compressed G2 point
    error InvalidBLSPubkey();
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
    /// @notice Thrown when a low-level ETH transfer to the Issuance contract fails
    error IssuanceTransferFailed();
    /// @notice Thrown when cancelling a stake version change for a validator with none pending
    error NoPendingVersionChange();
    /// @notice Thrown when `claimRefund` is called by an address with no claimable refund credit
    error NoClaimableRefund();
    /// @notice Thrown when no BLS public key is stored for the queried validator address
    /// @dev Covers both the zero-address case and addresses that have never staked
    /// (or have been burned/retired and had their pubkey state cleared)
    /// @param validatorAddress The address whose BLS pubkey lookup failed
    error BlsPubkeyNotFound(address validatorAddress);

    /// @dev Accepts the native TEL stake amount from the calling validator, enabling later self-activation
    /// @notice Caller must already have been issued a `ConsensusNFT` by Telcoin governance
    /// @notice Ensuring `uncompressedPubkey` corresponds to `ValidatorInfo::blsPubkey` is better
    /// performed externally in Rust by the protocol due to EIP2537 precompile & EVM limitations
    /// so this contract does not perform any (un)compression checks
    function stake(
        bytes calldata blsPubkey,
        ProofOfPossession calldata proofOfPossession
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
        ProofOfPossession calldata proofOfPossession,
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
    /// @param acceptRewardShortfall When true, caps the rewards payout at the Issuance contract's available
    /// balance and permanently forfeits only the shortfall, so an underfunded reward pool can never
    /// block a stake withdrawal; identical to a normal unstake whenever Issuance can cover the rewards
    function unstake(address validatorAddress, bool acceptRewardShortfall) external;

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

    /// @dev Returns the stake version active for the current epoch, ie the version stamped
    /// into the epoch's info at its start
    /// @notice Differs from `getCurrentStakeConfig` during any epoch in which governance has
    /// authored a new version, since newly authored versions activate at the next epoch start
    function getCurrentStakeVersion() external view returns (uint8);

    /// @dev Returns the queried stake configuration
    function stakeConfig(uint8 version) external view returns (StakeConfig memory);

    /// @dev Returns the latest authored stake configuration, which becomes active at the
    /// next epoch start
    /// @notice Not necessarily the epoch-active config: during any epoch in which governance
    /// has authored a new version, this differs from `stakeConfig(getCurrentStakeVersion())`
    function getCurrentStakeConfig() external view returns (StakeConfig memory);

    /// @dev Permissioned function to upgrade stake, withdrawal, and consensus block reward configurations
    /// @notice The new version takes effect in the next epoch
    function upgradeStakeVersion(StakeConfig calldata newVersion) external returns (uint8);

    /// @dev Permissioned function to allocate TEL for epoch issuance, ie consensus block rewards
    /// @notice Allocated TEL leaves the Issuance contract only as staking issuance rewards or
    /// through a governance withdrawal via `issuanceWithdrawal`
    /// @notice Only governance may allocate TEL in this manner
    function allocateIssuance() external payable;

    /// @dev Requests a stake version change for a validator; callable by the validator or its delegator.
    /// Only callable for validators with status Staked, PendingActivation, or Active.
    /// @param validatorAddress The validator whose stake version should change
    /// @param targetVersion The version to adopt (must be strictly greater than current and not
    /// exceed the latest authored version)
    /// @notice `Staked` validators settle immediately: they are not in service, are never members of
    /// a committee, and can already reclaim their full stake at any time via `unstake`.
    /// @notice In-service (PendingActivation/Active) validators are queued instead: the change is
    /// applied automatically inside `concludeEpoch` at an epoch boundary, after that boundary's
    /// slashes have landed, so no request or settlement timing can move value ahead of a slash.
    /// Stake increases settle at the first boundary; stake decreases settle only once
    /// `STAKE_DECREASE_DELAY_EPOCHS` further boundaries have passed, covering slashes whose
    /// detection lags the offense by up to that many epochs.
    /// @notice If the new version requires more stake, `msg.value` must equal the exact deficit; it
    /// is escrowed in the queue entry (not in the stake balance) until the boundary flip.
    /// @notice If the new version requires less stake, no value moves at request time. At settlement
    /// the surplus above the new stake amount is refunded to the reward recipient from the balance
    /// as it stands post-slash; the slashed remainder of the surplus is consolidated on Issuance.
    /// @notice A repeat request overwrites the pending entry, returning any prior escrow to its
    /// funder and re-stamping the request epoch.
    /// @notice If a validator has been slashed and has accrued rewards, settling a lower
    /// `stakeAmount` may zero claimable rewards since rewards are derived as `balance - stakeAmount`.
    /// The recipient still receives the correct total ETH via the refund. Validators should claim
    /// rewards before requesting if they have both accrued rewards and pending slashes.
    function requestStakeVersionChange(address validatorAddress, uint8 targetVersion) external payable;

    /// @dev Withdraws a pending stake version change without settling it, returning any escrow to
    /// its funder
    /// @param validatorAddress The validator whose pending change should be cancelled
    /// @notice Callable by the validator or its delegator
    function cancelStakeVersionChange(address validatorAddress) external;

    /// @dev Transfers the caller's accumulated refund credit
    /// @notice Credits accrue when a boundary refund or escrow return could not be pushed to its
    /// recipient (or when the recipient was retired mid-queue); they are detached from the validator
    /// lifecycle and survive burns and retirement
    function claimRefund() external;

    /// @dev Permissioned function to withdraw TEL from the Issuance contract to the caller
    /// @notice Only governance may withdraw in this manner, eg to recover consolidated slash
    /// funds or to reduce a prior issuance allocation
    /// @param amount The amount of TEL to withdraw from the Issuance contract
    function issuanceWithdrawal(uint256 amount) external;
}
