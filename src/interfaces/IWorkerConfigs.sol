// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

/// @title IWorkerConfigs
/// @notice Interface for a strategy-agnostic per-worker fee config store.
///
/// Every worker `0 .. numWorkers-1` must have a config that was explicitly written
/// (via the constructor or one of the setters). The `strategy` field is a raw
/// `uint8` stored without contract interpretation; the protocol layer handles
/// strategy semantics (e.g. EIP-1559 vs Static).
interface IWorkerConfigs {
    // ── Constants
    // ────────────────────────────────────────────────────────

    /// @notice Highest strategy id this contract recognises.
    /// @dev Mirrors the `WorkerFeeConfig` enum in `tn-types::gas_accumulator`:
    ///      0 = EIP-1559, 1 = Static. New strategies bump this constant in lockstep
    ///      with the Rust side and the contract upgrade.
    function MAX_STRATEGY() external pure returns (uint8);

    // ── Errors
    // ──────────────────────────────────────────────────────────

    /// @notice Thrown when a strategy id is greater than `MAX_STRATEGY`.
    /// @param strategy The rejected strategy id.
    error InvalidStrategy(uint8 strategy);

    /// @notice Thrown when `setNumWorkers` is called but worker `workerId` has no config set.
    /// @param workerId The worker missing a config.
    error MissingWorkerConfig(uint256 workerId);

    /// @notice Thrown when constructor array lengths do not match.
    error LengthMismatch();

    /// @notice Thrown when the number of workers is set to zero.
    error NumWorkersBelowMinimum();

    /// @notice Thrown when `setNumWorkers` is called with the current value.
    error NumWorkersUnchanged();

    // ── Events
    // ──────────────────────────────────────────────────────────

    /// @notice Emitted when a worker's config is created or updated.
    /// @param workerId The worker identifier.
    /// @param strategy The raw strategy id.
    /// @param value The config value.
    /// @param data Strategy-specific packed data forwarded to the protocol layer.
    event WorkerConfigUpdated(uint256 indexed workerId, uint8 strategy, uint64 value, uint128 data);

    /// @notice Emitted when the number of workers changes.
    /// @param oldValue Previous worker count.
    /// @param newValue New worker count.
    event NumWorkersUpdated(uint16 oldValue, uint16 newValue);

    // ── Mutators
    // ────────────────────────────────────────────────────────

    /// @notice Set the number of workers.
    /// @dev Reverts with `MissingWorkerConfig(i)` if any worker `0 .. numWorkers_-1`
    ///      has never had a config explicitly written.
    /// @param numWorkers_ The new worker count.
    function setNumWorkers(uint16 numWorkers_) external;

    /// @notice Set or update the fee config for a specific worker.
    /// @dev Allows setting configs for any `workerId`, including those beyond the
    ///      current `numWorkers`. Coverage is validated when `setNumWorkers` is called.
    ///      Reverts `InvalidStrategy(strategy)` if `strategy > MAX_STRATEGY`.
    /// @param workerId The worker identifier.
    /// @param strategy The raw strategy id (stored without interpretation).
    /// @param value The config value.
    /// @param data Strategy-specific packed data forwarded to the protocol layer.
    function setWorkerConfig(uint16 workerId, uint8 strategy, uint64 value, uint128 data) external;

    /// @notice Set or update fee configs for multiple workers in a single call.
    /// @dev Reverts `LengthMismatch()` if array lengths differ.
    ///      Reverts `InvalidStrategy(strategy)` if any `strategy > MAX_STRATEGY`.
    /// @param workerIds Array of worker identifiers.
    /// @param strategies Array of strategy ids, one per worker.
    /// @param values Array of config values, one per worker.
    /// @param datas Array of strategy-specific packed data, one per worker.
    function setWorkerConfigsBatch(
        uint16[] calldata workerIds,
        uint8[] calldata strategies,
        uint64[] calldata values,
        uint128[] calldata datas
    )
        external;

    // ── Views
    // ───────────────────────────────────────────────────────────

    /// @notice Return the stored config for a worker.
    /// @dev Returns `(0, 0, 0)` for workers that have never been configured.
    /// @param workerId The worker identifier.
    /// @return strategy The raw strategy id.
    /// @return value The config value.
    /// @return data The strategy-specific packed data.
    function getWorkerConfig(uint16 workerId) external view returns (uint8 strategy, uint64 value, uint128 data);

    /// @notice Return every worker's config in one call.
    /// @dev Lets the protocol layer fetch the full per-epoch fee policy with a single EVM
    ///      transition instead of `numWorkers + 1` separate reads.
    /// @return count The current number of workers (== `numWorkers()`).
    /// @return strategies_ Strategy id for each worker, indexed by worker id.
    /// @return values_ Config value for each worker, indexed by worker id.
    /// @return datas_ Strategy-specific packed data for each worker, indexed by worker id.
    function getAllWorkerConfigs()
        external
        view
        returns (uint16 count, uint8[] memory strategies_, uint64[] memory values_, uint128[] memory datas_);

    /// @notice Return the current number of workers.
    /// @dev The protocol reads this value at epoch boundaries to determine how many
    ///      worker configs to fetch. Each worker `0 .. numWorkers()-1` is guaranteed
    ///      to have had a config explicitly written.
    function numWorkers() external view returns (uint16);
}
