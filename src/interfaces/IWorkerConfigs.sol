// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

/// @title IWorkerConfigs
/// @notice Interface for a strategy-agnostic per-worker fee config store.
///
/// Every worker `0 .. numWorkers-1` must have a config whose `value >= MIN_GAS`.
/// The `strategy` field is a raw `uint8` stored without contract interpretation;
/// the protocol layer handles strategy semantics (e.g. EIP-1559 vs Static).
interface IWorkerConfigs {
    // ── Constants ────────────────────────────────────────────────────────

    /// @notice Absolute minimum gas value any worker config may hold.
    /// @dev Matches `MIN_PROTOCOL_BASE_FEE` on the Rust side (7 wei).
    function MIN_GAS() external pure returns (uint64);

    // ── Errors ──────────────────────────────────────────────────────────

    /// @notice Thrown when a config value is below `MIN_GAS`.
    /// @param value The rejected value.
    error ValueBelowMinGas(uint64 value);

    /// @notice Thrown when `setNumWorkers` is called but worker `workerId` has no config set.
    /// @param workerId The worker missing a config.
    error MissingWorkerConfig(uint16 workerId);

    /// @notice Thrown when constructor array lengths do not match.
    error LengthMismatch();

    /// @notice Thrown when the number of workers is set to zero.
    error NumWorkersBelowMinimum();

    /// @notice Thrown when `setNumWorkers` is called with the current value.
    error NumWorkersUnchanged();

    /// @notice Thrown when the strategies array length exceeds `type(uint16).max`.
    error TooManyWorkers();

    // ── Events ──────────────────────────────────────────────────────────

    /// @notice Emitted when a worker's config is created or updated.
    /// @param workerId The worker identifier.
    /// @param strategy The raw strategy id.
    /// @param value The config value (must be >= MIN_GAS).
    event WorkerConfigUpdated(uint16 indexed workerId, uint8 strategy, uint64 value);

    /// @notice Emitted when the number of workers changes.
    /// @param oldValue Previous worker count.
    /// @param newValue New worker count.
    event NumWorkersUpdated(uint16 oldValue, uint16 newValue);

    // ── Mutators ────────────────────────────────────────────────────────

    /// @notice Set the number of workers.
    /// @dev Reverts with `MissingWorkerConfig(i)` if any worker `0 .. numWorkers_-1`
    ///      has a config with `value < MIN_GAS` (including unset entries whose value is 0).
    /// @param numWorkers_ The new worker count.
    function setNumWorkers(uint16 numWorkers_) external;

    /// @notice Set or update the fee config for a specific worker.
    /// @dev Allows setting configs for any `workerId`, including those beyond the
    ///      current `numWorkers`. Coverage is validated when `setNumWorkers` is called.
    /// @param workerId The worker identifier.
    /// @param strategy The raw strategy id (stored without interpretation).
    /// @param value The config value (must be >= MIN_GAS).
    function setWorkerConfig(uint16 workerId, uint8 strategy, uint64 value) external;

    // ── Views ───────────────────────────────────────────────────────────

    /// @notice Return the stored config for a worker.
    /// @dev Returns `(0, 0)` for workers that have never been configured.
    /// @param workerId The worker identifier.
    /// @return strategy The raw strategy id.
    /// @return value The config value.
    function getWorkerConfig(uint16 workerId) external view returns (uint8 strategy, uint64 value);

    /// @notice Return the current number of workers.
    /// @dev The protocol reads this value at epoch boundaries to determine how many
    ///      worker configs to fetch. Each worker `0 .. numWorkers()-1` is guaranteed
    ///      to have a config with `value >= MIN_GAS`.
    function numWorkers() external view returns (uint16);
}
