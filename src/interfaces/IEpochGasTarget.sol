// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

/// @title IEpochGasTarget
/// @notice Interface for managing per-epoch gas targets. A default target applies to all workers
/// unless a per-worker override is set.
interface IEpochGasTarget {
    /// @notice Thrown when a zero value is provided for a gas target.
    error ZeroTargetGas();

    /// @notice Emitted when the default gas target is updated.
    event DefaultTargetGasUpdated(uint64 oldValue, uint64 newValue);

    /// @notice Emitted when a worker's gas target override is set.
    event WorkerTargetGasUpdated(uint16 indexed workerId, uint64 oldValue, uint64 newValue);

    /// @notice Emitted when a worker's gas target override is cleared.
    event WorkerTargetGasCleared(uint16 indexed workerId);

    /// @notice Set the default gas target used by workers without an override.
    /// @param targetGas The new default gas target (must be non-zero).
    function setDefaultTargetGas(uint64 targetGas) external;

    /// @notice Set a gas target override for a specific worker.
    /// @param workerId The worker identifier.
    /// @param targetGas The gas target for this worker (must be non-zero).
    function setWorkerTargetGas(uint16 workerId, uint64 targetGas) external;

    /// @notice Remove a worker's gas target override, reverting it to the default.
    /// @param workerId The worker identifier.
    function clearWorkerTargetGas(uint16 workerId) external;

    /// @notice Return the effective gas target for a worker. Returns the worker-specific override
    /// if one is set, otherwise returns the default.
    /// @param workerId The worker identifier.
    /// @return The effective gas target.
    function getTargetGas(uint16 workerId) external view returns (uint64);

    /// @notice Return the default gas target.
    /// @return The default gas target.
    function defaultTargetGas() external view returns (uint64);
}
