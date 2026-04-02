// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { IWorkerConfigs } from "../interfaces/IWorkerConfigs.sol";

/// @title WorkerConfigs
/// @notice Strategy-agnostic per-worker fee config store.
///
/// The constructor atomically sets `numWorkers` and every worker's config,
/// guaranteeing full coverage from deployment. After deployment the owner can
/// update individual configs and resize the worker set (with coverage checks).
///
/// @dev Protocol usage: at each epoch boundary the execution layer reads
/// `numWorkers()` and iterates `getWorkerConfig(0 .. numWorkers-1)` to
/// build the per-worker fee parameters for the upcoming epoch. The contract
/// therefore acts as the on-chain source of truth for worker fee policy.
contract WorkerConfigs is Ownable2Step, IWorkerConfigs {
    /// @notice Absolute minimum gas value any worker config may hold (7 wei).
    uint64 public constant MIN_GAS = 7;

    /// @notice The number of workers (used by protocol at epoch boundaries).
    uint16 public numWorkers;

    /// @notice Per-worker fee config.
    /// @dev strategy is a raw uint8 used by the protocol to map strategies.
    /// @dev value must be >= MIN_GAS for configured workers.
    struct WorkerConfig {
        uint8 strategy;
        uint64 value;
    }

    /// @notice Per-worker config storage.
    mapping(uint256 => WorkerConfig) internal _workerConfigs;

    /// @notice Deploy with initial configs for every worker.
    /// @dev Reverts `LengthMismatch()` if array lengths differ.
    ///      Reverts `ValueBelowMinGas(value)` if any value < MIN_GAS.
    /// @param strategies Array of strategy ids, one per worker (index = workerId).
    /// @param values Array of config values, one per worker.
    /// @param owner_ The address that will own this contract.
    constructor(uint8[] memory strategies, uint64[] memory values, address owner_) Ownable(owner_) {
        uint16 count = uint16(strategies.length);
        if (count == 0) revert NumWorkersBelowMinimum();
        if (count != values.length) revert LengthMismatch();
        numWorkers = count;

        for (uint16 i; i < count; i++) {
            if (values[i] < MIN_GAS) revert ValueBelowMinGas(values[i]);
            _workerConfigs[i] = WorkerConfig({ strategy: strategies[i], value: values[i] });
            emit WorkerConfigUpdated(i, strategies[i], values[i]);
        }
    }

    /// @inheritdoc IWorkerConfigs
    function setNumWorkers(uint16 numWorkers_) external onlyOwner {
        if (numWorkers_ == 0) revert NumWorkersBelowMinimum();
        if (numWorkers_ == numWorkers) revert NumWorkersUnchanged();

        // Validate that every worker 0..numWorkers_-1 has a valid config.
        for (uint256 i; i < numWorkers_; i++) {
            if (_workerConfigs[i].value < MIN_GAS) revert MissingWorkerConfig(i);
        }

        uint16 oldValue = numWorkers;
        numWorkers = numWorkers_;
        emit NumWorkersUpdated(oldValue, numWorkers_);
    }

    /// @inheritdoc IWorkerConfigs
    function setWorkerConfig(uint16 workerId, uint8 strategy, uint64 value) external onlyOwner {
        if (value < MIN_GAS) revert ValueBelowMinGas(value);
        _workerConfigs[workerId] = WorkerConfig({ strategy: strategy, value: value });
        emit WorkerConfigUpdated(workerId, strategy, value);
    }

    /// @inheritdoc IWorkerConfigs
    function setWorkerConfigsBatch(
        uint16[] calldata workerIds,
        uint8[] calldata strategies,
        uint64[] calldata values
    )
        external
        onlyOwner
    {
        if (workerIds.length != strategies.length || workerIds.length != values.length) revert LengthMismatch();
        for (uint256 i; i < workerIds.length; i++) {
            if (values[i] < MIN_GAS) revert ValueBelowMinGas(values[i]);
            _workerConfigs[workerIds[i]] = WorkerConfig({ strategy: strategies[i], value: values[i] });
            emit WorkerConfigUpdated(workerIds[i], strategies[i], values[i]);
        }
    }

    /// @inheritdoc IWorkerConfigs
    function getWorkerConfig(uint16 workerId) external view returns (uint8 strategy, uint64 value) {
        WorkerConfig storage c = _workerConfigs[workerId];
        return (c.strategy, c.value);
    }
}
