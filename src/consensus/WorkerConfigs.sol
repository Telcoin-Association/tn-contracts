// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IWorkerConfigs} from "../interfaces/IWorkerConfigs.sol";

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
contract WorkerConfigs is Ownable, IWorkerConfigs {
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
    mapping(uint16 => WorkerConfig) internal _workerConfigs;

    /// @notice Deploy with initial configs for every worker.
    /// @dev Reverts `LengthMismatch()` if array lengths differ.
    ///      Reverts `ValueBelowMinGas(value)` if any value < MIN_GAS.
    /// @param strategies Array of strategy ids, one per worker (index = workerId).
    /// @param values Array of config values, one per worker.
    /// @param owner_ The address that will own this contract.
    constructor(uint8[] memory strategies, uint64[] memory values, address owner_) Ownable(owner_) {
        if (strategies.length != values.length) revert LengthMismatch();
        if (strategies.length > type(uint16).max) revert TooManyWorkers();

        uint16 count = uint16(strategies.length);
        if (count < 1) revert NumWorkersBelowMinimum();
        numWorkers = count;

        for (uint16 i = 0; i < count; i++) {
            if (values[i] < MIN_GAS) revert ValueBelowMinGas(values[i]);
            _workerConfigs[i] = WorkerConfig({strategy: strategies[i], value: values[i]});
            emit WorkerConfigUpdated(i, strategies[i], values[i]);
        }
    }

    /// @inheritdoc IWorkerConfigs
    function setNumWorkers(uint16 numWorkers_) external onlyOwner {
        if (numWorkers_ < 1) revert NumWorkersBelowMinimum();

        // Validate that every worker 0..numWorkers_-1 has a valid config.
        for (uint16 i = 0; i < numWorkers_; i++) {
            if (_workerConfigs[i].value < MIN_GAS) revert MissingWorkerConfig(i);
        }

        uint16 oldValue = numWorkers;
        numWorkers = numWorkers_;
        emit NumWorkersUpdated(oldValue, numWorkers_);
    }

    /// @inheritdoc IWorkerConfigs
    function setWorkerConfig(uint16 workerId, uint8 strategy, uint64 value) external onlyOwner {
        if (value < MIN_GAS) revert ValueBelowMinGas(value);
        _workerConfigs[workerId] = WorkerConfig({strategy: strategy, value: value});
        emit WorkerConfigUpdated(workerId, strategy, value);
    }

    /// @inheritdoc IWorkerConfigs
    function getWorkerConfig(uint16 workerId) external view returns (uint8 strategy, uint64 value) {
        WorkerConfig storage c = _workerConfigs[workerId];
        return (c.strategy, c.value);
    }
}
