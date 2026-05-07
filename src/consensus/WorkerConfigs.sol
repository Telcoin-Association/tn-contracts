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
    /// @notice Highest strategy id this contract accepts.
    /// @dev Must move in lockstep with the `WorkerFeeConfig` enum in
    ///      `tn-types::gas_accumulator` (0 = EIP-1559, 1 = Static).
    uint8 public constant MAX_STRATEGY = 1;

    /// @notice The number of workers (used by protocol at epoch boundaries).
    uint16 public numWorkers;

    /// @notice Per-worker fee config.
    /// @dev strategy is a raw uint8 used by the protocol to map strategies.
    /// @dev value is a raw uint64 used by the strategy ("target gas" for EIP1559, "flat fee" for static, etc).
    /// @dev data is reserved space for packing data for the protocol.
    struct WorkerConfig {
        uint8 strategy;
        uint64 value;
        uint128 data;
    }

    /// @notice Per-worker config storage.
    mapping(uint256 => WorkerConfig) internal _workerConfigs;

    /// @notice Tracks whether a worker id has ever had a config explicitly written.
    /// @dev Lets us treat zero values as legal data (e.g. `Static{fee: 0}`) while still
    ///      detecting "never configured" workers in `setNumWorkers`.
    mapping(uint256 => bool) internal _workerConfigSet;

    /// @notice Deploy with initial configs for every worker.
    /// @dev Reverts `NumWorkersBelowMinimum()` if `strategies` is empty.
    ///      Reverts `LengthMismatch()` if array lengths differ.
    ///      Reverts `InvalidStrategy(strategy)` if any strategy > `MAX_STRATEGY`.
    /// @param strategies Array of strategy ids, one per worker (index = workerId).
    /// @param values Array of config values, one per worker.
    /// @param datas Array of strategy-specific packed data, one per worker.
    /// @param owner_ The address that will own this contract.
    constructor(
        uint8[] memory strategies,
        uint64[] memory values,
        uint128[] memory datas,
        address owner_
    )
        Ownable(owner_)
    {
        uint16 count = uint16(strategies.length);
        if (count == 0) revert NumWorkersBelowMinimum();
        if (count != values.length || count != datas.length) revert LengthMismatch();
        numWorkers = count;

        for (uint256 i; i < count; i++) {
            if (strategies[i] > MAX_STRATEGY) revert InvalidStrategy(strategies[i]);
            _workerConfigs[i] = WorkerConfig({ strategy: strategies[i], value: values[i], data: datas[i] });
            _workerConfigSet[i] = true;
            emit WorkerConfigUpdated(uint16(i), strategies[i], values[i], datas[i]);
        }
    }

    /// @inheritdoc IWorkerConfigs
    function setNumWorkers(uint16 numWorkers_) external onlyOwner {
        if (numWorkers_ == 0) revert NumWorkersBelowMinimum();
        if (numWorkers_ == numWorkers) revert NumWorkersUnchanged();

        // Validate that every worker 0..numWorkers_-1 has had a config explicitly set.
        for (uint256 i; i < numWorkers_; i++) {
            if (!_workerConfigSet[i]) revert MissingWorkerConfig(i);
        }

        uint16 oldValue = numWorkers;
        numWorkers = numWorkers_;
        emit NumWorkersUpdated(oldValue, numWorkers_);
    }

    /// @inheritdoc IWorkerConfigs
    function setWorkerConfig(uint16 workerId, uint8 strategy, uint64 value, uint128 data) external onlyOwner {
        if (strategy > MAX_STRATEGY) revert InvalidStrategy(strategy);
        _workerConfigs[workerId] = WorkerConfig({ strategy: strategy, value: value, data: data });
        _workerConfigSet[workerId] = true;
        emit WorkerConfigUpdated(workerId, strategy, value, data);
    }

    /// @inheritdoc IWorkerConfigs
    function setWorkerConfigsBatch(
        uint16[] calldata workerIds,
        uint8[] calldata strategies,
        uint64[] calldata values,
        uint128[] calldata datas
    )
        external
        onlyOwner
    {
        if (
            workerIds.length != strategies.length || workerIds.length != values.length
                || workerIds.length != datas.length
        ) {
            revert LengthMismatch();
        }
        for (uint256 i; i < workerIds.length; i++) {
            if (strategies[i] > MAX_STRATEGY) revert InvalidStrategy(strategies[i]);
            _workerConfigs[workerIds[i]] = WorkerConfig({ strategy: strategies[i], value: values[i], data: datas[i] });
            _workerConfigSet[workerIds[i]] = true;
            emit WorkerConfigUpdated(workerIds[i], strategies[i], values[i], datas[i]);
        }
    }

    /// @inheritdoc IWorkerConfigs
    function getWorkerConfig(uint16 workerId) external view returns (uint8 strategy, uint64 value, uint128 data) {
        WorkerConfig storage c = _workerConfigs[workerId];
        return (c.strategy, c.value, c.data);
    }

    /// @inheritdoc IWorkerConfigs
    function getAllWorkerConfigs()
        external
        view
        returns (uint16 count, uint8[] memory strategies_, uint64[] memory values_, uint128[] memory datas_)
    {
        count = numWorkers;
        strategies_ = new uint8[](count);
        values_ = new uint64[](count);
        datas_ = new uint128[](count);
        for (uint256 i; i < count; i++) {
            WorkerConfig storage c = _workerConfigs[i];
            strategies_[i] = c.strategy;
            values_[i] = c.value;
            datas_[i] = c.data;
        }
    }
}
