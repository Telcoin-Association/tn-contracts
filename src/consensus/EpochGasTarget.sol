// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IEpochGasTarget} from "../interfaces/IEpochGasTarget.sol";

/// @title EpochGasTarget
/// @notice Manages per-epoch gas targets for workers. The owner can set a default gas target and
/// per-worker overrides. Workers without an override fall back to the default.
contract EpochGasTarget is Ownable, IEpochGasTarget {
    /// @notice The default gas target applied to workers without a specific override.
    uint64 public defaultTargetGas;

    /// @notice Per-worker gas target overrides. A zero value means no override is set.
    mapping(uint16 => uint64) internal _workerTargetGas;

    /// @notice Deploy with an initial default gas target and contract owner.
    /// @param defaultTargetGas_ The initial default gas target (must be non-zero).
    /// @param owner_ The address that will own this contract.
    constructor(uint64 defaultTargetGas_, address owner_) Ownable(owner_) {
        if (defaultTargetGas_ == 0) revert ZeroTargetGas();
        defaultTargetGas = defaultTargetGas_;
    }

    /// @inheritdoc IEpochGasTarget
    function setDefaultTargetGas(uint64 targetGas) external onlyOwner {
        if (targetGas == 0) revert ZeroTargetGas();
        defaultTargetGas = targetGas;
    }

    /// @inheritdoc IEpochGasTarget
    function setWorkerTargetGas(uint16 workerId, uint64 targetGas) external onlyOwner {
        if (targetGas == 0) revert ZeroTargetGas();
        _workerTargetGas[workerId] = targetGas;
    }

    /// @inheritdoc IEpochGasTarget
    function clearWorkerTargetGas(uint16 workerId) external onlyOwner {
        delete _workerTargetGas[workerId];
    }

    /// @inheritdoc IEpochGasTarget
    function getTargetGas(uint16 workerId) external view returns (uint64) {
        uint64 t = _workerTargetGas[workerId];
        return t > 0 ? t : defaultTargetGas;
    }
}
