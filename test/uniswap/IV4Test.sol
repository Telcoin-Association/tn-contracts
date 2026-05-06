// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

// Minimal V4 interface set for fork-test interactions. Hand-rolled because
// V4 source ships as bytecode literals in this repo (V4 needs via_ir +
// 44M optimizer-runs which can't be reconciled with this project's pinned
// solc settings). These mirror the canonical V4 ABIs at Uniswap/v4-core
// (commit 59d3ecf) + Uniswap/v4-periphery (commit 9dafaae).

/// @notice V4 currency type. The canonical v4-core uses a `Currency` user-defined
///         value type wrapping `address`. For test purposes we treat it as address.
type Currency is address;

/// @notice V4 PoolKey. The canonical struct from v4-core/src/types/PoolKey.sol.
///         Mirrors the Solidity layout exactly.
struct PoolKey {
    Currency currency0;
    Currency currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

interface IPoolManager {
    function initialize(PoolKey memory key, uint160 sqrtPriceX96) external returns (int24 tick);
    function unlock(bytes calldata data) external returns (bytes memory);
    function owner() external view returns (address);
}

interface IPositionManager {
    function poolManager() external view returns (address);
    function permit2() external view returns (address);
}

interface IV4Quoter {
    function poolManager() external view returns (address);
}

interface IStateView {
    function poolManager() external view returns (address);
    function getSlot0(bytes32 poolId)
        external
        view
        returns (uint160 sqrtPriceX96, int24 tick, uint24 protocolFee, uint24 lpFee);
    function getLiquidity(bytes32 poolId) external view returns (uint128 liquidity);
}
