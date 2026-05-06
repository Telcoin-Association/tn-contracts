// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title IWETH9
/// @notice Canonical wrapped-native interface. Mirrors the IWETH9 surface that
///         Uniswap V3 / V4 periphery and the position descriptors expect at
///         their constructor `_WETH9` argument.
interface IWETH9 is IERC20 {
    /// @notice Deposit native value to mint an equal amount of wrapped balance.
    function deposit() external payable;

    /// @notice Burn `wad` wrapped balance and return the same amount of native.
    function withdraw(uint256 wad) external;
}
