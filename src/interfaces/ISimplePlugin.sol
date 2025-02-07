// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface ISimplePlugin is IERC165 {
    function increaseClaimableBy(address account, uint256 amount) external returns (bool);
    function tel() external view returns (IERC20);
    function totalClaimable() external view returns (uint256);
    function deactivated() external view returns (bool);
}
