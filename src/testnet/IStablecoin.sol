// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import {ERC20PermitUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";

/// @title Interface for Telcoin-Contracts Stablecoins
/// @notice This is a lightweight interface used to call TN stablecoin ERC20s
interface IStablecoin {
    function initialize(
        string memory name_,
        string memory symbol_,
        uint8 decimals_
    ) external;

    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function decimals() external view returns (uint256);

    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function allowance(
        address owner,
        address spender
    ) external view returns (uint256);

    function approve(address spender, uint256 value) external returns (bool);

    function transfer(address to, uint256 value) external returns (bool);

    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool);

    function mint(uint256 value) external;

    function mintTo(address account, uint256 value) external;

    function burn(uint256 value) external;

    function burnFrom(address account, uint256 value) external;

    function blacklisted(address user) external view returns (bool);

    function addBlackList(address user) external;

    function removeBlackList(address user) external;

    function erc20Rescue(
        ERC20PermitUpgradeable token,
        address destination,
        uint256 amount
    ) external;
}
