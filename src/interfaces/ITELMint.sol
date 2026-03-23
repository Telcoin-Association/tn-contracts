// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

// testnet only
interface ITELMint {
    function mint(address recipient, uint256 amount) external;
}
