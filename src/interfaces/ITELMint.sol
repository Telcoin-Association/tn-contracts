// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

/// @title ITELMint
/// @notice Testnet-only interface for minting native TEL tokens
/// @dev Used by the StakeManager to fund staking reward distributions
// testnet only
interface ITELMint {
    /// @notice Mints native TEL tokens to the specified recipient
    /// @param recipient The address that will receive the minted TEL
    /// @param amount The amount of TEL to mint
    function mint(address recipient, uint256 amount) external;
}
