// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.26;

/// @notice Resolves the per-network deployments json by chain id so a script
///         pointed at a devnet RPC can never read or write the testnet address book.
/// @dev Genesis-assigned addresses (Safe infrastructure, ConsensusRegistry, magic
///      addresses) are identical across networks because every network shares the
///      same genesis configuration; only script-deployed addresses diverge, which
///      is why each network keeps its own json.
library DeploymentsResolver {
    /// @notice Adiri testnet
    uint256 internal constant TESTNET_CHAIN_ID = 0x7e1; // 2017
    /// @notice Devnet, reset frequently to validate changes against a fresh genesis
    uint256 internal constant DEVNET_CHAIN_ID = 0x7e1d; // 32285
    // TODO: add MAINNET_CHAIN_ID and its mapping below once the mainnet chain id is
    // finalized. Until then deployments-mainnet.json (genesis-assigned addresses only)
    // serves as the genesis source of truth consumed by GenerateGenesisPrecompileConfig.

    /// @notice Returns the deployments json path relative to the project root
    /// @dev Defaults to the testnet file for all other chain ids (testnet itself,
    ///      local simulations, and tests), preserving pre-devnet behavior
    ///      everywhere except on a devnet fork
    function relativePath() internal view returns (string memory) {
        if (block.chainid == DEVNET_CHAIN_ID) return "/deployments/deployments-devnet.json";
        return "/deployments/deployments-testnet.json";
    }
}
