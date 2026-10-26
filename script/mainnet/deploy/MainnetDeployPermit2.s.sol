// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Permit2Bytecode } from "external/uniswap/precompiles/v4/Permit2Bytecode.sol";
import { MainnetDeployBase } from "../MainnetDeployBase.sol";

/// @title Deploy Permit2 on Telcoin Network mainnet
///
/// @notice Deploys Uniswap's Permit2 at its canonical cross-chain address
///         0x000000000022D473030F116dDEE9F6B43aC78BA3 through the Arachnid proxy with the
///         canonical salt. Permit2 is version-independent signature-based approval
///         infrastructure used by routers and aggregators; it has no owner and no dependency on
///         any Uniswap deployment.
///
/// @dev Permit2 fixes its EIP-712 chain id and domain separator at construction, so its runtime
///      bytes differ per chain; the canonical address (which pins the initcode) is the check.
///      Recorded under `uniswapV4.Permit2`, the address book's existing Permit2 key.
///
/// @dev Usage: `forge script script/mainnet/deploy/MainnetDeployPermit2.s.sol -vvvv \
///      --rpc-url $TN_MAINNET_RPC_URL --private-key $DEPLOYER_PK --broadcast`
contract MainnetDeployPermit2 is MainnetDeployBase, Permit2Bytecode {
    bytes32 internal constant PERMIT2_INITCODE_HASH =
        0xe2be1e05eedf35dacd66c65c862f8150ff9ab4b6b24b9bbe62be71b6b16cf0f8;

    function run() public {
        _loadMainnet();
        require(
            keccak256(PERMIT2_CREATION_BYTECODE) == PERMIT2_INITCODE_HASH,
            "MainnetDeployPermit2: vendored Permit2 initcode hash mismatch"
        );

        vm.startBroadcast();
        address permit2 = _deployDeterministic(PERMIT2_CANONICAL_SALT, PERMIT2_CREATION_BYTECODE, "Permit2");
        vm.stopBroadcast();

        require(permit2 == PERMIT2_CANONICAL_ADDRESS, "MainnetDeployPermit2: non-canonical Permit2 address");
        _record(".uniswapV4.Permit2", permit2);
    }
}
