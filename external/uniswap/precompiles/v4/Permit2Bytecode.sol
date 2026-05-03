// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

// Stub for canonical Permit2 creation bytecode.
//
// PERMIT2_CREATION_BYTECODE is intentionally empty in this commit. Permit2's
// canonical universal address (0x000000000022D473030F116dDEE9F6B43aC78BA3)
// is reproducible across chains only when Arachnid CREATE2 is fed:
//   - The exact creation bytecode produced by compiling the Permit2 source
//     at the canonical commit (Uniswap/permit2 @ cc306b6) under
//     solc 0.8.17 + via_ir + 1_000_000 optimizer runs + bytecode_hash=none.
//   - The canonical salt
//     0x0000000000000000000000000000000000000000d3af2663da51c10215000000.
//
// We cannot compile that bytecode under tn-contracts' pinned 0.8.26 / 200-runs
// settings without producing a different keccak256, which would shift the
// CREATE2 address off canonical. The deploy script reverts when this stub is
// empty rather than silently deploying Permit2 at a non-canonical address.
//
// To populate this stub:
//
//   1. Clone Uniswap/permit2 at commit cc306b601f172c51bc04334a109e98340456620b
//      (the tag named after the canonical address itself).
//   2. Run `forge build` against that repo with its own foundry.toml
//      (solc 0.8.17, via_ir, optimizer_runs=1_000_000, bytecode_hash=none).
//   3. Copy `out/Permit2.sol/Permit2.json`'s `bytecode.object` field.
//   4. Paste it as the hex literal below (drop the 0x prefix).
//   5. Verify the resulting CREATE2 address is exactly
//      0x000000000022D473030F116dDEE9F6B43aC78BA3 by running
//      TestnetDeployUniswapV4.s.sol against a local fork before broadcasting.
//
// Alternative: extract the creation bytecode from the canonical Permit2 deploy
// transaction on Ethereum mainnet via an archive RPC (the calldata to the
// Arachnid factory IS `salt || creationCode`).
//
// Until populated, the V4 deploy script's Permit2 step short-circuits with a
// clear error pointing back to this file. The orchestrator gates on the
// bytecode being non-empty, so the V4 step is skipped (with a "deferred"
// message) on a fresh chain until the populate step lands.
contract Permit2Bytecode {
    bytes public constant PERMIT2_CREATION_BYTECODE = hex"";

    // Canonical CREATE2 salt that, combined with the bytecode above and the
    // Arachnid deployer address, yields 0x000000000022D473030F116dDEE9F6B43aC78BA3.
    // Pinned by Uniswap's permit2 deploy script:
    //   https://github.com/Uniswap/permit2/blob/cc306b6/script/DeployPermit2.s.sol
    bytes32 public constant PERMIT2_CANONICAL_SALT =
        bytes32(uint256(0x0000000000000000000000000000000000000000d3af2663da51c10215000000));

    address public constant PERMIT2_CANONICAL_ADDRESS =
        0x000000000022D473030F116dDEE9F6B43aC78BA3;
}
