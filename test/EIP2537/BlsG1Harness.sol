// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BlsG1 } from "../../src/consensus/BlsG1.sol";

/// @title BlsG1 Test Harness
/// @notice Extends BlsG1 library with functions beyond those used for TN PoP
/// @author Telcoin Association

contract BlsG1Harness {
    using BlsG1 for bytes;

    /// @notice Never do this onchain in production!! Only for testing
    /// @dev Returns a 96-byte compressed G2 key whose x-coordinate matches the real uncompressed key for
    /// `secret`, so it satisfies `ConsensusRegistry`'s compressed/uncompressed alignment check. blst's
    /// compressed form is `x.c1 || x.c0` (the uncompressed key's first 96 bytes) with the compression flag
    /// in byte 0's most-significant bit; the y-sign bit is irrelevant to the on-chain x-match, so only the
    /// compression flag is set (this is not necessarily the exact blst compressed key, but its x matches).
    function _blsDummyPubkeyFromSecret(uint256 secret) internal view returns (bytes memory) {
        bytes memory uncompressed = BlsG1.decodeG2PointFromEIP2537(_blsEIP2537PubkeyFromSecret(secret));
        bytes memory compressed = new bytes(96);
        for (uint256 i; i < 96; ++i) {
            compressed[i] = uncompressed[i];
        }
        compressed[0] = compressed[0] | 0x80; // set blst compression flag in the top bit of byte 0

        return compressed;
    }

    /// @notice Never do this onchain in production!! Only for testing
    function _blsEIP2537PubkeyFromSecret(uint256 secret) internal view returns (bytes memory) {
        return BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, secret);
    }

    /// @notice Never do this onchain in production!! Only for testing
    function _blsEIP2537SignatureFromSecret(
        uint256 secret,
        bytes memory message
    )
        internal
        view
        returns (bytes memory)
    {
        bytes memory g1MsgHash = message.hashToG1(BlsG1.HASH_TO_G1_DST);
        return BlsG1.scalarMulG1(g1MsgHash, secret);
    }
}
