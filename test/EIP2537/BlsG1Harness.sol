// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BlsG1 } from "../../src/consensus/BlsG1.sol";

/// @title BlsG1 Test Harness
/// @notice Extends BlsG1 library with functions beyond those used for TN PoP
/// @author Telcoin Association

contract BlsG1Harness {
    using BlsG1 for bytes;

    /// @notice Never do this onchain in production!! Only for testing
    /// @dev Returns a *dummy* BLS public key simulating the compressed representation of `_blsEIP2537PubkeyFromSecret`
    /// This is not a valid BLS public key but required for testing to pass length checks
    function _blsDummyPubkeyFromSecret(uint256 secret) internal view returns (bytes memory) {
        bytes32 eip2537PubkeyHash = keccak256(_blsEIP2537PubkeyFromSecret(secret));
        bytes memory dummyPubkey = bytes.concat(eip2537PubkeyHash, eip2537PubkeyHash, eip2537PubkeyHash);

        return dummyPubkey;
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
