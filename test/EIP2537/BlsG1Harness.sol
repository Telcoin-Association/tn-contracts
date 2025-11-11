// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BlsG1 } from "../../src/consensus/BlsG1.sol";

/// @title BlsG1 Test Harness
/// @notice Extends BlsG1 library with functions beyond those used for TN PoP
/// @author Telcoin Association

contract BlsG1Harness {
    using BlsG1 for bytes;

    /// @dev Not used for TN's G1 verification schema but required for testing
    address constant BLS12_G1MSM = address(0x0C);
    address constant BLS12_G2MSM = address(0x0E);
    bytes constant G1_GENERATOR =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    bytes constant G2_GENERATOR =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    /// @dev Scalar multiply the G1 curve point using the `EIP2537::BLS12_G1MSM` precompile
    /// @notice Included as a test helper for BLS12-381 cryptographic arithmetic within EVM context
    /// **Never do this onchain in production to derive a public key using a secret key! Testing only!**
    /// @return _ The resulting G1 point after scalar multiplication
    function mulG1(bytes memory g1Point, uint256 scalar) internal view returns (bytes memory) {
        bytes memory input = bytes.concat(g1Point, bytes32(scalar));
        (bool r, bytes memory res) = BLS12_G1MSM.staticcall(input);
        if (!r) revert BlsG1.LowLevelCallFailure(res);

        return res;
    }

    /// @dev Scalar multiply the G2 curve point using the `EIP2537::BLS12_G2MSM` precompile
    /// @notice Included as a test helper for BLS12-381 cryptographic arithmetic within EVM context
    /// **Never do this onchain in production to derive a public key using a secret key! Testing only!**
    /// @return _ The resulting G2 point after scalar multiplication
    function mulG2(bytes memory g2Point, uint256 scalar) internal view returns (bytes memory) {
        bytes memory input = bytes.concat(g2Point, bytes32(scalar));
        (bool r, bytes memory res) = BLS12_G2MSM.staticcall(input);
        if (!r) revert BlsG1.LowLevelCallFailure(res);

        return res;
    }

    /// @dev Convert EIP2537-encoded G1 point (128 bytes) to uncompressed format (96 bytes)
    function eip2537PointG1ToUncompressed(bytes memory eip2537PointG1) internal pure returns (bytes memory) {
        if (eip2537PointG1.length != BlsG1.EIP2537_G1_POINT_SIZE) {
            revert BlsG1.InvalidPoint(eip2537PointG1.length, BlsG1.EIP2537_G1_POINT_SIZE);
        }

        bytes memory uncompressedPointG1 = new bytes(96);

        for (uint256 i; i < BlsG1.FIELD_ELEMENT_SIZE; ++i) {
            // extract x coordinate (skip first 16 padding bytes)
            uncompressedPointG1[i] = eip2537PointG1[16 + i];
            // extract y coordinate (skip padding at byte 64)
            uncompressedPointG1[48 + i] = eip2537PointG1[80 + i];
        }

        return uncompressedPointG1;
    }

    /// @dev Convert EIP2537-encoded G2 point (256 bytes) to uncompressed format (192 bytes)
    function eip2537PointG2ToUncompressed(bytes memory eip2537PointG2) internal pure returns (bytes memory) {
        if (eip2537PointG2.length != BlsG1.EIP2537_G2_POINT_SIZE) {
            revert BlsG1.InvalidPoint(eip2537PointG2.length, BlsG1.EIP2537_G2_POINT_SIZE);
        }

        bytes memory uncompressedPointG2 = new bytes(192);

        // reorder from EIP2537 (x.c0 || x.c1 || y.c0 || y.c1) to BLST (x.c1 || x.c0 || y.c1 || y.c0)
        for (uint256 i; i < BlsG1.FIELD_ELEMENT_SIZE; ++i) {
            // x.c1 <- eip2537PointG2[64:112] (skip 16 padding bytes at 64)
            uncompressedPointG2[i] = eip2537PointG2[80 + i];
            // x.c0 <- eip2537PointG2[0:48] (skip 16 padding bytes at 0)
            uncompressedPointG2[48 + i] = eip2537PointG2[16 + i];
            // y.c1 <- eip2537PointG2[192:240] (skip 16 padding bytes at 192)
            uncompressedPointG2[96 + i] = eip2537PointG2[208 + i];
            // y.c0 <- eip2537PointG2[128:176] (skip 16 padding bytes at 128)
            uncompressedPointG2[144 + i] = eip2537PointG2[144 + i];
        }

        return uncompressedPointG2;
    }

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
        return mulG2(G2_GENERATOR, secret);
    }

    /// @notice Never do this onchain in production!! Only for testing
    function _blsEIP2537SignatureFromSecret(uint256 secret, bytes memory message) internal view returns (bytes memory) {
        bytes memory g1MsgHash = message.hashToG1();
        return mulG1(g1MsgHash, secret);
    }
}
