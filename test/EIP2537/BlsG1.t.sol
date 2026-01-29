// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { BlsG1 } from "../../src/consensus/BlsG1.sol";
import { BlsG1Harness } from "../EIP2537/BlsG1Harness.sol";

/// @notice Test suite for BLS12-381 G1 Proof of Possession
/// @dev Resource for verifying G1: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.1

contract BlsG1Test is Test, BlsG1Harness {
    bytes5 constant POP_INTENT_PREFIX = 0x000000d501;
    bytes1 constant ADDRESS_LEN_PREFIX = 0x14;

    function proofOfPossessionMessage(
        bytes memory blsPubkey,
        address validatorAddress
    )
        public
        view
        returns (bytes memory)
    {
        bytes memory blsPubkeyEIP2537 = BlsG1.encodeG2PointForEIP2537(blsPubkey);
        if (!BlsG1.validatePointG2(blsPubkeyEIP2537)) revert BlsG1.InvalidBLSPubkey();

        return bytes.concat(POP_INTENT_PREFIX, blsPubkey, ADDRESS_LEN_PREFIX, bytes20(validatorAddress));
    }

    function test_verifyProofOfPossessionG1(address fuzzValidator, uint256 sk) public view {
        vm.assume(sk > 0);

        /// @notice Never do this onchain in production!! Only for fuzz testing
        bytes memory fuzzedBLSPubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory message = bytes.concat(fuzzedBLSPubkey, bytes20(fuzzValidator));

        // craft proof of possession
        bytes memory g1MsgHash = BlsG1.hashToG1(message, BlsG1.HASH_TO_G1_DST);
        bytes memory g1Signature = BlsG1.scalarMulG1(g1MsgHash, sk);

        assertTrue(BlsG1.verifyProofOfPossessionG1(fuzzedBLSPubkey, g1Signature, message, BlsG1.HASH_TO_G1_DST));
    }

    function test_verifyProofOfPossessionG1_negative(address fuzzValidator, uint256 sk) public view {
        vm.assume(sk > 0);

        /// @notice Never do this onchain in production!! Only for fuzz testing
        bytes memory fuzzedBLSPubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory message = bytes.concat(fuzzedBLSPubkey, bytes20(fuzzValidator));

        // craft proof of possession
        bytes memory g1MsgHash = BlsG1.hashToG1(message, BlsG1.HASH_TO_G1_DST);
        bytes memory g1Signature = BlsG1.scalarMulG1(g1MsgHash, sk);

        // mutated pubkey should fail
        uint256 fakeSK = uint256(keccak256(abi.encodePacked(sk)));
        bytes memory fakePubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, fakeSK);
        assertFalse(BlsG1.verifyProofOfPossessionG1(fakePubkey, g1Signature, message, BlsG1.HASH_TO_G1_DST));

        // mutated signature should fail
        bytes memory fakeSignature = BlsG1.scalarMulG1(g1MsgHash, fakeSK);
        assertFalse(BlsG1.verifyProofOfPossessionG1(fuzzedBLSPubkey, fakeSignature, message, BlsG1.HASH_TO_G1_DST));

        // mutated message should fail
        bytes memory fakeMessage = bytes("DEADBEEF");
        assertFalse(BlsG1.verifyProofOfPossessionG1(fuzzedBLSPubkey, g1Signature, fakeMessage, BlsG1.HASH_TO_G1_DST));
    }

    function test_verifyProofOfPossessionG1_zeroPoint() public {
        // use zero points
        bytes memory zeroG2Pubkey = BlsG1.G2_IDENTITY; // 256 bytes of zeros
        bytes memory zeroG1Signature = BlsG1.G1_IDENTITY; // 128 bytes of zeros

        // invalid message fails
        bytes memory message1 = bytes("pop message");
        vm.expectRevert(BlsG1.InvalidBLSPubkey.selector);
        BlsG1.verifyProofOfPossessionG1(zeroG2Pubkey, zeroG1Signature, message1, BlsG1.HASH_TO_G1_DST);

        // test with valid pubkey but zero signature
        uint256 sk = 54_321;
        bytes memory validPubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory message2 = bytes.concat(validPubkey, bytes20(address(0x33)));

        vm.expectRevert();
        BlsG1.verifyProofOfPossessionG1(validPubkey, zeroG1Signature, message2, BlsG1.HASH_TO_G1_DST);
    }

    // Helper function to create invalid length pubkeys
    function createInvalidLengthPubkey(uint256 length) internal pure returns (bytes memory) {
        bytes memory invalidPubkey = new bytes(length);
        // Fill with some dummy data
        for (uint256 i = 0; i < length; i++) {
            invalidPubkey[i] = bytes1(uint8(i % 256));
        }
        return invalidPubkey;
    }

    // Helper function to truncate existing valid pubkey
    function truncatePubkey(bytes memory validPubkey, uint256 newLength) internal pure returns (bytes memory) {
        require(newLength < validPubkey.length, "New length must be shorter");
        bytes memory truncated = new bytes(newLength);
        for (uint256 i = 0; i < newLength; i++) {
            truncated[i] = validPubkey[i];
        }
        return truncated;
    }

    function test_invalidPubkeyLength_tooShort() public {
        address validator = address(0x123);

        // test various lengths that are too short (< 96 bytes)
        uint256[] memory invalidLengths = new uint256[](5);
        invalidLengths[0] = 0; // Empty
        invalidLengths[1] = 32; // 32 bytes
        invalidLengths[2] = 48; // 48 bytes
        invalidLengths[3] = 64; // 64 bytes
        invalidLengths[4] = 95; // Just 1 byte short

        for (uint256 i = 0; i < invalidLengths.length; i++) {
            bytes memory invalidPubkey = createInvalidLengthPubkey(invalidLengths[i]);

            // This should revert due to invalid length
            vm.expectRevert(3);
            proofOfPossessionMessage(invalidPubkey, validator);
        }
    }

    function test_invalidPubkeyLength_tooLong() public {
        address validator = address(0x123);

        // Test lengths that are too long (> 96 bytes)
        uint256[] memory invalidLengths = new uint256[](4);
        invalidLengths[0] = 97; // Just 1 byte too long
        invalidLengths[1] = 128; // 128 bytes
        invalidLengths[2] = 192; // 192 bytes
        invalidLengths[3] = 256; // 256 bytes

        for (uint256 i = 0; i < invalidLengths.length; i++) {
            bytes memory invalidPubkey = createInvalidLengthPubkey(invalidLengths[i]);

            vm.expectRevert(3);
            proofOfPossessionMessage(invalidPubkey, validator);
        }
    }

    function test_invalidPubkeyLength_truncatedValidKey() public {
        // generate a valid pubkey first
        uint256 sk = 12_345;
        bytes memory validPubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        address validator = address(0x123);

        // truncate to various invalid lengths
        uint256[] memory truncateLengths = new uint256[](3);
        truncateLengths[0] = 32;
        truncateLengths[1] = 64;
        truncateLengths[2] = 95;

        for (uint256 i = 0; i < truncateLengths.length; i++) {
            bytes memory truncatedPubkey = truncatePubkey(validPubkey, truncateLengths[i]);

            vm.expectRevert(3);
            proofOfPossessionMessage(truncatedPubkey, validator);
        }
    }

    function test_invalidPubkeyLength_fuzzed(uint8 invalidLength) public {
        // Fuzz test with random invalid lengths
        vm.assume(invalidLength != 192); // valid uncompressed length
        vm.assume(invalidLength < 200); // reasonable for gas costs

        address validator = address(0x123);
        bytes memory invalidPubkey = createInvalidLengthPubkey(invalidLength);

        vm.expectRevert(3);
        proofOfPossessionMessage(invalidPubkey, validator);
    }
}
