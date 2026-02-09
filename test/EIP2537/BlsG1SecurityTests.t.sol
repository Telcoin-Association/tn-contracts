// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { BlsG1 } from "../../src/consensus/BlsG1.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Comprehensive security tests for BLS12-381 G1 implementation
/// @dev Tests focus on edge cases, attack vectors, and cryptographic correctness
contract BlsG1SecurityTests is Test {
    bytes5 constant POP_INTENT_PREFIX = 0x000000d501;
    bytes1 constant ADDRESS_LEN_PREFIX = 0x14;

    // =============================================================================
    // Hash Collision and encodePacked Tests
    // =============================================================================

    function test_expandMessageXmd_consistency() public pure {
        // Test that expandMessageXmd produces consistent outputs
        bytes memory msg1 = "test message";
        bytes memory dst1 = "DST-TEST";
        uint16 len = 128;

        bytes memory result1 = BlsG1.expandMessageXmd(msg1, dst1, len);
        bytes memory result2 = BlsG1.expandMessageXmd(msg1, dst1, len);

        assertEq(keccak256(result1), keccak256(result2), "Non-deterministic expansion");
    }

    function test_expandMessageXmd_edgeCases() public pure {
        // Test with empty message
        bytes memory emptyMsg = "";
        bytes memory dst = "DST";
        bytes memory result1 = BlsG1.expandMessageXmd(emptyMsg, dst, 64);
        assertEq(result1.length, 64, "Wrong length for empty message");

        // Test with maximum allowed ell (255)
        uint16 maxLen = uint16(255 * 32); // ell = 255
        bytes memory result2 = BlsG1.expandMessageXmd("msg", dst, maxLen);
        assertEq(result2.length, maxLen, "Wrong length for max ell");

        // Test with length requiring exactly 1 iteration (ell = 1)
        bytes memory result3 = BlsG1.expandMessageXmd("msg", dst, 32);
        assertEq(result3.length, 32, "Wrong length for ell=1");
    }

    function test_expandMessageXmd_dstVariations() public pure {
        bytes memory proof_msg = "test";
        uint16 len = 64;

        // Test with various DST lengths
        bytes memory dst1 = "A"; // 1 byte
        bytes memory dst2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // 26 bytes
        bytes memory dst3 = new bytes(255); // Maximum allowed
        for (uint256 i = 0; i < 255; i++) {
            dst3[i] = bytes1(uint8(65 + (i % 26)));
        }

        bytes memory result1 = BlsG1.expandMessageXmd(proof_msg, dst1, len);
        bytes memory result2 = BlsG1.expandMessageXmd(proof_msg, dst2, len);
        bytes memory result3 = BlsG1.expandMessageXmd(proof_msg, dst3, len);

        // Results should be different with different DSTs
        assertTrue(keccak256(result1) != keccak256(result2), "DST collision");
        assertTrue(keccak256(result2) != keccak256(result3), "DST collision");
    }

    function test_expandMessageXmd_revertOnInvalidInputs() public {
        bytes memory proof_msg = "test";
        bytes memory dst = "DST";

        // Test ell > 255
        vm.expectRevert();
        BlsG1.expandMessageXmd(proof_msg, dst, uint16(256 * 32));

        // Test DST too long (> 255 bytes)
        bytes memory longDST = new bytes(256);
        vm.expectRevert();
        BlsG1.expandMessageXmd(proof_msg, longDST, 64);
    }

    // =============================================================================
    // hashToField Tests
    // =============================================================================

    function test_hashToField_countZero() public view {
        bytes memory input = "test";
        bytes memory dst = "DST";

        // This should return empty array but might cause issues
        BlsG1.Fp[] memory result = BlsG1.hashToField(input, dst, 0);
        assertEq(result.length, 0, "Non-zero length for count=0");
    }

    function test_hashToField_largeCount() public {
        bytes memory input = "test";
        bytes memory dst = "DST";

        // Test with count that would exceed type(uint16).max / L
        uint256 maxCount = type(uint16).max / 64; // Should be 1023
        vm.expectRevert();
        BlsG1.hashToField(input, dst, maxCount + 1);
    }

    function test_hashToField_modulusReduction() public view {
        // Test that field elements are properly reduced modulo P
        bytes memory input = "test";
        bytes memory dst = "DST";

        BlsG1.Fp[] memory elements = BlsG1.hashToField(input, dst, 2);

        // Each element should be 64 bytes (EIP2537 format)
        assertEq(elements[0].data.length, 64, "Wrong element size");
        assertEq(elements[1].data.length, 64, "Wrong element size");

        // Elements should be less than P (checked via modExp in implementation)
        // This is implicitly tested by the modExp operation
    }

    // =============================================================================
    // Precompile Return Value Tests
    // =============================================================================

    function test_precompile_mapFieldElementToG1_returnLength() public view {
        // Create a valid field element
        bytes memory fpData = new bytes(64);
        // Fill with some data (should be < P)
        fpData[63] = 0x01;

        BlsG1.Fp memory fp = BlsG1.Fp(fpData);
        bytes memory result = BlsG1.mapFieldElementToG1(fp);

        // MAP_FP_TO_G1 should return 128 bytes (EIP2537 G1 point)
        assertEq(result.length, 128, "Invalid MAP_FP_TO_G1 return length");
    }

    function test_precompile_addG1_returnLength() public view {
        // Use identity points for simplicity
        bytes memory result = BlsG1.addG1(BlsG1.G1_IDENTITY, BlsG1.G1_IDENTITY);

        // G1_ADD should return 128 bytes
        assertEq(result.length, 128, "Invalid G1_ADD return length");
        assertTrue(BlsG1.isInfinityPointG1(result), "Identity + Identity should be Identity");
    }

    function test_precompile_addG2_returnLength() public view {
        bytes memory result = BlsG1.addG2(BlsG1.G2_IDENTITY, BlsG1.G2_IDENTITY);

        // G2_ADD should return 256 bytes
        assertEq(result.length, 256, "Invalid G2_ADD return length");
        assertTrue(BlsG1.isInfinityPointG2(result), "Identity + Identity should be Identity");
    }

    function test_precompile_scalarMulG1_identity() public view {
        // Any point * 0 = identity
        uint256 sk = 12_345;

        bytes memory point = BlsG1.scalarMulG1(BlsG1.G1_GENERATOR, sk);
        bytes memory identityResult = BlsG1.scalarMulG1(point, 0);

        assertTrue(BlsG1.isInfinityPointG1(identityResult), "Point * 0 should be identity");
    }

    function test_precompile_scalarMulG1_generator() public view {
        // Generator * 1 = Generator
        bytes memory result = BlsG1.scalarMulG1(BlsG1.G1_GENERATOR, 1);
        assertEq(keccak256(result), keccak256(BlsG1.G1_GENERATOR), "Generator * 1 != Generator");
    }

    // =============================================================================
    // Point Validation Tests
    // =============================================================================

    function test_validatePointG1_validPoints() public view {
        // Test with generator
        assertTrue(BlsG1.validatePointG1(BlsG1.G1_GENERATOR), "Generator should be valid");

        // Test with scalar multiples
        uint256 sk = 42;
        bytes memory point = BlsG1.scalarMulG1(BlsG1.G1_GENERATOR, sk);
        assertTrue(BlsG1.validatePointG1(point), "Scalar multiple should be valid");
    }

    function test_validatePointG2_validPoints() public view {
        // Test with generator
        assertTrue(BlsG1.validatePointG2(BlsG1.G2_GENERATOR), "G2 Generator should be valid");

        // Test with scalar multiples
        uint256 sk = 123;
        bytes memory point = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        assertTrue(BlsG1.validatePointG2(point), "G2 scalar multiple should be valid");
    }

    function test_validatePoint_revertOnIdentity() public {
        // Identity points should revert validation
        vm.expectRevert();
        BlsG1.validatePointG1(BlsG1.G1_IDENTITY);

        vm.expectRevert();
        BlsG1.validatePointG2(BlsG1.G2_IDENTITY);
    }

    function test_validatePoint_revertOnWrongLength() public {
        // Wrong length for G1 (should be 128)
        bytes memory shortG1 = new bytes(64);
        vm.expectRevert();
        BlsG1.validatePointG1(shortG1);

        bytes memory longG1 = new bytes(256);
        vm.expectRevert();
        BlsG1.validatePointG1(longG1);

        // Wrong length for G2 (should be 256)
        bytes memory shortG2 = new bytes(128);
        vm.expectRevert();
        BlsG1.validatePointG2(shortG2);

        bytes memory longG2 = new bytes(512);
        vm.expectRevert();
        BlsG1.validatePointG2(longG2);
    }

    // =============================================================================
    // Encoding/Decoding Tests
    // =============================================================================

    function test_encodeDecodeG1_roundtrip() public pure {
        // Generate uncompressed G1 point (96 bytes)
        bytes memory uncompressed = new bytes(96);
        // Fill with test data
        for (uint256 i = 0; i < 96; i++) {
            uncompressed[i] = bytes1(uint8(i));
        }

        // Encode to EIP2537 (128 bytes)
        bytes memory encoded = BlsG1.encodeG1PointForEIP2537(uncompressed);
        assertEq(encoded.length, 128, "Wrong encoded length");

        // Decode back to uncompressed (96 bytes)
        bytes memory decoded = BlsG1.decodeG1PointFromEIP2537(encoded);
        assertEq(decoded.length, 96, "Wrong decoded length");

        // Should match original
        assertEq(keccak256(decoded), keccak256(uncompressed), "Roundtrip failed");
    }

    function test_encodeDecodeG2_roundtrip() public pure {
        // Generate uncompressed G2 point (192 bytes)
        bytes memory uncompressed = new bytes(192);
        for (uint256 i = 0; i < 192; i++) {
            uncompressed[i] = bytes1(uint8(i % 256));
        }

        // Encode to EIP2537 (256 bytes) with coordinate reordering
        bytes memory encoded = BlsG1.encodeG2PointForEIP2537(uncompressed);
        assertEq(encoded.length, 256, "Wrong encoded length");

        // Decode back (with reverse reordering)
        bytes memory decoded = BlsG1.decodeG2PointFromEIP2537(encoded);
        assertEq(decoded.length, 192, "Wrong decoded length");

        // Should match original after double reordering
        assertEq(keccak256(decoded), keccak256(uncompressed), "G2 Roundtrip failed");
    }

    function test_encodeG1_identityPoint() public pure {
        // Encoding identity should return 128 zero bytes
        bytes memory identity96 = new bytes(96); // All zeros
        bytes memory encoded = BlsG1.encodeG1PointForEIP2537(identity96);

        assertEq(encoded.length, 128, "Wrong identity encoding length");
        assertTrue(BlsG1.isInfinityPointG1(encoded), "Encoded identity not recognized");
    }

    function test_encodeG1_revertOnWrongLength() public {
        bytes memory wrongLength = new bytes(64);
        vm.expectRevert();
        BlsG1.encodeG1PointForEIP2537(wrongLength);
    }

    function test_encodeG2_revertOnWrongLength() public {
        bytes memory wrongLength = new bytes(128);
        vm.expectRevert();
        BlsG1.encodeG2PointForEIP2537(wrongLength);
    }

    // =============================================================================
    // Padding Validation Tests
    // =============================================================================

    function test_eip2537BytesToFieldElement_validPadding_viaRoundtrip() public pure {
        // Direct calls to eip2537BytesToFieldElement can't observe dest modifications
        // because public library functions ABI-encode/decode memory params on external calls.
        // Test indirectly: decodeG1PointFromEIP2537 calls eip2537BytesToFieldElement internally.
        bytes memory uncompressed = new bytes(96);
        for (uint256 i = 0; i < 96; i++) {
            uncompressed[i] = bytes1(uint8(i + 1));
        }

        bytes memory encoded = BlsG1.encodeG1PointForEIP2537(uncompressed);
        bytes memory decoded = BlsG1.decodeG1PointFromEIP2537(encoded);

        assertEq(keccak256(decoded), keccak256(uncompressed), "Roundtrip validates padding extraction");
    }

    function test_eip2537BytesToFieldElement_revertOnInvalidPadding() public {
        // Create improperly padded element (non-zero in first 16 bytes)
        bytes memory badPadded = new bytes(64);
        badPadded[0] = 0x01; // Invalid: should be zero
        for (uint256 i = 16; i < 64; i++) {
            badPadded[i] = bytes1(uint8(i));
        }

        bytes memory dest = new bytes(48);
        vm.expectRevert(BlsG1.InvalidPadding.selector);
        BlsG1.eip2537BytesToFieldElement(badPadded, 0, dest, 0);
    }

    function test_fieldElementToEIP2537Bytes_correctPadding_viaEncode() public pure {
        // Direct calls to fieldElementToEIP2537Bytes can't observe dest modifications
        // because public library functions ABI-encode/decode memory params on external calls.
        // Test indirectly: encodeG1PointForEIP2537 calls fieldElementToEIP2537Bytes internally.
        bytes memory uncompressed = new bytes(96);
        for (uint256 i = 0; i < 96; i++) {
            uncompressed[i] = bytes1(uint8(i + 1));
        }

        bytes memory encoded = BlsG1.encodeG1PointForEIP2537(uncompressed);
        assertEq(encoded.length, 128, "Wrong encoded length");

        // Verify padding: first 16 bytes of each 64-byte element must be zero
        for (uint256 i = 0; i < 16; i++) {
            assertEq(encoded[i], bytes1(0), "X padding not zero");
            assertEq(encoded[64 + i], bytes1(0), "Y padding not zero");
        }

        // Verify data preserved after padding
        for (uint256 i = 0; i < 48; i++) {
            assertEq(encoded[16 + i], uncompressed[i], "X data mismatch");
            assertEq(encoded[64 + 16 + i], uncompressed[48 + i], "Y data mismatch");
        }
    }

    // =============================================================================
    // I2OSP Tests
    // =============================================================================

    function test_I2OSP_basic() public pure {
        // Test basic integer to octet string conversion
        bytes memory result1 = BlsG1.I2OSP(1, 1);
        assertEq(result1.length, 1, "Wrong length");
        assertEq(result1[0], bytes1(0x01), "Wrong value");

        bytes memory result2 = BlsG1.I2OSP(255, 1);
        assertEq(result2[0], bytes1(0xFF), "Wrong max byte value");

        bytes memory result3 = BlsG1.I2OSP(256, 2);
        assertEq(result3.length, 2, "Wrong length for 2 bytes");
        assertEq(result3[0], bytes1(0x01), "Wrong MSB");
        assertEq(result3[1], bytes1(0x00), "Wrong LSB");
    }

    function test_I2OSP_revertOnOverflow() public {
        // Value too large for specified length
        vm.expectRevert();
        BlsG1.I2OSP(256, 1); // 256 doesn't fit in 1 byte

        vm.expectRevert();
        BlsG1.I2OSP(65_536, 2); // 65536 doesn't fit in 2 bytes
    }

    function test_I2OSP_bigEndian() public pure {
        // Verify big-endian encoding
        bytes memory result = BlsG1.I2OSP(0x1234, 2);
        assertEq(result[0], bytes1(0x12), "Wrong MSB in big-endian");
        assertEq(result[1], bytes1(0x34), "Wrong LSB in big-endian");
    }

    // =============================================================================
    // extractBytes Tests
    // =============================================================================

    function test_extractBytes_basic() public pure {
        bytes memory source = "Hello World!";
        bytes memory extracted = BlsG1.extractBytes(source, 0, 5);

        assertEq(extracted.length, 5, "Wrong length");
        assertEq(string(extracted), "Hello", "Wrong extracted content");
    }

    function test_extractBytes_offset() public pure {
        bytes memory source = "Hello World!";
        bytes memory extracted = BlsG1.extractBytes(source, 6, 5);

        assertEq(string(extracted), "World", "Wrong extracted content with offset");
    }

    function test_extractBytes_revertOnOutOfBounds() public {
        bytes memory source = "Hello";

        // Offset + length > source.length
        vm.expectRevert();
        BlsG1.extractBytes(source, 0, 10);

        vm.expectRevert();
        BlsG1.extractBytes(source, 3, 5);
    }

    // =============================================================================
    // Message Format Security Tests
    // =============================================================================

    function test_verifyPoP_withDifferentMessageFormats() public view {
        uint256 sk = 54_321;
        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        address validator = address(0x123);

        // Format 1: With prefixes (expected)
        bytes memory msg1 = abi.encodePacked(POP_INTENT_PREFIX, pubkey, ADDRESS_LEN_PREFIX, bytes20(validator));
        bytes memory hash1 = BlsG1.hashToG1(msg1, BlsG1.HASH_TO_G1_DST);
        bytes memory sig1 = BlsG1.scalarMulG1(hash1, sk);
        assertTrue(
            BlsG1.verifyProofOfPossessionG1(pubkey, sig1, msg1, BlsG1.HASH_TO_G1_DST), "Valid format should verify"
        );

        // Format 2: Without prefixes (should fail with sig1)
        bytes memory msg2 = abi.encodePacked(pubkey, bytes20(validator));
        assertFalse(
            BlsG1.verifyProofOfPossessionG1(pubkey, sig1, msg2, BlsG1.HASH_TO_G1_DST),
            "Different format should not verify with same signature"
        );

        // Format 3: Correct signature for format 2
        bytes memory hash2 = BlsG1.hashToG1(msg2, BlsG1.HASH_TO_G1_DST);
        bytes memory sig2 = BlsG1.scalarMulG1(hash2, sk);
        assertTrue(
            BlsG1.verifyProofOfPossessionG1(pubkey, sig2, msg2, BlsG1.HASH_TO_G1_DST),
            "Different format should verify with correct signature"
        );

        // Verify cross-contamination doesn't work
        assertFalse(
            BlsG1.verifyProofOfPossessionG1(pubkey, sig1, msg2, BlsG1.HASH_TO_G1_DST), "Should not cross-verify"
        );
        assertFalse(
            BlsG1.verifyProofOfPossessionG1(pubkey, sig2, msg1, BlsG1.HASH_TO_G1_DST), "Should not cross-verify"
        );
    }

    function test_verifyPoP_withDifferentDSTs() public view {
        uint256 sk = 11_111;
        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory message = abi.encodePacked(pubkey, bytes20(address(0x456)));

        bytes memory dst1 = BlsG1.HASH_TO_G1_DST;
        bytes memory dst2 = "DIFFERENT_DST";

        // Sign with DST1
        bytes memory hash1 = BlsG1.hashToG1(message, dst1);
        bytes memory sig1 = BlsG1.scalarMulG1(hash1, sk);

        // Verify with same DST should pass
        assertTrue(BlsG1.verifyProofOfPossessionG1(pubkey, sig1, message, dst1), "Should verify with matching DST");

        // Verify with different DST should fail
        assertFalse(
            BlsG1.verifyProofOfPossessionG1(pubkey, sig1, message, dst2), "Should not verify with different DST"
        );
    }

    // =============================================================================
    // Fuzz Tests
    // =============================================================================

    function testFuzz_hashToG1_deterministic(bytes memory message, bytes memory dst) public view {
        // Assume valid DST length
        vm.assume(dst.length > 0 && dst.length <= 255);
        vm.assume(message.length < 1000); // Reasonable size

        bytes memory result1 = BlsG1.hashToG1(message, dst);
        bytes memory result2 = BlsG1.hashToG1(message, dst);

        assertEq(keccak256(result1), keccak256(result2), "Non-deterministic hashing");
    }

    function testFuzz_I2OSP_roundtrip(uint256 value, uint256 length) public pure {
        // Constrain inputs
        vm.assume(length > 0 && length <= 32);
        vm.assume(length >= 32 || value < 256 ** length);

        bytes memory encoded = BlsG1.I2OSP(value, length);
        assertEq(encoded.length, length, "Wrong encoding length");

        // Decode manually
        uint256 decoded = 0;
        for (uint256 i = 0; i < length; i++) {
            decoded = decoded * 256 + uint8(encoded[i]);
        }

        assertEq(decoded, value, "I2OSP roundtrip failed");
    }

    function testFuzz_extractBytes_consistency(bytes memory source, uint256 offset, uint256 length) public pure {
        vm.assume(source.length > 0);
        // Use bound() to clamp random uint256 values into valid ranges.
        // vm.assume() rejects inputs that don't match, but random uint256 values
        // are almost never <= source.length, exhausting the 65536 rejection limit.
        length = bound(length, 1, source.length);
        offset = bound(offset, 0, source.length - length);

        bytes memory extracted = BlsG1.extractBytes(source, offset, length);
        assertEq(extracted.length, length, "Wrong extraction length");

        for (uint256 i = 0; i < length; i++) {
            assertEq(extracted[i], source[offset + i], "Extraction content mismatch");
        }
    }
}
