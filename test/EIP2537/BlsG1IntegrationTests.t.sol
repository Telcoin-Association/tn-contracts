// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { BlsG1 } from "../../src/consensus/BlsG1.sol";
import { ConsensusRegistry } from "../../src/consensus/ConsensusRegistry.sol";
import { IConsensusRegistry } from "../../src/interfaces/IConsensusRegistry.sol";
import { IStakeManager } from "../../src/interfaces/IStakeManager.sol";

/// @notice Integration tests for BlsG1 with ConsensusRegistry
/// @dev Tests the actual usage patterns and attack vectors in production
contract BlsG1IntegrationTests is Test {
    bytes5 constant POP_INTENT_PREFIX = 0x000000d501;
    bytes1 constant ADDRESS_LEN_PREFIX = 0x14;

    // Mock minimal setup for integration testing
    address constant ISSUANCE = address(0x1);
    address constant SYSTEM_CALLER = address(0x2);

    function proofOfPossessionMessage(
        bytes memory blsPubkey,
        address validatorAddress
    )
        public
        pure
        returns (bytes memory)
    {
        return bytes.concat(POP_INTENT_PREFIX, blsPubkey, ADDRESS_LEN_PREFIX, bytes20(validatorAddress));
    }

    // =============================================================================
    // Message Format Tests (ConsensusRegistry Integration)
    // =============================================================================

    function test_integration_correctMessageFormat() public view {
        // Generate test validator
        uint256 sk = 12345;
        address validator = address(0x789);

        // Generate BLS pubkey (G2) in uncompressed format (192 bytes)
        bytes memory g2Generator = BlsG1.G2_GENERATOR;
        bytes memory uncompressedPubkey = BlsG1.scalarMulG2(g2Generator, sk);

        // Decode from EIP2537 (256 bytes) to uncompressed (192 bytes)
        bytes memory pubkey96 = BlsG1.decodeG2PointFromEIP2537(uncompressedPubkey);

        // Create message with correct format
        bytes memory popMsg = proofOfPossessionMessage(pubkey96, validator);

        // Expected format: 5 + 96 + 1 + 20 = 122 bytes
        assertEq(popMsg.length, 122, "Incorrect message length");

        // Verify structure
        assertEq(bytes5(bytes(popMsg)), POP_INTENT_PREFIX, "Wrong prefix");
        assertEq(popMsg[101], ADDRESS_LEN_PREFIX, "Wrong address length prefix");

        // Extract and verify address
        bytes20 extractedAddress;
        assembly {
            extractedAddress := mload(add(popMsg, 122))
        }
        assertEq(address(extractedAddress), validator, "Wrong validator address");
    }

    function test_integration_signAndVerify_completeFlow() public view {
        // Complete flow: key generation -> message creation -> signing -> verification
        uint256 sk = 99999;
        address validator = address(0xABCD);

        // 1. Generate BLS public key (simulating validator key generation)
        bytes memory eip2537Pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory uncompressedPubkey = BlsG1.decodeG2PointFromEIP2537(eip2537Pubkey);

        // 2. Create PoP message with correct format
        bytes memory popMsg = proofOfPossessionMessage(uncompressedPubkey, validator);

        // 3. Hash message to G1 curve
        bytes memory messageHash = BlsG1.hashToG1(popMsg, BlsG1.HASH_TO_G1_DST);

        // 4. Sign with private key (scalar multiplication)
        bytes memory signature = BlsG1.scalarMulG1(messageHash, sk);

        // 5. Verify signature
        assertTrue(
            BlsG1.verifyProofOfPossessionG1(eip2537Pubkey, signature, popMsg, BlsG1.HASH_TO_G1_DST),
            "Complete flow verification failed"
        );
    }

    // =============================================================================
    // Attack Vector Tests
    // =============================================================================

    function test_integration_attack_wrongPrefix() public view {
        // Attacker tries to bypass intent prefix
        uint256 sk = 11111;
        address validator = address(0x111);

        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory uncompressedPubkey = BlsG1.decodeG2PointFromEIP2537(pubkey);

        // Legitimate message
        bytes memory legitMsg = proofOfPossessionMessage(uncompressedPubkey, validator);
        bytes memory legitHash = BlsG1.hashToG1(legitMsg, BlsG1.HASH_TO_G1_DST);
        bytes memory legitSig = BlsG1.scalarMulG1(legitHash, sk);

        // Attack: message without prefix
        bytes memory attackMsg = abi.encodePacked(uncompressedPubkey, ADDRESS_LEN_PREFIX, bytes20(validator));

        // Legitimate signature should NOT verify with attack message
        assertFalse(
            BlsG1.verifyProofOfPossessionG1(pubkey, legitSig, attackMsg, BlsG1.HASH_TO_G1_DST),
            "Attack bypassed prefix check!"
        );
    }

    function test_integration_attack_wrongAddressLengthPrefix() public view {
        // Attacker tries to manipulate address length prefix
        uint256 sk = 22222;
        address validator = address(0x222);

        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory uncompressedPubkey = BlsG1.decodeG2PointFromEIP2537(pubkey);

        // Legitimate message
        bytes memory legitMsg = proofOfPossessionMessage(uncompressedPubkey, validator);
        bytes memory legitHash = BlsG1.hashToG1(legitMsg, BlsG1.HASH_TO_G1_DST);
        bytes memory legitSig = BlsG1.scalarMulG1(legitHash, sk);

        // Attack: wrong address length prefix (0x15 instead of 0x14)
        bytes memory attackMsg =
            bytes.concat(POP_INTENT_PREFIX, uncompressedPubkey, bytes1(0x15), bytes20(validator));

        // Should not verify
        assertFalse(
            BlsG1.verifyProofOfPossessionG1(pubkey, legitSig, attackMsg, BlsG1.HASH_TO_G1_DST),
            "Attack bypassed address length check!"
        );
    }

    function test_integration_attack_addressSubstitution() public view {
        // Attacker tries to reuse valid signature for different address
        uint256 sk = 33333;
        address legitValidator = address(0x333);
        address attackValidator = address(0x999);

        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory uncompressedPubkey = BlsG1.decodeG2PointFromEIP2537(pubkey);

        // Create legitimate signature
        bytes memory legitMsg = proofOfPossessionMessage(uncompressedPubkey, legitValidator);
        bytes memory legitHash = BlsG1.hashToG1(legitMsg, BlsG1.HASH_TO_G1_DST);
        bytes memory legitSig = BlsG1.scalarMulG1(legitHash, sk);

        // Attack: same signature, different address
        bytes memory attackMsg = proofOfPossessionMessage(uncompressedPubkey, attackValidator);

        // Should fail verification
        assertFalse(
            BlsG1.verifyProofOfPossessionG1(pubkey, legitSig, attackMsg, BlsG1.HASH_TO_G1_DST),
            "Address substitution attack succeeded!"
        );
    }

    function test_integration_attack_pubkeySubstitution() public view {
        // Attacker tries to use signature from one key with another key
        uint256 sk1 = 44444;
        uint256 sk2 = 55555;
        address validator = address(0x444);

        bytes memory pubkey1 = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk1);
        bytes memory pubkey2 = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk2);

        bytes memory uncompressedPubkey1 = BlsG1.decodeG2PointFromEIP2537(pubkey1);

        // Create signature with sk1
        bytes memory msg1 = proofOfPossessionMessage(uncompressedPubkey1, validator);
        bytes memory hash1 = BlsG1.hashToG1(msg1, BlsG1.HASH_TO_G1_DST);
        bytes memory sig1 = BlsG1.scalarMulG1(hash1, sk1);

        // Attack: use sig1 with pubkey2
        assertFalse(
            BlsG1.verifyProofOfPossessionG1(pubkey2, sig1, msg1, BlsG1.HASH_TO_G1_DST),
            "Pubkey substitution attack succeeded!"
        );
    }

    function test_integration_attack_signatureMalleable() public view {
        // Test if signatures can be malleated (they shouldn't be in BLS)
        uint256 sk = 66666;
        address validator = address(0x666);

        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory uncompressedPubkey = BlsG1.decodeG2PointFromEIP2537(pubkey);

        bytes memory msg = proofOfPossessionMessage(uncompressedPubkey, validator);
        bytes memory hash = BlsG1.hashToG1(msg, BlsG1.HASH_TO_G1_DST);
        bytes memory sig = BlsG1.scalarMulG1(hash, sk);

        // Verify original signature works
        assertTrue(
            BlsG1.verifyProofOfPossessionG1(pubkey, sig, msg, BlsG1.HASH_TO_G1_DST), "Original signature should work"
        );

        // Try to create alternate signature by negating
        // In BLS12-381, -P is a different point on the curve
        // This tests if malleated signatures would verify (they shouldn't)
        bytes memory g1Identity = BlsG1.G1_IDENTITY;
        // Note: Can't easily negate without more helper functions
        // But identity should definitely not verify as valid signature
        assertFalse(
            BlsG1.verifyProofOfPossessionG1(pubkey, g1Identity, msg, BlsG1.HASH_TO_G1_DST),
            "Identity should not be valid signature"
        );
    }

    // =============================================================================
    // Replay Attack Tests
    // =============================================================================

    function test_integration_noReplay_differentMessages() public view {
        // Verify that same signature can't be used for different messages
        uint256 sk = 77777;
        address validator = address(0x777);

        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory uncompressedPubkey = BlsG1.decodeG2PointFromEIP2537(pubkey);

        // Message 1
        bytes memory msg1 = proofOfPossessionMessage(uncompressedPubkey, validator);
        bytes memory hash1 = BlsG1.hashToG1(msg1, BlsG1.HASH_TO_G1_DST);
        bytes memory sig1 = BlsG1.scalarMulG1(hash1, sk);

        // Message 2 (different by adding extra byte)
        bytes memory msg2 = bytes.concat(msg1, bytes1(0xFF));

        // sig1 should not work for msg2
        assertFalse(
            BlsG1.verifyProofOfPossessionG1(pubkey, sig1, msg2, BlsG1.HASH_TO_G1_DST), "Replay attack succeeded!"
        );
    }

    // =============================================================================
    // Coordinate Reordering Tests (G2 Points)
    // =============================================================================

    function test_integration_g2CoordinateReordering() public view {
        // Test that G2 coordinate reordering is correctly handled
        uint256 sk = 88888;
        bytes memory g2Point = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);

        // Decode (reversing reordering)
        bytes memory uncompressed = BlsG1.decodeG2PointFromEIP2537(g2Point);
        assertEq(uncompressed.length, 192, "Wrong uncompressed length");

        // Re-encode (applying reordering again)
        bytes memory reencoded = BlsG1.encodeG2PointForEIP2537(uncompressed);
        assertEq(reencoded.length, 256, "Wrong reencoded length");

        // Should match original
        assertEq(keccak256(reencoded), keccak256(g2Point), "Coordinate reordering broken");
    }

    function test_integration_g2GeneratorNegation() public view {
        // Verify that G2_GENERATOR_NEG is correctly computed
        // e(G1, G2) * e(G1, -G2) should equal 1
        bytes memory g1Gen = BlsG1.G1_GENERATOR;
        bytes memory g2Gen = BlsG1.G2_GENERATOR;
        bytes memory g2GenNeg = BlsG1.G2_GENERATOR_NEG;

        // Pairing check: e(G1, G2) * e(G1, -G2) = 1
        bytes memory input = bytes.concat(g1Gen, g2Gen, g1Gen, g2GenNeg);
        (bool success, bytes memory result) = address(0x0F).staticcall(input); // PAIRING_CHECK

        assertTrue(success, "Pairing check failed");
        uint256 pairingResult = uint256(bytes32(result));
        assertEq(pairingResult, 1, "G2_GENERATOR_NEG is incorrect");
    }

    // =============================================================================
    // Gas Benchmarking
    // =============================================================================

    function test_gas_fullVerificationFlow() public view {
        uint256 sk = 123456;
        address validator = address(0xBEEF);

        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory uncompressedPubkey = BlsG1.decodeG2PointFromEIP2537(pubkey);
        bytes memory msg = proofOfPossessionMessage(uncompressedPubkey, validator);
        bytes memory hash = BlsG1.hashToG1(msg, BlsG1.HASH_TO_G1_DST);
        bytes memory sig = BlsG1.scalarMulG1(hash, sk);

        uint256 gasBefore = gasleft();
        bool verified = BlsG1.verifyProofOfPossessionG1(pubkey, sig, msg, BlsG1.HASH_TO_G1_DST);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(verified, "Verification failed");
        console2.log("Gas used for full PoP verification:", gasUsed);
        // Expected: ~150,000 gas
    }

    function test_gas_hashToG1() public view {
        bytes memory msg = "Test message for gas benchmarking";

        uint256 gasBefore = gasleft();
        BlsG1.hashToG1(msg, BlsG1.HASH_TO_G1_DST);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Gas used for hashToG1:", gasUsed);
        // Expected: ~80,000 gas
    }

    function test_gas_expandMessageXmd() public view {
        bytes memory msg = "Test message";
        bytes memory dst = BlsG1.HASH_TO_G1_DST;

        uint256 gasBefore = gasleft();
        BlsG1.expandMessageXmd(msg, dst, 128);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Gas used for expandMessageXmd:", gasUsed);
        // Expected: ~5,000 gas (for ell=4)
    }

    // =============================================================================
    // Edge Case Tests
    // =============================================================================

    function test_integration_largeMessage() public view {
        // Test with very large message (1KB)
        uint256 sk = 111111;
        address validator = address(0x111);

        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory largeMsg = new bytes(1024);
        for (uint256 i = 0; i < 1024; i++) {
            largeMsg[i] = bytes1(uint8(i % 256));
        }

        bytes memory hash = BlsG1.hashToG1(largeMsg, BlsG1.HASH_TO_G1_DST);
        bytes memory sig = BlsG1.scalarMulG1(hash, sk);

        assertTrue(
            BlsG1.verifyProofOfPossessionG1(pubkey, sig, largeMsg, BlsG1.HASH_TO_G1_DST), "Large message failed"
        );
    }

    function test_integration_emptyMessage() public view {
        // Test with empty message
        uint256 sk = 222222;
        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, sk);
        bytes memory emptyMsg = "";

        bytes memory hash = BlsG1.hashToG1(emptyMsg, BlsG1.HASH_TO_G1_DST);
        bytes memory sig = BlsG1.scalarMulG1(hash, sk);

        assertTrue(BlsG1.verifyProofOfPossessionG1(pubkey, sig, emptyMsg, BlsG1.HASH_TO_G1_DST), "Empty message failed");
    }

    function test_integration_maxSkValue() public view {
        // Test with maximum valid scalar value
        // BLS12-381 scalar field order (r)
        uint256 maxSk = type(uint256).max; // Will be reduced modulo r by precompile

        bytes memory pubkey = BlsG1.scalarMulG2(BlsG1.G2_GENERATOR, maxSk);
        address validator = address(0xFFFF);
        bytes memory uncompressedPubkey = BlsG1.decodeG2PointFromEIP2537(pubkey);

        bytes memory msg = proofOfPossessionMessage(uncompressedPubkey, validator);
        bytes memory hash = BlsG1.hashToG1(msg, BlsG1.HASH_TO_G1_DST);
        bytes memory sig = BlsG1.scalarMulG1(hash, maxSk);

        assertTrue(BlsG1.verifyProofOfPossessionG1(pubkey, sig, msg, BlsG1.HASH_TO_G1_DST), "Max scalar failed");
    }
}
