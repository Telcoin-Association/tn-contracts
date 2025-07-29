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
        bytes memory fuzzedBLSPubkey = mulG2(G2_GENERATOR, sk);
        bytes memory message = bytes.concat(fuzzedBLSPubkey, bytes20(fuzzValidator));

        // craft proof of possession
        bytes memory g1MsgHash = BlsG1.hashToG1(message);
        bytes memory g1Signature = mulG1(g1MsgHash, sk);

        assertTrue(BlsG1.verifyProofOfPossessionG1(fuzzedBLSPubkey, g1Signature, message));
    }

    function test_verifyProofOfPossessionG1_negative(address fuzzValidator, uint256 sk) public view {
        vm.assume(sk > 0);

        /// @notice Never do this onchain in production!! Only for fuzz testing
        bytes memory fuzzedBLSPubkey = mulG2(G2_GENERATOR, sk);
        bytes memory message = bytes.concat(fuzzedBLSPubkey, bytes20(fuzzValidator));

        // craft proof of possession
        bytes memory g1MsgHash = BlsG1.hashToG1(message);
        bytes memory g1Signature = mulG1(g1MsgHash, sk);

        // mutated pubkey should fail
        uint256 fakeSK = uint256(keccak256(abi.encodePacked(sk)));
        bytes memory fakePubkey = mulG2(G2_GENERATOR, fakeSK);
        assertFalse(BlsG1.verifyProofOfPossessionG1(fakePubkey, g1Signature, message));

        // mutated signature should fail
        bytes memory fakeSignature = mulG1(g1MsgHash, fakeSK);
        assertFalse(BlsG1.verifyProofOfPossessionG1(fuzzedBLSPubkey, fakeSignature, message));

        // mutated message should fail
        bytes memory fakeMessage = bytes("DEADBEEF");
        assertFalse(BlsG1.verifyProofOfPossessionG1(fuzzedBLSPubkey, g1Signature, fakeMessage));
    }
}
