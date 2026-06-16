// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Canonical address of the native BLS proof-of-possession precompile that this library
/// forwards to. It is the single source of truth for the link address and MUST be mirrored in
/// `foundry.toml`'s `libraries` setting (TOML cannot reference Solidity constants) and in the
/// Telcoin-Network protocol genesis. The precompile reuses the protocol's `blst` (min_sig)
/// verification, so the on-chain check cannot drift from the off-chain signing encoding.
address constant BLS_G1_ADDRESS = 0x000000000000000000000000000000000000B151;

/// @title BlsG1 Proof of Possession Library
/// @notice Thin wrapper forwarding BLS12-381 proof-of-possession verification to the native
/// precompile at `BLS_G1_ADDRESS`. Implements the 'min-sig' variant (signatures in G1, public keys
/// in G2) using compressed encodings: 48-byte signatures and 96-byte public keys.
/// @dev Consumers (e.g. `ConsensusRegistry`) are linked against `BLS_G1_ADDRESS` at genesis, so a
/// `BlsG1.verifyProofOfPossession` call lands directly on the precompile. The wrapper body below is
/// the reference path used when the library is exercised outside that linkage (e.g. Foundry tests
/// against a mocked precompile).
/// @author Robriks 📯️📯️📯️.eth
library BlsG1 {
    /// @dev Represents a validator's compressed BLS12-381 proof of possession.
    /// @param signature A 48-byte compressed G1 point: the PoP over the protocol's PoP message.
    /// @notice The proven public key is the separate 96-byte compressed `blsPubkey` passed to stake
    /// and genesis; the precompile verifies `signature` against it, so no pubkey is carried here.
    struct ProofOfPossession {
        bytes signature;
    }

    /// @notice Thrown when the precompile staticcall fails or returns an unexpected payload
    error LowLevelCallFailure(bytes err);

    /// @notice Thrown when a registered BLS public key is not a well-formed 96-byte compressed G2 point
    error InvalidBLSPubkey();

    /// @notice Verifies a validator's BLS12-381 proof of possession via the native precompile.
    /// @param signature 48-byte compressed G1 signature (the proof of possession)
    /// @param pubkey 96-byte compressed G2 public key whose possession is proven
    /// @param validatorAddress The validator's execution address bound into the PoP message
    /// @return _ True if the proof of possession is valid
    /// @dev Parameter order (signature, pubkey, address) matches the precompile ABI and the
    /// protocol's Rust `verify_proof_of_possession_bls(proof, public_key, address)`. A staticcall
    /// failure or any non-32-byte return reverts, so an absent precompile cannot decode as `false`
    /// and silently pass an unverified key.
    function verifyProofOfPossession(
        bytes memory signature,
        bytes memory pubkey,
        address validatorAddress
    )
        external
        view
        returns (bool)
    {
        (bool ok, bytes memory res) = BLS_G1_ADDRESS.staticcall(
            abi.encodeWithSignature("verifyProofOfPossession(bytes,bytes,address)", signature, pubkey, validatorAddress)
        );
        if (!ok || res.length != 32) revert LowLevelCallFailure(res);

        return abi.decode(res, (bool));
    }
}
