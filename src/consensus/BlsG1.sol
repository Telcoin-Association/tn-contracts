// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Canonical address of the native BLS verification precompile that this library forwards to.
/// It is the single source of truth for the link address and MUST be mirrored in `foundry.toml`'s
/// `libraries` setting (TOML cannot reference Solidity constants) and in the Telcoin-Network protocol
/// genesis. The precompile reuses the protocol's `blst` (min_sig) verification, so the on-chain check
/// cannot drift from the off-chain signing encoding.
address constant BLS_G1_ADDRESS = 0x000000000000000000000000000000000000B151;

/// @title BlsG1 Verification Library
/// @notice Thin wrapper forwarding BLS12-381 signature verification to the native precompile at
/// `BLS_G1_ADDRESS`. Implements the 'min-sig' variant (signatures in G1, public keys in G2) using
/// compressed encodings: 48-byte signatures and 96-byte public keys. The verify is generic - the
/// message is opaque - so it is reusable beyond proof-of-possession; `proofOfPossessionMessage`
/// builds the consensus PoP message that `ConsensusRegistry` verifies.
/// @dev Consumers (e.g. `ConsensusRegistry`) are linked against `BLS_G1_ADDRESS` at genesis, so a
/// `BlsG1.blsVerify` call lands directly on the precompile. The wrapper body below is the reference
/// path used when the library is exercised outside that linkage (e.g. Foundry tests against a mocked
/// precompile).
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

    /// @dev The serialized telcoin proof-of-possession intent prefix (`scope=0, version=0, app=0`),
    /// which domain-separates PoP messages from other BLS signatures. Mirrors
    /// `Intent::telcoin(IntentScope::ProofOfPossession)` in tn-types; the off-chain
    /// `pop_message_layout_is_onchain_constructible` test pins it to `0x000000`.
    bytes3 internal constant POP_INTENT_PREFIX = 0x000000;

    /// @notice Builds the proof-of-possession message a validator signs: the 3-byte intent prefix, the
    /// 96-byte compressed `pubkey`, and the 20-byte `validatorAddress`.
    /// @dev Constructed entirely on-chain from the compressed key and the raw address (no
    /// decompression), so it reproduces byte-for-byte the message tn-types signs off-chain in
    /// `construct_proof_of_possession_message`.
    function proofOfPossessionMessage(
        bytes memory pubkey,
        address validatorAddress
    )
        internal
        pure
        returns (bytes memory)
    {
        // Self-contained length gate: `abi.encodePacked` of a dynamic `pubkey` between fixed-size
        // fields is only unambiguous when `pubkey` has a fixed length, so enforce the 96-byte
        // compressed G2 form here rather than relying on every caller to pre-check it.
        if (pubkey.length != 96) revert InvalidBLSPubkey();
        return abi.encodePacked(POP_INTENT_PREFIX, pubkey, validatorAddress);
    }

    /// @notice Verifies a BLS12-381 signature over `message` via the native precompile.
    /// @param signature 48-byte compressed G1 signature
    /// @param pubkey 96-byte compressed G2 public key
    /// @param message The signed message bytes
    /// @return _ True iff `signature` is a valid BLS signature over `message` under `pubkey`
    /// @dev Generic primitive: the precompile treats `message` as opaque, so any caller can verify any
    /// BLS-signed message (proof-of-possession is just one, built by `proofOfPossessionMessage`). The
    /// argument order matches the precompile ABI and the protocol's Rust `bls_verify_secure(signature,
    /// public_key, message)`. A staticcall failure or any non-32-byte return reverts, so an absent
    /// precompile cannot decode as `false` and silently pass an unverified signature.
    function blsVerify(
        bytes memory signature,
        bytes memory pubkey,
        bytes memory message
    )
        external
        view
        returns (bool)
    {
        (bool ok, bytes memory res) = BLS_G1_ADDRESS.staticcall(
            abi.encodeWithSignature("blsVerify(bytes,bytes,bytes)", signature, pubkey, message)
        );
        if (!ok || res.length != 32) revert LowLevelCallFailure(res);

        return abi.decode(res, (bool));
    }
}
