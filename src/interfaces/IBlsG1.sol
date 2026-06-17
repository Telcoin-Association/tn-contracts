// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Canonical address of the native BLS verification precompile. It is the single source of
/// truth for callers - `IBlsG1(BLS_G1_ADDRESS).blsVerify(...)` - and MUST be mirrored in the
/// Telcoin-Network protocol genesis (`BLS_G1_PRECOMPILE_ADDRESS`). The precompile reuses the
/// protocol's `blst` (min_sig) verification, so the on-chain check cannot drift from the off-chain
/// signing encoding. At genesis the address carries a single `0xfe` (INVALID) byte of code: this
/// satisfies the `extcodesize` guard Solidity emits before a high-level interface call (so the call
/// dispatches to the precompile) and ensures any call that bypasses precompile dispatch reverts.
address constant BLS_G1_ADDRESS = 0x000000000000000000000000000000000000B151;

/// @title IBlsG1
/// @author Telcoin Association
/// @notice Interface for the native BLS12-381 signature-verification precompile at `BLS_G1_ADDRESS`.
/// Implements the 'min-sig' variant (signatures in G1, public keys in G2) using compressed
/// encodings: 48-byte signatures and 96-byte public keys. The verify is generic - the `message` is
/// opaque - so any caller can verify any BLS-signed message (proof-of-possession is just one such
/// message, built by `ConsensusRegistry`).
/// @dev Callers reach the precompile with a low-level `staticcall` carrying
/// `abi.encodeWithSelector(IBlsG1.blsVerify.selector, ...)`, rather than a typed `IBlsG1(addr)` call.
/// This is the protocol's convention for precompile calls (see also `StablecoinManager`): it avoids
/// the `EXTCODESIZE` guard Solidity emits before typed external calls, since precompiles are
/// dispatched by the EVM and need not carry on-chain bytecode. Treating a failed call or any
/// non-32-byte return as a revert keeps an absent precompile from decoding as `false` and silently
/// passing an unverified signature.
interface IBlsG1 {
    /// @notice Verifies a BLS12-381 signature over `message`.
    /// @param signature 48-byte compressed G1 signature
    /// @param pubkey 96-byte compressed G2 public key
    /// @param message The signed message bytes (opaque to the precompile)
    /// @return _ True iff `signature` is a valid BLS signature over `message` under `pubkey`
    function blsVerify(
        bytes calldata signature,
        bytes calldata pubkey,
        bytes calldata message
    )
        external
        view
        returns (bool);
}
