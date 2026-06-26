// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Canonical address of the native BLS verification precompile; must match
/// `BLS_G1_PRECOMPILE_ADDRESS` in the Telcoin-Network genesis. The precompile reuses the protocol's
/// `blst` (min_sig) verification, so the on-chain check can't drift from off-chain signing. Genesis
/// gives the address one `0xfe` (INVALID) byte of code so the account is non-empty (never
/// state-pruned) and any call bypassing precompile dispatch reverts instead of hitting an empty account.
address constant BLS_G1_ADDRESS = 0x000000000000000000000000000000000000B151;

/// @title IBlsG1
/// @author Telcoin Association
/// @notice Native BLS12-381 verification precompile (min-sig: G1 signatures, G2 pubkeys) in
/// compressed form - 48-byte signatures, 96-byte pubkeys. `message` is opaque, so any caller can
/// verify any BLS-signed message; proof-of-possession (built by `ConsensusRegistry`) is one use.
/// @dev Call via low-level `staticcall` of `abi.encodeWithSelector(IBlsG1.blsVerify.selector, ...)`,
/// not a typed `IBlsG1(addr)` call - the protocol's precompile convention (cf. `StablecoinManager`).
/// Treat a failed call or any non-32-byte return as a revert, so an absent precompile can't decode
/// as `false` and pass an unverified signature.
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
