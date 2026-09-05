// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

/// @title ShieldPrecompileSelectors
/// @author Telcoin Association
/// @notice Hardcoded 4-byte function selectors for the TN-SHIELD v1 shielded-stablecoin precompile
///         at `ShieldVault.PRECOMPILE` (0x0000000000000000000000000000000123456789).
/// @dev The precompile's `sol!` block in the Telcoin-Network node (tn-reth `shielded_precompile`)
///      is the v1 interface source of truth and `IShieldedStablecoin` is its typed Solidity mirror.
///      These constants pin the selectors that mirror produces, so an interface edit that drifted
///      from the node fails the parity test instead of silently re-targeting calldata; callers
///      that want no interface dependency can encode against them directly.
/// @dev Every constant must equal `bytes4(keccak256(signature))` for the exact v1 signature noted
///      on it AND `IShieldedStablecoin.<fn>.selector`; `test/shield/ShieldVault.t.sol` asserts
///      both parities for all thirteen selectors.
library ShieldPrecompileSelectors {
    // ---------------------------------------------------------------------
    // state-mutating selectors (the precompile rejects nonzero call value on
    // EVERY selector and rejects STATICCALL frames for all of these)
    // ---------------------------------------------------------------------

    /// @dev `shield(address token, bytes32 ownerAddr, bytes32 salt, uint128 amount)`;
    ///      caller must be `vaultOf[token]`
    bytes4 internal constant SHIELD = 0x93c1da85;

    /// @dev `unshield(bytes proof, bytes publicValues) returns (address recipient, uint128 amount)`;
    ///      caller must be `vaultOf[token]`
    bytes4 internal constant UNSHIELD = 0x7ee768dd;

    /// @dev `transfer(bytes proof, bytes publicValues)`; any caller (relayable)
    bytes4 internal constant TRANSFER = 0x80ad628e;

    /// @dev `approve(bytes proof, bytes publicValues)`; any caller (relayable)
    bytes4 internal constant APPROVE = 0x1e9c33b7;

    /// @dev `transferFrom(bytes proof, bytes publicValues)`; any caller (relayable)
    bytes4 internal constant TRANSFER_FROM = 0xf33fd564;

    /// @dev `reclaim(bytes proof, bytes publicValues)`; any caller (relayable)
    bytes4 internal constant RECLAIM = 0xf2420f87;

    /// @dev `setTokenConfig(address token, address vault, bytes32 auditorKey)`;
    ///      caller must be the governance safe
    bytes4 internal constant SET_TOKEN_CONFIG = 0x7cb6cbd0;

    // ---------------------------------------------------------------------
    // view selectors (STATICCALL-allowed; still zero call value only)
    // ---------------------------------------------------------------------

    /// @dev `root() returns (bytes32)`
    bytes4 internal constant ROOT = 0xebf0c717;

    /// @dev `isKnownRoot(bytes32 root_) returns (bool)`
    bytes4 internal constant IS_KNOWN_ROOT = 0x6d9833e3;

    /// @dev `isSpent(bytes32 nullifier) returns (bool)`
    bytes4 internal constant IS_SPENT = 0xe5285dcc;

    /// @dev `nextIndex() returns (uint64)`
    bytes4 internal constant NEXT_INDEX = 0xfc7e9c6f;

    /// @dev `totalShielded(address token) returns (uint128)`
    bytes4 internal constant TOTAL_SHIELDED = 0x6d7f2685;

    /// @dev `tokenConfig(address token) returns (address vault, bytes32 auditorKey)`
    bytes4 internal constant TOKEN_CONFIG = 0xfe136c4e;
}
