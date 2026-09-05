// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

/// @title IShieldedStablecoin
/// @author Telcoin Association
/// @notice Typed Solidity mirror of the TN-SHIELD v1 shielded-stablecoin precompile ABI served at
///         `ShieldVault.PRECOMPILE` (0x0000000000000000000000000000000123456789).
/// @dev The precompile's `sol!` block in the Telcoin-Network node (tn-reth `shielded_precompile`)
///      is the frozen v1 source of truth. Every function here matches it in name, parameter types,
///      parameter order, and parameter names, so `abi.encodeCall(IShieldedStablecoin.<fn>, (...))`
///      produces exactly the calldata the node decodes. `ShieldPrecompileSelectors` pins the
///      selectors this interface produces and `test/shield/ShieldVault.t.sol` asserts the two agree
///      for all thirteen functions, so an edit that drifts from the node fails the parity test.
/// @dev DO NOT call the precompile through this interface with a high-level call. Solidity's typed
///      call inserts an EXTCODESIZE guard that reverts wherever the precompile account has no code
///      (pre-genesis and unit-test contexts), and every precompile rejection is a frame HALT
///      (`success == false`, EMPTY returndata at every depth, all forwarded gas consumed), which a
///      high-level call would bubble up as a reasonless revert. Encode with `abi.encodeCall`, send
///      with a low-level `.call`, and revert your own frame when `success` is false (see
///      `ShieldVault`).
/// @dev Every function rejects nonzero call value; the state-mutating functions also reject
///      STATICCALL frames. Gas is a fixed per-selector charge consumed up front.
interface IShieldedStablecoin {
    // ---------------------------------------------------------------------
    // state-mutating
    // ---------------------------------------------------------------------

    /// @notice Deposits `amount` of `token` into the pool as a note with the PUBLIC opening
    ///         `(token, ownerAddr, salt, amount)`; the precompile recomputes the commitment itself
    ///         (inflation resistance).
    /// @dev Caller MUST be `vaultOf[token]`; `amount > 0`.
    function shield(address token, bytes32 ownerAddr, bytes32 salt, uint128 amount) external;

    /// @notice Withdraws a proven public amount to a public recipient; returns the pair the vault
    ///         mints against.
    /// @dev Caller MUST be `vaultOf[token]`.
    function unshield(
        bytes calldata proof,
        bytes calldata publicValues
    )
        external
        returns (address recipient, uint128 amount);

    /// @notice Fully shielded transfer (any caller; relayable).
    function transfer(bytes calldata proof, bytes calldata publicValues) external;

    /// @notice Creates an escrow note approving a spender (any caller; relayable).
    function approve(bytes calldata proof, bytes calldata publicValues) external;

    /// @notice Spends from an escrow note as the approved spender (any caller; relayable).
    function transferFrom(bytes calldata proof, bytes calldata publicValues) external;

    /// @notice Reclaims a full escrow note as its owner (any caller; relayable).
    function reclaim(bytes calldata proof, bytes calldata publicValues) external;

    /// @notice Registers or overwrites `token`'s vault and auditor key; `vault == 0` disables.
    /// @dev Caller MUST be the governance safe.
    function setTokenConfig(address token, address vault, bytes32 auditorKey) external;

    // ---------------------------------------------------------------------
    // views (STATICCALL-allowed)
    // ---------------------------------------------------------------------

    /// @notice Current Merkle root (`EMPTY_ROOT` before the first insertion).
    function root() external view returns (bytes32);

    /// @notice Whether `root_` is inside the 128-root history window.
    function isKnownRoot(bytes32 root_) external view returns (bool);

    /// @notice Whether `nullifier` has been spent.
    function isSpent(bytes32 nullifier) external view returns (bool);

    /// @notice The next leaf index (equally the tree size).
    function nextIndex() external view returns (uint64);

    /// @notice Total shielded supply of `token`.
    function totalShielded(address token) external view returns (uint128);

    /// @notice The registered `(vault, auditorKey)` for `token` (both zero when unregistered).
    function tokenConfig(address token) external view returns (address vault, bytes32 auditorKey);
}
