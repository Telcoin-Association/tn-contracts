// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import { IStablecoin } from "../testnet/IStablecoin.sol";
import { IShieldedStablecoin } from "./IShieldedStablecoin.sol";

/// @title ShieldVault
/// @author Telcoin Association
/// @notice Public-side vault for ONE shielded stablecoin (eXYZ). `shield` burns public tokens from
///         the caller and credits a shielded note inside the TN-SHIELD precompile's Merkle tree;
///         `unshield` submits a zk proof to the precompile and mints the proven public amount back
///         out. One vault is deployed per token and registered with the precompile as
///         `vaultOf[token]` via governance `setTokenConfig`, making this contract the only address
///         the precompile accepts for its token's `shield`/`unshield` selectors.
/// @dev OPERATIONAL PREREQUISITE: the token's admin must grant this vault
///      `Stablecoin::MINTER_ROLE` AND `Stablecoin::BURNER_ROLE` out-of-band (roles live on the
///      token contract, not here). Without them `shield`/`unshield` revert on the token leg.
/// @dev Precompile calls use the protocol's low-level `.call` convention (cf. `StablecoinManager`,
///      `IBlsG1`): the precompile account carries a single `0xfe` code byte at genesis and is
///      dispatched by revm at runtime, so low-level calls sidestep Solidity's typed-interface
///      EXTCODESIZE guard (which reverts outright in pre-genesis/test contexts where the account
///      has no code at all). Calldata is still typed: it is built with `abi.encodeCall` against
///      `IShieldedStablecoin`, which only encodes and never emits the guard.
/// @dev ERROR IDIOM: precompile failures are `PrecompileError`-style frame halts with EMPTY
///      returndata (the tel/bls precompile idiom); distinct failure reasons exist only in node
///      traces/logs, never on-chain. `LowLevelCallFailure.returnData` is therefore empty for
///      precompile-side failures - callers must not expect decodable revert reasons.
/// @dev The precompile's `sol!` block in the node is the v1 interface source of truth;
///      `IShieldedStablecoin` mirrors it and `ShieldPrecompileSelectors` pins the selectors it
///      produces, with a parity test tying the two together.
/// @dev UUPS-upgradeable and pausable; the owner (intended: the governance safe) gates
///      `pause`/`unpause` and upgrades. Ownership moves only by two-step transfer
///      (`transferOwnership` then `acceptOwnership` by the nominee) and can never be renounced, so
///      a paused vault can always be unpaused or upgraded by someone.
contract ShieldVault is Ownable2StepUpgradeable, PausableUpgradeable, UUPSUpgradeable {
    /// @notice Canonical address of the TN-SHIELD shielded-stablecoin precompile; must match
    ///         `SHIELDED_PRECOMPILE_ADDRESS` in the Telcoin-Network node. Genesis gives the
    ///         address one `0xfe` (INVALID) byte of code so the account is never state-pruned and
    ///         any call bypassing precompile dispatch reverts instead of hitting an empty account.
    address public constant PRECOMPILE = 0x0000000000000000000000000000000123456789;

    /// @notice A low-level precompile call failed. `returnData` is EMPTY for precompile-side
    ///         failures (frame halts carry no returndata; see the contract-level error-idiom note).
    error LowLevelCallFailure(bytes returnData);
    /// @notice `shield` requires a nonzero amount (mirrors the precompile's own `amount > 0` gate).
    error ZeroAmount();
    /// @notice The initializer rejects the zero address for the token.
    error ZeroAddress();
    /// @notice Ownership cannot be renounced: an ownerless vault could never be unpaused or
    ///         upgraded; transfer it with `transferOwnership`/`acceptOwnership` instead.
    error OwnershipNotRenounceable();
    /// @notice `shield`/`unshield` refuse to run while the precompile account has no code: a CALL
    ///         to a codeless account succeeds with empty returndata, which would let `shield`
    ///         burn with no note ever created.
    error PrecompileNotLive();
    /// @notice `unshield` rejects a public-values blob that is not exactly `PV_LEN` bytes.
    error PublicValuesLength(uint256 length);
    /// @notice `unshield` rejects a proof whose public values name a token other than this vault's.
    error TokenMismatch(address proven, address vault);
    /// @notice The precompile's `unshield` returndata is not exactly the 64-byte
    ///         `abi.encode(address recipient, uint128 amount)`.
    error MalformedReturndata(uint256 length);

    /// @dev Byte length of the TN-SHIELD v1 public-values blob (`PV_LEN`, TNEP §4.8).
    uint256 internal constant PV_LEN = 1192;
    /// @dev Offset of the 20-byte originating token address inside the blob (TNEP §4.8).
    uint256 internal constant PV_TOKEN_OFFSET = 10;

    /// @custom:storage-location erc7201:telcoin.storage.ShieldVault
    struct ShieldVaultStorage {
        /// @notice The single eXYZ stablecoin this vault shields. Immutable-style: set once by the
        ///         initializer, no setter exists - deploy a new vault for a new token.
        IStablecoin _token;
    }

    // keccak256(abi.encode(uint256(keccak256("telcoin.storage.ShieldVault")) - 1))
    //   & ~bytes32(uint256(0xff)): the ERC-7201 slot of the annotated namespace id above, so
    //   tooling that derives the slot from the annotation agrees with the code
    bytes32 internal constant ShieldVaultStorageSlot =
        0xa8fc5eec84208657c7c9e20b20a0fed5f647f5011f2f5e39e54e9e8876af1400;

    /// @dev Locks the bare implementation: `initialize` can only ever run through a proxy's
    ///      delegatecall, so nobody can claim the implementation's owner slot. The e2e harness
    ///      etches `deployedBytecode` directly (the constructor never runs there); that is fine
    ///      because the etched implementation is only ever reached through its proxy.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the vault for exactly one token; called once via proxy deployment.
    /// @param token_ The eXYZ stablecoin this vault shields (must expose `mintTo`/`burnFrom`).
    /// @param owner_ The owner (intended: the governance safe); gates pause/unpause and upgrades.
    ///               Set directly here (no acceptance step); later transfers are two-step.
    function initialize(address token_, address owner_) external initializer {
        if (token_ == address(0)) revert ZeroAddress();
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __Pausable_init();

        _shieldVaultStorage()._token = IStablecoin(token_);
    }

    /// @notice The eXYZ stablecoin this vault shields.
    function token() public view returns (IStablecoin) {
        return _shieldVaultStorage()._token;
    }

    /// @notice Shields `amount` of the vault's token: burns it from the caller's public balance,
    ///         then has the precompile append a note commitment owned by `ownerAddr`.
    /// @dev ALLOWANCE PREREQUISITE: `Stablecoin.burnFrom` spends the caller's ERC-20 allowance
    ///      even for BURNER_ROLE holders, so the user MUST `token.approve(address(this), amount)`
    ///      before calling.
    /// @dev The shield opening is public calldata (no memo): the precompile itself recomputes
    ///      `cm = keccak256(DOM_NOTE || token || ownerAddr || amount_be16 || salt)`, so a hidden
    ///      amount larger than the burned amount cannot be smuggled in.
    /// @dev Burn-then-credit order: if the precompile leg fails, the whole transaction - burn
    ///      included - reverts atomically (the precompile halt carries empty returndata; the
    ///      revert surfaces as `LowLevelCallFailure` with empty `returnData`).
    /// @dev A blacklisted caller cannot shield: the token's `_update` hook reverts the burn.
    /// @dev PRECOMPILE LIVENESS: reverts with `PrecompileNotLive` while the precompile account has
    ///      no code (a chain whose genesis lacks the account, before the fork injects it, or any
    ///      foreign chain), because a CALL to a codeless account "succeeds" and the burn would
    ///      stand with no note created.
    /// @param amount Token amount to shield; must be nonzero (u128 per TN-SHIELD v1).
    /// @param ownerAddr Shielded address `a = keccak256(DOM_ADDR || pk_spend || pk_view)` that
    ///                  owns the new note.
    /// @param salt Fresh 32-byte note salt chosen by the caller.
    function shield(uint128 amount, bytes32 ownerAddr, bytes32 salt) external whenNotPaused {
        if (PRECOMPILE.code.length == 0) revert PrecompileNotLive();
        if (amount == 0) revert ZeroAmount();

        IStablecoin token_ = _shieldVaultStorage()._token;
        token_.burnFrom(msg.sender, amount);

        (bool ok, bytes memory ret) =
            PRECOMPILE.call(abi.encodeCall(IShieldedStablecoin.shield, (address(token_), ownerAddr, salt, amount)));
        if (!ok) revert LowLevelCallFailure(ret);
    }

    /// @notice Unshields tokens: submits `(proof, publicValues)` to the precompile, which verifies
    ///         the proof, marks the input nullifiers spent, and returns the proven
    ///         `(recipient, amount)`; the vault then mints `amount` of its token to `recipient`.
    /// @dev TOKEN BINDING: the precompile only checks that the caller is `vaultOf[pv.token]`, not
    ///      that the caller's token is `pv.token`, so after a registry re-point
    ///      (`setTokenConfig(T, V2, k)` with `V2.token() == T2`) a T-bound proof would otherwise
    ///      mint T2. The vault therefore requires the blob to be exactly `PV_LEN` bytes and its
    ///      token field (offset `PV_TOKEN_OFFSET`, frozen v1 layout) to equal its own token, and
    ///      reverts before the precompile leg otherwise.
    /// @dev COMPLIANCE: a blacklisted `recipient` makes the token's `_update` hook revert
    ///      (`Blacklisted(to)`), rolling back the WHOLE transaction - including the precompile's
    ///      nullifier marks and tree insertion - so the shielded note stays unspent and remains
    ///      spendable toward a compliant recipient.
    /// @dev Callable by anyone (relayable): recipient and amount are fixed by the proof's public
    ///      values, not by the caller. The precompile independently enforces that this vault is
    ///      `vaultOf[token]` for the proof's token.
    /// @dev PRECOMPILE LIVENESS: reverts with `PrecompileNotLive` while the precompile account has
    ///      no code, for symmetry with `shield` (the 64-byte returndata guard would already stop
    ///      the mint leg on its own).
    /// @dev On success the precompile returns exactly `abi.encode(address recipient, uint128
    ///      amount)`; the vault mints only when the returndata is exactly 64 bytes (TNEP §4.11)
    ///      and `abi.decode` rejects dirty high-order bits in either word.
    /// @param proof TN-SHIELD v1 Plonk proof envelope bytes (opaque to the vault).
    /// @param publicValues The TN-SHIELD v1 public-values blob (op = unshield; opaque to the vault).
    function unshield(bytes calldata proof, bytes calldata publicValues) external whenNotPaused {
        if (PRECOMPILE.code.length == 0) revert PrecompileNotLive();
        if (publicValues.length != PV_LEN) revert PublicValuesLength(publicValues.length);
        IStablecoin token_ = _shieldVaultStorage()._token;
        address proven = address(bytes20(publicValues[PV_TOKEN_OFFSET:PV_TOKEN_OFFSET + 20]));
        if (proven != address(token_)) revert TokenMismatch(proven, address(token_));

        (bool ok, bytes memory ret) =
            PRECOMPILE.call(abi.encodeCall(IShieldedStablecoin.unshield, (proof, publicValues)));
        if (!ok) revert LowLevelCallFailure(ret);
        if (ret.length != 64) revert MalformedReturndata(ret.length);

        (address recipient, uint128 amount) = abi.decode(ret, (address, uint128));
        token_.mintTo(recipient, amount);
    }

    /// @notice Pauses `shield` and `unshield`. Only the owner (governance safe) may pause.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses `shield` and `unshield`. Only the owner (governance safe) may unpause.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Ownership cannot be renounced (see `OwnershipNotRenounceable`); reverts for everyone.
    function renounceOwnership() public pure override {
        revert OwnershipNotRenounceable();
    }

    /// @notice Only the owner (governance safe) may perform an upgrade
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner { }

    function _shieldVaultStorage() internal pure returns (ShieldVaultStorage storage $) {
        assembly {
            $.slot := ShieldVaultStorageSlot
        }
    }
}
