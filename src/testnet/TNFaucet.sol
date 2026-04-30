// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title Faucet
 * @author Robriks 📯️📯️📯️.eth
 * @author Huwonk
 * @notice A Telcoin Contract
 *
 * @notice This abstract contract provides unopinionated scaffolding for faucet implementations
 *         It is intended to manage Telcoin testnet tokens by being inherited by the StablecoinManager
 *
 * @notice The chain's native token is keyed by `NATIVE_TOKEN_POINTER` (the conventional
 *         "EEEE" magic address) throughout this contract, including for storage lookups
 *         (e.g. `_baselineMaxDripAmount[NATIVE_TOKEN_POINTER]`)
 *
 * @notice Argument convention: any function taking both a recipient and a token address takes
 *         `(recipient, token, ...)` in that order. This matches how the override / timestamp
 *         storage maps are keyed (`map[recipient][token]`).
 */
abstract contract TNFaucet {
    /// @notice Thrown when a drip is requested before the recipient's cooldown has elapsed.
    /// @param unixTimestamp The earliest block timestamp at which the recipient becomes eligible.
    error RequestIneligibleUntil(uint256 unixTimestamp);

    /// @notice Thrown when the requested drip exceeds the recipient's effective max drip amount.
    /// @param requestedAmount The amount the caller asked for.
    /// @param maxAmount The cap that was effective for this `(recipient, token)` pair.
    error RequestedAmountTooHigh(uint256 requestedAmount, uint256 maxAmount);

    /// @notice Thrown when a setter would be a no-op (the new value equals the existing one).
    error SettingAlreadyConfigured();

    /// @notice Thrown when a baseline drip-amount setter is called with a zero amount.
    /// @dev Prevents accidentally disabling a token by setting its max to 0; remove the token
    ///      from the drippable set instead.
    /// @param dripAmount The (zero) amount that was rejected.
    error InvalidDripAmount(uint256 dripAmount);

    /// @notice Emitted when a token's baseline max drip amount is updated.
    /// @param token The token whose baseline was changed (use `NATIVE_TOKEN_POINTER` for native).
    /// @param newDripAmount The new baseline max drip amount.
    event DripAmountUpdated(address token, uint256 newDripAmount);

    /// @notice Emitted on every successful drip.
    /// @param recipient The wallet that received the drip.
    /// @param token The token that was dripped (or `NATIVE_TOKEN_POINTER` for native).
    /// @param amount The amount that was dripped.
    event Drip(address recipient, address token, uint256 amount);

    /// @notice Emitted when the baseline drip cooldown is updated.
    /// @param amountInSeconds The new baseline cooldown, in seconds.
    event BaselineDripCooldownUpdated(uint256 amountInSeconds);

    /// @notice Emitted when a per-recipient cooldown override is set or changed.
    /// @param overriddenAddress The recipient whose cooldown was overridden.
    /// @param amount The new cooldown for this recipient, in seconds.
    event DripCooldownOverrideUpdated(address overriddenAddress, uint256 amount);

    /// @notice Emitted when a per-recipient max-drip-amount override is set or changed.
    /// @param overriddenAddress The recipient whose cap was overridden.
    /// @param token The token the override applies to.
    /// @param amount The new max drip amount for this `(recipient, token)`.
    event MaxDripAmountOverrideUpdated(address overriddenAddress, address token, uint256 amount);

    /// @notice Sentinel address used to refer to the chain's native token throughout the faucet.
    /// @notice Also the storage key for native-token drip configuration. Uses the conventional
    ///         "EEEE" magic address (popularised by 1inch / Aave) so callers can supply it
    ///         intentionally rather than relying on the zero address.
    address public constant NATIVE_TOKEN_POINTER = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @custom:storage-location erc7201:telcoin.storage.Faucet
    struct FaucetStorage {
        uint256 _baselineDripCooldown;
        mapping(address => mapping(address => uint256)) _lastDripTimestamp; // recipient => token => unixTimestamp
        mapping(address => uint256) _dripCooldownOverride; // recipient => amountInSeconds
        mapping(address => mapping(address => uint256)) _maxDripAmountOverride; // recipient => token => amount
        mapping(address => uint256) _baselineMaxDripAmount; // token => amount
    }

    // keccak256(abi.encode(uint256(keccak256("erc7201.telcoin.storage.Faucet")) - 1))
    //   & ~bytes32(uint256(0xff))
    bytes32 internal constant FaucetStorageSlot = 0x331c20f00e5afe412d6bf194b51e8f2d981ce2eedc3a9ed8e5a5801a2017e900;

    /// @dev For use with proxies- implement without code if not using.
    /// @notice Could not be implemented here with the `initializer` modifier due to a clash with
    ///         StablecoinHandler's own initializer; the inheriting contract owns initialization.
    /// @notice Seeds the baseline cooldown. Baseline max drip amounts (including native) are
    ///         seeded by the inheriting contract when it enables tokens.
    /// @param baseDripCooldown_ Initial baseline cooldown applied to recipients without an override.
    function __Faucet_init(uint256 baseDripCooldown_) internal virtual;

    // -------------
    // Faucet
    // -------------

    /// @notice Permissionless: anyone can request a drip on behalf of `recipient`. Rate-limited
    ///         by per-recipient cooldown and per-recipient/token max amount.
    /// @notice Pass `NATIVE_TOKEN_POINTER` as `token` to drip the chain's native token.
    /// @param recipient The wallet that receives the drip and whose cooldown advances.
    /// @param token The token to drip, or `NATIVE_TOKEN_POINTER` for native.
    /// @param amount Requested amount; must not exceed the effective max for `(recipient, token)`.
    function dripTo(address recipient, address token, uint256 amount) public virtual {
        _checkDrip(recipient, token, amount);
        _setLastFulfilledDripTimestamp(recipient, token, block.timestamp);
        _drip(recipient, token, amount);

        emit Drip(recipient, token, amount);
    }

    /// @notice Permissionless: convenience wrapper that drips to `msg.sender`. See `dripTo`.
    /// @param token The token to drip, or `NATIVE_TOKEN_POINTER` for native.
    /// @param amount Requested amount; must not exceed the effective max for `(msg.sender, token)`.
    function drip(address token, uint256 amount) public virtual {
        dripTo(msg.sender, token, amount);
    }

    /// @notice Sets the baseline max drip amount for `token`.
    /// @dev Should be inherited with a form of access control.
    /// @dev Reverts with `InvalidDripAmount(0)` if `newDripAmount == 0`; remove the token from
    ///      the drippable set rather than zeroing its baseline.
    /// @param token The token whose baseline is being set (use `NATIVE_TOKEN_POINTER` for native).
    /// @param newDripAmount The new baseline max drip amount.
    function setMaxDripAmount(address token, uint256 newDripAmount) external virtual;

    /// @notice Sets the baseline drip cooldown that applies to recipients without an override.
    /// @dev Should be inherited with a form of access control.
    /// @dev Reverts with `SettingAlreadyConfigured` if the value is unchanged.
    /// @param amountInSeconds The new baseline cooldown, in seconds.
    function setBaselineDripCooldown(uint256 amountInSeconds) external virtual;

    /// @notice Sets a per-recipient max drip amount override for `(overrideAddress, token)`.
    /// @dev Should be inherited with a form of access control.
    /// @dev Reverts with `SettingAlreadyConfigured` if the override is unchanged.
    /// @param overrideAddress The recipient whose cap is being overridden.
    /// @param token The token the override applies to (use `NATIVE_TOKEN_POINTER` for native).
    /// @param amount The new max for this recipient/token pair. Pass 0 to clear (revert to baseline).
    function setMaxDripAmountOverride(address overrideAddress, address token, uint256 amount) external virtual;

    /// @notice Sets a per-recipient cooldown override.
    /// @dev Should be inherited with a form of access control.
    /// @dev Reverts with `SettingAlreadyConfigured` if the override is unchanged.
    /// @param overrideAddress The recipient whose cooldown is being overridden.
    /// @param amountInSeconds The new cooldown for this recipient, in seconds. Pass 0 to clear
    ///                        (revert to baseline).
    function setDripCooldownOverride(address overrideAddress, uint256 amountInSeconds) external virtual;

    /// @notice Returns the effective max drip amount for `recipient` on `token`. Applies the
    ///         per-recipient override if set, else falls back to the baseline.
    /// @notice For the chain's native token, pass `NATIVE_TOKEN_POINTER` as `token`.
    /// @param recipient The wallet whose effective cap is being queried.
    /// @param token The token of interest (use `NATIVE_TOKEN_POINTER` for native).
    /// @return dripAmount The effective max drip amount.
    function getMaxDripAmount(address recipient, address token) public view returns (uint256 dripAmount) {
        FaucetStorage storage $ = _faucetStorage();
        uint256 _override = $._maxDripAmountOverride[recipient][token];
        dripAmount = _override > 0 ? _override : $._baselineMaxDripAmount[token];
    }

    /// @notice Returns the baseline max drip amount for `token`, ignoring per-recipient overrides.
    /// @param token The token of interest (use `NATIVE_TOKEN_POINTER` for native).
    /// @return dripAmount The baseline amount.
    function getBaselineMaxDripAmount(address token) public view returns (uint256 dripAmount) {
        FaucetStorage storage $ = _faucetStorage();
        dripAmount = $._baselineMaxDripAmount[token];
    }

    /// @notice Returns the effective drip cooldown (seconds) for `recipient`. Applies the
    ///         per-recipient override if set, else falls back to the baseline.
    /// @param recipient The wallet whose effective cooldown is being queried.
    /// @return cooldown The effective cooldown, in seconds.
    function getDripCooldown(address recipient) public view returns (uint256 cooldown) {
        FaucetStorage storage $ = _faucetStorage();
        uint256 _override = $._dripCooldownOverride[recipient];
        cooldown = _override > 0 ? _override : $._baselineDripCooldown;
    }

    /// @notice Returns the baseline drip cooldown (seconds), ignoring per-recipient overrides.
    /// @return cooldown The baseline cooldown, in seconds.
    function getBaselineDripCooldown() public view returns (uint256 cooldown) {
        FaucetStorage storage $ = _faucetStorage();
        cooldown = $._baselineDripCooldown;
    }

    /// @notice Exposes the timestamp of the last fulfilled drip for a `(recipient, token)` pair.
    ///         Returns 0 for a `(recipient, token)` pair that has never received a drip.
    /// @param recipient The wallet of interest.
    /// @param token The token of interest (use `NATIVE_TOKEN_POINTER` for native).
    /// @return timestamp The unix timestamp of the last successful drip.
    function getLastFulfilledDripTimestamp(address recipient, address token) public view returns (uint256 timestamp) {
        FaucetStorage storage $ = _faucetStorage();
        timestamp = $._lastDripTimestamp[recipient][token];
    }

    /// @notice Returns the unix timestamp at which `recipient` becomes eligible to receive another
    ///         drip of `token`. If the returned value is <= `block.timestamp`, the wallet is
    ///         eligible now. A wallet that has never received a drip returns just the cooldown
    ///         (i.e. `lastFulfilled == 0`), which is in the past for any sane chain so the
    ///         caller will read it as "eligible now".
    /// @param recipient The wallet of interest.
    /// @param token The token of interest (use `NATIVE_TOKEN_POINTER` for native).
    /// @return timestamp The next-eligible unix timestamp.
    function getNextEligibleDripTimestamp(
        address recipient,
        address token
    )
        public
        view
        returns (uint256 timestamp)
    {
        timestamp = getLastFulfilledDripTimestamp(recipient, token) + getDripCooldown(recipient);
    }

    // -------------
    // Internals
    // -------------

    /// @notice Validates a pending drip for `recipient` on `token` for `amount`. Revert paths:
    ///         `RequestIneligibleUntil` (cooldown not elapsed), `RequestedAmountTooHigh` (over
    ///         cap), or any subclass-specific rejection (e.g. token not enabled).
    /// @dev Implementer is expected to handle access control / token enablement checks.
    /// @param recipient The wallet whose eligibility and cap are being checked.
    /// @param token The token to drip (use `NATIVE_TOKEN_POINTER` for native).
    /// @param amount The requested drip amount.
    function _checkDrip(address recipient, address token, uint256 amount) internal virtual;

    /// @notice Performs the actual mint/transfer for a drip. Must not duplicate the eligibility
    ///         checks done by `_checkDrip`; called only after `_checkDrip` has passed.
    /// @dev Implementer dispatches to the appropriate mint/transfer mechanism for the token.
    /// @param recipient The wallet receiving the drip.
    /// @param token The token to drip (use `NATIVE_TOKEN_POINTER` for native).
    /// @param amount The amount to drip.
    function _drip(address recipient, address token, uint256 amount) internal virtual;

    /// @notice Internal: writes the baseline cooldown. Reverts on no-op writes.
    /// @param amountInSeconds The new baseline cooldown, in seconds.
    function _setBaselineDripCooldown(uint256 amountInSeconds) internal {
        FaucetStorage storage $ = _faucetStorage();
        if ($._baselineDripCooldown == amountInSeconds) revert SettingAlreadyConfigured();

        $._baselineDripCooldown = amountInSeconds;
        emit BaselineDripCooldownUpdated(amountInSeconds);
    }

    /// @notice Internal: writes a token's baseline max drip amount. Rejects zero.
    /// @param token The token whose baseline is being set.
    /// @param newDripAmount The new baseline (must be > 0).
    function _setMaxDripAmount(address token, uint256 newDripAmount) internal {
        if (newDripAmount == 0) revert InvalidDripAmount(newDripAmount);
        FaucetStorage storage $ = _faucetStorage();
        if($._baselineMaxDripAmount[token] == newDripAmount) revert SettingAlreadyConfigured();
        $._baselineMaxDripAmount[token] = newDripAmount;

        emit DripAmountUpdated(token, newDripAmount);
    }

    /// @notice Internal: writes a per-recipient max-amount override. Reverts on no-op writes.
    /// @param overrideAddress The recipient whose cap is being overridden.
    /// @param token The token the override applies to.
    /// @param amount The new override; pass 0 to clear and fall back to the baseline.
    function _setMaxDripAmountOverride(address overrideAddress, address token, uint256 amount) internal {
        FaucetStorage storage $ = _faucetStorage();
        if ($._maxDripAmountOverride[overrideAddress][token] == amount) revert SettingAlreadyConfigured();

        $._maxDripAmountOverride[overrideAddress][token] = amount;
        emit MaxDripAmountOverrideUpdated(overrideAddress, token, amount);
    }

    /// @notice Internal: writes a per-recipient cooldown override. Reverts on no-op writes.
    /// @param overrideAddress The recipient whose cooldown is being overridden.
    /// @param amountInSeconds The new cooldown override; pass 0 to clear and fall back to baseline.
    function _setDripCooldownOverride(address overrideAddress, uint256 amountInSeconds) internal {
        FaucetStorage storage $ = _faucetStorage();
        if ($._dripCooldownOverride[overrideAddress] == amountInSeconds) revert SettingAlreadyConfigured();

        $._dripCooldownOverride[overrideAddress] = amountInSeconds;
        emit DripCooldownOverrideUpdated(overrideAddress, amountInSeconds);
    }

    /// @notice Internal: stamps the last-fulfilled-drip timestamp for `(recipient, token)`.
    /// @param recipient The wallet that just received a drip.
    /// @param token The token that was dripped.
    /// @param timestamp The unix timestamp of the drip (typically `block.timestamp`).
    function _setLastFulfilledDripTimestamp(address recipient, address token, uint256 timestamp) internal {
        FaucetStorage storage $ = _faucetStorage();
        $._lastDripTimestamp[recipient][token] = timestamp;
    }

    /// @notice Internal: returns a pointer to the ERC-7201 faucet storage struct.
    function _faucetStorage() internal pure returns (FaucetStorage storage $) {
        assembly {
            $.slot := FaucetStorageSlot
        }
    }
}
