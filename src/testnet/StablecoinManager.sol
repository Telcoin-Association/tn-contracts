// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { StablecoinHandler } from "./StablecoinHandler.sol";
import { IStablecoin } from "./IStablecoin.sol";
import { TNFaucet } from "./TNFaucet.sol";
import { ITELMint } from "../interfaces/ITELMint.sol";

/**
 * @title StablecoinManager
 * @author Robriks 📯️📯️📯️.eth
 * @author Huwonk
 * @notice A Telcoin Contract
 *
 * @notice This contract extends the StablecoinHandler which manages the minting and burning of stablecoins
 */
contract StablecoinManager is StablecoinHandler, TNFaucet, UUPSUpgradeable {
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.AddressSet;

    struct XYZMetadata {
        address token;
        string name;
        string symbol;
        uint256 decimals;
    }

    struct TokenDripAmount {
        address token;
        uint256 dripAmount;
    }

    error LowLevelCallFailure(bytes returnData);
    error InvalidOrDisabled(address token);
    error AlreadyEnabled(address token);
    /// @notice Thrown when callers reach the inherited 4-arg `UpdateXYZ`; they must use the
    ///         5-arg variant on this contract so every enabled token gets a baseline drip amount.
    error UpdateXYZRequiresBaseDripAmount();

    event XYZAdded(address token);
    event XYZRemoved(address token);

    struct StablecoinManagerInitParams {
        address admin_;
        address maintainer_;
        address[] tokens_;
        uint256 initMaxLimit;
        uint256 initMinLimit;
        uint256 dripAmount_;
        uint256 nativeDripAmount_;
        uint256 baseDripCooldown_;
    }

    /// @custom:storage-location erc7201:telcoin.storage.StablecoinManager
    struct StablecoinManagerStorage {
        /// @notice Tokens this faucet will drip. Despite the public-facing "XYZ" naming
        ///         on related views (`isEnabledXYZ`, `getEnabledXYZs`, etc.), this set
        ///         also includes `NATIVE_TOKEN_POINTER` when native drips are enabled.
        ///         The XYZ-specific views filter native back out for downstream consumers.
        EnumerableSet.AddressSet _drippableTokens;
    }

    // keccak256(abi.encode(uint256(keccak256("erc7201.telcoin.storage.StablecoinManager")) - 1))
    //   & ~bytes32(uint256(0xff))
    bytes32 internal constant StablecoinManagerStorageSlot =
        0x77dc539bf9c224afa178d31bf07d5109c2b5c5e56656e49b25e507fec3a69f00;

    // TN-custom precompile
    ITELMint public constant TEL_MINT = ITELMint(address(0x7e1));

    /// @notice Divisor used to derive the minimum acceptable drip from the effective max:
    ///         `minAmount = effectiveMax / MIN_DRIP_DIVISOR`. Forces a `dripTo` caller to mint
    ///         at least 1/Nth of the cap to a recipient, raising the cost of dust-grief on
    ///         the recipient's cooldown without preventing larger-amount griefing.
    uint256 internal constant MIN_DRIP_DIVISOR = 10;

    /// @dev Invokes `__Pausable_init()`
    function initialize(StablecoinManagerInitParams calldata initParams) public initializer {
        __StablecoinHandler_init();
        __Faucet_init(initParams.baseDripCooldown_);

        // native token faucet drips are enabled by default
        UpdateXYZ(NATIVE_TOKEN_POINTER, true, type(uint256).max, 1e18, initParams.nativeDripAmount_);
        for (uint256 i; i < initParams.tokens_.length; ++i) {
            UpdateXYZ(
                initParams.tokens_[i],
                true,
                initParams.initMaxLimit,
                initParams.initMinLimit,
                initParams.dripAmount_
            );
        }

        _grantRole(DEFAULT_ADMIN_ROLE, initParams.admin_);
        _grantRole(MAINTAINER_ROLE, initParams.maintainer_);
    }

    /// @notice Enables or disables a drippable token, mirroring StablecoinHandler's mint/burn
    ///         caps and atomically seeding the baseline max drip amount on enable.
    /// @dev On `validity == true`: validates non-duplicate, records the token in the drippable
    ///      set, forwards `(maxLimit, minLimit)` to StablecoinHandler, and seeds the faucet's
    ///      baseline drip amount via `_setMaxDripAmount` (which itself rejects 0).
    /// @dev On `validity == false`: removes the token from the drippable set, forwards to
    ///      StablecoinHandler, and clears the faucet's baseline drip slot via
    ///      `_resetMaxDripAmount` so a future re-enable can pass any `baseDripAmount`
    ///      (including the previous one) without a `SettingAlreadyConfigured` revert.
    ///      `baseDripAmount` is ignored on this path.
    /// @param token Token address to enable or disable. Use `NATIVE_TOKEN_POINTER` for native.
    /// @param validity True to enable, false to disable.
    /// @param maxLimit StablecoinHandler max mint cap.
    /// @param minLimit StablecoinHandler min burn cap.
    /// @param baseDripAmount Baseline max drip amount for this token (only consumed on enable).
    function UpdateXYZ(
        address token,
        bool validity,
        uint256 maxLimit,
        uint256 minLimit,
        uint256 baseDripAmount
    )
        public
        virtual
        onlyRole(MAINTAINER_ROLE)
    {
        // to avoid recording duplicate members in storage set, revert
        if (validity && isEnabledXYZ(token)) revert AlreadyEnabled(token);

        _recordXYZ(token, validity);
        super.UpdateXYZ(token, validity, maxLimit, minLimit);
        if (validity) {
            _setMaxDripAmount(token, baseDripAmount);
        } else {
            _resetMaxDripAmount(token);
        }
    }

    /// @dev Fetches all currently valid stablecoin addresses
    /// @notice Excludes `NATIVE_TOKEN_POINTER` if it is enabled
    function getEnabledXYZs() public view returns (address[] memory enabledXYZs) {
        StablecoinManagerStorage storage $ = _stablecoinManagerStorage();
        address[] memory all = $._drippableTokens.values();

        if (!$._drippableTokens.contains(NATIVE_TOKEN_POINTER)) return all;

        // filter out `NATIVE_TOKEN_POINTER`
        enabledXYZs = new address[](all.length - 1);
        uint256 dynCounter;
        for (uint256 i; i < all.length; ++i) {
            if (all[i] == NATIVE_TOKEN_POINTER) continue;
            enabledXYZs[dynCounter] = all[i];
            ++dynCounter;
        }
    }

    /// @dev Fetches all currently valid stablecoins with metadata for dynamic rendering by a frontend
    /// @notice Intended for use in a view context to save on RPC calls
    function getEnabledXYZsWithMetadata() public view returns (XYZMetadata[] memory enabledXYZMetadatas) {
        // excludes `NATIVE_TOKEN_POINTER`
        address[] memory enabledXYZs = getEnabledXYZs();

        enabledXYZMetadatas = new XYZMetadata[](enabledXYZs.length);
        for (uint256 i; i < enabledXYZs.length; ++i) {
            string memory name = IStablecoin(enabledXYZs[i]).name();
            string memory symbol = IStablecoin(enabledXYZs[i]).symbol();
            uint256 decimals = IStablecoin(enabledXYZs[i]).decimals();

            enabledXYZMetadatas[i] = XYZMetadata(enabledXYZs[i], name, symbol, decimals);
        }
    }

    /// @dev Fetches every drippable token (XYZ stablecoins **plus** `NATIVE_TOKEN_POINTER` when
    ///      enabled) paired with its baseline max drip amount.
    /// @notice Intended for use in a view context to save on RPC calls
    function getDrippableTokensWithDripAmount() public view returns (TokenDripAmount[] memory dripAmounts) {
        StablecoinManagerStorage storage $ = _stablecoinManagerStorage();
        address[] memory drippable = $._drippableTokens.values();

        dripAmounts = new TokenDripAmount[](drippable.length);
        for (uint256 i; i < drippable.length; ++i) {
            dripAmounts[i] = TokenDripAmount(drippable[i], getBaselineMaxDripAmount(drippable[i]));
        }
    }

    /// @notice To identify if faucet has the native token enabled, pass in `NATIVE_TOKEN_POINTER`
    function isEnabledXYZ(address eXYZ) public view returns (bool isEnabled) {
        StablecoinManagerStorage storage $ = _stablecoinManagerStorage();
        return $._drippableTokens.contains(eXYZ);
    }

    // -------------
    // Faucet
    // -------------

    /// @inheritdoc TNFaucet
    /// @dev Dispatches between the TEL precompile (for native, keyed by `NATIVE_TOKEN_POINTER`)
    ///      and the per-eXYZ `IStablecoin.mintTo`. This contract must be given
    ///      `Stablecoin::MINTER_ROLE` on each eXYZ contract.
    /// @dev The native branch uses a low-level call rather than the typed `TEL_MINT.mint(...)`
    ///      because Solidity 0.8.x emits an `EXTCODESIZE` guard before typed-interface calls,
    ///      and the TEL precompile at `0x07e1` has no on-chain bytecode (revm dispatches it
    ///      at runtime). Mirrors the pattern in `BlsG1.sol`. See PR #95.
    function _drip(address recipient, address token, uint256 amount) internal virtual override {
        if (token == NATIVE_TOKEN_POINTER) {
            // Low-level call bypasses Solidity's typed-interface EXTCODESIZE guard, which
            // would otherwise revert because the TEL precompile at 0x07e1 has no bytecode
            // in state (revm dispatches it at runtime). Mirrors the BlsG1.sol pattern.
            (bool ok, bytes memory ret) =
                address(TEL_MINT).call(abi.encodeWithSelector(ITELMint.mint.selector, recipient, amount));
            if (!ok) revert LowLevelCallFailure(ret);
        } else {
            IStablecoin(token).mintTo(recipient, amount);
        }
    }

    /// @inheritdoc TNFaucet
    function _checkDrip(address recipient, address token, uint256 amount) internal virtual override {
        if (!isEnabledXYZ(token)) revert InvalidOrDisabled(token);

        // cooldown check, applies per-recipient override if set
        uint256 nextEligibleAt = getNextEligibleDripTimestamp(recipient, token);
        if (block.timestamp < nextEligibleAt) revert RequestIneligibleUntil(nextEligibleAt);

        // amount check, applies per-recipient override if set
        uint256 maxAmount = getMaxDripAmount(recipient, token);
        if (amount > maxAmount) revert RequestedAmountTooHigh(amount, maxAmount);

        // floor at MIN_DRIP_DIVISOR; explicit `amount == 0` guard catches the rounding edge
        // where `maxAmount < MIN_DRIP_DIVISOR` would otherwise let zero-amount drips through.
        uint256 minAmount = maxAmount / MIN_DRIP_DIVISOR;
        if (amount == 0 || amount < minAmount) revert RequestedAmountTooLow(amount, minAmount);
    }

    /// @inheritdoc TNFaucet
    function setMaxDripAmount(address token, uint256 newDripAmount) external override onlyRole(MAINTAINER_ROLE) {
        _setMaxDripAmount(token, newDripAmount);
    }

    /// @inheritdoc TNFaucet
    function setBaselineDripCooldown(uint256 amountInSeconds) external override onlyRole(MAINTAINER_ROLE) {
        _setBaselineDripCooldown(amountInSeconds);
    }

    /// @inheritdoc TNFaucet
    function setMaxDripAmountOverride(
        address overrideAddress,
        address token,
        uint256 amount
    )
        external
        override
        onlyRole(MAINTAINER_ROLE)
    {
        _setMaxDripAmountOverride(overrideAddress, token, amount);
    }

    /// @inheritdoc TNFaucet
    function setDripCooldownOverride(
        address overrideAddress,
        uint256 amountInSeconds
    )
        external
        override
        onlyRole(MAINTAINER_ROLE)
    {
        _setDripCooldownOverride(overrideAddress, amountInSeconds);
    }

    /// @inheritdoc TNFaucet
    function __Faucet_init(uint256 baseDripCooldown_) internal virtual override initializer {
        _setBaselineDripCooldown(baseDripCooldown_);
    }

    // -------------
    // Support
    // -------------

    /**
     * @notice Rescues crypto assets mistakenly sent to the contract.
     * @dev Allows for the recovery of both ERC20 tokens and native token sent to the contract.
     * @param token The token to rescue. Use `NATIVE_TOKEN_POINTER` for native token.
     * @param amount The amount of the token to rescue.
     */
    function rescueCrypto(IERC20 token, uint256 amount) public onlyRole(MAINTAINER_ROLE) {
        if (address(token) == NATIVE_TOKEN_POINTER) {
            // Native Token
            (bool r, bytes memory ret) = _msgSender().call{ value: amount }("");
            if (!r) revert LowLevelCallFailure(ret);
        } else {
            // ERC20s
            token.safeTransfer(_msgSender(), amount);
        }
    }

    // -------------
    // Internals
    // -------------
    function _recordXYZ(address token, bool validity) internal virtual {
        if (validity == true) {
            _addEnabledXYZ(token);
        } else {
            _removeEnabledXYZ(token);
        }
    }

    function _addEnabledXYZ(address token) internal {
        StablecoinManagerStorage storage $ = _stablecoinManagerStorage();
        $._drippableTokens.add(token);

        emit XYZAdded(token);
    }

    function _removeEnabledXYZ(address token) internal {
        StablecoinManagerStorage storage $ = _stablecoinManagerStorage();
        if (!$._drippableTokens.remove(token)) revert InvalidOrDisabled(token);

        emit XYZRemoved(token);
    }

    function _stablecoinManagerStorage() internal pure returns (StablecoinManagerStorage storage $) {
        assembly {
            $.slot := StablecoinManagerStorageSlot
        }
    }

    /// @dev Extends `StablecoinHandler::AccessControlUpgradeable` to bypass `onlyRole()` modifier during initialization
    /// This is necessary because this contract is intended to be deployed via Arachnid Deterministic Deployment proxy
    function _checkRole(bytes32 role) internal view virtual override {
        address caller = _msgSender();
        bool hasRoleOrInitializing = hasRole(role, caller) || _isInitializing();
        if (!hasRoleOrInitializing) {
            revert AccessControlUnauthorizedAccount(caller, role);
        }
    }

    /// @notice Only the admin may perform an upgrade
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyRole(DEFAULT_ADMIN_ROLE) { }

    /// @dev Accepts native token for recovery via `rescueCrypto`
    receive() external payable { }
}
