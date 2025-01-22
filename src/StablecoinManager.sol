// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { StablecoinHandler } from "telcoin-contracts/contracts/stablecoin/StablecoinHandler.sol";
import { IStablecoin } from "external/telcoin-contracts/interfaces/IStablecoin.sol";
import { TNFaucet } from "./faucet/TNFaucet.sol";

/**
 * @title StablecoinManager
 * @author Robriks 📯️📯️📯️.eth
 * @notice A Telcoin Contract
 *
 * @notice This contract extends the StablecoinHandler which manages the minting and burning of stablecoins
 */
contract StablecoinManager is StablecoinHandler, TNFaucet, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    struct XYZMetadata {
        address token;
        string name;
        string symbol;
        uint256 decimals;
    }

    error LowLevelCallFailure();
    error InvalidOrDisabled(address token);
    error AlreadyEnabled(address token);
    error InvalidDripAmount(uint256 dripAmount);

    event XYZAdded(address token);
    event XYZRemoved(address token);

    struct StablecoinManagerInitParams {
        address admin_;
        address maintainer_;
        address[] tokens_;
        uint256 initMaxLimit;
        uint256 initMinLimit;
        address[] authorizedFaucets_;
        uint256 dripAmount_;
        uint256 nativeDripAmount_;
    }

    /// @custom:storage-location erc7201:telcoin.storage.StablecoinManager
    struct StablecoinManagerStorage {
        address[] _enabledXYZs;
        uint256 _dripAmount;
        uint256 _nativeDripAmount;
    }

    // keccak256(abi.encode(uint256(keccak256("erc7201.telcoin.storage.StablecoinHandler")) - 1))
    //   & ~bytes32(uint256(0xff))
    bytes32 internal constant StablecoinHandlerStorageSlot =
        0x38361881985b0f585e6124dca158a3af102bffba0feb9c42b0b40825f41a3300;

    // keccak256(abi.encode(uint256(keccak256("erc7201.telcoin.storage.StablecoinManager")) - 1))
    //   & ~bytes32(uint256(0xff))
    bytes32 internal constant StablecoinManagerStorageSlot =
        0x77dc539bf9c224afa178d31bf07d5109c2b5c5e56656e49b25e507fec3a69f00;

    bytes32 public constant FAUCET_ROLE = keccak256("FAUCET_ROLE");

    address public constant NATIVE_TOKEN_POINTER = address(0x0);

    /// @dev Invokes `__Pausable_init()`
    function initialize(StablecoinManagerInitParams calldata initParams) public initializer {
        __StablecoinHandler_init();
        __Faucet_init(initParams.dripAmount_, initParams.nativeDripAmount_);
        _setLowBalanceThreshold(10_000);

        // native token faucet drips are enabled by default
        UpdateXYZ(NATIVE_TOKEN_POINTER, true, type(uint256).max, 1);
        for (uint256 i; i < initParams.tokens_.length; ++i) {
            UpdateXYZ(initParams.tokens_[i], true, initParams.initMaxLimit, initParams.initMinLimit);
        }

        _grantRole(DEFAULT_ADMIN_ROLE, initParams.admin_);
        _grantRole(MAINTAINER_ROLE, initParams.maintainer_);

        for (uint256 i; i < initParams.authorizedFaucets_.length; ++i) {
            _grantRole(FAUCET_ROLE, initParams.authorizedFaucets_[i]);
        }
    }

    function UpdateXYZ(
        address token,
        bool validity,
        uint256 maxLimit,
        uint256 minLimit
    )
        public
        virtual
        override
        onlyRole(MAINTAINER_ROLE)
    {
        // to avoid recording duplicate members in storage array, revert
        if (validity && isEnabledXYZ(token)) revert AlreadyEnabled(token);

        _recordXYZ(token, validity);
        super.UpdateXYZ(token, validity, maxLimit, minLimit);
    }

    /// @dev Fetches all currently valid stablecoin addresses
    /// @notice Excludes `NATIVE_TOKEN_POINTER` if it is enabled
    function getEnabledXYZs() public view returns (address[] memory enabledXYZs) {
        StablecoinManagerStorage storage $ = _stablecoinManagerStorage();
        address[] memory unfilteredEnabledXYZs = $._enabledXYZs;
        // avoid underflow condition by terminating early if all tokens are disabled
        if (unfilteredEnabledXYZs.length == 0) return new address[](0);

        (bool nativeFound, uint256 nativeIndex) = _findNativeTokenIndex(unfilteredEnabledXYZs);
        if (!nativeFound) {
            return unfilteredEnabledXYZs;
        } else {
            // filter out `NATIVE_TOKEN_POINTER`
            uint256 filteredLen = unfilteredEnabledXYZs.length - 1;
            enabledXYZs = new address[](filteredLen);

            uint256 dynCounter;
            for (uint256 i; i < unfilteredEnabledXYZs.length; ++i) {
                if (i == nativeIndex) continue;

                enabledXYZs[dynCounter] = unfilteredEnabledXYZs[i];
                ++dynCounter;
            }
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

    /// @notice To identify if faucet has the native token enabled, pass in `address(0x0)`
    function isEnabledXYZ(address eXYZ) public view returns (bool isEnabled) {
        StablecoinManagerStorage storage $ = _stablecoinManagerStorage();
        address[] memory enabledXYZs = $._enabledXYZs;
        for (uint256 i; i < enabledXYZs.length; ++i) {
            if (enabledXYZs[i] == eXYZ) return true;
        }

        return false;
    }

    /**
     *
     *   faucet
     *
     */

    /// @dev Faucet function defining this contract as the onchain entrypoint for minting testnet tokens to users
    /// @dev To mint the chain's native token, use `NATIVE_TOKEN_POINTER == address(0x0)`
    /// @notice This contract must be given `Stablecoin::MINTER_ROLE` on each eXYZ contract
    /// @notice Implements Access Control, requiring callers to possess the `FAUCET_ROLE`
    function drip(address token, address recipient) public virtual override onlyRole(FAUCET_ROLE) {
        super.drip(token, recipient);
    }

    /// @inheritdoc TNFaucet
    function _drip(address token, address recipient) internal virtual override {
        uint256 amount;
        if (token == NATIVE_TOKEN_POINTER) {
            amount = getNativeDripAmount();

            (bool r,) = recipient.call{ value: amount }("");
            if (!r) revert LowLevelCallFailure();

            // reentrancy safe- does not perform state change
            _checkLowNativeBalance();
        } else {
            amount = getDripAmount();
            IStablecoin(token).mintTo(recipient, amount);
        }

        emit Drip(token, recipient, amount);
    }

    /// @inheritdoc TNFaucet
    function _checkDrip(address token, address recipient) internal virtual override {
        if (!isEnabledXYZ(token)) revert InvalidOrDisabled(token);

        uint256 lastFulfilledDrip = getLastFulfilledDripTimestamp(token, recipient);
        if (block.timestamp < lastFulfilledDrip + 1 days) {
            revert RequestIneligibleUntil(lastFulfilledDrip + 1 days);
        }
    }

    /// @dev Provides a way for Telcoin maintainers to alter the faucet's eXYZ drip amount onchain
    /// @notice Rather than set `dripAmount` to 0, disable the token
    /// @inheritdoc TNFaucet
    function setDripAmount(uint256 newDripAmount) external override onlyRole(MAINTAINER_ROLE) {
        if (newDripAmount == 0) revert InvalidDripAmount(newDripAmount);

        _setDripAmount(newDripAmount);
    }

    /// @dev Provides a way for Telcoin maintainers to alter the faucet's native token drip amount onchain
    /// @notice Rather than set `nativeDripAmount` to 0, disable the token
    /// @inheritdoc TNFaucet
    function setNativeDripAmount(uint256 newNativeDripAmount) external override onlyRole(MAINTAINER_ROLE) {
        if (newNativeDripAmount == 0) {
            revert InvalidDripAmount(newNativeDripAmount);
        }
        _setNativeDripAmount(newNativeDripAmount);
    }

    /// @dev Provides a way for Telcoin maintainers to configure the faucet's threshold for top-up alerts
    /// @inheritdoc TNFaucet
    function setLowBalanceThreshold(uint256 newThreshold) external virtual override onlyRole(MAINTAINER_ROLE) {
        _setLowBalanceThreshold(newThreshold);
    }

    function __Faucet_init(uint256 dripAmount_, uint256 nativeDripAmount_) internal virtual override initializer {
        _setDripAmount(dripAmount_);
        _setNativeDripAmount(nativeDripAmount_);
    }

    /**
     *
     *   support
     *
     */

    /**
     * @notice Rescues crypto assets mistakenly sent to the contract.
     * @dev Allows for the recovery of both ERC20 tokens and native token sent to the contract.
     * @param token The token to rescue. Use `address(0x0)` for native token.
     * @param amount The amount of the token to rescue.
     */
    function rescueCrypto(IERC20 token, uint256 amount) public onlyRole(MAINTAINER_ROLE) {
        if (address(token) == address(0x0)) {
            // Native Token
            (bool r,) = _msgSender().call{ value: amount }("");
            if (!r) revert LowLevelCallFailure();
        } else {
            // ERC20s
            token.safeTransfer(_msgSender(), amount);
        }
    }

    /**
     *
     *   internals
     *
     */
    function _recordXYZ(address token, bool validity) internal virtual {
        if (validity == true) {
            _addEnabledXYZ(token);
        } else {
            _removeEnabledXYZ(token);
        }
    }

    function _addEnabledXYZ(address token) internal {
        StablecoinManagerStorage storage $ = _stablecoinManagerStorage();
        $._enabledXYZs.push(token);

        emit XYZAdded(token);
    }

    function _removeEnabledXYZ(address token) internal {
        StablecoinManagerStorage storage $ = _stablecoinManagerStorage();

        // cache in memory
        address[] memory enabledXYZs = $._enabledXYZs;
        // find matching index in memory
        uint256 matchingIndex = type(uint256).max;
        for (uint256 i; i < enabledXYZs.length; ++i) {
            if (enabledXYZs[i] == token) matchingIndex = i;
        }

        // in the case no match was found, revert with info detailing invalid state
        if (matchingIndex == type(uint256).max) revert InvalidOrDisabled(token);

        // if match is not the final array member, write final array member into the matching index
        uint256 lastIndex = enabledXYZs.length - 1;
        if (matchingIndex != lastIndex) {
            $._enabledXYZs[matchingIndex] = enabledXYZs[lastIndex];
        }
        // pop member which is no longer relevant off end of array
        $._enabledXYZs.pop();

        emit XYZRemoved(token);
    }

    /// @notice Returns the index of the NATIVE_TOKEN_POINTER in storage array if found, otherwise `0xfffffff...`
    function _findNativeTokenIndex(address[] memory _enabledXYZs)
        internal
        pure
        returns (bool found, uint256 _enabledXYZsIndex)
    {
        for (uint256 i; i < _enabledXYZs.length; ++i) {
            if (_enabledXYZs[i] == NATIVE_TOKEN_POINTER) {
                found = true;
                _enabledXYZsIndex = i;
                break;
            }
        }

        if (!found) _enabledXYZsIndex = type(uint256).max;
    }

    /// @notice Despite having similar names, `StablecoinManagerStorage` != `StablecoinHandlerStorage` !!
    function _stablecoinManagerStorage() internal pure returns (StablecoinManagerStorage storage $) {
        assembly {
            $.slot := StablecoinManagerStorageSlot
        }
    }

    /// @notice Despite having similar names, `StablecoinHandlerStorage` != `StablecoinManagerStorage` !!
    function _stablecoinHandlerStorage() internal pure returns (StablecoinHandlerStorage storage $) {
        assembly {
            $.slot := StablecoinHandlerStorageSlot
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

    /// @dev To operate as a faucet, this contract must accept native token
    receive() external payable { }
}
