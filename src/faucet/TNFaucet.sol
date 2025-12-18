// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title Faucet
 * @author Robriks 📯️📯️📯️.eth
 * @notice A Telcoin Contract
 *
 * @notice This abstract contract provides unopinionated scaffolding for faucet implementations
 *         It is intended to manage Telcoin testnet tokens by being inherited by the StablecoinManager
 */
abstract contract TNFaucet {
    error RequestIneligibleUntil(uint256 unixTimestamp);

    event NativeDripAmountUpdated(uint256 newNativeDripAmount);
    event DripAmountUpdated(uint256 newDripAmount);
    event Drip(address token, address recipient, uint256 amount);
    event FaucetLowNativeBalance();

    /// @custom:storage-location erc7201:telcoin.storage.Faucet
    struct FaucetStorage {
        uint256 _dripAmount;
        uint256 _nativeDripAmount;
        uint256 _lowBalanceThreshold;
        mapping(address => mapping(address => uint256)) _lastDripTimestamp;
    }

    // keccak256(abi.encode(uint256(keccak256("erc7201.telcoin.storage.Faucet")) - 1))
    //   & ~bytes32(uint256(0xff))
    bytes32 internal constant FaucetStorageSlot = 0x331c20f00e5afe412d6bf194b51e8f2d981ce2eedc3a9ed8e5a5801a2017e900;

    /// @dev For use with proxies- implement without code if not using
    /// @notice Could not be implemented here with `initializer` modifier due to StablecoinHandler conflict
    function __Faucet_init(uint256 dripAmount_, uint256 nativeDripAmount_) internal virtual;

    /**
     *
     *   faucet
     *
     */

    /// @notice Developers may find it useful to extend this method with access control
    function drip(address token, address recipient) public virtual {
        _checkDrip(token, recipient);
        _setLastFulfilledDripTimestamp(token, recipient, block.timestamp);
        _drip(token, recipient);
    }

    /// @dev Should be inherited with a form of access control
    function setDripAmount(uint256 newDripAmount) external virtual;

    /// @dev Should be inherited with a form of access control
    function setNativeDripAmount(uint256 newNativeDripAmount) external virtual;

    /// @dev Should be inherited with a form of access control
    function setLowBalanceThreshold(uint256 newThreshold) external virtual;

    /// @notice Agnostic to enabled/disabled status for data availability
    function getDripAmount() public view returns (uint256 dripAmount) {
        FaucetStorage storage $ = _faucetStorage();
        return $._dripAmount;
    }

    /// @notice Agnostic to enabled/disabled status for data availability
    function getNativeDripAmount() public view returns (uint256 nativeDripAmount) {
        FaucetStorage storage $ = _faucetStorage();
        return $._nativeDripAmount;
    }

    /// @dev Exposes the timestamp of the last fulfilled faucet drip for a given `token` and `recipient`
    function getLastFulfilledDripTimestamp(
        address token,
        address recipient
    )
        public
        view
        returns (uint256 timestamp)
    {
        FaucetStorage storage $ = _faucetStorage();
        timestamp = $._lastDripTimestamp[recipient][token];
    }

    /**
     *
     *   internals
     *
     */

    /// @notice Developers may find it useful to implement this method with access control
    function _checkDrip(address token, address recipient) internal virtual;

    /// @notice Developers may find it useful to implement this method with access control
    function _drip(address token, address recipient) internal virtual;

    function _setDripAmount(uint256 newDripAmount) internal {
        FaucetStorage storage $ = _faucetStorage();
        $._dripAmount = newDripAmount;

        emit DripAmountUpdated(newDripAmount);
    }

    function _setNativeDripAmount(uint256 newNativeDripAmount) internal {
        FaucetStorage storage $ = _faucetStorage();
        $._nativeDripAmount = newNativeDripAmount;

        emit NativeDripAmountUpdated(newNativeDripAmount);
    }

    function _setLastFulfilledDripTimestamp(address token, address recipient, uint256 timestamp) internal {
        FaucetStorage storage $ = _faucetStorage();
        $._lastDripTimestamp[recipient][token] = timestamp;
    }

    /// @dev Emits an alert for indexer when faucet balance can only process <= 10_000 more requests
    function _checkLowNativeBalance() internal {
        uint256 thresholdDripsLeft = _getLowBalanceThreshold();
        if (address(this).balance <= getNativeDripAmount() * thresholdDripsLeft) {
            emit FaucetLowNativeBalance();
        }
    }

    function _getLowBalanceThreshold() internal view returns (uint256 thresholdDripsLeft) {
        FaucetStorage storage $ = _faucetStorage();
        thresholdDripsLeft = $._lowBalanceThreshold;
    }

    function _setLowBalanceThreshold(uint256 newThreshold) internal {
        FaucetStorage storage $ = _faucetStorage();
        $._lowBalanceThreshold = newThreshold;
    }

    function _faucetStorage() internal pure returns (FaucetStorage storage $) {
        assembly {
            $.slot := FaucetStorageSlot
        }
    }
}
