// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import { MintBurnOFTAdapter } from "@layerzerolabs/oft-evm/contracts/MintBurnOFTAdapter.sol";
import { IMintableBurnable } from "@layerzerolabs/oft-evm/contracts/interfaces/IMintableBurnable.sol";
import { OFTCore } from "@layerzerolabs/oft-evm/contracts/OFTCore.sol";
import { SendParam, OFTReceipt } from "@layerzerolabs/oft-evm/contracts/interfaces/IOFT.sol";
import { MessagingReceipt, MessagingFee } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { WETH } from "solady/tokens/WETH.sol";
import { SystemCallable } from "./consensus/SystemCallable.sol";
import { IInterchainTELAdapter } from "./interfaces/IInterchainTELAdapter.sol";

/// @title InterchainTELAdapter
/// @notice LayerZero OFT adapter that bridges WTEL between Telcoin Network and remote chains
/// @dev Inherits MintBurnOFTAdapter with WTEL as the underlying token but overrides _debit/_credit
/// to convert between WTEL and native TEL. Inbound bridge credits are delivered as native TEL.
/// The contract holds native TEL as a credit pool for inbound deliveries.
contract InterchainTELAdapter is IInterchainTELAdapter, MintBurnOFTAdapter, SystemCallable, Pausable {
    /// @param wtel_ Address of the WTEL (Wrapped TEL) contract
    /// @param lzEndpoint_ Address of the LayerZero endpoint on Telcoin Network
    /// @param delegate_ Initial owner and LayerZero OApp delegate
    constructor(
        address wtel_,
        address lzEndpoint_,
        address delegate_
    ) MintBurnOFTAdapter(wtel_, IMintableBurnable(address(0)), lzEndpoint_, delegate_) Ownable(delegate_) {}

    /**
     *
     *   OFT Configuration
     *
     */

    /// @notice Returns 2 shared decimals to match TEL's 2-decimal representation on origin chains
    /// @dev This gives decimalConversionRate = 10^(18-2) = 1e16
    function sharedDecimals() public pure override returns (uint8) {
        return 2;
    }

    /// @notice Returns true because send() requires the caller to approve WTEL spending
    function approvalRequired() external pure override returns (bool) {
        return true;
    }

    /**
     *
     *   Bridge Operations
     *
     */

    /// @notice Debits WTEL from sender and unwraps to native TEL held in contract
    /// @dev Overrides MintBurnOFTAdapter._debit to take WTEL via transferFrom and unwrap to native TEL.
    /// The native TEL stays in the contract as a credit pool for inbound bridge deliveries.
    function _debit(
        address _from,
        uint256 _amountLD,
        uint256 _minAmountLD,
        uint32 _dstEid
    ) internal virtual override whenNotPaused returns (uint256 amountSentLD, uint256 amountReceivedLD) {
        (amountSentLD, amountReceivedLD) = _debitView(_amountLD, _minAmountLD, _dstEid);

        // Transfer WTEL from sender to this contract
        innerToken.transferFrom(_from, address(this), amountSentLD);

        // Unwrap WTEL to native TEL — stays in contract as credit pool for inbound deliveries
        WETH(payable(address(innerToken))).withdraw(amountSentLD);
    }

    /// @notice Credits native TEL directly to recipient instead of minting WTEL
    /// @dev Overrides MintBurnOFTAdapter._credit to deliver native TEL via low-level call.
    /// Reverts if delivery fails, causing the LZ message to enter failed state (retryable after unpause).
    function _credit(
        address _to,
        uint256 _amountLD,
        uint32 /* _srcEid */
    ) internal virtual override whenNotPaused returns (uint256 amountReceivedLD) {
        if (_to == address(0x0)) _to = address(0xdead);

        (bool success,) = _to.call{ value: _amountLD }("");
        if (!success) revert CreditFailed(_to, _amountLD);

        return _amountLD;
    }

    /// @notice Relaxes OAppSender's strict msg.value == nativeFee check
    /// @dev Required because sendNative() bundles bridge amount + LZ fee in a single msg.value,
    /// and send() with WTEL needs msg.value for just the LZ fee while native TEL from _debit stays in contract
    function _payNative(uint256 _nativeFee) internal virtual override returns (uint256 nativeFee) {
        if (msg.value < _nativeFee) revert NotEnoughNative(msg.value);
        return _nativeFee;
    }

    /// @inheritdoc IInterchainTELAdapter
    function sendNative(
        SendParam calldata _sendParam,
        MessagingFee calldata _fee,
        address _refundAddress
    ) external payable whenNotPaused returns (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt) {
        if (msg.value < _sendParam.amountLD + _fee.nativeFee) revert InsufficientMsgValue();

        // Remove dust and check slippage — same as _debit's first step
        (uint256 amountSentLD, uint256 amountReceivedLD) =
            _debitView(_sendParam.amountLD, _sendParam.minAmountLD, _sendParam.dstEid);

        // Native TEL from msg.value stays in contract as credit pool.
        // Dust (amountLD - amountSentLD, always < 1e16 wei) also stays in contract.

        // Build and send LZ message — replicates OFTCore.send() flow without _debit
        (bytes memory message, bytes memory options) = _buildMsgAndOptions(_sendParam, amountReceivedLD);
        msgReceipt = _lzSend(_sendParam.dstEid, message, options, _fee, _refundAddress);

        oftReceipt = OFTReceipt(amountSentLD, amountReceivedLD);
        emit OFTSent(msgReceipt.guid, _sendParam.dstEid, msg.sender, amountSentLD, amountReceivedLD);
    }

    /**
     *
     *   Admin
     *
     */

    function pause() external onlyOwner whenNotPaused {
        _pause();
    }

    function unpause() external onlyOwner whenPaused {
        _unpause();
    }

    /// @notice Accepts native TEL from WTEL.withdraw() and direct funding for the credit pool
    receive() external payable {}
}
