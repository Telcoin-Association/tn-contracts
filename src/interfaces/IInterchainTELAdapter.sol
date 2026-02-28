// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import { SendParam, OFTReceipt } from "@layerzerolabs/oft-evm/contracts/interfaces/IOFT.sol";
import { MessagingReceipt, MessagingFee } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

/// @title IInterchainTELAdapter
/// @notice Interface for the LayerZero OFT adapter that bridges WTEL between Telcoin Network and remote chains
interface IInterchainTELAdapter {
    /// @notice Emitted when native TEL delivery fails during inbound bridge credit
    error CreditFailed(address to, uint256 amount);

    /// @notice Emitted when sendNative msg.value is insufficient to cover bridge amount + LZ fee
    error InsufficientMsgValue();

    /// @notice Bridge native TEL to a remote chain in one transaction
    /// @dev Wraps native TEL directly without requiring WTEL. msg.value must cover amountLD + fee.nativeFee
    /// @param _sendParam OFT send parameters where amountLD is the native TEL amount to bridge
    /// @param _fee LayerZero messaging fee
    /// @param _refundAddress Address to refund excess LZ fees
    function sendNative(
        SendParam calldata _sendParam,
        MessagingFee calldata _fee,
        address _refundAddress
    )
        external
        payable
        returns (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt);

    function pause() external;
    function unpause() external;
}
