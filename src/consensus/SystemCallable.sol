// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

/**
 * @title SystemCallable
 * @author Telcoin Association
 * @notice A Telcoin Contract
 *
 * @notice This utility serves as a modular utility to support and access-gate system calls
 * @dev This abstract contract should be inherited for use with system calls directly from the protocol
 */
abstract contract SystemCallable {
    error OnlySystemCall(address invalidCaller);

    address public constant SYSTEM_ADDRESS =
        address(0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE);

    modifier onlySystemCall() {
        if (msg.sender != SYSTEM_ADDRESS) revert OnlySystemCall(msg.sender);
        _;
    }
}
