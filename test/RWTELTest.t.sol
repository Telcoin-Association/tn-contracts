// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {RecoverableWrapper} from "recoverable-wrapper/contracts/rwt/RecoverableWrapper.sol";
import {WTEL} from "../src/WTEL.sol";

contract RWTELTest is Test {
    WTEL wTEL;
    RecoverableWrapper rwTEL;

    // rwTEL constructor params
    string name_;
    string symbol_;
    uint256 recoverableWindow_;
    address governanceAddress_;
    address baseERC20_;
    uint16 maxToClean;

    function setUp() public {
        wTEL = new WTEL();

        name_ = "Recoverable Wrapped Telcoin";
        symbol_ = "rwTEL";
        recoverableWindow_ = 86_400; // ~1 day; Telcoin Network blocktime is ~1s
        governanceAddress_ = address(this); // multisig/council/DAO address in prod
        baseERC20_ = address(wTEL);
        maxToClean = type(uint16).max; // gas is not expected to be an obstacle; clear all relevant storage

        rwTEL = new RecoverableWrapper(
            name_,
            symbol_,
            recoverableWindow_,
            governanceAddress_,
            baseERC20_,
            maxToClean
        );
    }

    function test_setUp() public view {
        // wTEL sanity tests
        assertTrue(address(wTEL).code.length > 0);
        string memory wName = wTEL.name();
        assertEq(wName, "Wrapped Telcoin");
        string memory wSymbol = wTEL.symbol();
        assertEq(wSymbol, "wTEL");

        // rwTEL sanity tests
        assertTrue(address(rwTEL).code.length > 0);
        string memory rwName = rwTEL.name();
        assertEq(rwName, "Recoverable Wrapped Telcoin");
        string memory rwSymbol = rwTEL.symbol();
        assertEq(rwSymbol, "rwTEL");
        uint256 recoverableWindow = rwTEL.recoverableWindow();
        assertEq(recoverableWindow, 86_400);
        address governanceAddress = rwTEL.governanceAddress();
        assertEq(governanceAddress, address(this));
    }
}
