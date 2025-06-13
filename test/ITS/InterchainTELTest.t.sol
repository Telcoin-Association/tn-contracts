// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IRecoverableWrapper } from "../../src/interfaces/IRecoverableWrapper.sol";
import { RecoverableWrapper } from "../../src/recoverable-wrapper/RecoverableWrapper.sol";
import { WTEL } from "../../src/WTEL.sol";
import { InterchainTEL } from "../../src/InterchainTEL.sol";
import { IInterchainTEL } from "../../src/interfaces/IInterchainTEL.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { Create3Utils, Salts, ImplSalts } from "../../deployments/utils/Create3Utils.sol";
import { MockTEL, ITSTestHelper } from "./ITSTestHelper.sol";

contract InterchainTELTest is Test, ITSTestHelper {
    address admin = address(0xbeef);
    address user = address(0xabc);

    function setUp() public {
        setUp_tnFork_devnetConfig_create3(admin, originTEL);
    }

    function test_setUp() public view {
        // wTEL sanity tests
        assertTrue(address(wTEL).code.length > 0);
        string memory wName = wTEL.name();
        assertEq(wName, "Wrapped Telcoin");
        string memory wSymbol = wTEL.symbol();
        assertEq(wSymbol, "wTEL");

        // iTEL sanity tests
        assertEq(address(iTEL.interchainTokenService()), address(its));
        assertTrue(address(iTEL).code.length > 0);
        string memory rwName = iTEL.name();
        assertEq(rwName, "Interchain Telcoin");
        string memory rwSymbol = iTEL.symbol();
        assertEq(rwSymbol, "iTEL");
        uint256 recoverableWindow = iTEL.recoverableWindow();
        assertEq(recoverableWindow, recoverableWindow_);
        address owner = iTEL.owner();
        assertEq(owner, owner_);
    }

    function testFuzz_permitWrap(uint96 amount, uint256 deadline) public {
        vm.assume(amount > 0 && deadline > block.timestamp);

        uint256 zeroPK = uint256(keccak256("zero"));
        address testAddr = vm.addr(zeroPK);
        vm.deal(testAddr, amount);
        vm.prank(testAddr);
        wTEL.deposit{ value: amount }();

        bytes32 domainSeparator = wTEL.DOMAIN_SEPARATOR();
        bytes32 permitTypehash = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
        // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

        bytes32 permitDigest = keccak256(
            abi.encodePacked(
                hex"1901",
                domainSeparator,
                keccak256(abi.encode(permitTypehash, testAddr, address(iTEL), amount, wTEL.nonces(testAddr), deadline))
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(zeroPK, permitDigest);

        vm.expectEmit(true, true, true, true);
        emit IRecoverableWrapper.Wrap(testAddr, amount);

        iTEL.permitWrap(testAddr, amount, deadline, v, r, s);

        assertEq(wTEL.balanceOf(testAddr), 0);
        assertEq(wTEL.balanceOf(address(iTEL)), amount);
        assertEq(iTEL.balanceOf(testAddr), 0);
        vm.warp(block.timestamp + recoverableWindow_);
        assertEq(iTEL.balanceOf(testAddr), amount);
        assertEq(iTEL.totalSupply(), amount);
    }

    function testFuzz_doubleWrap(uint96 amount) public {
        vm.assume(amount > 0);
        // uint96 is ~ the total supply of TEL
        vm.deal(address(this), amount);

        vm.expectEmit(true, true, true, true);
        emit IRecoverableWrapper.Wrap(address(this), amount);

        uint256 wtelBalBefore = address(wTEL).balance;

        iTEL.doubleWrap{ value: amount }();

        assertEq(address(wTEL).balance, wtelBalBefore + amount);
        assertEq(address(this).balance, 0);
        assertEq(iTEL.balanceOf(address(this)), 0);
        assertEq(iTEL.unsettledRecords(address(this)).length, 1);

        vm.warp(block.timestamp + recoverableWindow_);
        assertEq(iTEL.balanceOf(address(this)), amount);
        assertEq(iTEL.totalSupply(), amount);

        iTEL.transfer(address(user), 1);
        assertEq(iTEL.unsettledRecords(address(this)).length, 0);
    }

    function testRevert_doubleWrap_mintFailed() public {
        uint256 amount = 0;
        vm.expectRevert();
        iTEL.doubleWrap{ value: amount }();
    }

    function testFuzz_mint(uint96 nativeAmount) public {
        vm.assume(nativeAmount > 0 && nativeAmount < telTotalSupply);

        uint256 initialRecipientBalance = user.balance;
        assertEq(initialRecipientBalance, 0);
        uint256 itelBal = address(iTEL).balance;
        assertEq(itelBal, telTotalSupply);

        vm.startPrank(iTEL.tokenManagerAddress());

        vm.expectEmit(true, true, true, false);
        emit IInterchainTEL.Minted(user, nativeAmount);
        iTEL.mint(user, nativeAmount);

        assertEq(user.balance, initialRecipientBalance + nativeAmount);
        assertEq(address(iTEL).balance, itelBal - nativeAmount);

        vm.stopPrank();
    }

    function testRevert_mint_revertIfNotTokenManager(uint40 interchainAmount) public {
        vm.assume(interchainAmount > 0);

        vm.expectRevert();
        iTEL.mint(user, interchainAmount);
    }

    function testFuzz_burn(uint96 nativeAmount) public {
        vm.assume(nativeAmount > 0 && nativeAmount < 1e29);

        vm.deal(user, nativeAmount);
        vm.prank(user);
        iTEL.doubleWrap{ value: nativeAmount }();
        vm.warp(block.timestamp + recoverableWindow_);

        uint256 initialBal = iTEL.balanceOf(user);
        assertEq(initialBal, nativeAmount);
        uint256 itelBal = address(iTEL).balance;
        assertEq(itelBal, telTotalSupply);
        uint256 governanceBal = iTEL.owner().balance;

        vm.startPrank(iTEL.tokenManagerAddress());

        bool willRevert = nativeAmount < DECIMALS_CONVERTER;
        if (willRevert) vm.expectRevert();
        (, uint256 remainder) = this.toTwoDecimals(nativeAmount);

        if (willRevert) {
            vm.expectRevert();
        } else {
            vm.expectEmit(true, true, true, false);
            emit IInterchainTEL.Burned(user, nativeAmount);
        }
        iTEL.burn(user, nativeAmount);

        vm.stopPrank();

        if (!willRevert) {
            assertEq(iTEL.balanceOf(user), 0);
            assertEq(address(iTEL).balance, itelBal + nativeAmount - remainder);
            assertEq(iTEL.owner().balance, governanceBal + remainder);
        }
    }

    function test_burn_revertIfNotTokenManager(uint96 nativeAmount) public {
        vm.assume(nativeAmount > 0 && nativeAmount >= DECIMALS_CONVERTER);

        vm.expectRevert();
        iTEL.burn(user, nativeAmount);
    }

    function test_transfer_zero() public {
        // RecoverableWrapper allows zero amount transfers
        iTEL.transfer(address(wTEL), 0);
    }

    function testRevert_transfer_self(uint8 amount) public {
        vm.assume(amount > 0);
        iTEL.doubleWrap{ value: amount }();
        vm.expectRevert();
        iTEL.transfer(address(this), amount);
    }

    function test_pause() public {
        vm.prank(owner_);
        iTEL.pause();
        assertTrue(iTEL.paused());

        uint256 zeroPK = uint256(keccak256("zero"));
        user = vm.addr(zeroPK);
        bytes memory expectedErr = abi.encodeWithSelector(Pausable.EnforcedPause.selector);
        uint256 amt = 1e16;

        vm.startPrank(iTEL.tokenManagerAddress());
        vm.expectRevert(expectedErr);
        iTEL.mint(user, amt);
        vm.expectRevert(expectedErr);
        iTEL.burn(user, amt);
        vm.stopPrank();

        vm.startPrank(user);
        vm.deal(user, amt * 2);
        wTEL.approve(address(iTEL), amt);
        wTEL.deposit{ value: amt }();

        uint32 deadline = uint32(block.timestamp + 1);
        bytes32 permitTypehash = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
        bytes32 permitDigest = keccak256(
            abi.encodePacked(
                hex"1901",
                wTEL.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(permitTypehash, user, address(iTEL), amt, wTEL.nonces(user), deadline))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(zeroPK, permitDigest);
        vm.expectRevert(expectedErr);
        iTEL.permitWrap(user, amt, deadline, v, r, s);

        vm.expectRevert(expectedErr);
        iTEL.wrap(amt);
        vm.expectRevert(expectedErr);
        iTEL.doubleWrap{ value: amt }();
        vm.expectRevert(expectedErr);
        iTEL.unwrap(amt);
        vm.expectRevert(expectedErr);
        iTEL.unwrapTo(admin, amt);
        vm.stopPrank();
    }

    function testRevert_pause_governanceOnly() public {
        bytes memory expectedErr = abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this));
        vm.expectRevert(expectedErr);
        iTEL.pause();

        assertFalse(iTEL.paused());
    }

    function test_unpause() public {
        vm.startPrank(owner_);
        iTEL.pause();
        assertTrue(iTEL.paused());

        iTEL.unpause();
        vm.stopPrank();
        assertFalse(iTEL.paused());

        // wrapping re-enabled
        uint256 amt = 1;
        vm.deal(user, amt);
        vm.prank(user);
        iTEL.doubleWrap{ value: amt }();
    }

    function testRevert_unpause_governanceOnly() public {
        vm.prank(owner_);
        iTEL.pause();

        bytes memory expectedErr = abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this));
        vm.expectRevert(expectedErr);
        iTEL.unpause();

        assertTrue(iTEL.paused());
    }
}
