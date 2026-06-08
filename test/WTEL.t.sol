// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Test } from "forge-std/Test.sol";
import { WTEL } from "../src/WTEL.sol";
import { IWETH9 } from "../src/interfaces/IWETH9.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title WTEL unit tests
///
/// @notice Pure-EVM tests against a fresh WTEL deployment. No fork required;
///         WTEL is a standalone wrapped-native contract with no chain-specific
///         dependencies.
contract WTELTest is Test {
    WTEL wtel;

    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address carol = makeAddr("carol");

    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function setUp() public {
        wtel = new WTEL();

        vm.deal(alice, 1_000 ether);
        vm.deal(bob, 1_000 ether);
        vm.deal(carol, 1_000 ether);
    }

    // ---------- Metadata ----------

    function test_NameSymbolDecimals() public view {
        assertEq(wtel.name(), "Wrapped Tel");
        assertEq(wtel.symbol(), "WTEL");
        assertEq(wtel.decimals(), 18);
    }

    function test_InheritsIWETH9Interface() public view {
        // Compile-time confirmation that WTEL satisfies IWETH9 (and IERC20 transitively).
        IWETH9 weth = IWETH9(address(wtel));
        IERC20 erc20 = IERC20(address(wtel));
        assertEq(weth.totalSupply(), 0);
        assertEq(erc20.balanceOf(alice), 0);
    }

    // ---------- Deposit ----------

    function test_DepositCreditsBalanceAndEmits() public {
        vm.expectEmit(true, false, false, true, address(wtel));
        emit Deposit(alice, 5 ether);

        vm.prank(alice);
        wtel.deposit{ value: 5 ether }();

        assertEq(wtel.balanceOf(alice), 5 ether);
        assertEq(address(wtel).balance, 5 ether);
        assertEq(wtel.totalSupply(), 5 ether);
    }

    function test_DepositAccumulatesAcrossCalls() public {
        vm.startPrank(alice);
        wtel.deposit{ value: 1 ether }();
        wtel.deposit{ value: 2 ether }();
        wtel.deposit{ value: 3 ether }();
        vm.stopPrank();

        assertEq(wtel.balanceOf(alice), 6 ether);
        assertEq(wtel.totalSupply(), 6 ether);
    }

    function test_ReceiveTriggersDeposit() public {
        vm.expectEmit(true, false, false, true, address(wtel));
        emit Deposit(alice, 7 ether);

        vm.prank(alice);
        (bool ok,) = address(wtel).call{ value: 7 ether }("");
        require(ok, "send failed");

        assertEq(wtel.balanceOf(alice), 7 ether);
    }

    // ---------- Withdraw ----------

    function test_WithdrawDebitsAndSendsNative() public {
        vm.startPrank(alice);
        wtel.deposit{ value: 10 ether }();

        uint256 nativeBefore = alice.balance;
        vm.expectEmit(true, false, false, true, address(wtel));
        emit Withdrawal(alice, 4 ether);

        wtel.withdraw(4 ether);
        vm.stopPrank();

        assertEq(wtel.balanceOf(alice), 6 ether);
        assertEq(alice.balance, nativeBefore + 4 ether);
        assertEq(address(wtel).balance, 6 ether);
    }

    function test_WithdrawRevertsOnInsufficientBalance() public {
        vm.startPrank(alice);
        wtel.deposit{ value: 1 ether }();

        vm.expectRevert(abi.encodeWithSelector(WTEL.InsufficientBalance.selector, 1 ether, 2 ether));
        wtel.withdraw(2 ether);
        vm.stopPrank();
    }

    function test_WithdrawRevertsWhenRecipientRejectsNative() public {
        // A contract with no receive / fallback rejects native sends, forcing
        // the low-level `call` in `withdraw` to return ok=false.
        NativeRejecter rejecter = new NativeRejecter();
        vm.deal(address(rejecter), 5 ether);
        rejecter.depositTo(wtel, 5 ether);

        vm.expectRevert(WTEL.NativeSendFailed.selector);
        rejecter.withdrawFrom(wtel, 1 ether);
    }

    // ---------- Transfer ----------

    function test_TransferMovesBalance() public {
        vm.prank(alice);
        wtel.deposit{ value: 3 ether }();

        vm.expectEmit(true, true, false, true, address(wtel));
        emit Transfer(alice, bob, 1 ether);

        vm.prank(alice);
        bool ok = wtel.transfer(bob, 1 ether);

        assertTrue(ok);
        assertEq(wtel.balanceOf(alice), 2 ether);
        assertEq(wtel.balanceOf(bob), 1 ether);
    }

    function test_TransferRevertsOnInsufficientBalance() public {
        vm.prank(alice);
        wtel.deposit{ value: 1 ether }();

        vm.expectRevert(abi.encodeWithSelector(WTEL.InsufficientBalance.selector, 1 ether, 2 ether));
        vm.prank(alice);
        wtel.transfer(bob, 2 ether);
    }

    // ---------- Approve / TransferFrom ----------

    function test_ApproveSetsAllowanceAndEmits() public {
        vm.expectEmit(true, true, false, true, address(wtel));
        emit Approval(alice, bob, 5 ether);

        vm.prank(alice);
        bool ok = wtel.approve(bob, 5 ether);

        assertTrue(ok);
        assertEq(wtel.allowance(alice, bob), 5 ether);
    }

    function test_TransferFromDecrementsFiniteAllowance() public {
        vm.startPrank(alice);
        wtel.deposit{ value: 10 ether }();
        wtel.approve(bob, 4 ether);
        vm.stopPrank();

        vm.prank(bob);
        bool ok = wtel.transferFrom(alice, carol, 3 ether);

        assertTrue(ok);
        assertEq(wtel.balanceOf(alice), 7 ether);
        assertEq(wtel.balanceOf(carol), 3 ether);
        assertEq(wtel.allowance(alice, bob), 1 ether);
    }

    function test_TransferFromMaxAllowanceDoesNotDecrement() public {
        vm.startPrank(alice);
        wtel.deposit{ value: 10 ether }();
        wtel.approve(bob, type(uint256).max);
        vm.stopPrank();

        vm.prank(bob);
        wtel.transferFrom(alice, carol, 4 ether);

        // Allowance unchanged after the max-allowance optimization.
        assertEq(wtel.allowance(alice, bob), type(uint256).max);
        assertEq(wtel.balanceOf(alice), 6 ether);
        assertEq(wtel.balanceOf(carol), 4 ether);
    }

    function test_TransferFromSelfDoesNotConsumeAllowance() public {
        vm.startPrank(alice);
        wtel.deposit{ value: 10 ether }();
        // No approval set; alice transferring her own balance shouldn't need one.
        bool ok = wtel.transferFrom(alice, bob, 2 ether);
        vm.stopPrank();

        assertTrue(ok);
        assertEq(wtel.balanceOf(alice), 8 ether);
        assertEq(wtel.balanceOf(bob), 2 ether);
        assertEq(wtel.allowance(alice, alice), 0);
    }

    function test_TransferFromRevertsOnInsufficientAllowance() public {
        vm.startPrank(alice);
        wtel.deposit{ value: 10 ether }();
        wtel.approve(bob, 1 ether);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(WTEL.InsufficientAllowance.selector, 1 ether, 2 ether));
        vm.prank(bob);
        wtel.transferFrom(alice, carol, 2 ether);
    }

    function test_TransferFromRevertsOnInsufficientBalance() public {
        vm.startPrank(alice);
        wtel.deposit{ value: 1 ether }();
        wtel.approve(bob, type(uint256).max);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(WTEL.InsufficientBalance.selector, 1 ether, 2 ether));
        vm.prank(bob);
        wtel.transferFrom(alice, carol, 2 ether);
    }

    // ---------- TotalSupply ----------

    function test_TotalSupplyTracksDepositsAndWithdrawals() public {
        vm.startPrank(alice);
        wtel.deposit{ value: 10 ether }();
        assertEq(wtel.totalSupply(), 10 ether);

        wtel.withdraw(3 ether);
        assertEq(wtel.totalSupply(), 7 ether);
        vm.stopPrank();

        vm.prank(bob);
        wtel.deposit{ value: 5 ether }();
        assertEq(wtel.totalSupply(), 12 ether);
    }

    // ---------- Fuzz: deposit -> withdraw round-trip ----------

    // ---------- Helpers ----------

    function testFuzz_DepositWithdrawRoundTrip(uint96 amount) public {
        vm.assume(amount > 0);
        vm.deal(alice, amount);

        uint256 before = alice.balance;
        vm.startPrank(alice);
        wtel.deposit{ value: amount }();
        assertEq(wtel.balanceOf(alice), amount);
        wtel.withdraw(amount);
        vm.stopPrank();

        assertEq(wtel.balanceOf(alice), 0);
        assertEq(alice.balance, before);
        assertEq(wtel.totalSupply(), 0);
    }
}

/// @dev Helper contract with no `receive`/`fallback`, so any native send into it
///      reverts. Used to drive the `withdraw` native-send-failure branch in WTEL.
contract NativeRejecter {
    function depositTo(WTEL wtel, uint256 wad) external {
        wtel.deposit{ value: wad }();
    }

    function withdrawFrom(WTEL wtel, uint256 wad) external {
        wtel.withdraw(wad);
    }
}
