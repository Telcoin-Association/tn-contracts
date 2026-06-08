// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Test } from "forge-std/Test.sol";
import { V4SwapHelper } from "../src/uniswap/V4SwapHelper.sol";
import { IPoolManager } from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import { Currency } from "@uniswap/v4-core/src/types/Currency.sol";
import { PoolKey } from "@uniswap/v4-core/src/types/PoolKey.sol";
import { IHooks } from "@uniswap/v4-core/src/interfaces/IHooks.sol";

/// @title V4SwapHelper unit tests
///
/// @notice Covers the helper's pure-EVM, PoolManager-independent branches:
///         constructor wiring, native-receive, the InvalidNativeValue guard
///         (both directions of the native/ERC-20 split), and the
///         NotPoolManager guard on the unlock callback. The deep swap-flow
///         branches (swap / settle / take, sqrtPriceLimit substitution,
///         output forwarding) live in V4IntegrationFork.t.sol where they run
///         against the real PoolManager, since stubbing the unlock dance
///         end-to-end would itself reimplement most of PoolManager.
contract V4SwapHelperTest is Test {
    V4SwapHelper helper;

    address poolManagerStub = makeAddr("poolManagerStub");
    address alice = makeAddr("alice");
    address erc20A = makeAddr("erc20A");
    address erc20B = makeAddr("erc20B");

    function setUp() public {
        helper = new V4SwapHelper(IPoolManager(poolManagerStub));
        vm.deal(alice, 100 ether);
    }

    // ---------- Constructor / metadata ----------

    function test_ConstructorPinsPoolManager() public view {
        assertEq(address(helper.poolManager()), poolManagerStub);
    }

    function test_ReceiveAcceptsNative() public {
        // Plain native send routes through receive().
        vm.prank(alice);
        (bool ok,) = address(helper).call{ value: 3 ether }("");
        require(ok, "receive failed");
        assertEq(address(helper).balance, 3 ether);
    }

    // ---------- exactInputSingle value-check guard ----------

    function _erc20Key() internal view returns (PoolKey memory) {
        // Both currencies are non-zero addresses → both treated as ERC-20.
        return PoolKey({
            currency0: Currency.wrap(erc20A),
            currency1: Currency.wrap(erc20B),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(0))
        });
    }

    function _nativeAsToken0Key() internal view returns (PoolKey memory) {
        // currency0 = address(0) → native input when zeroForOne = true.
        return PoolKey({
            currency0: Currency.wrap(address(0)),
            currency1: Currency.wrap(erc20A),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(0))
        });
    }

    function test_ExactInputRevertsOnNonZeroValueForErc20Input() public {
        V4SwapHelper.ExactInputSingleParams memory params = V4SwapHelper.ExactInputSingleParams({
            poolKey: _erc20Key(),
            zeroForOne: true,
            amountIn: 1 ether,
            amountOutMinimum: 0,
            recipient: alice,
            sqrtPriceLimitX96: 0,
            deadline: type(uint48).max,
            hookData: ""
        });

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(V4SwapHelper.InvalidNativeValue.selector, uint256(7), uint256(0))
        );
        helper.exactInputSingle{ value: 7 }(params);
    }

    function test_ExactInputRevertsOnZeroValueForNativeInput() public {
        // currency0 = address(0), zeroForOne = true → native input expected.
        // Sending msg.value = 0 with amountIn = 1 ether trips the guard.
        V4SwapHelper.ExactInputSingleParams memory params = V4SwapHelper.ExactInputSingleParams({
            poolKey: _nativeAsToken0Key(),
            zeroForOne: true,
            amountIn: 1 ether,
            amountOutMinimum: 0,
            recipient: alice,
            sqrtPriceLimitX96: 0,
            deadline: type(uint48).max,
            hookData: ""
        });

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(V4SwapHelper.InvalidNativeValue.selector, uint256(0), uint256(1 ether))
        );
        helper.exactInputSingle(params);
    }

    function test_ExactInputRevertsOnUnderpaidNativeInput() public {
        // Native input expected with amountIn = 1 ether, sending only 0.5 ether.
        V4SwapHelper.ExactInputSingleParams memory params = V4SwapHelper.ExactInputSingleParams({
            poolKey: _nativeAsToken0Key(),
            zeroForOne: true,
            amountIn: 1 ether,
            amountOutMinimum: 0,
            recipient: alice,
            sqrtPriceLimitX96: 0,
            deadline: type(uint48).max,
            hookData: ""
        });

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                V4SwapHelper.InvalidNativeValue.selector, uint256(0.5 ether), uint256(1 ether)
            )
        );
        helper.exactInputSingle{ value: 0.5 ether }(params);
    }

    function test_ExactInputRevertsOnExpiredDeadline() public {
        // Set a fixed timestamp so we can put the deadline strictly in the past.
        vm.warp(1_700_000_000);
        uint48 staleDeadline = uint48(block.timestamp - 1);

        V4SwapHelper.ExactInputSingleParams memory params = V4SwapHelper.ExactInputSingleParams({
            poolKey: _erc20Key(),
            zeroForOne: true,
            amountIn: 1 ether,
            amountOutMinimum: 0,
            recipient: alice,
            sqrtPriceLimitX96: 0,
            deadline: staleDeadline,
            hookData: ""
        });

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(V4SwapHelper.ExpiredDeadline.selector, block.timestamp, staleDeadline)
        );
        helper.exactInputSingle(params);
    }

    // ---------- unlockCallback access guard ----------

    function test_UnlockCallbackRevertsForNonPoolManagerCaller() public {
        // Non-PoolManager calling unlockCallback directly must revert.
        vm.prank(alice);
        vm.expectRevert(V4SwapHelper.NotPoolManager.selector);
        helper.unlockCallback(hex"");
    }
}
