// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { IPoolManager } from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import { IUnlockCallback } from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import { Currency, CurrencyLibrary } from "@uniswap/v4-core/src/types/Currency.sol";
import { PoolKey } from "@uniswap/v4-core/src/types/PoolKey.sol";
import { SwapParams } from "@uniswap/v4-core/src/types/PoolOperation.sol";
import { BalanceDelta } from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import { TickMath } from "@uniswap/v4-core/src/libraries/TickMath.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title V4SwapHelper
/// @notice Single-hop V4 swap mediator. Mirrors V3 SwapRouter02's
///         exactInputSingle ABI so the front-end's swap dispatcher can
///         treat V2 / V3 / V4 swaps with one shape.
/// @dev    V4's PoolManager.swap is gated behind an unlock context: only the
///         contract that called `PoolManager.unlock(bytes data)` can call
///         swap/take/settle, and only inside the `unlockCallback(bytes)` that
///         PoolManager fires back. EOAs can't satisfy that callback signature,
///         so this helper is the mediator.
/// @dev    Handles both ERC-20 and native (Currency.unwrap == address(0))
///         currencies. ERC-20: pulls tokens via standard transferFrom (no
///         Permit2 dance for swaps). Native: requires msg.value and uses
///         PoolManager's settle{value:} path.
contract V4SwapHelper is IUnlockCallback {
    using CurrencyLibrary for Currency;
    using SafeERC20 for IERC20;

    /// @notice Mirror of V3 SwapRouter02.ExactInputSingleParams, plus the
    ///         V4-only PoolKey + zeroForOne direction.
    struct ExactInputSingleParams {
        PoolKey poolKey;
        bool zeroForOne;
        uint128 amountIn;
        uint128 amountOutMinimum;
        address recipient;
        /// @dev 0 = no clamp (helper substitutes MIN_SQRT or MAX_SQRT
        ///      based on zeroForOne); otherwise direction-specific limit.
        uint160 sqrtPriceLimitX96;
        bytes hookData;
    }

    IPoolManager public immutable poolManager;

    error NotPoolManager();
    error InsufficientOutput(uint256 received, uint256 minimum);
    error InvalidNativeValue(uint256 sent, uint256 expected);

    constructor(IPoolManager _poolManager) {
        poolManager = _poolManager;
    }

    /// @notice Accept native refunds from PoolManager (e.g. unused settle change).
    receive() external payable { }

    function exactInputSingle(ExactInputSingleParams calldata params)
        external
        payable
        returns (uint256 amountOut)
    {
        // Validate msg.value matches expectation: native-in must send
        // exactly amountIn; ERC-20-in must send 0.
        Currency currencyIn = params.zeroForOne ? params.poolKey.currency0 : params.poolKey.currency1;
        bool inputIsNative = currencyIn.isAddressZero();
        if (inputIsNative) {
            if (msg.value != params.amountIn) revert InvalidNativeValue(msg.value, params.amountIn);
        } else {
            if (msg.value != 0) revert InvalidNativeValue(msg.value, 0);
        }

        bytes memory data = abi.encode(params, msg.sender);
        bytes memory result = poolManager.unlock(data);
        amountOut = abi.decode(result, (uint256));
        if (amountOut < params.amountOutMinimum) {
            revert InsufficientOutput(amountOut, params.amountOutMinimum);
        }
    }

    /// @notice PoolManager unlock callback. Performs the swap, settles
    ///         the input side, and takes the output side to recipient.
    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        if (msg.sender != address(poolManager)) revert NotPoolManager();
        (ExactInputSingleParams memory params, address payer) =
            abi.decode(data, (ExactInputSingleParams, address));

        // Direction-aware sqrtPriceLimit. 0 means "no clamp" - use the
        // canonical TickMath bound on the opposite side of zeroForOne.
        uint160 limit = params.sqrtPriceLimitX96;
        if (limit == 0) {
            limit = params.zeroForOne ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1;
        }

        // PoolManager.swap takes a SwapParams with a SIGNED amountSpecified.
        // Negative = exact input (we send `amountIn`); positive = exact output.
        // int256(uint128) is always representable.
        int256 amountSpecified = -int256(uint256(params.amountIn));

        BalanceDelta delta = poolManager.swap(
            params.poolKey,
            SwapParams({
                zeroForOne: params.zeroForOne,
                amountSpecified: amountSpecified,
                sqrtPriceLimitX96: limit
            }),
            params.hookData
        );

        Currency currencyIn = params.zeroForOne ? params.poolKey.currency0 : params.poolKey.currency1;
        Currency currencyOut = params.zeroForOne ? params.poolKey.currency1 : params.poolKey.currency0;

        // Settle the input side (we owe PoolManager the input amount).
        // Sign convention: amount0/1 in BalanceDelta is positive when
        // PoolManager owes us, negative when we owe PoolManager.
        int128 deltaIn = params.zeroForOne ? delta.amount0() : delta.amount1();
        // For exact-input swaps, deltaIn is negative; -deltaIn is what we owe.
        uint256 amountInOwed = uint256(int256(-deltaIn));
        _settle(currencyIn, payer, amountInOwed);

        // Take the output to the user-specified recipient.
        int128 deltaOut = params.zeroForOne ? delta.amount1() : delta.amount0();
        uint256 amountOut = uint256(int256(deltaOut));
        if (amountOut > 0) {
            poolManager.take(currencyOut, params.recipient, amountOut);
        }

        return abi.encode(amountOut);
    }

    /// @dev Pay PoolManager for the input side. Native: forward msg.value
    ///      via settle{value:}. ERC-20: sync, transferFrom from payer to
    ///      PoolManager, settle.
    function _settle(Currency currency, address payer, uint256 amount) internal {
        if (currency.isAddressZero()) {
            poolManager.settle{ value: amount }();
        } else {
            poolManager.sync(currency);
            IERC20(Currency.unwrap(currency)).safeTransferFrom(payer, address(poolManager), amount);
            poolManager.settle();
        }
    }
}
