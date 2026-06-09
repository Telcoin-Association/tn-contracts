// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { IWETH9 } from "./interfaces/IWETH9.sol";

/// @title WTEL - Wrapped TEL
/// @notice 0.8.x port of canonical WETH9 (https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2),
///         retaining its functional shape (deposit / withdraw / IERC20 with native-balance totalSupply,
///         max-allowance optimization, fallback-deposit) and updated only where Solidity 0.8.x demands:
///         `payable(...)` casts, low-level `call` instead of `transfer`, named `receive()` over the legacy
///         unnamed fallback, and explicit `IWETH9` inheritance so V3 / V4 periphery can type-check at the
///         constructor `_WETH9` arg.
contract WTEL is IWETH9 {
    string public constant name = "Wrapped Tel";
    string public constant symbol = "WTEL";
    uint8 public constant decimals = 18;

    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    /// @dev `available` is the caller / `src` balance; `required` is the wad asked for.
    error InsufficientBalance(uint256 available, uint256 required);
    /// @dev `available` is the spender's current allowance; `required` is the wad asked for.
    error InsufficientAllowance(uint256 available, uint256 required);
    /// @dev Raised when the low-level native send in `withdraw` returns ok=false (recipient rejected ETH).
    error NativeSendFailed();

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// @dev Bare native sends are treated as `deposit()` calls, matching canonical WETH9.
    receive() external payable {
        deposit();
    }

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 wad) public {
        uint256 available = balanceOf[msg.sender];
        if (available < wad) revert InsufficientBalance(available, wad);
        balanceOf[msg.sender] = available - wad;
        (bool ok,) = payable(msg.sender).call{ value: wad }("");
        if (!ok) revert NativeSendFailed();
        emit Withdrawal(msg.sender, wad);
    }

    /// @notice Wrapped supply equals the native balance this contract custodies.
    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    function approve(address spender, uint256 wad) public returns (bool) {
        allowance[msg.sender][spender] = wad;
        emit Approval(msg.sender, spender, wad);
        return true;
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        uint256 srcBalance = balanceOf[src];
        if (srcBalance < wad) revert InsufficientBalance(srcBalance, wad);

        // Max-allowance optimization: skip the decrement when the spender holds the
        // sentinel `type(uint256).max` allowance. Matches canonical WETH9 + OZ.
        if (src != msg.sender) {
            uint256 allowed = allowance[src][msg.sender];
            if (allowed != type(uint256).max) {
                if (allowed < wad) revert InsufficientAllowance(allowed, wad);
                allowance[src][msg.sender] = allowed - wad;
            }
        }

        balanceOf[src] = srcBalance - wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);
        return true;
    }
}
