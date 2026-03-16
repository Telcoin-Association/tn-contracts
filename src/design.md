# TEL Native ERC20 Precompile Design

## Background

- **Native Currency and ERC20**: Telcoin Network uses TEL as its native gas currency. The TEL precompile at `0x00000000000000000000000000000000000007e1` exposes TEL as a full ERC20 token with a unified balance model: `balanceOf(account)` returns the native account balance directly — no wrapping needed.
- **Bridging**: Cross-chain TEL bridging is being migrated to LayerZero (out of scope for this document).

### TEL Precompile

- **Unified Balance Model**: The precompile uses a unified balance model where `balanceOf(account)` returns the native account balance. There is no wrapping or unwrapping — native TEL is the ERC20 balance.
- **Full ERC20 Interface**: The precompile supports `transfer`, `approve`, `transferFrom`, `balanceOf`, `allowance`, `totalSupply`, `name`, `symbol`, and `decimals`.
- **Governance Lifecycle**: The precompile includes governance-gated `mint`, `claim`, and `burn` functions for TEL lifecycle management.
- **No EIP-2612 Permit**: The precompile does not support EIP-2612 permit signatures.

## Interacting with TEL as ERC20

Since the precompile exposes TEL as an ERC20 at a fixed address, contracts and scripts can interact with it via the `ITelcoinPrecompile` interface:

```solidity
import { ITelcoinPrecompile, TELCOIN_PRECOMPILE } from "src/interfaces/ITelcoinPrecompile.sol";

ITelcoinPrecompile tel = ITelcoinPrecompile(TELCOIN_PRECOMPILE);
tel.transfer(recipient, amount);
tel.approve(spender, amount);
uint256 balance = tel.balanceOf(account);
```

## Uniswap V2 Integration

The TEL precompile address is passed as the WETH constructor argument to the Uniswap V2 Router. The router's `*ETH*` convenience functions (`swapExactETHForTokens`, `addLiquidityETH`, etc.) are **not compatible** with the precompile. Users should use the standard ERC20 swap functions (`swapExactTokensForTokens`, `addLiquidity`, etc.) after approving the router via the precompile.
