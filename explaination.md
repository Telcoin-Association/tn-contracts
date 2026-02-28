# InterchainTEL & WTEL: Technical Breakdown

## Overview

Telcoin Network (TN) uses TEL as its native gas token (analogous to ETH on Ethereum). TEL also exists as an ERC20 on other chains (e.g. Ethereum). The goal of this architecture is to provide a seamless bridge between ERC20 TEL on remote chains and native TEL on TN, using an intermediate ERC20 representation on TN called **InterchainTEL (iTEL)**.

The current implementation uses **Axelar's Interchain Token Service (ITS)** as the bridging protocol. The architecture is designed to be replaced with **LayerZero's Omnichain Fungible Token (OFT)** standard.

---

## Token Layers

There are three token representations on TN, each serving a distinct role:

```
Native TEL  <-->  wTEL (WETH wrapper)  <-->  iTEL (bridged ERC20)  <-->  Remote ERC20 TEL
```

| Token | Type | Contract | Purpose |
|-------|------|----------|---------|
| TEL | Native gas token | n/a (protocol-level) | Gas payments, staking, native transfers |
| wTEL | ERC20 (Solady WETH) | `WTEL.sol` | ERC20 wrapper for native TEL, identical to WETH on Ethereum |
| iTEL | ERC20 (OZ + bridge standard) | `InterchainTEL.sol` | Bridge-compatible ERC20 that the token service mints/burns |

---

## WTEL.sol

`WTEL` is a trivial wrapper around Solady's battle-tested `WETH` implementation. It only overrides `name()` and `symbol()`.

```
deposit()   : native TEL -> wTEL (ERC20)
withdraw()  : wTEL (ERC20) -> native TEL
```

The WTEL contract is **not bridge-aware**. It is a general-purpose utility for any protocol on TN that needs an ERC20 representation of native TEL. Its relationship to bridging is indirect: InterchainTEL holds wTEL as backing collateral.

**Key property for the new implementation:** WTEL supports EIP-2612 `permit()`, which enables gasless approval flows (used in `permitWrap()`).

---

## InterchainTEL.sol — Current Axelar Implementation

### Role

InterchainTEL is the on-chain ERC20 that the bridge protocol's token manager interacts with. It acts as the accounting layer between the bridge and native TEL:

- **Inbound bridging (mint):** The bridge delivers native TEL directly to the recipient — iTEL is NOT minted to the user. The contract holds native TEL balance to facilitate this.
- **Outbound bridging (burn):** The user must hold iTEL. The bridge's token manager calls `burn()`, which destroys the iTEL, unwraps the backing wTEL to native TEL, and hands it off to the bridge.
- **Local wrapping:** Users can freely convert between wTEL and iTEL via `wrap()`/`unwrap()` for local DeFi usage.

### Inheritance

```
InterchainTEL
├── ERC20                        (OpenZeppelin — core ERC20 logic)
├── InterchainTokenStandard      (Axelar — interchainTransfer(), interchainTransferFrom())
├── Create3AddressFixed          (Axelar — deterministic address derivation for TokenManager)
├── SystemCallable               (TN — access gate for protocol-level system calls)
├── Ownable                      (OpenZeppelin — pause/unpause governance)
└── Pausable                     (OpenZeppelin — emergency circuit breaker)
```

**What to keep for LayerZero:** `ERC20`, `SystemCallable`, `Ownable`, `Pausable`
**What to replace:** `InterchainTokenStandard`, `Create3AddressFixed` — these are Axelar-specific

---

### Wrapping Flows (Local, Not Bridge-Related)

These are purely on-chain conversions between wTEL and iTEL. They do NOT involve the bridge.

#### `wrap(uint256 amount)`
1. User pre-approves wTEL spending by iTEL contract
2. iTEL mints `amount` iTEL to user
3. iTEL pulls `amount` wTEL from user via `transferFrom`

#### `unwrap(uint256 amount)` / `unwrapTo(address to, uint256 amount)`
1. iTEL burns `amount` from caller
2. iTEL transfers `amount` wTEL back to caller (or `to`)

#### `doubleWrap() payable`
Convenience: converts native TEL to iTEL in a single transaction.
1. Deposits `msg.value` into WTEL (native -> wTEL)
2. Mints equivalent iTEL to caller

#### `permitWrap(owner, amount, deadline, v, r, s)`
Wraps using an EIP-2612 permit signature instead of a prior `approve()` transaction.

**These wrap/unwrap flows are bridge-agnostic and should be preserved in the LayerZero implementation.**

---

### Bridge Flows (Axelar-Specific)

#### Inbound: Remote Chain -> TN (`mint`)

```
Remote ERC20 TEL locked on origin
    --> Axelar Hub routes message
        --> TN's ITS TokenManager calls InterchainTEL.mint(to, nativeAmount)
            --> InterchainTEL sends native TEL to recipient via low-level call
```

**Critical detail:** `mint()` does NOT mint any ERC20 tokens. It sends native TEL directly to the recipient. The contract must hold sufficient native TEL balance (sourced from previous `burn()` calls or initial funding).

```solidity
function mint(address to, uint256 nativeAmount) external whenNotPaused onlyTokenManager {
    (bool r,) = to.call{ value: nativeAmount }("");
    if (!r) revert MintFailed(to, nativeAmount);
}
```

#### Outbound: TN -> Remote Chain (`burn`)

```
User holds iTEL
    --> TokenManager calls InterchainTEL.burn(from, nativeAmount)
        --> iTEL burned from user's balance
        --> Backing wTEL withdrawn to native TEL
        --> Remainder pre-truncated (see Decimals section)
        --> Axelar Hub routes to destination, mints ERC20 TEL to recipient
```

```solidity
function burn(address from, uint256 nativeAmount) external whenNotPaused onlyTokenManager {
    if (nativeAmount < DECIMALS_CONVERTER) revert InvalidAmount(nativeAmount);
    _burn(from, nativeAmount);
    WETH(payable(WTEL)).withdraw(nativeAmount);

    uint256 remainder = nativeAmount % DECIMALS_CONVERTER;
    if (remainder != 0) {
        (bool r,) = owner().call{ value: remainder }("");
        if (!r) emit RemainderTransferFailed(from, remainder);
    }
}
```

---

### Access Control: TokenManager

Only the Axelar TokenManager can call `mint()` and `burn()`. The TokenManager address is derived deterministically via CREATE3:

```solidity
modifier onlyTokenManager() {
    if (msg.sender != tokenManager) revert OnlyTokenManager(tokenManager);
    _;
}
```

The TokenManager address is computed from a chain of deterministic hashes rooted in the **origin chain's custom linked token registration**:

```
originSalt + originLinker + originChainNameHash
    --> linkedTokenDeploySalt()
        --> interchainTokenId()
            --> tokenManagerCreate3Salt()
                --> tokenManagerAddress() (CREATE3 derivation using ITS address)
```

**For LayerZero:** This entire derivation chain is Axelar-specific. LayerZero OFT uses a different model — the OFT contract itself handles send/receive, and access control is managed through LayerZero endpoint and peer configuration rather than a separate TokenManager contract. The `onlyTokenManager` modifier should be replaced with the equivalent LayerZero access control (e.g., ensuring calls come from the LZ endpoint).

---

### Decimal Conversion

Origin chain TEL (Ethereum) has **2 decimals**. Native TEL on TN has **18 decimals**. The conversion factor is `1e16`.

```solidity
uint256 private constant DECIMALS_CONVERTER = 1e16;
```

**Where this matters:**

- **Inbound (mint):** Axelar Hub handles the 2→18 decimal conversion before calling `mint()`. The `nativeAmount` parameter arrives already in 18-decimal form. No conversion needed in the contract.
- **Outbound (burn):** When bridging out, amounts in 18-decimal form may have precision that cannot be represented in 2 decimals. The contract **pre-truncates** the remainder before the bridge processes it:
  - Amounts below `1e16` wei are rejected (would round to 0 on origin)
  - Any sub-`1e16` remainder is forwarded to the governance `owner()` rather than being silently destroyed

**For LayerZero:** LayerZero OFT has its own shared decimals concept. OFT typically normalizes to 6 "shared decimals" across chains. You'll need to evaluate whether to:
1. Use OFT's built-in `sharedDecimals` mechanism (which handles dust removal internally)
2. Retain custom pre-truncation logic similar to the current approach

Either way, the decimal mismatch between 2-decimal origin TEL and 18-decimal native TN TEL must be handled. The current pre-truncation pattern of forwarding dust to governance rather than destroying it is worth preserving.

---

### Pausability

All user-facing operations are gated by `whenNotPaused`:
- `wrap`, `unwrap`, `unwrapTo`, `doubleWrap`, `permitWrap`
- `mint`, `burn` (bridge operations)

Only the `owner` (governance) can pause/unpause. This is a critical safety mechanism — **preserve it in the LayerZero implementation**.

---

### The `receive()` Function

```solidity
receive() external payable {
    if (msg.sender != WTEL) revert OnlyBaseToken(WTEL);
}
```

InterchainTEL only accepts native TEL from the WTEL contract (during `withdraw()` calls in `burn()`). This prevents accidental native TEL deposits that would break accounting.

**For LayerZero:** You may need to also allow the LZ endpoint or other bridge components to send native TEL to the contract, depending on how OFT handles native token mechanics.

---

## Axelar-Specific Components to Replace

| Axelar Component | What It Does | LayerZero Equivalent |
|---|---|---|
| `InterchainTokenStandard` | Provides `interchainTransfer()` and `interchainTransferFrom()` | OFT's `send()` function via `OFTCore` |
| `Create3AddressFixed` | Deterministic TokenManager address derivation | Not needed — OFT doesn't use a separate TokenManager |
| `TokenManager` (external) | Separate contract that calls `mint()`/`burn()` | LZ Endpoint calls the OFT contract directly |
| `interchainTokenId()` derivation | Global token ID across all chains | OFT uses peer configuration instead of a global token ID |
| `interchainTokenService()` | Returns the ITS gateway address | LZ Endpoint address (passed to OFT constructor) |
| Constructor params: `originTEL`, `originLinker`, `originSalt`, `originChainName` | Used to derive deterministic IDs for Axelar's custom linked token model | Replaced by LZ peer configuration (`setPeer()` per destination chain) |

---

## What to Preserve in the LayerZero Implementation

1. **The three-layer token model:** native TEL <-> wTEL <-> bridged ERC20. This is fundamental to the architecture.
2. **All wrapping/unwrapping flows:** `wrap`, `unwrap`, `unwrapTo`, `doubleWrap`, `permitWrap` — these are bridge-agnostic.
3. **The `receive()` guard** (may need adjustment for LZ).
4. **Pausability** on all operations.
5. **Decimal dust handling:** Pre-truncation with remainder forwarding to governance.
6. **The mint behavior:** Inbound bridged tokens should arrive as native TEL, not as an ERC20 balance.
7. **The burn behavior:** Outbound bridging requires iTEL, which gets burned and unwrapped to native TEL.
8. **SystemCallable inheritance** (TN protocol requirement).
9. **`IInterchainTEL` interface** — update with LZ-specific functions but keep the wrapping API stable.

---

## Architectural Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Remote Chain (Ethereum)               │
│                                                         │
│   ERC20 TEL (2 decimals)                                │
│       │                                                 │
│       │  lock/unlock                                    │
│       ▼                                                 │
│   [Token Manager / OFT Adapter]                         │
│       │                                                 │
└───────┼─────────────────────────────────────────────────┘
        │  bridge message (Axelar Hub / LayerZero DVNs)
        │
┌───────┼─────────────────────────────────────────────────┐
│       ▼            Telcoin Network                      │
│                                                         │
│   [Token Manager / OFT Endpoint]                        │
│       │                                                 │
│       │ mint(): sends native TEL to recipient           │
│       │ burn(): burns iTEL, unwraps wTEL to native TEL  │
│       ▼                                                 │
│   ┌─────────────────┐                                   │
│   │  InterchainTEL   │  ERC20 "iTEL" (18 decimals)     │
│   │  (bridge token)  │                                   │
│   └────────┬────────┘                                   │
│            │ wrap/unwrap                                 │
│            ▼                                             │
│   ┌─────────────────┐                                   │
│   │      WTEL        │  ERC20 "wTEL" (18 decimals)     │
│   │  (WETH wrapper)  │                                   │
│   └────────┬────────┘                                   │
│            │ deposit/withdraw                            │
│            ▼                                             │
│      Native TEL                                         │
│      (18 decimals)                                      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Key Design Decisions to Revisit for LayerZero

1. **Should the OFT contract itself be iTEL?** In the Axelar model, InterchainTEL is a standalone ERC20 that the TokenManager calls into. In the OFT model, the OFT contract IS the token. This is likely a cleaner fit — make iTEL inherit from `OFT` (or `OFTCore`) directly.

2. **Native TEL delivery on mint:** The current `mint()` sends native TEL via a low-level call. With OFT, the `_lzReceive()` hook is where inbound tokens land. You'll need to override this to convert received OFT tokens into native TEL for the recipient (burn the OFT ERC20 balance, unwrap wTEL, send native).

3. **Outbound burn flow:** With OFT, `send()` automatically debits the sender's token balance. You'll need to ensure the outbound path still unwraps to native TEL and handles decimal dust correctly.

4. **Shared decimals:** OFT uses a `sharedDecimals` parameter (typically 6) to normalize precision across chains. Since origin TEL has only 2 decimals, you'll want `sharedDecimals = 2` to avoid any further precision loss beyond what already exists.

5. **Peer configuration vs. deterministic IDs:** Axelar uses a global `interchainTokenId` derived from origin chain parameters. LayerZero uses explicit peer-to-peer configuration (`setPeer(eid, peerAddress)`). This is simpler but requires governance to manage peer mappings.
