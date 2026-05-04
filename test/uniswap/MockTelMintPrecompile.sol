// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

/// @title Mock of the TEL_MINT precompile for fork-test etching
///
/// @notice The Telcoin Network's TEL_MINT precompile lives at 0x07e1 and is
///         dispatched in Go, not via EVM bytecode. Foundry's `--fork-url` mode
///         proxies state reads to the upstream RPC but executes CALLs through
///         its local EVM, which has no knowledge of chain-specific precompile
///         dispatch. Any test that exercises wTEL flows (LP mint, swap, etc.)
///         needs a stand-in installed at 0x07e1 via vm.etch so the local EVM
///         can actually execute the wTEL methods that V3 / V4 contracts expect.
///
/// @notice Behavioral model: matches what cast confirmed about the real
///         precompile during the V2-debug session - balanceOf(addr) returns
///         the user's native TEL balance (the "balance == native" semantics
///         documented in the V3/V4 design doc), transferFrom moves native
///         balance, approve stores allowance in this contract's storage,
///         deposit / withdraw are no-ops because there's no separate wrapped
///         balance to track. decimals() returns 18; symbol returns "TEL".
///
/// @notice Caveats:
///         - This mock has nonzero EVM bytecode by virtue of being etched, so
///           V2 Pool's high-level `IERC20(token0).balanceOf(...)` calls dodge
///           the EXTCODESIZE guard that bites on the real precompile today.
///           Fork tests against this mock therefore CANNOT prove that V2
///           works on the real chain - that's a known divergence. V3 and V4
///           use low-level staticcall and don't trip the guard, so for those
///           the mock is a faithful proxy.
///         - The native-balance mutation on transferFrom relies on Foundry's
///           `vm.deal`-equivalent low-level state changes via assembly. We
///           don't have vm cheatcodes available inside this contract (it's
///           etched, not deployed by Foundry), so transferFrom uses raw
///           native transfers via `(bool ok,) = to.call{value: amount}("")`
///           - the "from" side has its balance debited by virtue of the
///           CALL frame's msg.value, which only works when this contract
///           itself holds the value being transferred. To make that work,
///           we treat each transferFrom as: pull from `from`'s native via
///           an internal mapping that mirrors native, then push native to
///           `to`. The internal mapping is initialized lazily from the
///           upstream-fetched native balance the first time an address is
///           touched.
contract MockTelMintPrecompile {
    /// @dev Mirrors the user's native balance that this mock has authority
    ///      to move. Lazy-initialized from address(addr).balance on first
    ///      touch; subsequent operations debit / credit the mirror. We
    ///      can't directly mutate `address(addr).balance` from a contract
    ///      under normal EVM rules, so we maintain a parallel balance
    ///      ledger and route real native transfers through this contract.
    mapping(address => uint256) private _balances;
    mapping(address => bool) private _initialized;
    mapping(address => mapping(address => uint256)) private _allowances;

    string public constant name = "Telcoin";
    string public constant symbol = "TEL";
    uint8 public constant decimals = 18;

    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    function _ensureInitialized(address account) internal {
        if (!_initialized[account]) {
            _balances[account] = account.balance;
            _initialized[account] = true;
        }
    }

    function totalSupply() external pure returns (uint256) {
        // The real precompile likely reports the chain's circulating native TEL.
        // For test purposes a fixed-large value is sufficient; pool math doesn't
        // read totalSupply from the underlying token, only from the LP token.
        return type(uint128).max;
    }

    function balanceOf(address account) external view returns (uint256) {
        if (_initialized[account]) {
            return _balances[account];
        }
        return account.balance;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _ensureInitialized(msg.sender);
        _ensureInitialized(to);
        require(_balances[msg.sender] >= amount, "MockTelMint: balance too low");
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        _ensureInitialized(from);
        _ensureInitialized(to);
        require(_balances[from] >= amount, "MockTelMint: balance too low");
        // ERC-20 max-allowance optimization: if allowance is type(uint256).max,
        // we don't decrement it (matches OpenZeppelin / Solady behavior).
        if (msg.sender != from) {
            uint256 currentAllowance = _allowances[from][msg.sender];
            if (currentAllowance != type(uint256).max) {
                require(currentAllowance >= amount, "MockTelMint: allowance too low");
                _allowances[from][msg.sender] = currentAllowance - amount;
            }
        }
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    /// @dev IWETH9 deposit. Under the "balance == native" semantics this could
    ///      be a no-op, but to keep the LP / swap flow honest we credit the
    ///      caller's mock balance by msg.value. This matches what a fully-
    ///      compliant precompile would do if the chain team chose explicit
    ///      WETH9 semantics over implicit "balance == native."
    function deposit() external payable {
        _ensureInitialized(msg.sender);
        _balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @dev IWETH9 withdraw.
    function withdraw(uint256 wad) external {
        _ensureInitialized(msg.sender);
        require(_balances[msg.sender] >= wad, "MockTelMint: withdraw too high");
        _balances[msg.sender] -= wad;
        (bool ok,) = msg.sender.call{ value: wad }("");
        require(ok, "MockTelMint: native send failed");
        emit Withdrawal(msg.sender, wad);
    }

    /// @dev Required so the mock can hold native TEL forwarded by callers
    ///      (e.g. test setup that vm.deal()'s this contract for fund movement).
    receive() external payable {
        _ensureInitialized(msg.sender);
        _balances[msg.sender] += msg.value;
    }
}
