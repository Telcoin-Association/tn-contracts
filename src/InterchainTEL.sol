// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import { InterchainTokenStandard } from
    "@axelar-network/interchain-token-service/contracts/interchain-token/InterchainTokenStandard.sol";
import { Create3AddressFixed } from "@axelar-network/interchain-token-service/contracts/utils/Create3AddressFixed.sol";

import { RecoverableWrapper } from "recoverable-wrapper/contracts/rwt/RecoverableWrapper.sol";
import { RecordsDeque, RecordsDequeLib, Record } from "recoverable-wrapper/contracts/util/RecordUtil.sol";
import { Pausable } from "@openzeppelin-contracts/security/Pausable.sol";
import { ERC20 } from "@openzeppelin-contracts/token/ERC20/ERC20.sol";

import { SafeCastLib } from "solady/utils/SafeCastLib.sol";
import { WETH } from "solady/tokens/WETH.sol";

import { SystemCallable } from "./consensus/SystemCallable.sol";
import { IInterchainTEL } from "./interfaces/IInterchainTEL.sol";

/// @title Recoverable Wrapped Telcoin
/// @notice The InterchainTEL module serves as an Axelar InterchainToken merging functionality of TEL
/// both as ITS ERC20 token and as native gas currency for TN
/// @dev Inbound ERC20 TEL from other networks is delivered as native TEL through custom mint logic
/// whereas outbound native TEL must first be double-wrapped to iTEL & elapse the recoverable window
/// @dev Pausability restricts all wrapping/unwrapping actions and execution of ITS bridge messages
contract InterchainTEL is
    IInterchainTEL,
    RecoverableWrapper,
    InterchainTokenStandard,
    Create3AddressFixed,
    SystemCallable,
    Pausable
{
    using RecordsDequeLib for RecordsDeque;

    /// @dev The precompiled Axelar ITS TokenManager contract address for this token
    address private immutable tokenManager;
    /// @dev The precompiled Axelar ITS contract address for this chain
    address private immutable _interchainTokenService;

    /// @dev Constants for deriving the origin chain's ITS custom linked deploy salt, token id, and TokenManager address
    address private immutable originTEL;
    address private immutable originLinker;
    bytes32 private immutable originSalt;
    bytes32 private immutable originChainNameHash;
    bytes32 private constant PREFIX_CUSTOM_TOKEN_SALT = keccak256("custom-token-salt");
    bytes32 private constant PREFIX_INTERCHAIN_TOKEN_ID = keccak256("its-interchain-token-id");

    /// @notice Token factory flag to be create3-agnostic; see `InterchainTokenService::TOKEN_FACTORY_DEPLOYER`
    address private constant TOKEN_FACTORY_DEPLOYER = address(0x0);
    uint256 private constant DECIMALS_CONVERTER = 1e16;

    /// @notice Extends RecoverableWrapper with `OZ::Ownable2Step` for governance rotation without forking
    address private _pendingGovernance;

    modifier onlyTokenManager() {
        if (msg.sender != tokenManager) revert OnlyTokenManager(tokenManager);
        _;
    }

    /// @dev Required by `RecoverableWrapper` and `AxelarGMPExecutable` deps to write immutable vars to bytecode
    /// @param name_ Not used; required for `RecoverableWrapper::constructor()` but is overridden
    /// @param symbol_ Not used; required for `RecoverableWrapper::constructor()` but is overridden
    constructor(
        address originTEL_,
        address originLinker_,
        bytes32 originSalt_,
        string memory originChainName_,
        address interchainTokenService_,
        string memory name_,
        string memory symbol_,
        uint256 recoverableWindow_,
        address governanceAddress_,
        address baseERC20_,
        uint16 maxToClean
    )
        RecoverableWrapper(name_, symbol_, recoverableWindow_, governanceAddress_, baseERC20_, maxToClean)
    {
        _interchainTokenService = interchainTokenService_;
        originTEL = originTEL_;
        originLinker = originLinker_;
        originSalt = originSalt_;
        originChainNameHash = keccak256(bytes(originChainName_));
        tokenManager = tokenManagerAddress();
    }

    /**
     *
     *   InterchainTEL Core
     *
     */

    /// @inheritdoc IInterchainTEL
    function doubleWrap() external payable virtual {
        address caller = msg.sender;
        uint256 amount = msg.value;
        if (amount == 0) revert MintFailed(caller, amount);

        WETH wTEL = WETH(payable(address(baseERC20)));
        wTEL.deposit{ value: amount }();

        _mint(caller, amount);
        emit Wrap(caller, amount);
    }

    /// @inheritdoc IInterchainTEL
    function permitWrap(
        address owner,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        external
        virtual
    {
        if (amount == 0) revert MintFailed(owner, amount);

        WETH wTEL = WETH(payable(address(baseERC20)));
        wTEL.permit(owner, address(this), amount, deadline, v, r, s);

        bool success = wTEL.transferFrom(owner, address(this), amount);
        if (!success) revert PermitWrapFailed(owner, amount);

        _mint(owner, amount);
        emit Wrap(owner, amount);
    }

    /// @dev Includes pausability for wrapping
    /// @notice Named by inheritance: has no relationship to `mint()`
    function _mint(address account, uint256 amount) internal virtual override whenNotPaused {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        _clean(account);

        // 10e12 TEL supply can never overflow w/out inflating 27 orders of magnitude
        uint128 bytes16Amount = SafeCastLib.toUint128(amount);
        _unsettledRecords[account].enqueue(bytes16Amount, block.timestamp + recoverableWindow);

        _totalSupply += amount;
        _accountState[account].nonce++;
        _accountState[account].balance += bytes16Amount;

        emit Transfer(address(0), account, amount);
    }

    /// @dev Includes pausability for unwrapping, incl outbound bridging
    function _burn(address account, uint256 amount) internal virtual override whenNotPaused {
        super._burn(account, amount);

        emit Transfer(account, address(0), amount);
    }

    /// @inheritdoc IInterchainTEL
    function unsettledRecords(address account) public view returns (Record[] memory) {
        RecordsDeque storage rd = _unsettledRecords[account];
        if (rd.isEmpty()) return new Record[](0);

        Record[] memory temp = new Record[](rd.tail - rd.head + 1);
        uint256 count = 0;

        uint256 currentIndex = rd.tail;
        while (currentIndex != 0) {
            Record storage currentRecord = rd.queue[currentIndex];

            if (currentRecord.settlementTime > block.timestamp) {
                temp[count] = currentRecord;
                count++;
            }

            currentIndex = currentRecord.prev;
        }

        Record[] memory unsettled = new Record[](count);
        for (uint256 i = 0; i < count; ++i) {
            unsettled[i] = temp[i];
        }

        return unsettled;
    }

    /**
     *
     *   Axelar Interchain Token Service
     *
     */

    /// @inheritdoc IInterchainTEL
    function mint(address to, uint256 nativeAmount) external virtual override whenNotPaused onlyTokenManager {
        (bool r,) = to.call{ value: nativeAmount }("");
        if (!r) revert MintFailed(to, nativeAmount);

        emit Minted(to, nativeAmount);
    }

    /// @inheritdoc IInterchainTEL
    function burn(address from, uint256 nativeAmount) external virtual override onlyTokenManager {
        // cannot bridge an amount that will be less than 0 TEL on remote chains
        if (nativeAmount < DECIMALS_CONVERTER) revert InvalidAmount(nativeAmount);
        // burn from settled balance only, reverts if paused
        _burn(from, nativeAmount);
        // reclaim native TEL to maintain integrity of iTEL <> wTEL <> TEL ledgers
        WETH(payable(address(baseERC20))).withdraw(nativeAmount);

        // pre-truncate before leaving TN even though Axelar Hub does it to avoid destroying remainder
        uint256 remainder = nativeAmount % DECIMALS_CONVERTER;
        if (remainder != 0) {
            // do not revert bridging if forwarding truncated unbridgeable amount fails
            (bool r,) = governanceAddress.call{ value: remainder }("");
            if (!r) emit RemainderTransferFailed(from, remainder);
        }

        emit Burned(from, nativeAmount);
    }

    /// @inheritdoc IInterchainTEL
    function isMinter(address addr) external view virtual returns (bool) {
        if (addr == tokenManager) return true;

        return false;
    }

    /// @inheritdoc IInterchainTEL
    function tokenManagerCreate3Salt() public view override returns (bytes32) {
        return interchainTokenId();
    }

    /// @notice Returns the top-level ITS interchain token ID for InterchainTEL
    /// @dev The interchain token ID is *custom-linked*, ie based on Ethereum ERC20 TEL, and shared across chains
    function interchainTokenId() public view override returns (bytes32) {
        return keccak256(abi.encode(PREFIX_INTERCHAIN_TOKEN_ID, TOKEN_FACTORY_DEPLOYER, linkedTokenDeploySalt()));
    }

    /// @inheritdoc IInterchainTEL
    function linkedTokenDeploySalt() public view override returns (bytes32) {
        return keccak256(abi.encode(PREFIX_CUSTOM_TOKEN_SALT, originChainNameHash, originLinker, originSalt));
    }

    /// @inheritdoc IInterchainTEL
    function tokenManagerAddress() public view override returns (address) {
        address createDeploy = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff", interchainTokenService(), tokenManagerCreate3Salt(), CREATE_DEPLOY_BYTECODE_HASH
                        )
                    )
                )
            )
        );

        return address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", createDeploy, hex"01")))));
    }

    /// @inheritdoc InterchainTokenStandard
    function interchainTokenService() public view virtual override returns (address) {
        return _interchainTokenService;
    }

    /// @dev OZ 4.9 ERC20 required by RecoverableWrapper
    function _spendAllowance(
        address sender,
        address spender,
        uint256 amount
    )
        internal
        virtual
        override(ERC20, InterchainTokenStandard)
    {
        ERC20._spendAllowance(sender, spender, amount);
    }

    /**
     *
     *   permissioned
     *
     */
    function pause() public whenNotPaused governanceOnly {
        _pause();
    }

    function unpause() public whenPaused governanceOnly {
        _unpause();
    }

    /// @inheritdoc IInterchainTEL
    function transferGovernance(address newGovernance) external virtual override governanceOnly {
        _pendingGovernance = newGovernance;
        emit GovernanceTransferStarted(governanceAddress, newGovernance);
    }

    /// @inheritdoc IInterchainTEL
    function acceptGovernance() external virtual override {
        if (msg.sender != _pendingGovernance) revert CallerMustBeGovernance(msg.sender);

        delete _pendingGovernance;
        address oldGovernance = governanceAddress;
        governanceAddress = msg.sender;

        emit GovernanceTransferred(oldGovernance, msg.sender);
    }

    receive() external payable {
        address wTEL = address(baseERC20);
        if (msg.sender != wTEL) revert OnlyBaseToken(wTEL);
    }
}
