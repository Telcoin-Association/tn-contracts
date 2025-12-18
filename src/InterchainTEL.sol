// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import {
    InterchainTokenStandard
} from "@axelar-network/interchain-token-service/contracts/interchain-token/InterchainTokenStandard.sol";
import { Create3AddressFixed } from "@axelar-network/interchain-token-service/contracts/utils/Create3AddressFixed.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { WETH } from "solady/tokens/WETH.sol";
import { SystemCallable } from "./consensus/SystemCallable.sol";
import { IInterchainTEL } from "./interfaces/IInterchainTEL.sol";

/// @title Interchain Telcoin
/// @notice The InterchainTEL module serves as an Axelar InterchainToken merging functionality of TEL
/// both as ITS ERC20 token and as native gas currency for TN
/// @dev Inbound ERC20 TEL from other networks is delivered as native TEL through custom mint logic
/// @dev Pausability restricts all wrapping/unwrapping actions and execution of ITS bridge messages
contract InterchainTEL is
    IInterchainTEL,
    ERC20,
    InterchainTokenStandard,
    Create3AddressFixed,
    SystemCallable,
    Ownable,
    Pausable
{
    /// @dev The precompiled Axelar ITS TokenManager contract address for this token
    address private immutable tokenManager;
    /// @dev The precompiled Axelar ITS contract address for this chain
    address private immutable _interchainTokenService;
    /// @dev The wrapped Telcoin contract address for this chain
    address public immutable WTEL;

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

    modifier onlyTokenManager() {
        if (msg.sender != tokenManager) revert OnlyTokenManager(tokenManager);
        _;
    }

    constructor(
        address originTEL_,
        address originLinker_,
        bytes32 originSalt_,
        string memory originChainName_,
        address interchainTokenService_,
        string memory name_,
        string memory symbol_,
        address owner_,
        address WTEL_
    )
        ERC20(name_, symbol_)
        Ownable(owner_)
    {
        _interchainTokenService = interchainTokenService_;
        originTEL = originTEL_;
        originLinker = originLinker_;
        originSalt = originSalt_;
        originChainNameHash = keccak256(bytes(originChainName_));
        tokenManager = tokenManagerAddress();
        WTEL = WTEL_;
    }

    /**
     *
     *   InterchainTEL Core
     *
     */

    /// @inheritdoc IInterchainTEL
    function wrap(uint256 amount) external virtual override whenNotPaused {
        _mint(msg.sender, amount);
        WETH(payable(WTEL)).transferFrom(msg.sender, address(this), amount);

        emit Wrap(msg.sender, amount);
    }

    /// @inheritdoc IInterchainTEL
    function unwrap(uint256 amount) external virtual override whenNotPaused {
        _burn(msg.sender, amount);
        WETH(payable(WTEL)).transfer(msg.sender, amount);

        emit Unwrap(msg.sender, msg.sender, amount);
    }

    /// @inheritdoc IInterchainTEL
    function unwrapTo(address to, uint256 amount) external virtual override whenNotPaused {
        _burn(msg.sender, amount);
        WETH(payable(WTEL)).transfer(to, amount);

        emit Unwrap(msg.sender, to, amount);
    }

    /// @inheritdoc IInterchainTEL
    function doubleWrap() external payable virtual whenNotPaused {
        address caller = msg.sender;
        uint256 amount = msg.value;
        if (amount == 0) revert MintFailed(caller, amount);

        WETH wTEL = WETH(payable(WTEL));
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
        whenNotPaused
    {
        if (amount == 0) revert MintFailed(owner, amount);

        WETH wTEL = WETH(payable(WTEL));
        wTEL.permit(owner, address(this), amount, deadline, v, r, s);

        bool success = wTEL.transferFrom(owner, address(this), amount);
        if (!success) revert PermitWrapFailed(owner, amount);

        _mint(owner, amount);
        emit Wrap(owner, amount);
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
    function burn(address from, uint256 nativeAmount) external virtual override whenNotPaused onlyTokenManager {
        // cannot bridge an amount that will be less than 0 TEL on remote chains
        if (nativeAmount < DECIMALS_CONVERTER) revert InvalidAmount(nativeAmount);
        // burn from settled balance only, reverts if paused
        _burn(from, nativeAmount);
        // reclaim native TEL to maintain integrity of iTEL <> wTEL <> TEL ledgers
        WETH(payable(WTEL)).withdraw(nativeAmount);

        // pre-truncate before leaving TN even though Axelar Hub does it to avoid destroying remainder
        uint256 remainder = nativeAmount % DECIMALS_CONVERTER;
        if (remainder != 0) {
            // do not revert bridging if forwarding truncated unbridgeable amount fails
            (bool r,) = owner().call{ value: remainder }("");
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

    /// @dev Required by InterchainTokenStandard
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
    function pause() public whenNotPaused onlyOwner {
        _pause();
    }

    function unpause() public whenPaused onlyOwner {
        _unpause();
    }

    receive() external payable {
        if (msg.sender != WTEL) revert OnlyBaseToken(WTEL);
    }
}
