// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import {AxelarGMPExecutable} from "@axelar-network/axelar-gmp-sdk-solidity/contracts/executable/AxelarGMPExecutable.sol";
import {RecoverableWrapper} from "recoverable-wrapper/contracts/rwt/RecoverableWrapper.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {IRWTEL} from "./interfaces/IRWTEL.sol";

/* RecoverableWrapper Storage Layout (Provided because RW is non-ERC7201 compliant)
     _______________________________________________________________________________________
    | Name              | Type                                                       | Slot |
    |-------------------|------------------------------------------------------------|------|
    | _balances         | mapping(address => uint256)                                | 0    |
    | _allowances       | mapping(address => mapping(address => uint256))            | 1    |
    | _totalSupply      | uint256                                                    | 2    |
    | _name             | string                                                     | 3    |
    | _symbol           | string                                                     | 4    |
    | _accountState     | mapping(address => struct RecoverableWrapper.AccountState) | 5    |
    | frozen            | mapping(address => uint256)                                | 6    |
    | _unsettledRecords | mapping(address => struct RecordsDeque)                    | 7    |
    | unwrapDisabled    | mapping(address => bool)                                   | 8    |
    | _totalSupply      | uint256                                                    | 9    |
    | governanceAddress | address                                                    | 10   |
*/

contract RWTEL is
    IRWTEL,
    RecoverableWrapper,
    AxelarGMPExecutable,
    UUPSUpgradeable,
    Ownable
{
    address private immutable consensusRegistry;

    /// @dev Overrides for `ERC20` storage since `RecoverableWrapper` dep restricts them
    string internal _name_;
    string internal _symbol_;

    /// @notice For use when deployed as singleton
    /// @dev Required by `RecoverableWrapper` and `AxelarGMPExecutable` deps to write immutable vars to bytecode
    constructor(
        address consensusRegistry_,
        address gateway_,
        string memory name_,
        string memory symbol_,
        uint256 recoverableWindow_,
        address governanceAddress_,
        address baseERC20_,
        uint16 maxToClean
    )
        AxelarGMPExecutable(gateway_)
        RecoverableWrapper(
            name_,
            symbol_,
            recoverableWindow_,
            governanceAddress_,
            baseERC20_,
            maxToClean
        )
    {
        consensusRegistry = consensusRegistry_;
    }

    /// @inheritdoc IRWTEL
    function distributeStakeReward(
        address validator,
        uint256 rewardAmount
    ) external {
        if (msg.sender != consensusRegistry) revert OnlyConsensusRegistry();

        (bool res, ) = validator.call{value: rewardAmount}("");
        if (!res) revert RewardDistributionFailure(validator);
    }

    /**
     *
     *   upgradeability
     *
     */

    /// @inheritdoc IRWTEL
    function initialize(
        string memory name_,
        string memory symbol_,
        address governanceAddress_,
        uint16 maxToClean_,
        address owner_
    ) public initializer {
        _initializeOwner(owner_);
        setName(name_);
        setSymbol(symbol_);
        setGovernanceAddress(governanceAddress_);
        setMaxToClean(maxToClean_);
    }

    function setName(string memory newName) public override onlyOwner {
        _name_ = newName;
    }

    function setSymbol(string memory newSymbol) public override onlyOwner {
        _symbol_ = newSymbol;
    }

    function setGovernanceAddress(
        address newGovernanceAddress
    ) public override onlyOwner {
        governanceAddress = newGovernanceAddress;
    }

    /// @inheritdoc IRWTEL
    function setMaxToClean(uint16 newMaxToClean) public override onlyOwner {
        assembly {
            sstore(11, newMaxToClean)
        }
    }

    /// @notice Overrides `RecoverableWrapper::ERC20::name()` which accesses a private var
    function name() public view virtual override returns (string memory) {
        return _name_;
    }

    /// @notice Overrides `RecoverableWrapper::ERC20::name()` which accesses a private var
    function symbol() public view virtual override returns (string memory) {
        return _symbol_;
    }

    /**
     *
     *   internals
     *
     */

    /// @notice Only invoked after `commandId` is verified by Axelar gateway, ie in the context of an incoming message
    /// @notice Params `sourceChain` and `sourceAddress` are not currently used for vanilla bridging but may later on
    function _execute(
        bytes32 commandId,
        string calldata /* sourceChain */,
        string calldata /* sourceAddress */,
        bytes calldata payload
    ) internal virtual override {
        ExtCall memory bridgeMsg = abi.decode(payload, (ExtCall));
        address target = bridgeMsg.target;
        (bool res, ) = target.call{value: bridgeMsg.value}(bridgeMsg.data);
        // to prevent stuck messages, emit failure event rather than revert
        if (!res) emit ExecutionFailed(commandId, target);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal virtual override onlyOwner {}
}
