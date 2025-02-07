// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../../../src/interfaces/ISimplePlugin.sol";

/// @title Mock contracts for TANIssuanceHistory integration testing. Do NOT use any in production

/// @notice This contract is deployed onchain for testing as no testing AmirX existed
contract MockAmirX is Ownable {
    struct DefiSwap {
        // Address for fee deposit
        address defiSafe;
        // Address of the swap aggregator or router
        address aggregator;
        // Plugin for handling referral fees
        ISimplePlugin plugin;
        // Token collected as fees
        IERC20 feeToken;
        // Address to receive referral fees
        address referrer;
        // Amount of referral fee
        uint256 referralFee;
        // Data for wallet interaction, if any
        bytes walletData;
        // Data for performing the swap, if any
        bytes swapData;
    }

    event Transfer(address from, address to, uint256 value);

    IERC20 public immutable tel;

    address public immutable defiAggIntermediary;

    constructor(IERC20 tel_, address owner_, address defiAggIntermediary_) Ownable(owner_) {
        tel = tel_;
        defiAggIntermediary = defiAggIntermediary_;
    }

    function defiSwap(address, DefiSwap memory defi) external payable onlyOwner {
        /// @notice the `DefiSwap.referralFee` actually refers to a separate referral program than this one
        /// but it is used here for simplicity
        tel.transferFrom(defiAggIntermediary, address(this), defi.referralFee);
    }

    fallback() external { }
}

/// @notice This contract did not need to be deployed for testing as one already exists
contract MockTel is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) { }

    /// @notice Unprotected for simplicity
    function mint(address to, uint256 value) public {
        _mint(to, value);
    }
}

/// @notice This contract did not need to be deployed for testing as one already exists
contract MockStakingModule {
    event StakeChanged(address account, uint256 oldStake, uint256 newStake);

    mapping(address => uint256) _stakes;

    function stake(uint256 amount) external {
        uint256 oldStake = _stakes[msg.sender];
        uint256 newStake = _stakes[msg.sender] += amount;

        emit StakeChanged(msg.sender, oldStake, newStake);
    }

    function stakedByAt(address account, uint256 blockNumber) public view returns (uint256) {
        // ignore actual block number checkpoints
        require(blockNumber <= block.number, "Future lookup");

        return _stakes[account];
    }
}

/// @notice  This contract did not need to be deployed for testing as one already exists
contract MockPlugin is ISimplePlugin {
    bool public deactivated;
    IERC20 public tel;
    uint256 public totalClaimable;
    mapping(address => uint256) public claimable;

    constructor(IERC20 tel_) {
        tel = tel_;
    }

    function setDeactivated(bool newVal) external {
        deactivated = newVal;
    }

    function increaseClaimableBy(address account, uint256 amount) external override returns (bool) {
        // simplified mock implementation
        claimable[account] += amount;
        return true;
    }

    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }
}
