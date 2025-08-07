// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

/**
 * @title Issuance
 * @author Telcoin Association
 * @notice A Telcoin Contract
 *
 * @notice This contract manages staking issuance rewards for consensus validators
 * @dev Designed to periodically receives issuance allocations from governance for stake rewards
 */
contract Issuance {
    error InsufficientBalance(uint256 available, uint256 required);
    error RewardDistributionFailure(address recipient);
    error OnlyStakeManager(address stakeManager);

    /// @dev ConsensusRegistry system precompile assigned by protocol to a constant address
    address private immutable stakeManager;
    /// @dev Wrapped TEL contract, used to enable unrevertable TEL sends
    address private immutable wTEL;

    modifier onlyStakeManager() {
        if (msg.sender != stakeManager) revert OnlyStakeManager(stakeManager);
        _;
    }

    constructor(address stakeManager_, address wTEL_) {
        stakeManager = stakeManager_;
        wTEL = wTEL_;
    }

    /// @notice May only be called by StakeManager as part of claim, unstake or burn flow
    /// @dev Sends `rewardAmount` and forwards `msg.value` if stake amount is additionally provided
    function distributeStakeReward(address recipient, uint256 rewardAmount) external payable virtual onlyStakeManager {
        uint256 bal = address(this).balance;
        uint256 totalAmount = rewardAmount + msg.value;
        if (bal < totalAmount) {
            revert InsufficientBalance(bal, totalAmount);
        }

        (bool r,) = wTEL.call{ value: totalAmount }("");
        bytes memory transferData = abi.encodeCall(WTEL.transfer, (recipient, totalAmount));
        (bool res, bytes memory ret) = wTEL.call(transferData);
        bool success = abi.decode(ret, (bool));
        if (!r || !res || !success) revert RewardDistributionFailure(recipient);
    }

    /// @notice Received TEL cannot be recovered; it is effectively burned cryptographically
    /// The only way received TEL can be re-minted is as staking issuance rewards
    /// @notice Only governance may burn TEL in this manner
    receive() external payable onlyStakeManager { }
}

/// @dev Minimal interface for WTEL to enable unrevertable transfers of TEL (via ERC20)
/// while optimizing for small bytecode size
interface WTEL {
    function transfer(address to, uint256 amount) external returns (bool);
}
