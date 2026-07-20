// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

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
    address private constant stakeManager = 0x07E17e17E17e17E17e17E17E17E17e17e17E17e1;

    modifier onlyStakeManager() {
        if (msg.sender != stakeManager) revert OnlyStakeManager(stakeManager);
        _;
    }

    /// @notice May only be called by StakeManager as part of claim, unstake or burn flow
    /// @dev Sends `rewardAmount` and forwards `msg.value` if stake amount is additionally provided
    /// @param emergencyExit When true, forfeits `rewardAmount` and forwards only `msg.value`, so a
    /// stake withdrawal can proceed even when this contract's balance cannot cover accrued rewards
    function distributeStakeReward(
        address recipient,
        uint256 rewardAmount,
        bool emergencyExit
    )
        external
        payable
        virtual
        onlyStakeManager
    {
        uint256 bal = address(this).balance;
        uint256 totalAmount = emergencyExit ? msg.value : rewardAmount + msg.value;
        if (bal < totalAmount) {
            revert InsufficientBalance(bal, totalAmount);
        }

        (bool res,) = recipient.call{ value: totalAmount }("");
        if (!res) revert RewardDistributionFailure(recipient);
    }

    /// @notice Received TEL cannot be recovered; it is effectively burned cryptographically
    /// The only way received TEL can be re-minted is as staking issuance rewards
    /// @notice Only governance may burn TEL in this manner
    receive() external payable onlyStakeManager { }
}
