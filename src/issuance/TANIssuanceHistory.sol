// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import { Checkpoints } from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import { Time } from "@openzeppelin/contracts/utils/types/Time.sol";
import { SafeERC20, IERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ISimplePlugin } from "../interfaces/ISimplePlugin.sol";

/**
 * @title TANIssuanceHistory
 * @author Robriks 📯️📯️📯️.eth
 * @notice A Telcoin Contract
 *
 * @notice This contract persists historical information related to TAN Issuance onchain
 * The stored data is required for TAN Issuance rewards calculations, specifically rewards caps
 * It is designed to serve as the `increaser` for a Telcoin `SimplePlugin` module
 * which is attached to the canonical TEL `StakingModule` contract.
 */
contract TANIssuanceHistory is Ownable {
    using Checkpoints for Checkpoints.Trace224;
    using SafeERC20 for IERC20;

    error ArityMismatch();
    error Deactivated();
    error ERC6372InconsistentClock();
    error InvalidAddress(address invalidAddress);
    error InvalidBlock(uint256 endBlock);
    error FutureLookup(uint256 queriedBlock, uint48 clockBlock);

    ISimplePlugin public tanIssuancePlugin;
    IERC20 public immutable tel;

    mapping(address => Checkpoints.Trace224) private _cumulativeRewards;

    uint256 public lastSettlementBlock;

    /// @notice Emitted when users' (temporarily mocked) claimable rewards are increased
    event ClaimableIncreased(address indexed account, uint256 oldClaimable, uint256 newClaimable);

    modifier whenNotDeactivated() {
        if (deactivated()) revert Deactivated();
        _;
    }

    constructor(ISimplePlugin tanIssuancePlugin_, address owner_) Ownable(owner_) {
        tanIssuancePlugin = tanIssuancePlugin_;
        tel = tanIssuancePlugin.tel();
    }

    /**
     * Views
     */

    /// @dev Returns the current cumulative rewards for an account
    function cumulativeRewards(address account) public view returns (uint256) {
        return _cumulativeRewards[account].latest();
    }

    /// @dev Returns the cumulative rewards for an account at the **end** of the supplied block
    function cumulativeRewardsAtBlock(address account, uint256 queryBlock) external view returns (uint256) {
        uint32 validatedBlock = SafeCast.toUint32(_validateQueryBlock(queryBlock));
        return _cumulativeRewards[account].upperLookupRecent(validatedBlock);
    }

    /// @dev Returns the cumulative rewards for `accounts` at the **end** of the supplied block
    /// @notice To query for the current block, supply `queryBlock == 0`
    function cumulativeRewardsAtBlockBatched(
        address[] calldata accounts,
        uint256 queryBlock
    )
        external
        view
        returns (address[] memory, uint256[] memory)
    {
        uint48 validatedBlock;
        if (queryBlock == 0) {
            // no need for safecast when dealing with global block number variable
            validatedBlock = uint48(block.number);
        } else {
            validatedBlock = _validateQueryBlock(queryBlock);
        }

        uint256 len = accounts.length;
        uint256[] memory rewards = new uint256[](accounts.length);
        for (uint256 i; i < len; ++i) {
            rewards[i] = _cumulativeRewardsAtBlock(accounts[i], validatedBlock);
        }

        return (accounts, rewards);
    }

    /// @dev The active status of this contract is tethered to its designated plugin
    function deactivated() public view returns (bool) {
        return tanIssuancePlugin.deactivated();
    }

    /**
     * Writes
     */

    /// @dev Saves the settlement block, updates cumulative rewards history, and settles TEL rewards on the plugin
    function increaseClaimableByBatch(
        address[] calldata accounts,
        uint256[] calldata amounts,
        uint256 endBlock
    )
        external
        onlyOwner
        whenNotDeactivated
    {
        uint256 len = accounts.length;
        if (amounts.length != len) revert ArityMismatch();

        if (endBlock > block.number) revert InvalidBlock(endBlock);
        lastSettlementBlock = endBlock;

        uint256 totalAmount;
        for (uint256 i; i < len; ++i) {
            if (amounts[i] == 0) continue;

            totalAmount += amounts[i];
            _incrementCumulativeRewards(accounts[i], amounts[i]);
        }

        // set approval as `SimplePlugin::increaseClaimableBy()` pulls TEL from this address to itself
        tel.approve(address(tanIssuancePlugin), totalAmount);
        for (uint256 i; i < len; ++i) {
            // event emission on this contract is omitted since the plugin emits a `ClaimableIncreased` event
            tanIssuancePlugin.increaseClaimableBy(accounts[i], amounts[i]);
        }
    }

    /// @dev Permissioned function to set a new issuance plugin
    function setTanIssuancePlugin(ISimplePlugin newPlugin) external onlyOwner {
        if (address(newPlugin) == address(0x0) || address(newPlugin).code.length == 0) {
            revert InvalidAddress(address(newPlugin));
        }
        tanIssuancePlugin = newPlugin;
    }

    /// @notice Rescues any tokens stuck on this contract
    /// @dev Provide `address(0x0)` to recover native gas token
    function rescueTokens(IERC20 token, address recipient) external onlyOwner {
        if (address(token) == address(0x0)) {
            uint256 bal = address(this).balance;
            (bool r,) = recipient.call{ value: bal }("");
            if (!r) revert InvalidAddress(recipient);
        } else {
            // for other ERC20 tokens, any tokens owned by this address are accidental; send the full balance.
            token.safeTransfer(recipient, token.balanceOf(address(this)));
        }
    }

    /**
     * ERC6372
     */
    function clock() public view returns (uint48) {
        return Time.blockNumber();
    }

    function CLOCK_MODE() public view returns (string memory) {
        if (clock() != Time.blockNumber()) {
            revert ERC6372InconsistentClock();
        }
        return "mode=blocknumber&from=default";
    }

    /**
     * Internals
     */
    function _incrementCumulativeRewards(address account, uint256 amount) internal {
        uint256 prevCumulativeReward = cumulativeRewards(account);
        uint224 newCumulativeReward = SafeCast.toUint224(prevCumulativeReward + amount);

        _cumulativeRewards[account].push(uint32(block.number), newCumulativeReward);
    }

    /// @dev Validate that user-supplied block is in the past, and return it as a uint48.
    function _validateQueryBlock(uint256 queryBlock) internal view returns (uint48) {
        uint48 currentBlock = clock();
        if (queryBlock > currentBlock) revert FutureLookup(queryBlock, currentBlock);
        return SafeCast.toUint48(queryBlock);
    }

    function _cumulativeRewardsAtBlock(address account, uint48 queryBlock) internal view returns (uint256) {
        return _cumulativeRewards[account].upperLookupRecent(SafeCast.toUint32(queryBlock));
    }
}
