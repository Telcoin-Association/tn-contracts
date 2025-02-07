// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../src/issuance/TANIssuanceHistory.sol";
import "../../src/interfaces/ISimplePlugin.sol";
import "./mocks/MockImplementations.sol";

contract TANIssuanceHistoryTest is Test {
    MockTel tel;
    TANIssuanceHistory public tanIssuanceHistory;
    ISimplePlugin public mockPlugin;

    // Addresses for testing
    address public owner = address(0x123);
    address public user1 = address(0x456);
    address public user2 = address(0x789);

    function setUp() public {
        // Deploy TEL and mock plugin
        tel = new MockTel("Telcoin", "TEL");
        mockPlugin = ISimplePlugin(address(new MockPlugin(IERC20(address(tel)))));

        // Deploy the TANIssuanceHistory contract as owner
        vm.prank(owner);
        tanIssuanceHistory = new TANIssuanceHistory(mockPlugin, owner);
    }

    /// @dev Useful as a benchmark for the maximum batch size which is ~15000 users
    function testFuzz_increaseClaimableByBatch(uint16 numUsers) public {
        numUsers = uint16(bound(numUsers, 0, 14_000));
        address[] memory accounts = new address[](numUsers);
        uint256[] memory amounts = new uint256[](numUsers);
        for (uint256 i; i < numUsers; ++i) {
            accounts[i] = address(uint160(uint256(numUsers) + i));
            amounts[i] = uint256(numUsers) + i;
        }

        vm.prank(owner); // Ensure the caller is the owner
        uint256 someBlock = block.number + 5;
        vm.roll(someBlock);
        tanIssuanceHistory.increaseClaimableByBatch(accounts, amounts, someBlock);

        for (uint256 i; i < numUsers; ++i) {
            assertEq(tanIssuanceHistory.cumulativeRewards(accounts[i]), amounts[i]);
        }

        assertEq(tanIssuanceHistory.lastSettlementBlock(), someBlock);
    }

    function testIncreaseClaimableByBatchRevertArityMismatch() public {
        address[] memory accounts = new address[](2);
        uint256[] memory amounts = new uint256[](1);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(TANIssuanceHistory.ArityMismatch.selector));
        tanIssuanceHistory.increaseClaimableByBatch(accounts, amounts, block.number);
    }

    function testIncreaseClaimableByBatchWhenDeactivated() public {
        // Mock the plugin to return deactivated
        MockPlugin(address(mockPlugin)).setDeactivated(true);

        address[] memory accounts = new address[](1);
        uint256[] memory amounts = new uint256[](1);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(TANIssuanceHistory.Deactivated.selector));
        tanIssuanceHistory.increaseClaimableByBatch(accounts, amounts, block.number);
    }

    function testCumulativeRewardsAtBlock() public {
        vm.prank(owner);
        address[] memory accounts = new address[](2);
        accounts[0] = user1;
        accounts[1] = user2;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 100;
        amounts[1] = 200;

        tanIssuanceHistory.increaseClaimableByBatch(accounts, amounts, block.number);

        // Move forward in blocks
        vm.roll(block.number + 10);

        assertEq(tanIssuanceHistory.cumulativeRewardsAtBlock(user1, block.number - 10), 100);
        assertEq(tanIssuanceHistory.cumulativeRewardsAtBlock(user2, block.number - 10), 200);

        uint256 queryBlock = block.number - 10;
        (address[] memory users, uint256[] memory rewards) =
            tanIssuanceHistory.cumulativeRewardsAtBlockBatched(accounts, queryBlock);
        for (uint256 i; i < users.length; ++i) {
            assertEq(users[i], accounts[i]);
            assertEq(rewards[i], amounts[i]);
        }
    }
}
