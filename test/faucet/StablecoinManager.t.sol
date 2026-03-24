// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { StablecoinHandler } from "../../src/testnet/StablecoinHandler.sol";
import { Stablecoin } from "../../src/testnet/Stablecoin.sol";
import { ITELMint } from "../../src/interfaces/ITELMint.sol";
import "../../src/testnet/StablecoinManager.sol";

contract StablecoinManagerTest is Test {
    StablecoinManager stablecoinManagerImpl;
    StablecoinManager stablecoinManager;
    bytes32 stablecoinManagerSalt = bytes32(hex"deadbeef");

    address admin = address(0xABCD);
    address maintainer = address(0x1234);

    address token1 = address(0x1111);
    address token2 = address(0x2222);
    uint256 max = type(uint256).max;
    uint256 min = 1000;

    uint256 dripAmount = 42;
    uint256 nativeDripAmount = 69;

    function setUp() public {
        stablecoinManagerImpl = new StablecoinManager{ salt: stablecoinManagerSalt }();

        bytes memory initCall = abi.encodeWithSelector(
            StablecoinManager.initialize.selector,
            StablecoinManager.StablecoinManagerInitParams(
                admin, maintainer, new address[](0), max, min, dripAmount, nativeDripAmount
            )
        );

        stablecoinManager = StablecoinManager(
            payable(new ERC1967Proxy{ salt: stablecoinManagerSalt }(address(stablecoinManagerImpl), initCall))
        );
    }

    function testUpdateXYZ() public {
        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1);

        bool validity = stablecoinManager.isXYZ(token1);
        uint256 maxLimit = stablecoinManager.getMaxLimit(token1);
        uint256 minLimit = stablecoinManager.getMinLimit(token1);
        assertEq(validity, true);
        assertEq(maxLimit, 1000);
        assertEq(minLimit, 1);

        stablecoinManager.UpdateXYZ(token1, false, 100, 10);
        bool updatedValidity = stablecoinManager.isXYZ(token1);
        uint256 updatedMaxLimit = stablecoinManager.getMaxLimit(token1);
        uint256 updatedMinLimit = stablecoinManager.getMinLimit(token1);
        assertEq(updatedValidity, false);
        assertEq(updatedMaxLimit, 100);
        assertEq(updatedMinLimit, 10);

        vm.stopPrank();
    }

    function testAddEnabledXYZ() public {
        // address(0x0) for native token should be enabled by default
        assertTrue(stablecoinManager.isEnabledXYZ(address(0x0)));

        // `NATIVE_TOKEN_POINTER` is excluded by `getEnabledXYZs()`
        address[] memory initEnabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(initEnabledXYZs.length, 0);

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1);
        address[] memory enabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(enabledXYZs.length, 1);
        assertEq(enabledXYZs[0], token1);

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(token2, true, 2000, 2);
        address[] memory moreEnabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(moreEnabledXYZs.length, 2);
        assertEq(moreEnabledXYZs[1], token2);

        vm.stopPrank();
    }

    function testRemoveEnabledXYZ() public {
        // address(0x0) for native token should be enabled by default
        assertTrue(stablecoinManager.isEnabledXYZ(address(0x0)));

        // `NATIVE_TOKEN_POINTER` is excluded by `getEnabledXYZs()`
        address[] memory initEnabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(initEnabledXYZs.length, 0);

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1);
        stablecoinManager.UpdateXYZ(token2, true, 2000, 2);
        stablecoinManager.UpdateXYZ(token1, false, 1000, 1);
        vm.stopPrank();

        address[] memory enabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(enabledXYZs.length, 1);
        assertEq(enabledXYZs[0], token2);
    }

    function testFuzzUpdateXYZ(uint8 numTokens, uint8 numRemove) public {
        vm.assume(numTokens >= numRemove);

        // address(0x0) for native token should be enabled by default
        assertTrue(stablecoinManager.isEnabledXYZ(address(0x0)));

        // `NATIVE_TOKEN_POINTER` is excluded by `getEnabledXYZs()`
        address[] memory initEnabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(initEnabledXYZs.length, 0);

        // make array of mock addresses, skipping `address(0x0)`
        address[] memory tokens = new address[](numTokens);
        for (uint256 i; i < numTokens; i++) {
            tokens[i] = address(uint160(i + 1)); // skip zero address
        }

        uint256 maxSupply = 1000;
        uint256 minSupply = 1;

        for (uint256 i; i < numTokens; i++) {
            address token = tokens[i];
            vm.prank(maintainer);
            stablecoinManager.UpdateXYZ(token, true, maxSupply, minSupply);

            bool validityStored = stablecoinManager.isXYZ(token);
            uint256 maxLimitStored = stablecoinManager.getMaxLimit(token);
            uint256 minLimitStored = stablecoinManager.getMinLimit(token);
            assertTrue(validityStored);
            assertEq(maxLimitStored, maxSupply);
            assertEq(minLimitStored, minSupply);
        }

        for (uint256 i; i < numRemove; i++) {
            address token = tokens[i];
            vm.prank(maintainer);
            stablecoinManager.UpdateXYZ(token, false, maxSupply, minSupply);

            bool validityStored = stablecoinManager.isXYZ(token);
            uint256 maxLimitStored = stablecoinManager.getMaxLimit(token);
            uint256 minLimitStored = stablecoinManager.getMinLimit(token);
            assertFalse(validityStored);
            assertEq(maxLimitStored, maxSupply);
            assertEq(minLimitStored, minSupply);
        }

        address[] memory enabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(enabledXYZs.length, numTokens - numRemove + initEnabledXYZs.length);

        for (uint256 i; i < tokens.length; ++i) {
            bool validity = i >= numRemove ? true : false;
            address token = tokens[i];
            bool found = false;
            for (uint256 j; j < enabledXYZs.length; ++j) {
                if (enabledXYZs[j] == token) {
                    found = true;
                    break;
                }
            }

            if (validity) {
                assertTrue(found);
            } else {
                assertFalse(found);
            }
        }
    }

    function testSetDripAmount(uint256 newDripAmount) public {
        vm.assume(newDripAmount != 0);

        vm.prank(maintainer);
        stablecoinManager.setDripAmount(newDripAmount);
        uint256 storedDripAmount = stablecoinManager.getDripAmount();
        assertEq(storedDripAmount, newDripAmount);
    }

    function testSetNativeDripAmount(uint256 newNativeDripAmount) public {
        vm.assume(newNativeDripAmount != 0);

        vm.prank(maintainer);
        stablecoinManager.setNativeDripAmount(newNativeDripAmount);
        uint256 storedNativeDripAmount = stablecoinManager.getNativeDripAmount();
        assertEq(storedNativeDripAmount, newNativeDripAmount);
    }

    function testDrip(address recipient, uint256 fuzzDripAmount) public {
        vm.assume(recipient != address(0));
        vm.assume(fuzzDripAmount > 0);

        // just use impl contract
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1);
        stablecoinManager.setDripAmount(fuzzDripAmount);
        vm.stopPrank();

        // fast forward 1 day
        vm.warp(block.timestamp + 1 days);

        uint256 balBefore = currency.balanceOf(recipient);
        vm.prank(recipient);
        stablecoinManager.drip(address(currency));
        uint256 balAfter = currency.balanceOf(recipient);

        uint256 dripAmt = stablecoinManager.getDripAmount();
        assertEq(balBefore + dripAmt, balAfter);

        uint256 lastFulfilledDrip = stablecoinManager.getLastFulfilledDripTimestamp(address(currency), recipient);
        assertEq(lastFulfilledDrip, block.timestamp);
    }

    function testNativeCurrencyDrip() public {
        address recipient = address(0xbeefbabe);

        uint256 nativeDripAmt = stablecoinManager.getNativeDripAmount();

        // mock the TEL precompile mint call
        vm.mockCall(
            address(0x7e1), abi.encodeWithSelector(ITELMint.mint.selector, recipient, nativeDripAmt), abi.encode()
        );
        vm.expectCall(address(0x7e1), abi.encodeWithSelector(ITELMint.mint.selector, recipient, nativeDripAmt));

        // fast forward 1 day
        vm.warp(block.timestamp + 1 days);

        vm.prank(recipient);
        stablecoinManager.drip(address(0));

        uint256 lastFulfilledDrip = stablecoinManager.getLastFulfilledDripTimestamp(address(0), recipient);
        assertEq(lastFulfilledDrip, block.timestamp);
    }

    function testDripTo(address funder, address recipient, uint256 fuzzDripAmount) public {
        vm.assume(funder != address(0));
        vm.assume(recipient != address(0));
        vm.assume(funder != recipient);
        vm.assume(fuzzDripAmount > 0);

        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1);
        stablecoinManager.setDripAmount(fuzzDripAmount);
        vm.stopPrank();

        // fast forward 1 day
        vm.warp(block.timestamp + 1 days);

        uint256 balBefore = currency.balanceOf(recipient);
        vm.prank(funder);
        stablecoinManager.dripTo(address(currency), recipient);
        uint256 balAfter = currency.balanceOf(recipient);

        uint256 dripAmt = stablecoinManager.getDripAmount();
        assertEq(balBefore + dripAmt, balAfter);

        // cooldown is set on recipient, not funder
        uint256 recipientLastDrip = stablecoinManager.getLastFulfilledDripTimestamp(address(currency), recipient);
        assertEq(recipientLastDrip, block.timestamp);
        uint256 funderLastDrip = stablecoinManager.getLastFulfilledDripTimestamp(address(currency), funder);
        assertEq(funderLastDrip, 0);
    }

    function testNativeCurrencyDripTo() public {
        address funder = address(0xf00d);
        address recipient = address(0xbeefbabe);

        uint256 nativeDripAmt = stablecoinManager.getNativeDripAmount();

        // mock the TEL precompile mint call
        vm.mockCall(
            address(0x7e1), abi.encodeWithSelector(ITELMint.mint.selector, recipient, nativeDripAmt), abi.encode()
        );
        vm.expectCall(address(0x7e1), abi.encodeWithSelector(ITELMint.mint.selector, recipient, nativeDripAmt));

        // fast forward 1 day
        vm.warp(block.timestamp + 1 days);

        vm.prank(funder);
        stablecoinManager.dripTo(address(0), recipient);

        uint256 lastFulfilledDrip = stablecoinManager.getLastFulfilledDripTimestamp(address(0), recipient);
        assertEq(lastFulfilledDrip, block.timestamp);
    }

    function testDripTo_RateLimitPerRecipient() public {
        address funderA = address(0xf00d);
        address funderB = address(0xbead);
        address recipient = address(0xbeefbabe);

        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1);

        // fast forward 1 day
        vm.warp(block.timestamp + 1 days);

        // funder A drips to recipient - succeeds
        vm.prank(funderA);
        stablecoinManager.dripTo(address(currency), recipient);

        // funder B tries to drip to same recipient immediately - reverts
        vm.prank(funderB);
        vm.expectRevert();
        stablecoinManager.dripTo(address(currency), recipient);
    }

    function testDripTo_IndependentRecipients() public {
        address funder = address(0xf00d);
        address recipientA = address(0xbeefbabe);
        address recipientB = address(0xcafebabe);

        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1);

        // fast forward 1 day
        vm.warp(block.timestamp + 1 days);

        // same funder drips to two different recipients in the same block - both succeed
        vm.startPrank(funder);
        stablecoinManager.dripTo(address(currency), recipientA);
        stablecoinManager.dripTo(address(currency), recipientB);
        vm.stopPrank();

        uint256 dripAmt = stablecoinManager.getDripAmount();
        assertEq(currency.balanceOf(recipientA), dripAmt);
        assertEq(currency.balanceOf(recipientB), dripAmt);
    }

    function testRescueCrypto(uint256 amount) public {
        vm.assume(amount > 0);

        // just use impl contract
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.prank(address(stablecoinManager));
        currency.mintTo(address(stablecoinManager), amount);

        uint256 balBefore = currency.balanceOf(address(stablecoinManager));
        assertEq(balBefore, amount);

        vm.prank(maintainer);
        stablecoinManager.rescueCrypto(IERC20(address(currency)), amount);

        uint256 balAfter = currency.balanceOf(address(stablecoinManager));
        assertEq(balAfter, 0);
    }
}
