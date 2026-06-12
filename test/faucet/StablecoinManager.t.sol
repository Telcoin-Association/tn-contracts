// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { StablecoinHandler } from "../../src/testnet/StablecoinHandler.sol";
import { Stablecoin } from "../../src/testnet/Stablecoin.sol";
import { ITELMint } from "../../src/interfaces/ITELMint.sol";
import { TNFaucet } from "../../src/testnet/TNFaucet.sol";
import "../../src/testnet/StablecoinManager.sol";

/// @title StablecoinManagerTest
/// @notice Unit tests for the StablecoinManager faucet entry points and TNFaucet scaffolding
///         it inherits.
/// @notice Coverage areas:
///         - **Init:** baseline cooldown + native drip seed, role grants, with-tokens loop.
///         - **UpdateXYZ / drippable set:** 5-arg enable/disable, AlreadyEnabled / InvalidOrDisabled
///           reverts, EnumerableSet membership, the inherited 4-arg tombstone revert, the
///           `getEnabledXYZs` early-return when native is disabled, and the
///           `getDrippableTokensWithDripAmount` view (which includes native).
///         - **Setters:** per-token max amount, baseline cooldown, per-recipient amount and
///           cooldown overrides, including their `SettingAlreadyConfigured` no-op guards and
///           access-control gating to MAINTAINER_ROLE.
///         - **Drip / dripTo:** ERC20 stablecoin path, native-token path (via TEL precompile
///           mock), recipient-vs-funder cooldown attribution on `dripTo`, sub-cap success,
///           amount-cap revert, cooldown enforcement, per-recipient overrides taking effect,
///           and the `getNextEligibleDripTimestamp` view in fresh / post-drip / override states.
///         - **Support:** ERC20 and native paths of `rescueCrypto`, including the
///           `LowLevelCallFailure` revert when the maintainer rejects the native send.
///         - **Upgradeability:** UUPS `_authorizeUpgrade` admin gate via `upgradeToAndCall`.
contract StablecoinManagerTest is Test {
    StablecoinManager stablecoinManagerImpl;
    StablecoinManager stablecoinManager;
    bytes32 stablecoinManagerSalt = bytes32(hex"deadbeef");

    address admin = address(0xABCD);
    address maintainer = address(0x1234);
    address nonMaintainer = address(0xDEAD);

    address token1 = address(0x1111);
    address token2 = address(0x2222);
    address constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    uint256 max = type(uint256).max;
    uint256 min = 1000;

    uint256 dripAmount = 42;
    uint256 nativeDripAmount = 69;
    uint256 baseDripCooldown = 1 days;

    function setUp() public {
        stablecoinManagerImpl = new StablecoinManager{ salt: stablecoinManagerSalt }();

        bytes memory initCall = abi.encodeWithSelector(
            StablecoinManager.initialize.selector,
            StablecoinManager.StablecoinManagerInitParams(
                admin,
                maintainer,
                new address[](0),
                max,
                min,
                dripAmount,
                nativeDripAmount,
                baseDripCooldown
            )
        );

        stablecoinManager = StablecoinManager(
            payable(new ERC1967Proxy{ salt: stablecoinManagerSalt }(address(stablecoinManagerImpl), initCall))
        );
    }

    // -------------
    // init
    // -------------

    function testInitializeSetsBaselines() public view {
        assertEq(
            stablecoinManager.getBaselineMaxDripAmount(NATIVE),
            nativeDripAmount,
            "native baseline drip amount not seeded by initializer"
        );
        assertEq(
            stablecoinManager.getBaselineDripCooldown(),
            baseDripCooldown,
            "baseline drip cooldown not seeded by initializer"
        );
        assertTrue(stablecoinManager.isEnabledXYZ(NATIVE), "native token should be enabled by default");
        assertTrue(
            stablecoinManager.hasRole(stablecoinManager.DEFAULT_ADMIN_ROLE(), admin),
            "admin should hold DEFAULT_ADMIN_ROLE after init"
        );
        assertTrue(
            stablecoinManager.hasRole(keccak256("MAINTAINER_ROLE"), maintainer),
            "maintainer should hold MAINTAINER_ROLE after init"
        );
    }

    // -------------
    // UpdateXYZ / enabled set
    // -------------

    function testUpdateXYZ() public {
        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1, 100);

        assertEq(stablecoinManager.isXYZ(token1), true, "token1 should be marked XYZ after enable");
        assertEq(stablecoinManager.getMaxLimit(token1), 1000, "token1 maxLimit not stored");
        assertEq(stablecoinManager.getMinLimit(token1), 1, "token1 minLimit not stored");

        stablecoinManager.UpdateXYZ(token1, false, 100, 10, 0);
        assertEq(stablecoinManager.isXYZ(token1), false, "token1 should be unmarked XYZ after disable");
        assertEq(stablecoinManager.getMaxLimit(token1), 100, "token1 maxLimit not updated on disable");
        assertEq(stablecoinManager.getMinLimit(token1), 10, "token1 minLimit not updated on disable");

        vm.stopPrank();
    }

    function testUpdateXYZRevertsIfAlreadyEnabled() public {
        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1, 100);
        vm.expectRevert(abi.encodeWithSelector(StablecoinManager.AlreadyEnabled.selector, token1));
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1, 100);
        vm.stopPrank();
    }

    function testUpdateXYZRevertsIfDisablingNonExistent() public {
        vm.prank(maintainer);
        vm.expectRevert(abi.encodeWithSelector(StablecoinManager.InvalidOrDisabled.selector, token1));
        stablecoinManager.UpdateXYZ(token1, false, 0, 0, 0);
    }

    function testAddEnabledXYZ() public {
        // NATIVE_TOKEN_POINTER (0xEee...EeE) for native token is enabled by default
        assertTrue(stablecoinManager.isEnabledXYZ(NATIVE), "native should be enabled by default");

        // `NATIVE_TOKEN_POINTER` is excluded by `getEnabledXYZs()`
        address[] memory initEnabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(initEnabledXYZs.length, 0, "getEnabledXYZs should exclude native and start empty");

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1, 100);
        address[] memory enabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(enabledXYZs.length, 1, "one XYZ enabled, expected length 1");
        assertEq(enabledXYZs[0], token1, "first enabled XYZ should be token1");

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(token2, true, 2000, 2, 100);
        address[] memory moreEnabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(moreEnabledXYZs.length, 2, "two XYZs enabled, expected length 2");

        // EnumerableSet does not guarantee insertion order, so check membership
        bool foundToken1;
        bool foundToken2;
        for (uint256 i; i < moreEnabledXYZs.length; ++i) {
            if (moreEnabledXYZs[i] == token1) foundToken1 = true;
            if (moreEnabledXYZs[i] == token2) foundToken2 = true;
        }
        assertTrue(foundToken1, "token1 missing from enabled set");
        assertTrue(foundToken2, "token2 missing from enabled set");
    }

    function testRemoveEnabledXYZ() public {
        assertTrue(stablecoinManager.isEnabledXYZ(NATIVE), "native should be enabled by default");

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1, 100);
        stablecoinManager.UpdateXYZ(token2, true, 2000, 2, 100);
        stablecoinManager.UpdateXYZ(token1, false, 1000, 1, 0);
        vm.stopPrank();

        address[] memory enabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(enabledXYZs.length, 1, "after removing token1 only token2 should remain");
        assertEq(enabledXYZs[0], token2, "remaining enabled XYZ should be token2");
        assertFalse(stablecoinManager.isEnabledXYZ(token1), "token1 should not be enabled after removal");
    }

    function testUpdateXYZDisableClearsBaseline() public {
        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1, 100);
        assertEq(stablecoinManager.getBaselineMaxDripAmount(token1), 100, "baseline should equal seeded amount");

        vm.expectEmit(true, true, true, true);
        emit TNFaucet.DripAmountUpdated(token1, 0);
        stablecoinManager.UpdateXYZ(token1, false, 1000, 1, 0);
        vm.stopPrank();

        assertEq(
            stablecoinManager.getBaselineMaxDripAmount(token1),
            0,
            "disable should clear baseline slot to 0"
        );
    }

    function testReEnableAfterDisableWithSameBaseDripAmountSucceeds() public {
        // regression: prior to the disable-path reset, re-enabling with the same baseDripAmount
        // would revert with `SettingAlreadyConfigured` because the slot still held the old value.
        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1, 100);
        stablecoinManager.UpdateXYZ(token1, false, 1000, 1, 0);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1, 100);
        vm.stopPrank();

        assertTrue(stablecoinManager.isEnabledXYZ(token1), "token1 should be re-enabled");
        assertEq(
            stablecoinManager.getBaselineMaxDripAmount(token1),
            100,
            "baseline should match the re-enable value"
        );
    }

    function testDisableSucceedsWhenBaselineWasOneWei() public {
        // edge case: a token enabled with baseDripAmount=1 must still be disableable.
        // (Earlier "set to 1 on disable" approach would have made this token undisableable.)
        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1, 1);
        stablecoinManager.UpdateXYZ(token1, false, 1000, 1, 0);
        vm.stopPrank();

        assertFalse(stablecoinManager.isEnabledXYZ(token1), "token1 should be disabled");
        assertEq(
            stablecoinManager.getBaselineMaxDripAmount(token1),
            0,
            "baseline should be cleared even when prior value was 1"
        );
    }

    function testFuzzUpdateXYZ(uint8 numTokens, uint8 numRemove) public {
        vm.assume(numTokens >= numRemove);

        address[] memory tokens = new address[](numTokens);
        for (uint256 i; i < numTokens; ++i) {
            tokens[i] = address(uint160(i + 1)); // skip zero address
        }

        for (uint256 i; i < numTokens; ++i) {
            vm.prank(maintainer);
            stablecoinManager.UpdateXYZ(tokens[i], true, 1000, 1, 100);
            assertTrue(stablecoinManager.isEnabledXYZ(tokens[i]), "token should be enabled after UpdateXYZ(true)");
        }

        for (uint256 i; i < numRemove; ++i) {
            vm.prank(maintainer);
            stablecoinManager.UpdateXYZ(tokens[i], false, 1000, 1, 0);
            assertFalse(stablecoinManager.isEnabledXYZ(tokens[i]), "token should be disabled after UpdateXYZ(false)");
        }

        address[] memory enabledXYZs = stablecoinManager.getEnabledXYZs();
        assertEq(
            enabledXYZs.length,
            numTokens - numRemove,
            "enabled XYZ count should equal added minus removed"
        );
    }

    function testGetEnabledXYZsWithDripAmounts() public {
        Stablecoin tokenA = new Stablecoin();
        tokenA.initialize("0x", "A", 6);
        Stablecoin tokenB = new Stablecoin();
        tokenB.initialize("0x", "B", 6);

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(tokenA), true, 1000, 1, 100);
        stablecoinManager.UpdateXYZ(address(tokenB), true, 1000, 1, 100);
        stablecoinManager.setMaxDripAmount(address(tokenA), 111);
        stablecoinManager.setMaxDripAmount(address(tokenB), 222);
        vm.stopPrank();

        StablecoinManager.TokenDripAmount[] memory pairs = stablecoinManager.getDrippableTokensWithDripAmount();
        assertEq(pairs.length, 3, "two stablecoins + native, expected three drippable entries");

        bool sawNative;
        bool sawA;
        bool sawB;
        for (uint256 i; i < pairs.length; ++i) {
            if (pairs[i].token == NATIVE) {
                assertEq(pairs[i].dripAmount, nativeDripAmount, "native drip amount mismatch");
                sawNative = true;
            } else if (pairs[i].token == address(tokenA)) {
                assertEq(pairs[i].dripAmount, 111, "tokenA drip amount mismatch");
                sawA = true;
            } else if (pairs[i].token == address(tokenB)) {
                assertEq(pairs[i].dripAmount, 222, "tokenB drip amount mismatch");
                sawB = true;
            } else {
                revert("unexpected token");
            }
        }
        assertTrue(sawNative, "native missing from drippable set");
        assertTrue(sawA, "tokenA missing from drippable set");
        assertTrue(sawB, "tokenB missing from drippable set");
    }

    function testGetEnabledXYZsWithMetadata() public {
        Stablecoin tokenA = new Stablecoin();
        tokenA.initialize("AlphaCoin", "ALPHA", 18);
        Stablecoin tokenB = new Stablecoin();
        tokenB.initialize("BetaCoin", "BETA", 6);

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(tokenA), true, 1000, 1, 100);
        stablecoinManager.UpdateXYZ(address(tokenB), true, 1000, 1, 100);
        vm.stopPrank();

        StablecoinManager.XYZMetadata[] memory metadatas = stablecoinManager.getEnabledXYZsWithMetadata();
        assertEq(metadatas.length, 2, "two enabled XYZs, expected two metadata entries");

        for (uint256 i; i < metadatas.length; ++i) {
            if (metadatas[i].token == address(tokenA)) {
                assertEq(metadatas[i].name, "AlphaCoin", "tokenA name mismatch");
                assertEq(metadatas[i].symbol, "ALPHA", "tokenA symbol mismatch");
                assertEq(metadatas[i].decimals, 18, "tokenA decimals mismatch");
            } else if (metadatas[i].token == address(tokenB)) {
                assertEq(metadatas[i].name, "BetaCoin", "tokenB name mismatch");
                assertEq(metadatas[i].symbol, "BETA", "tokenB symbol mismatch");
                assertEq(metadatas[i].decimals, 6, "tokenB decimals mismatch");
            } else {
                revert("unexpected token");
            }
        }
    }

    function testGetEnabledXYZsWhenNativeDisabled() public {
        // exercises the early-return branch of getEnabledXYZs (no native filter needed)
        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(token1, true, 1000, 1, 100);
        stablecoinManager.UpdateXYZ(NATIVE, false, 1000, 1, 0);
        vm.stopPrank();

        address[] memory enabled = stablecoinManager.getEnabledXYZs();
        assertEq(enabled.length, 1, "only token1 should remain enabled");
        assertEq(enabled[0], token1, "remaining enabled XYZ should be token1");
        assertFalse(stablecoinManager.isEnabledXYZ(NATIVE), "native should be disabled");
    }

    function testInitializeWithTokensList() public {
        Stablecoin t1 = new Stablecoin();
        t1.initialize("T1", "T1", 6);
        Stablecoin t2 = new Stablecoin();
        t2.initialize("T2", "T2", 6);

        address[] memory toks = new address[](2);
        toks[0] = address(t1);
        toks[1] = address(t2);

        StablecoinManager freshImpl = new StablecoinManager();
        bytes memory initCall = abi.encodeWithSelector(
            StablecoinManager.initialize.selector,
            StablecoinManager.StablecoinManagerInitParams(
                admin,
                maintainer,
                toks,
                1000,
                1,
                dripAmount,
                nativeDripAmount,
                baseDripCooldown
            )
        );
        StablecoinManager mgr = StablecoinManager(payable(new ERC1967Proxy(address(freshImpl), initCall)));

        assertTrue(mgr.isEnabledXYZ(address(t1)), "t1 should be enabled by initialize loop");
        assertTrue(mgr.isEnabledXYZ(address(t2)), "t2 should be enabled by initialize loop");
        assertEq(mgr.getMaxLimit(address(t1)), 1000, "t1 maxLimit not seeded by initialize loop");
        assertEq(mgr.getMinLimit(address(t1)), 1, "t1 minLimit not seeded by initialize loop");
        assertEq(
            mgr.getBaselineMaxDripAmount(address(t1)),
            dripAmount,
            "t1 drip amount should be seeded by initialize loop"
        );
        assertEq(
            mgr.getBaselineMaxDripAmount(address(t2)),
            dripAmount,
            "t2 drip amount should be seeded by initialize loop"
        );
    }

    // -------------
    // max drip amount setters
    // -------------

    function testSetMaxDripAmount(uint256 newDripAmount) public {
        vm.assume(newDripAmount != 0);

        vm.prank(maintainer);
        stablecoinManager.setMaxDripAmount(token1, newDripAmount);
        assertEq(
            stablecoinManager.getBaselineMaxDripAmount(token1),
            newDripAmount,
            "setMaxDripAmount did not update baseline"
        );
    }

    function testSetMaxDripAmountRevertsOnZero() public {
        vm.prank(maintainer);
        vm.expectRevert(abi.encodeWithSelector(TNFaucet.InvalidDripAmount.selector, 0));
        stablecoinManager.setMaxDripAmount(token1, 0);
    }

    function testSetMaxDripAmountAccessControl() public {
        vm.prank(nonMaintainer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                nonMaintainer,
                keccak256("MAINTAINER_ROLE")
            )
        );
        stablecoinManager.setMaxDripAmount(token1, 100);
    }

    function testSetMaxDripAmountForNative(uint256 newNativeDripAmount) public {
        vm.assume(newNativeDripAmount != 0);
        // setUp seeds native baseline to `nativeDripAmount` via `UpdateXYZ` in initialize;
        // setting it to the same value would revert with `SettingAlreadyConfigured`.
        vm.assume(newNativeDripAmount != nativeDripAmount);

        vm.prank(maintainer);
        stablecoinManager.setMaxDripAmount(NATIVE, newNativeDripAmount);
        assertEq(
            stablecoinManager.getBaselineMaxDripAmount(NATIVE),
            newNativeDripAmount,
            "setMaxDripAmount(NATIVE_TOKEN_POINTER, _) did not update native baseline"
        );
    }

    function testSetMaxDripAmountRevertsIfUnchanged() public {
        // Seed a baseline, then set the same value again - should hit the no-op guard.
        vm.startPrank(maintainer);
        stablecoinManager.setMaxDripAmount(token1, 123);
        vm.expectRevert(TNFaucet.SettingAlreadyConfigured.selector);
        stablecoinManager.setMaxDripAmount(token1, 123);
        vm.stopPrank();
    }

    // -------------
    // cooldown setters
    // -------------

    function testSetBaselineDripCooldown() public {
        vm.prank(maintainer);
        stablecoinManager.setBaselineDripCooldown(2 days);
        assertEq(
            stablecoinManager.getBaselineDripCooldown(),
            2 days,
            "setBaselineDripCooldown did not update baseline"
        );
    }

    function testSetBaselineDripCooldownRevertsIfUnchanged() public {
        vm.prank(maintainer);
        vm.expectRevert(TNFaucet.SettingAlreadyConfigured.selector);
        stablecoinManager.setBaselineDripCooldown(baseDripCooldown);
    }

    function testSetBaselineDripCooldownAccessControl() public {
        vm.prank(nonMaintainer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                nonMaintainer,
                keccak256("MAINTAINER_ROLE")
            )
        );
        stablecoinManager.setBaselineDripCooldown(2 days);
    }

    // -------------
    // override setters
    // -------------

    function testSetMaxDripAmountOverride() public {
        address recipient = address(0xbeef);

        vm.prank(maintainer);
        stablecoinManager.setMaxDripAmountOverride(recipient, token1, 999);

        assertEq(
            stablecoinManager.getMaxDripAmount(recipient, token1),
            999,
            "per-recipient override should be returned"
        );
        // baseline unchanged
        assertEq(
            stablecoinManager.getBaselineMaxDripAmount(token1),
            0,
            "override should not write to baseline"
        );
    }

    function testSetMaxDripAmountOverrideRevertsIfUnchanged() public {
        address recipient = address(0xbeef);

        vm.startPrank(maintainer);
        stablecoinManager.setMaxDripAmountOverride(recipient, token1, 999);
        vm.expectRevert(TNFaucet.SettingAlreadyConfigured.selector);
        stablecoinManager.setMaxDripAmountOverride(recipient, token1, 999);
        vm.stopPrank();
    }

    function testSetMaxDripAmountOverrideAccessControl() public {
        vm.prank(nonMaintainer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                nonMaintainer,
                keccak256("MAINTAINER_ROLE")
            )
        );
        stablecoinManager.setMaxDripAmountOverride(address(0xbeef), token1, 999);
    }

    function testSetDripCooldownOverride() public {
        address recipient = address(0xbeef);

        vm.prank(maintainer);
        stablecoinManager.setDripCooldownOverride(recipient, 1 hours);

        assertEq(
            stablecoinManager.getDripCooldown(recipient),
            1 hours,
            "per-recipient cooldown override should be returned"
        );
    }

    function testSetDripCooldownOverrideRevertsIfUnchanged() public {
        address recipient = address(0xbeef);

        vm.startPrank(maintainer);
        stablecoinManager.setDripCooldownOverride(recipient, 1 hours);
        vm.expectRevert(TNFaucet.SettingAlreadyConfigured.selector);
        stablecoinManager.setDripCooldownOverride(recipient, 1 hours);
        vm.stopPrank();
    }

    function testSetDripCooldownOverrideAccessControl() public {
        vm.prank(nonMaintainer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                nonMaintainer,
                keccak256("MAINTAINER_ROLE")
            )
        );
        stablecoinManager.setDripCooldownOverride(address(0xbeef), 1 hours);
    }

    // -------------
    // next-eligible view
    // -------------

    function testGetNextEligibleDripTimestampForFreshWallet() public {
        // never-dripped wallet: lastFulfilled is 0, so the returned timestamp is just the cooldown.
        // On a real chain that's well in the past; here we warp explicitly to confirm the
        // "eligible now" reading.
        address recipient = address(0xbeef);
        vm.warp(block.timestamp + baseDripCooldown);
        uint256 nextEligible = stablecoinManager.getNextEligibleDripTimestamp(recipient, token1);
        assertEq(nextEligible, baseDripCooldown, "fresh wallet next-eligible should be the bare cooldown");
        assertGe(block.timestamp, nextEligible, "fresh wallet should be eligible now (block.timestamp >= nextEligible)");
    }

    function testGetNextEligibleDripTimestampAfterDrip() public {
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);
        vm.stopPrank();

        vm.warp(block.timestamp + baseDripCooldown);
        uint256 dripTime = block.timestamp;
        vm.prank(recipient);
        stablecoinManager.drip(address(currency), 50);

        uint256 nextEligible = stablecoinManager.getNextEligibleDripTimestamp(recipient, address(currency));
        assertEq(
            nextEligible,
            dripTime + baseDripCooldown,
            "post-drip next-eligible should be lastFulfilled + baseline cooldown"
        );
    }

    function testGetNextEligibleDripTimestampUsesCooldownOverride() public {
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);
        stablecoinManager.setDripCooldownOverride(recipient, 1 hours);
        vm.stopPrank();

        vm.warp(block.timestamp + baseDripCooldown);
        uint256 dripTime = block.timestamp;
        vm.prank(recipient);
        stablecoinManager.drip(address(currency), 50);

        uint256 nextEligible = stablecoinManager.getNextEligibleDripTimestamp(recipient, address(currency));
        assertEq(
            nextEligible,
            dripTime + 1 hours,
            "next-eligible should reflect the recipient's per-wallet cooldown override"
        );
    }

    // -------------
    // drip / dripTo
    // -------------

    function testDrip(address recipient, uint256 fuzzDripAmount) public {
        vm.assume(recipient != address(0));
        vm.assume(fuzzDripAmount > 0 && fuzzDripAmount < type(uint128).max);

        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, fuzzDripAmount);

        vm.warp(block.timestamp + baseDripCooldown);

        uint256 balBefore = currency.balanceOf(recipient);
        vm.prank(recipient);
        stablecoinManager.drip(address(currency), fuzzDripAmount);
        uint256 balAfter = currency.balanceOf(recipient);

        assertEq(balBefore + fuzzDripAmount, balAfter, "recipient balance should increase by drip amount");
        assertEq(
            stablecoinManager.getLastFulfilledDripTimestamp(recipient, address(currency)),
            block.timestamp,
            "lastFulfilledDripTimestamp should be set to now"
        );
    }

    function testDripWithSmallerAmount() public {
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);
        vm.stopPrank();

        vm.warp(block.timestamp + baseDripCooldown);

        // request only 50 of the 100 max - should succeed
        vm.prank(recipient);
        stablecoinManager.drip(address(currency), 50);
        assertEq(currency.balanceOf(recipient), 50, "recipient balance should equal sub-cap drip");
    }

    function testDripRevertsWhenAmountExceedsMax() public {
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);
        vm.stopPrank();

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(recipient);
        vm.expectRevert(abi.encodeWithSelector(TNFaucet.RequestedAmountTooHigh.selector, 101, 100));
        stablecoinManager.drip(address(currency), 101);
    }

    function testDripRevertsWhenAmountBelowMin() public {
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);

        vm.warp(block.timestamp + baseDripCooldown);

        // min = 100 / MIN_DRIP_DIVISOR (10) = 10. Requesting 9 should revert.
        vm.prank(recipient);
        vm.expectRevert(abi.encodeWithSelector(TNFaucet.RequestedAmountTooLow.selector, 9, 10));
        stablecoinManager.drip(address(currency), 9);
    }

    function testDripSucceedsAtMinThreshold() public {
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(recipient);
        stablecoinManager.drip(address(currency), 10);
        assertEq(currency.balanceOf(recipient), 10, "drip at the exact min threshold should succeed");
    }

    function testDripRevertsOnZeroAmount() public {
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(recipient);
        vm.expectRevert(abi.encodeWithSelector(TNFaucet.RequestedAmountTooLow.selector, 0, 10));
        stablecoinManager.drip(address(currency), 0);
    }

    function testDripRevertsOnZeroAmountWithSubDivisorMax() public {
        // when effectiveMax < MIN_DRIP_DIVISOR, the floor `maxAmount / 10` rounds to 0; the
        // explicit `amount == 0` guard must still reject zero-amount drips.
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 5);

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(recipient);
        vm.expectRevert(abi.encodeWithSelector(TNFaucet.RequestedAmountTooLow.selector, 0, 0));
        stablecoinManager.drip(address(currency), 0);
    }

    function testMinDripUsesPerRecipientAmountOverride() public {
        // override raises the effective max for `recipient`, which should also raise the floor:
        // baseline-derived min would be 10, but override-derived min is 50.
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);
        stablecoinManager.setMaxDripAmountOverride(recipient, address(currency), 500);
        vm.stopPrank();

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(recipient);
        vm.expectRevert(abi.encodeWithSelector(TNFaucet.RequestedAmountTooLow.selector, 49, 50));
        stablecoinManager.drip(address(currency), 49);

        vm.prank(recipient);
        stablecoinManager.drip(address(currency), 50);
        assertEq(currency.balanceOf(recipient), 50, "drip at override-derived min should succeed");
    }

    function testDripRevertsOnDisabledToken() public {
        vm.warp(block.timestamp + baseDripCooldown);
        vm.prank(address(0xbeef));
        vm.expectRevert(abi.encodeWithSelector(StablecoinManager.InvalidOrDisabled.selector, token1));
        stablecoinManager.drip(token1, 1);
    }

    function testDripRespectsCooldown() public {
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);
        vm.stopPrank();

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(recipient);
        stablecoinManager.drip(address(currency), 50);

        // immediately try again - reverts
        vm.prank(recipient);
        vm.expectRevert(
            abi.encodeWithSelector(TNFaucet.RequestIneligibleUntil.selector, block.timestamp + baseDripCooldown)
        );
        stablecoinManager.drip(address(currency), 50);

        // wait the cooldown - succeeds again
        vm.warp(block.timestamp + baseDripCooldown);
        vm.prank(recipient);
        stablecoinManager.drip(address(currency), 50);
        assertEq(currency.balanceOf(recipient), 100, "two successful drips of 50 should total 100");
    }

    function testDripUsesPerRecipientAmountOverride() public {
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);
        // recipient gets a higher per-token cap
        stablecoinManager.setMaxDripAmountOverride(recipient, address(currency), 500);
        vm.stopPrank();

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(recipient);
        stablecoinManager.drip(address(currency), 500);
        assertEq(currency.balanceOf(recipient), 500, "recipient should be able to drip up to override cap");
    }

    function testDripUsesPerRecipientCooldownOverride() public {
        address recipient = address(0xbeef);
        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);
        // recipient has a 1-hour cooldown vs baseline 1-day
        stablecoinManager.setDripCooldownOverride(recipient, 1 hours);
        vm.stopPrank();

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(recipient);
        stablecoinManager.drip(address(currency), 50);

        // 1 hour later - succeeds because of override
        vm.warp(block.timestamp + 1 hours);
        vm.prank(recipient);
        stablecoinManager.drip(address(currency), 50);
        assertEq(
            currency.balanceOf(recipient),
            100,
            "recipient with shorter cooldown override should succeed twice within baseline cooldown"
        );
    }

    function testNativeCurrencyDrip() public {
        address recipient = address(0xbeefbabe);

        vm.mockCall(
            address(0x7e1),
            abi.encodeWithSelector(ITELMint.mint.selector, recipient, nativeDripAmount),
            abi.encode()
        );
        vm.expectCall(address(0x7e1), abi.encodeWithSelector(ITELMint.mint.selector, recipient, nativeDripAmount));

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(recipient);
        stablecoinManager.drip(NATIVE, nativeDripAmount);

        assertEq(
            stablecoinManager.getLastFulfilledDripTimestamp(recipient, NATIVE),
            block.timestamp,
            "native drip should record lastFulfilledDripTimestamp"
        );
    }

    /// @dev Regression guard: on the real chain, `0x07e1` has no bytecode (the precompile is
    /// dispatched by revm before bytecode is consulted), so a Solidity typed-interface call
    /// reverts on its auto-emitted EXTCODESIZE guard. The `.call()` path in `_drip` must not
    /// revert. Intentionally does NOT `vm.mockCall` (which would intercept the call before it
    /// reaches the EVM) nor `vm.etch` at 0x07e1 - leaving `extcodesize == 0` and proving the
    /// low-level path tolerates the empty target. See PR #95.
    function testNativeCurrencyDripLowLevelCallNoEtch() public {
        address recipient = address(0xbeefbabe);

        // sanity: 0x07e1 has no code, matching real-chain state
        assertEq(address(0x7e1).code.length, 0, "TEL precompile should have no on-chain bytecode");

        vm.warp(block.timestamp + baseDripCooldown);

        vm.expectEmit(true, true, true, true);
        emit TNFaucet.Drip(recipient, NATIVE, nativeDripAmount);

        vm.prank(recipient);
        stablecoinManager.drip(NATIVE, nativeDripAmount);

        assertEq(
            stablecoinManager.getLastFulfilledDripTimestamp(recipient, NATIVE),
            block.timestamp,
            "native drip should record lastFulfilledDripTimestamp"
        );
    }

    function testNativeCurrencyDripRevertsOnLowLevelCallFailure() public {
        // forces the TEL precompile call in `_drip` to revert, exercising the
        // `LowLevelCallFailure` branch on the native path.
        address recipient = address(0xbeefbabe);
        bytes memory revertData = bytes("nope");

        vm.mockCallRevert(
            address(0x7e1),
            abi.encodeWithSelector(ITELMint.mint.selector, recipient, nativeDripAmount),
            revertData
        );

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(recipient);
        vm.expectRevert(abi.encodeWithSelector(StablecoinManager.LowLevelCallFailure.selector, revertData));
        stablecoinManager.drip(NATIVE, nativeDripAmount);
    }

    function testDripTo(address funder, address recipient, uint256 fuzzDripAmount) public {
        vm.assume(funder != address(0));
        vm.assume(recipient != address(0));
        vm.assume(funder != recipient);
        vm.assume(fuzzDripAmount > 0 && fuzzDripAmount < type(uint128).max);

        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.prank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, fuzzDripAmount);

        vm.warp(block.timestamp + baseDripCooldown);

        uint256 balBefore = currency.balanceOf(recipient);
        vm.prank(funder);
        stablecoinManager.dripTo(recipient, address(currency), fuzzDripAmount);
        uint256 balAfter = currency.balanceOf(recipient);

        assertEq(balBefore + fuzzDripAmount, balAfter, "recipient balance should increase by drip amount");

        // cooldown is set on recipient, not funder
        assertEq(
            stablecoinManager.getLastFulfilledDripTimestamp(recipient, address(currency)),
            block.timestamp,
            "recipient cooldown timestamp should be set"
        );
        assertEq(
            stablecoinManager.getLastFulfilledDripTimestamp(funder, address(currency)),
            0,
            "funder cooldown timestamp should remain unset"
        );
    }

    function testNativeCurrencyDripTo() public {
        address funder = address(0xf00d);
        address recipient = address(0xbeefbabe);

        vm.mockCall(
            address(0x7e1),
            abi.encodeWithSelector(ITELMint.mint.selector, recipient, nativeDripAmount),
            abi.encode()
        );
        vm.expectCall(address(0x7e1), abi.encodeWithSelector(ITELMint.mint.selector, recipient, nativeDripAmount));

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(funder);
        stablecoinManager.dripTo(recipient, NATIVE, nativeDripAmount);

        assertEq(
            stablecoinManager.getLastFulfilledDripTimestamp(recipient, NATIVE),
            block.timestamp,
            "native dripTo should record lastFulfilledDripTimestamp on recipient"
        );
    }

    function testDripTo_RateLimitPerRecipient() public {
        address funderA = address(0xf00d);
        address funderB = address(0xbead);
        address recipient = address(0xbeefbabe);

        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);
        vm.stopPrank();

        vm.warp(block.timestamp + baseDripCooldown);

        vm.prank(funderA);
        stablecoinManager.dripTo(recipient, address(currency), 50);

        // funder B tries to drip to same recipient immediately - reverts
        vm.prank(funderB);
        vm.expectRevert(
            abi.encodeWithSelector(TNFaucet.RequestIneligibleUntil.selector, block.timestamp + baseDripCooldown)
        );
        stablecoinManager.dripTo(recipient, address(currency), 50);
    }

    function testDripToIndependentRecipients() public {
        address funder = address(0xf00d);
        address recipientA = address(0xbeefbabe);
        address recipientB = address(0xcafebabe);

        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.startPrank(maintainer);
        stablecoinManager.UpdateXYZ(address(currency), true, 1000, 1, 100);
        vm.stopPrank();

        vm.warp(block.timestamp + baseDripCooldown);

        vm.startPrank(funder);
        stablecoinManager.dripTo(recipientA, address(currency), 50);
        stablecoinManager.dripTo(recipientB, address(currency), 50);
        vm.stopPrank();

        assertEq(currency.balanceOf(recipientA), 50, "recipientA should receive its drip");
        assertEq(currency.balanceOf(recipientB), 50, "recipientB drip should not be blocked by recipientA cooldown");
    }

    // -------------
    // support
    // -------------

    function testRescueCrypto(uint256 amount) public {
        vm.assume(amount > 0);

        Stablecoin currency = new Stablecoin();
        currency.initialize("0x", "test", 6);
        currency.grantRole(currency.MINTER_ROLE(), address(stablecoinManager));

        vm.prank(address(stablecoinManager));
        currency.mintTo(address(stablecoinManager), amount);

        assertEq(
            currency.balanceOf(address(stablecoinManager)),
            amount,
            "manager should hold minted tokens before rescue"
        );

        vm.prank(maintainer);
        stablecoinManager.rescueCrypto(IERC20(address(currency)), amount);

        assertEq(
            currency.balanceOf(address(stablecoinManager)),
            0,
            "rescue should sweep all tokens out of the manager"
        );
    }

    function testRescueCryptoNative() public {
        uint256 amount = 1 ether;
        vm.deal(address(stablecoinManager), amount);

        uint256 maintainerBalBefore = maintainer.balance;
        vm.prank(maintainer);
        stablecoinManager.rescueCrypto(IERC20(NATIVE), amount);

        assertEq(
            address(stablecoinManager).balance,
            0,
            "manager native balance should be drained by rescue"
        );
        assertEq(
            maintainer.balance,
            maintainerBalBefore + amount,
            "maintainer should receive rescued native balance"
        );
    }

    function testRescueCryptoNativeRevertsOnLowLevelCallFailure() public {
        // a maintainer with no payable receive triggers the call() failure branch
        RejectsETH rejector = new RejectsETH();
        vm.prank(admin);
        stablecoinManager.grantRole(keccak256("MAINTAINER_ROLE"), address(rejector));
        vm.deal(address(stablecoinManager), 1 ether);

        vm.prank(address(rejector));
        // RejectsETH has no payable receive/fallback so the inner call fails with empty
        // return data; LowLevelCallFailure(bytes) carries that empty payload.
        vm.expectRevert(abi.encodeWithSelector(StablecoinManager.LowLevelCallFailure.selector, bytes("")));
        stablecoinManager.rescueCrypto(IERC20(NATIVE), 1 ether);
    }

    // -------------
    // upgrade authorization
    // -------------

    function testAuthorizeUpgradeAsAdmin() public {
        StablecoinManager newImpl = new StablecoinManager();
        vm.prank(admin);
        stablecoinManager.upgradeToAndCall(address(newImpl), "");
    }

    function testAuthorizeUpgradeRevertsForNonAdmin() public {
        StablecoinManager newImpl = new StablecoinManager();
        vm.prank(maintainer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                maintainer,
                bytes32(0) // DEFAULT_ADMIN_ROLE
            )
        );
        stablecoinManager.upgradeToAndCall(address(newImpl), "");
    }
}

/// @notice Helper: contract with no payable receive/fallback so any native send fails.
contract RejectsETH { }
