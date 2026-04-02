// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {WorkerConfigs} from "src/consensus/WorkerConfigs.sol";
import {IWorkerConfigs} from "src/interfaces/IWorkerConfigs.sol";

contract WorkerConfigsTest is Test {
    WorkerConfigs public wc;
    address public owner = address(0xc0ffee);

    // Default: 2 workers, both EIP-1559 strategy (0) with 30M gas target.
    uint8[] strategies;
    uint64[] values;

    function setUp() public {
        strategies.push(0);
        strategies.push(0);
        values.push(30_000_000);
        values.push(30_000_000);
        wc = new WorkerConfigs(strategies, values, owner);
    }

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    function test_constructor_setsConfigs() public view {
        assertEq(wc.numWorkers(), 2);
        (uint8 s0, uint64 v0) = wc.getWorkerConfig(0);
        assertEq(s0, 0);
        assertEq(v0, 30_000_000);
        (uint8 s1, uint64 v1) = wc.getWorkerConfig(1);
        assertEq(s1, 0);
        assertEq(v1, 30_000_000);
    }

    function test_constructor_setsOwner() public view {
        assertEq(wc.owner(), owner);
    }

    function test_constructor_multipleWorkers() public {
        uint8[] memory s = new uint8[](3);
        uint64[] memory v = new uint64[](3);
        s[0] = 0; v[0] = 100;
        s[1] = 1; v[1] = 200;
        s[2] = 255; v[2] = 7;
        WorkerConfigs multi = new WorkerConfigs(s, v, owner);
        assertEq(multi.numWorkers(), 3);
        (uint8 s2, uint64 v2) = multi.getWorkerConfig(2);
        assertEq(s2, 255);
        assertEq(v2, 7);
    }

    function test_constructor_revertsOnLengthMismatch() public {
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](1);
        s[0] = 0; s[1] = 0;
        v[0] = 100;
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.LengthMismatch.selector));
        new WorkerConfigs(s, v, owner);
    }

    function test_constructor_revertsOnValueBelowMinGas() public {
        uint8[] memory s = new uint8[](1);
        uint64[] memory v = new uint64[](1);
        s[0] = 0;
        v[0] = 6;
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.ValueBelowMinGas.selector, uint64(6)));
        new WorkerConfigs(s, v, owner);
    }

    function test_constructor_revertsOnZeroWorkers() public {
        uint8[] memory s = new uint8[](0);
        uint64[] memory v = new uint64[](0);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.NumWorkersBelowMinimum.selector));
        new WorkerConfigs(s, v, owner);
    }

    // ──────────────────────────────────────────────
    //  setNumWorkers
    // ──────────────────────────────────────────────

    function test_setNumWorkers_succeeds() public {
        // Configure worker 2 first, then expand.
        vm.startPrank(owner);
        wc.setWorkerConfig(2, 0, 50_000_000);
        wc.setNumWorkers(3);
        vm.stopPrank();
        assertEq(wc.numWorkers(), 3);
    }

    function test_setNumWorkers_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit IWorkerConfigs.NumWorkersUpdated(2, 1);
        wc.setNumWorkers(1);
    }

    function test_setNumWorkers_revertsOnMissingConfig() public {
        // Worker 2 is not configured → value=0 < MIN_GAS.
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.MissingWorkerConfig.selector, uint16(2)));
        wc.setNumWorkers(3);
    }

    function test_setNumWorkers_revertsNonOwner() public {
        address nonOwner = address(0xdead);
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        wc.setNumWorkers(1);
    }

    // ──────────────────────────────────────────────
    //  setWorkerConfig
    // ──────────────────────────────────────────────

    function test_setWorkerConfig_anyStrategy() public {
        vm.prank(owner);
        wc.setWorkerConfig(0, 42, 999);
        (uint8 s, uint64 v) = wc.getWorkerConfig(0);
        assertEq(s, 42);
        assertEq(v, 999);
    }

    function test_setWorkerConfig_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(1, 0, 50_000_000);
        wc.setWorkerConfig(1, 0, 50_000_000);
    }

    function test_setWorkerConfig_revertsOnValueBelowMinGas() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.ValueBelowMinGas.selector, uint64(6)));
        wc.setWorkerConfig(0, 0, 6);
    }

    function test_setWorkerConfig_revertsNonOwner() public {
        address nonOwner = address(0xdead);
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        wc.setWorkerConfig(0, 0, 50_000_000);
    }

    function test_setWorkerConfig_beyondNumWorkers() public {
        // Allowed: config for worker 100 even though numWorkers=2.
        vm.prank(owner);
        wc.setWorkerConfig(100, 1, 500);
        (uint8 s, uint64 v) = wc.getWorkerConfig(100);
        assertEq(s, 1);
        assertEq(v, 500);
    }

    // ──────────────────────────────────────────────
    //  getWorkerConfig
    // ──────────────────────────────────────────────

    function test_getWorkerConfig_returnsStoredConfig() public view {
        (uint8 s, uint64 v) = wc.getWorkerConfig(0);
        assertEq(s, 0);
        assertEq(v, 30_000_000);
    }

    function test_getWorkerConfig_unsetReturnsZero() public view {
        (uint8 s, uint64 v) = wc.getWorkerConfig(999);
        assertEq(s, 0);
        assertEq(v, 0);
    }

    // ──────────────────────────────────────────────
    //  MIN_GAS boundary
    // ──────────────────────────────────────────────

    function test_minGas_exactly7Allowed() public {
        vm.prank(owner);
        wc.setWorkerConfig(0, 0, 7);
        (uint8 s, uint64 v) = wc.getWorkerConfig(0);
        assertEq(s, 0);
        assertEq(v, 7);
    }

    function test_minGas_6Reverts() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.ValueBelowMinGas.selector, uint64(6)));
        wc.setWorkerConfig(0, 0, 6);
    }

    function test_minGas_constant() public view {
        assertEq(wc.MIN_GAS(), 7);
    }

    // ──────────────────────────────────────────────
    //  Fuzz
    // ──────────────────────────────────────────────

    function testFuzz_workerConfig(uint16 workerId, uint8 strategy, uint64 value) public {
        vm.assume(value >= 7);

        vm.prank(owner);
        wc.setWorkerConfig(workerId, strategy, value);

        (uint8 s, uint64 v) = wc.getWorkerConfig(workerId);
        assertEq(s, strategy);
        assertEq(v, value);
    }

    function testFuzz_coverageCheck(uint8 count) public {
        vm.assume(count > 0 && count <= 20);

        uint8[] memory s = new uint8[](count);
        uint64[] memory v = new uint64[](count);
        for (uint8 i = 0; i < count; i++) {
            s[i] = i;
            v[i] = uint64(i) + 7;
        }
        WorkerConfigs fresh = new WorkerConfigs(s, v, owner);
        assertEq(fresh.numWorkers(), count);

        for (uint16 i = 0; i < count; i++) {
            (uint8 rs, uint64 rv) = fresh.getWorkerConfig(i);
            assertEq(rs, uint8(i));
            assertEq(rv, uint64(i) + 7);
        }
    }

    // ──────────────────────────────────────────────
    //  Additional coverage
    // ──────────────────────────────────────────────

    function test_setNumWorkers_revertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.NumWorkersBelowMinimum.selector));
        wc.setNumWorkers(0);
    }

    function test_setNumWorkers_shrinkThenExpand() public {
        // Shrink 2 → 1, then expand back to 2. Stale config for worker 1 should persist.
        vm.startPrank(owner);
        wc.setNumWorkers(1);
        assertEq(wc.numWorkers(), 1);

        // Worker 1's config is still in storage even though numWorkers is 1.
        (uint8 s1, uint64 v1) = wc.getWorkerConfig(1);
        assertEq(s1, 0);
        assertEq(v1, 30_000_000);

        // Expand back — worker 1's stale config satisfies the coverage check.
        wc.setNumWorkers(2);
        assertEq(wc.numWorkers(), 2);
        vm.stopPrank();
    }

    function test_setWorkerConfig_overwrite() public {
        vm.startPrank(owner);
        wc.setWorkerConfig(0, 1, 100);
        (uint8 s, uint64 v) = wc.getWorkerConfig(0);
        assertEq(s, 1);
        assertEq(v, 100);

        // Overwrite with different values.
        wc.setWorkerConfig(0, 2, 200);
        (s, v) = wc.getWorkerConfig(0);
        assertEq(s, 2);
        assertEq(v, 200);
        vm.stopPrank();
    }

    function test_setNumWorkers_revertsOnSameValue() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.NumWorkersUnchanged.selector));
        wc.setNumWorkers(2);
    }

    function test_constructor_emitsEvents() public {
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](2);
        s[0] = 0; v[0] = 100;
        s[1] = 1; v[1] = 200;

        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(0, 0, 100);
        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(1, 1, 200);
        new WorkerConfigs(s, v, owner);
    }

    // ──────────────────────────────────────────────
    //  Ownable2Step
    // ──────────────────────────────────────────────

    function test_transferOwnership_twoStep() public {
        address newOwner = address(0xbeef);
        vm.prank(owner);
        wc.transferOwnership(newOwner);
        assertEq(wc.pendingOwner(), newOwner);
        // Owner hasn't changed yet.
        assertEq(wc.owner(), owner);

        vm.prank(newOwner);
        wc.acceptOwnership();
        assertEq(wc.owner(), newOwner);
        assertEq(wc.pendingOwner(), address(0));
    }

    function test_transferOwnership_onlyPendingCanAccept() public {
        address newOwner = address(0xbeef);
        address rando = address(0xdead);
        vm.prank(owner);
        wc.transferOwnership(newOwner);

        vm.prank(rando);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, rando));
        wc.acceptOwnership();
    }

    function test_renounceOwnership() public {
        vm.prank(owner);
        wc.renounceOwnership();
        assertEq(wc.owner(), address(0));
    }

    // ──────────────────────────────────────────────
    //  setWorkerConfigsBatch
    // ──────────────────────────────────────────────

    function test_setWorkerConfigsBatch_succeeds() public {
        uint16[] memory ids = new uint16[](3);
        uint8[] memory s = new uint8[](3);
        uint64[] memory v = new uint64[](3);
        ids[0] = 0; s[0] = 1; v[0] = 100;
        ids[1] = 1; s[1] = 2; v[1] = 200;
        ids[2] = 5; s[2] = 0; v[2] = 300;

        vm.prank(owner);
        wc.setWorkerConfigsBatch(ids, s, v);

        (uint8 s0, uint64 v0) = wc.getWorkerConfig(0);
        assertEq(s0, 1);
        assertEq(v0, 100);
        (uint8 s1, uint64 v1) = wc.getWorkerConfig(1);
        assertEq(s1, 2);
        assertEq(v1, 200);
        (uint8 s5, uint64 v5) = wc.getWorkerConfig(5);
        assertEq(s5, 0);
        assertEq(v5, 300);
    }

    function test_setWorkerConfigsBatch_emitsEvents() public {
        uint16[] memory ids = new uint16[](2);
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](2);
        ids[0] = 0; s[0] = 1; v[0] = 100;
        ids[1] = 1; s[1] = 2; v[1] = 200;

        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(0, 1, 100);
        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(1, 2, 200);
        wc.setWorkerConfigsBatch(ids, s, v);
    }

    function test_setWorkerConfigsBatch_revertsOnLengthMismatch() public {
        uint16[] memory ids = new uint16[](2);
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](1);
        ids[0] = 0; ids[1] = 1;
        s[0] = 0; s[1] = 0;
        v[0] = 100;

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.LengthMismatch.selector));
        wc.setWorkerConfigsBatch(ids, s, v);
    }

    function test_setWorkerConfigsBatch_revertsOnValueBelowMinGas() public {
        uint16[] memory ids = new uint16[](2);
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](2);
        ids[0] = 0; s[0] = 0; v[0] = 100;
        ids[1] = 1; s[1] = 0; v[1] = 6; // below MIN_GAS

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.ValueBelowMinGas.selector, uint64(6)));
        wc.setWorkerConfigsBatch(ids, s, v);
    }

    function test_setWorkerConfigsBatch_revertsNonOwner() public {
        uint16[] memory ids = new uint16[](1);
        uint8[] memory s = new uint8[](1);
        uint64[] memory v = new uint64[](1);
        ids[0] = 0; s[0] = 0; v[0] = 100;

        address nonOwner = address(0xdead);
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        wc.setWorkerConfigsBatch(ids, s, v);
    }

    function test_setWorkerConfigsBatch_empty() public {
        uint16[] memory ids = new uint16[](0);
        uint8[] memory s = new uint8[](0);
        uint64[] memory v = new uint64[](0);

        vm.prank(owner);
        wc.setWorkerConfigsBatch(ids, s, v);
        // No revert — empty batch is a no-op.
    }
}
