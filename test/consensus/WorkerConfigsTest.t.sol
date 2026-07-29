// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { WorkerConfigs } from "src/consensus/WorkerConfigs.sol";
import { SystemCallable } from "src/consensus/SystemCallable.sol";
import { IWorkerConfigs } from "src/interfaces/IWorkerConfigs.sol";

contract WorkerConfigsTest is Test {
    WorkerConfigs public wc;
    address public owner = address(0xc0ffee);

    // Default: 2 workers, both EIP-1559 strategy (0) with 30M gas target and zero data.
    uint8[] strategies;
    uint64[] values;
    uint184[] datas;

    function setUp() public {
        strategies.push(0);
        strategies.push(0);
        values.push(30_000_000);
        values.push(30_000_000);
        datas.push(0);
        datas.push(0);
        wc = new WorkerConfigs(strategies, values, datas, owner);
    }

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    function test_constructor_setsConfigs() public view {
        assertEq(wc.numWorkers(), 2);
        (uint8 s0, uint64 v0, uint184 d0) = wc.getWorkerConfig(0);
        assertEq(s0, 0);
        assertEq(v0, 30_000_000);
        assertEq(d0, 0);
        (uint8 s1, uint64 v1, uint184 d1) = wc.getWorkerConfig(1);
        assertEq(s1, 0);
        assertEq(v1, 30_000_000);
        assertEq(d1, 0);
    }

    function test_constructor_setsOwner() public view {
        assertEq(wc.owner(), owner);
    }

    function test_constructor_multipleWorkers() public {
        uint8[] memory s = new uint8[](3);
        uint64[] memory v = new uint64[](3);
        uint184[] memory d = new uint184[](3);
        s[0] = 0;
        v[0] = 100;
        d[0] = 0;
        s[1] = 1;
        v[1] = 200;
        d[1] = type(uint184).max;
        s[2] = 1;
        v[2] = 7;
        d[2] = 0xdeadbeef;
        WorkerConfigs multi = new WorkerConfigs(s, v, d, owner);
        assertEq(multi.numWorkers(), 3);
        (uint8 s2, uint64 v2, uint184 d2) = multi.getWorkerConfig(2);
        assertEq(s2, 1);
        assertEq(v2, 7);
        assertEq(d2, 0xdeadbeef);
        (,, uint184 d1) = multi.getWorkerConfig(1);
        assertEq(d1, type(uint184).max);
    }

    function test_constructor_revertsOnLengthMismatch() public {
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](1);
        uint184[] memory d = new uint184[](2);
        s[0] = 0;
        s[1] = 0;
        v[0] = 100;
        d[0] = 0;
        d[1] = 0;
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.LengthMismatch.selector));
        new WorkerConfigs(s, v, d, owner);
    }

    function test_constructor_revertsOnDataLengthMismatch() public {
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](2);
        uint184[] memory d = new uint184[](1);
        s[0] = 0;
        s[1] = 0;
        v[0] = 100;
        v[1] = 200;
        d[0] = 0;
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.LengthMismatch.selector));
        new WorkerConfigs(s, v, d, owner);
    }

    function test_constructor_zeroValueAllowed() public {
        uint8[] memory s = new uint8[](1);
        uint64[] memory v = new uint64[](1);
        uint184[] memory d = new uint184[](1);
        s[0] = 1; // Static strategy
        v[0] = 0;
        d[0] = 0;
        WorkerConfigs zeroFee = new WorkerConfigs(s, v, d, owner);
        (uint8 rs, uint64 rv, uint184 rd) = zeroFee.getWorkerConfig(0);
        assertEq(rs, 1);
        assertEq(rv, 0);
        assertEq(rd, 0);
        assertEq(zeroFee.numWorkers(), 1);
    }

    function test_constructor_revertsOnZeroWorkers() public {
        uint8[] memory s = new uint8[](0);
        uint64[] memory v = new uint64[](0);
        uint184[] memory d = new uint184[](0);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.NumWorkersBelowMinimum.selector));
        new WorkerConfigs(s, v, d, owner);
    }

    // ──────────────────────────────────────────────
    //  setNumWorkers
    // ──────────────────────────────────────────────

    function test_setNumWorkers_succeeds() public {
        // Configure worker 2 first, then expand.
        vm.startPrank(owner);
        wc.setWorkerConfig(2, 0, 50_000_000, 0);
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

    function test_setNumWorkers_revertsOnUnsetWorker() public {
        // Worker 2 has never had a config explicitly set → `_workerConfigSet[2]` is false.
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

    function test_setWorkerConfig_anyValidStrategy() public {
        vm.prank(owner);
        wc.setWorkerConfig(0, 1, 999, 0);
        (uint8 s, uint64 v, uint184 d) = wc.getWorkerConfig(0);
        assertEq(s, 1);
        assertEq(v, 999);
        assertEq(d, 0);
    }

    function test_setWorkerConfig_storesData() public {
        uint184 packed = (uint184(0xaaaa) << 64) | uint184(0xbbbb);
        vm.prank(owner);
        wc.setWorkerConfig(0, 1, 42, packed);
        (uint8 s, uint64 v, uint184 d) = wc.getWorkerConfig(0);
        assertEq(s, 1);
        assertEq(v, 42);
        assertEq(d, packed);
    }

    function test_setWorkerConfig_dataMaxBoundary() public {
        vm.prank(owner);
        wc.setWorkerConfig(0, 1, 0, type(uint184).max);
        (,, uint184 d) = wc.getWorkerConfig(0);
        assertEq(d, type(uint184).max);
    }

    function test_setWorkerConfig_invalidStrategyReverts() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.InvalidStrategy.selector, uint8(2)));
        wc.setWorkerConfig(0, 2, 30_000_000, 0);
    }

    function test_constructor_invalidStrategyReverts() public {
        uint8[] memory s = new uint8[](1);
        uint64[] memory v = new uint64[](1);
        uint184[] memory d = new uint184[](1);
        s[0] = 7;
        v[0] = 100;
        d[0] = 0;
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.InvalidStrategy.selector, uint8(7)));
        new WorkerConfigs(s, v, d, owner);
    }

    function test_setWorkerConfigsBatch_invalidStrategyReverts() public {
        uint16[] memory ids = new uint16[](2);
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](2);
        uint184[] memory d = new uint184[](2);
        ids[0] = 0;
        s[0] = 0;
        v[0] = 100;
        d[0] = 0;
        ids[1] = 1;
        s[1] = 9;
        v[1] = 200;
        d[1] = 0;

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.InvalidStrategy.selector, uint8(9)));
        wc.setWorkerConfigsBatch(ids, s, v, d);
    }

    function test_maxStrategy_constant() public view {
        assertEq(wc.MAX_STRATEGY(), 1);
    }

    function test_setWorkerConfig_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(1, 0, 50_000_000, 12_345);
        wc.setWorkerConfig(1, 0, 50_000_000, 12_345);
    }

    function test_setWorkerConfig_zeroValueAllowed() public {
        vm.prank(owner);
        wc.setWorkerConfig(0, 1, 0, 0);
        (uint8 s, uint64 v, uint184 d) = wc.getWorkerConfig(0);
        assertEq(s, 1);
        assertEq(v, 0);
        assertEq(d, 0);
    }

    function test_setWorkerConfig_revertsNonOwner() public {
        address nonOwner = address(0xdead);
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        wc.setWorkerConfig(0, 0, 50_000_000, 0);
    }

    function test_setWorkerConfig_beyondNumWorkers() public {
        // Allowed: config for worker 100 even though numWorkers=2.
        vm.prank(owner);
        wc.setWorkerConfig(100, 1, 500, 0xc0de);
        (uint8 s, uint64 v, uint184 d) = wc.getWorkerConfig(100);
        assertEq(s, 1);
        assertEq(v, 500);
        assertEq(d, 0xc0de);
    }

    // ──────────────────────────────────────────────
    //  getWorkerConfig
    // ──────────────────────────────────────────────

    function test_getWorkerConfig_returnsStoredConfig() public view {
        (uint8 s, uint64 v, uint184 d) = wc.getWorkerConfig(0);
        assertEq(s, 0);
        assertEq(v, 30_000_000);
        assertEq(d, 0);
    }

    function test_getWorkerConfig_unsetReturnsZero() public view {
        (uint8 s, uint64 v, uint184 d) = wc.getWorkerConfig(999);
        assertEq(s, 0);
        assertEq(v, 0);
        assertEq(d, 0);
    }

    function test_getAllWorkerConfigs_returnsAll() public {
        // At construction: 2 workers, both EIP-1559 with 30M target and zero data.
        (uint16 count, uint8[] memory s, uint64[] memory v, uint184[] memory d) = wc.getAllWorkerConfigs();
        assertEq(count, 2);
        assertEq(s.length, 2);
        assertEq(v.length, 2);
        assertEq(d.length, 2);
        assertEq(s[0], 0);
        assertEq(v[0], 30_000_000);
        assertEq(d[0], 0);
        assertEq(s[1], 0);
        assertEq(v[1], 30_000_000);
        assertEq(d[1], 0);

        // After mutating worker 0 the batch view reflects the change.
        vm.prank(owner);
        wc.setWorkerConfig(0, 1, 999, 0xfeed);
        (count, s, v, d) = wc.getAllWorkerConfigs();
        assertEq(count, 2);
        assertEq(s[0], 1);
        assertEq(v[0], 999);
        assertEq(d[0], 0xfeed);
        assertEq(s[1], 0);
        assertEq(v[1], 30_000_000);
        assertEq(d[1], 0);
    }

    function test_getAllWorkerConfigs_doesNotIncludeBeyondNumWorkers() public {
        // setWorkerConfig allows writing to ids beyond numWorkers, but getAllWorkerConfigs
        // should only surface the contiguous `0 .. numWorkers-1` slice.
        vm.prank(owner);
        wc.setWorkerConfig(100, 1, 500, 0xc0de);
        (uint16 count, uint8[] memory s, uint64[] memory v, uint184[] memory d) = wc.getAllWorkerConfigs();
        assertEq(count, 2);
        assertEq(s.length, 2);
        assertEq(v.length, 2);
        assertEq(d.length, 2);
    }

    // ──────────────────────────────────────────────
    //  Fuzz
    // ──────────────────────────────────────────────

    function testFuzz_workerConfig(uint16 workerId, uint8 strategy, uint64 value, uint184 data) public {
        vm.assume(strategy <= wc.MAX_STRATEGY());

        vm.prank(owner);
        wc.setWorkerConfig(workerId, strategy, value, data);

        (uint8 s, uint64 v, uint184 d) = wc.getWorkerConfig(workerId);
        assertEq(s, strategy);
        assertEq(v, value);
        assertEq(d, data);
    }

    function testFuzz_coverageCheck(uint8 count) public {
        vm.assume(count > 0 && count <= 20);

        uint8[] memory s = new uint8[](count);
        uint64[] memory v = new uint64[](count);
        uint184[] memory d = new uint184[](count);
        for (uint8 i = 0; i < count; i++) {
            s[i] = i % 2; // alternate the two valid strategy ids
            v[i] = uint64(i);
            d[i] = uint184(i) * 1000;
        }
        WorkerConfigs fresh = new WorkerConfigs(s, v, d, owner);
        assertEq(fresh.numWorkers(), count);

        for (uint16 i = 0; i < count; i++) {
            (uint8 rs, uint64 rv, uint184 rd) = fresh.getWorkerConfig(i);
            assertEq(rs, uint8(i % 2));
            assertEq(rv, uint64(i));
            assertEq(rd, uint184(i) * 1000);
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
        (uint8 s1, uint64 v1, uint184 d1) = wc.getWorkerConfig(1);
        assertEq(s1, 0);
        assertEq(v1, 30_000_000);
        assertEq(d1, 0);

        // Expand back - worker 1's stale config satisfies the coverage check.
        wc.setNumWorkers(2);
        assertEq(wc.numWorkers(), 2);
        vm.stopPrank();
    }

    function test_setWorkerConfig_overwrite() public {
        vm.startPrank(owner);
        wc.setWorkerConfig(0, 1, 100, 0xaa);
        (uint8 s, uint64 v, uint184 d) = wc.getWorkerConfig(0);
        assertEq(s, 1);
        assertEq(v, 100);
        assertEq(d, 0xaa);

        // Overwrite with different values, including data.
        wc.setWorkerConfig(0, 0, 200, 0xbb);
        (s, v, d) = wc.getWorkerConfig(0);
        assertEq(s, 0);
        assertEq(v, 200);
        assertEq(d, 0xbb);
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
        uint184[] memory d = new uint184[](2);
        s[0] = 0;
        v[0] = 100;
        d[0] = 0xa;
        s[1] = 1;
        v[1] = 200;
        d[1] = 0xb;

        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(0, 0, 100, 0xa);
        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(1, 1, 200, 0xb);
        new WorkerConfigs(s, v, d, owner);
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
        uint184[] memory d = new uint184[](3);
        ids[0] = 0;
        s[0] = 1;
        v[0] = 100;
        d[0] = 0xaa;
        ids[1] = 1;
        s[1] = 1;
        v[1] = 200;
        d[1] = 0xbb;
        ids[2] = 5;
        s[2] = 0;
        v[2] = 300;
        d[2] = 0xcc;

        vm.prank(owner);
        wc.setWorkerConfigsBatch(ids, s, v, d);

        (uint8 s0, uint64 v0, uint184 d0) = wc.getWorkerConfig(0);
        assertEq(s0, 1);
        assertEq(v0, 100);
        assertEq(d0, 0xaa);
        (uint8 s1, uint64 v1, uint184 d1) = wc.getWorkerConfig(1);
        assertEq(s1, 1);
        assertEq(v1, 200);
        assertEq(d1, 0xbb);
        (uint8 s5, uint64 v5, uint184 d5) = wc.getWorkerConfig(5);
        assertEq(s5, 0);
        assertEq(v5, 300);
        assertEq(d5, 0xcc);
    }

    function test_setWorkerConfigsBatch_emitsEvents() public {
        uint16[] memory ids = new uint16[](2);
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](2);
        uint184[] memory d = new uint184[](2);
        ids[0] = 0;
        s[0] = 1;
        v[0] = 100;
        d[0] = 0xaa;
        ids[1] = 1;
        s[1] = 0;
        v[1] = 200;
        d[1] = 0xbb;

        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(0, 1, 100, 0xaa);
        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(1, 0, 200, 0xbb);
        wc.setWorkerConfigsBatch(ids, s, v, d);
    }

    function test_setWorkerConfigsBatch_revertsOnLengthMismatch() public {
        uint16[] memory ids = new uint16[](2);
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](1);
        uint184[] memory d = new uint184[](2);
        ids[0] = 0;
        ids[1] = 1;
        s[0] = 0;
        s[1] = 0;
        v[0] = 100;
        d[0] = 0;
        d[1] = 0;

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.LengthMismatch.selector));
        wc.setWorkerConfigsBatch(ids, s, v, d);
    }

    function test_setWorkerConfigsBatch_revertsOnDataLengthMismatch() public {
        uint16[] memory ids = new uint16[](2);
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](2);
        uint184[] memory d = new uint184[](1);
        ids[0] = 0;
        ids[1] = 1;
        s[0] = 0;
        s[1] = 0;
        v[0] = 100;
        v[1] = 200;
        d[0] = 0;

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.LengthMismatch.selector));
        wc.setWorkerConfigsBatch(ids, s, v, d);
    }

    function test_setWorkerConfigsBatch_zeroValueAllowed() public {
        uint16[] memory ids = new uint16[](2);
        uint8[] memory s = new uint8[](2);
        uint64[] memory v = new uint64[](2);
        uint184[] memory d = new uint184[](2);
        ids[0] = 0;
        s[0] = 0;
        v[0] = 100;
        d[0] = 0;
        ids[1] = 1;
        s[1] = 1;
        v[1] = 0;
        d[1] = 0;

        vm.prank(owner);
        wc.setWorkerConfigsBatch(ids, s, v, d);

        (uint8 s1, uint64 v1, uint184 d1) = wc.getWorkerConfig(1);
        assertEq(s1, 1);
        assertEq(v1, 0);
        assertEq(d1, 0);
    }

    function test_setWorkerConfigsBatch_revertsNonOwner() public {
        uint16[] memory ids = new uint16[](1);
        uint8[] memory s = new uint8[](1);
        uint64[] memory v = new uint64[](1);
        uint184[] memory d = new uint184[](1);
        ids[0] = 0;
        s[0] = 0;
        v[0] = 100;
        d[0] = 0;

        address nonOwner = address(0xdead);
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        wc.setWorkerConfigsBatch(ids, s, v, d);
    }

    function test_setWorkerConfigsBatch_empty() public {
        uint16[] memory ids = new uint16[](0);
        uint8[] memory s = new uint8[](0);
        uint64[] memory v = new uint64[](0);
        uint184[] memory d = new uint184[](0);

        vm.prank(owner);
        wc.setWorkerConfigsBatch(ids, s, v, d);
        // No revert - empty batch is a no-op.
    }

    // ──────────────────────────────────────────────
    //  setWorkerConfigsData (system call)
    // ──────────────────────────────────────────────

    function test_setWorkerConfigsData_updatesDataOnly() public {
        uint16[] memory ids = new uint16[](2);
        uint184[] memory d = new uint184[](2);
        ids[0] = 0;
        ids[1] = 1;
        d[0] = 0xdeadbeef;
        d[1] = type(uint184).max;

        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(0, 0, 30_000_000, 0xdeadbeef);
        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(1, 0, 30_000_000, type(uint184).max);
        vm.prank(wc.SYSTEM_ADDRESS());
        wc.setWorkerConfigsData(ids, d);

        // data updated; strategy and value preserved
        (uint8 s0, uint64 v0, uint184 d0) = wc.getWorkerConfig(0);
        assertEq(s0, 0);
        assertEq(v0, 30_000_000);
        assertEq(d0, 0xdeadbeef);
        (uint8 s1, uint64 v1, uint184 d1) = wc.getWorkerConfig(1);
        assertEq(s1, 0);
        assertEq(v1, 30_000_000);
        assertEq(d1, type(uint184).max);
    }

    function test_setWorkerConfigsData_revertsForNonSystemCaller() public {
        uint16[] memory ids = new uint16[](1);
        uint184[] memory d = new uint184[](1);
        ids[0] = 0;
        d[0] = 1;

        // the owner is not the system address either
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(SystemCallable.OnlySystemCall.selector, owner));
        wc.setWorkerConfigsData(ids, d);

        address rando = address(0xbeef);
        vm.prank(rando);
        vm.expectRevert(abi.encodeWithSelector(SystemCallable.OnlySystemCall.selector, rando));
        wc.setWorkerConfigsData(ids, d);
    }

    function test_setWorkerConfigsData_revertsOnLengthMismatch() public {
        uint16[] memory ids = new uint16[](2);
        uint184[] memory d = new uint184[](1);
        ids[0] = 0;
        ids[1] = 1;
        d[0] = 1;

        vm.prank(wc.SYSTEM_ADDRESS());
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.LengthMismatch.selector));
        wc.setWorkerConfigsData(ids, d);
    }

    function test_setWorkerConfigsData_revertsOnUnconfiguredWorker() public {
        uint16[] memory ids = new uint16[](1);
        uint184[] memory d = new uint184[](1);
        ids[0] = 5; // never configured
        d[0] = 1;

        vm.prank(wc.SYSTEM_ADDRESS());
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.MissingWorkerConfig.selector, 5));
        wc.setWorkerConfigsData(ids, d);
    }

    function test_setWorkerConfigsData_cannotFabricateCoverageForSetNumWorkers() public {
        // a system call must not be able to mark worker 2 as configured
        uint16[] memory ids = new uint16[](1);
        uint184[] memory d = new uint184[](1);
        ids[0] = 2;
        d[0] = 1;

        vm.prank(wc.SYSTEM_ADDRESS());
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.MissingWorkerConfig.selector, 2));
        wc.setWorkerConfigsData(ids, d);

        // so growing the worker set still requires governance to configure worker 2 first
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.MissingWorkerConfig.selector, 2));
        wc.setNumWorkers(3);
    }

    // ──────────────────────────────────────────────
    //  setWorkerConfigsValue (system call)
    // ──────────────────────────────────────────────

    function test_setWorkerConfigsValue_updatesValueOnly() public {
        // give worker 1 distinct data first so preservation is observable
        vm.prank(owner);
        wc.setWorkerConfig(1, 1, 777, 0xabcd);

        uint16[] memory ids = new uint16[](2);
        uint64[] memory v = new uint64[](2);
        ids[0] = 0;
        ids[1] = 1;
        v[0] = 45_000_000;
        v[1] = 999;

        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(0, 0, 45_000_000, 0);
        vm.expectEmit(true, false, false, true);
        emit IWorkerConfigs.WorkerConfigUpdated(1, 1, 999, 0xabcd);
        vm.prank(wc.SYSTEM_ADDRESS());
        wc.setWorkerConfigsValue(ids, v);

        // value updated; strategy and data preserved
        (uint8 s0, uint64 v0, uint184 d0) = wc.getWorkerConfig(0);
        assertEq(s0, 0);
        assertEq(v0, 45_000_000);
        assertEq(d0, 0);
        (uint8 s1, uint64 v1, uint184 d1) = wc.getWorkerConfig(1);
        assertEq(s1, 1);
        assertEq(v1, 999);
        assertEq(d1, 0xabcd);
    }

    function test_setWorkerConfigsValue_revertsForNonSystemCaller() public {
        uint16[] memory ids = new uint16[](1);
        uint64[] memory v = new uint64[](1);
        ids[0] = 0;
        v[0] = 1;

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(SystemCallable.OnlySystemCall.selector, owner));
        wc.setWorkerConfigsValue(ids, v);
    }

    function test_setWorkerConfigsValue_revertsOnLengthMismatch() public {
        uint16[] memory ids = new uint16[](1);
        uint64[] memory v = new uint64[](2);
        ids[0] = 0;
        v[0] = 1;
        v[1] = 2;

        vm.prank(wc.SYSTEM_ADDRESS());
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.LengthMismatch.selector));
        wc.setWorkerConfigsValue(ids, v);
    }

    function test_setWorkerConfigsValue_revertsOnUnconfiguredWorker() public {
        uint16[] memory ids = new uint16[](1);
        uint64[] memory v = new uint64[](1);
        ids[0] = 9;
        v[0] = 1;

        vm.prank(wc.SYSTEM_ADDRESS());
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.MissingWorkerConfig.selector, 9));
        wc.setWorkerConfigsValue(ids, v);
    }

    // ──────────────────────────────────────────────
    //  setMaxStrategy
    // ──────────────────────────────────────────────

    function test_setMaxStrategy_raisesCeiling() public {
        assertEq(wc.MAX_STRATEGY(), 1);

        // strategy 2 is rejected under the current ceiling
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.InvalidStrategy.selector, 2));
        wc.setWorkerConfig(0, 2, 100, 0);

        vm.expectEmit(false, false, false, true);
        emit IWorkerConfigs.MaxStrategyUpdated(1, 2);
        vm.prank(owner);
        wc.setMaxStrategy(2);
        assertEq(wc.MAX_STRATEGY(), 2);

        // strategy 2 is now accepted, strategy 3 still rejected
        vm.prank(owner);
        wc.setWorkerConfig(0, 2, 100, 0);
        (uint8 s0,,) = wc.getWorkerConfig(0);
        assertEq(s0, 2);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.InvalidStrategy.selector, 3));
        wc.setWorkerConfig(1, 3, 100, 0);
    }

    function test_setMaxStrategy_revertsForNonOwner() public {
        address rando = address(0xbeef);
        vm.prank(rando);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, rando));
        wc.setMaxStrategy(2);

        // the system address holds no special authority over the ceiling
        address sys = wc.SYSTEM_ADDRESS();
        vm.prank(sys);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, sys));
        wc.setMaxStrategy(2);
    }

    function test_setMaxStrategy_revertsWhenNotIncreasing() public {
        // equal to the current ceiling
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.InvalidStrategy.selector, 1));
        wc.setMaxStrategy(1);

        // below the current ceiling after a raise
        vm.prank(owner);
        wc.setMaxStrategy(3);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IWorkerConfigs.InvalidStrategy.selector, 2));
        wc.setMaxStrategy(2);
    }
}
