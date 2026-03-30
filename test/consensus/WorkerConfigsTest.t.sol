// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
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

    function test_constructor_zeroWorkersAllowed() public {
        uint8[] memory s = new uint8[](0);
        uint64[] memory v = new uint64[](0);
        WorkerConfigs empty = new WorkerConfigs(s, v, owner);
        assertEq(empty.numWorkers(), 0);
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
}
