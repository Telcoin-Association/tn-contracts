// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { EpochGasTarget } from "src/consensus/EpochGasTarget.sol";
import { IEpochGasTarget } from "src/interfaces/IEpochGasTarget.sol";

contract EpochGasTargetTest is Test {
    EpochGasTarget public target;
    address public owner = address(0xc0ffee);
    uint64 public defaultTarget = 30_000_000;

    function setUp() public {
        target = new EpochGasTarget(defaultTarget, owner);
    }

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    function test_constructor_setsDefault() public view {
        assertEq(target.defaultTargetGas(), defaultTarget);
    }

    function test_constructor_setsOwner() public view {
        assertEq(target.owner(), owner);
    }

    function test_constructor_revertsOnZeroDefault() public {
        vm.expectRevert(abi.encodeWithSelector(IEpochGasTarget.ZeroTargetGas.selector));
        new EpochGasTarget(0, owner);
    }

    // ──────────────────────────────────────────────
    //  setDefaultTargetGas
    // ──────────────────────────────────────────────

    function test_setDefaultTargetGas_succeeds() public {
        vm.prank(owner);
        target.setDefaultTargetGas(50_000_000);
        assertEq(target.defaultTargetGas(), 50_000_000);
    }

    function test_setDefaultTargetGas_revertsNonOwner() public {
        address nonOwner = address(0xdead);
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        target.setDefaultTargetGas(50_000_000);
    }

    function test_setDefaultTargetGas_revertsZero() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IEpochGasTarget.ZeroTargetGas.selector));
        target.setDefaultTargetGas(0);
    }

    // ──────────────────────────────────────────────
    //  setWorkerTargetGas
    // ──────────────────────────────────────────────

    function test_setWorkerTargetGas_succeeds() public {
        vm.prank(owner);
        target.setWorkerTargetGas(1, 50_000_000);
        assertEq(target.getTargetGas(1), 50_000_000);
    }

    function test_setWorkerTargetGas_revertsNonOwner() public {
        address nonOwner = address(0xdead);
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        target.setWorkerTargetGas(1, 50_000_000);
    }

    function test_setWorkerTargetGas_revertsZero() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IEpochGasTarget.ZeroTargetGas.selector));
        target.setWorkerTargetGas(1, 0);
    }

    // ──────────────────────────────────────────────
    //  clearWorkerTargetGas
    // ──────────────────────────────────────────────

    function test_clearWorkerTargetGas_resetsToDefault() public {
        vm.startPrank(owner);
        target.setWorkerTargetGas(1, 50_000_000);
        assertEq(target.getTargetGas(1), 50_000_000);

        target.clearWorkerTargetGas(1);
        assertEq(target.getTargetGas(1), defaultTarget);
        vm.stopPrank();
    }

    function test_clearWorkerTargetGas_revertsNonOwner() public {
        address nonOwner = address(0xdead);
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        target.clearWorkerTargetGas(1);
    }

    // ──────────────────────────────────────────────
    //  getTargetGas
    // ──────────────────────────────────────────────

    function test_getTargetGas_returnsDefaultWhenNoOverride() public view {
        assertEq(target.getTargetGas(0), defaultTarget);
        assertEq(target.getTargetGas(1), defaultTarget);
        assertEq(target.getTargetGas(type(uint16).max), defaultTarget);
    }

    function test_getTargetGas_returnsOverrideWhenSet() public {
        vm.startPrank(owner);
        target.setWorkerTargetGas(5, 50_000_000);
        target.setWorkerTargetGas(10, 80_000_000);
        vm.stopPrank();

        assertEq(target.getTargetGas(5), 50_000_000);
        assertEq(target.getTargetGas(10), 80_000_000);
        // other workers still return default
        assertEq(target.getTargetGas(0), defaultTarget);
        assertEq(target.getTargetGas(7), defaultTarget);
    }

    function test_getTargetGas_returnsDefaultAfterClear() public {
        vm.startPrank(owner);
        target.setWorkerTargetGas(5, 50_000_000);
        assertEq(target.getTargetGas(5), 50_000_000);

        target.clearWorkerTargetGas(5);
        assertEq(target.getTargetGas(5), defaultTarget);
        vm.stopPrank();
    }

    // ──────────────────────────────────────────────
    //  Fuzz: worker target gas
    // ──────────────────────────────────────────────

    function testFuzz_workerTargetGas(uint16 workerId, uint64 targetGas) public {
        vm.assume(targetGas > 0);

        vm.prank(owner);
        target.setWorkerTargetGas(workerId, targetGas);

        assertEq(target.getTargetGas(workerId), targetGas);
    }

    function testFuzz_clearFallsBackToDefault(uint16 workerId, uint64 targetGas, uint64 newDefault) public {
        vm.assume(targetGas > 0);
        vm.assume(newDefault > 0);

        vm.startPrank(owner);
        target.setWorkerTargetGas(workerId, targetGas);
        assertEq(target.getTargetGas(workerId), targetGas);

        target.setDefaultTargetGas(newDefault);
        target.clearWorkerTargetGas(workerId);
        assertEq(target.getTargetGas(workerId), newDefault);
        vm.stopPrank();
    }

    function testFuzz_unsetWorkerReturnsDefault(uint16 workerId) public view {
        assertEq(target.getTargetGas(workerId), defaultTarget);
    }
}
