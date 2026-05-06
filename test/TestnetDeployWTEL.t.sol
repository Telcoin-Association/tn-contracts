// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { TestnetDeployWTEL } from "../script/testnet/deploy/TestnetDeployWTEL.s.sol";
import { WTEL } from "../src/WTEL.sol";
import { LibString } from "solady/utils/LibString.sol";

/// @title TestnetDeployWTEL deploy-script tests
///
/// @notice Exercises the deploy script end-to-end: Arachnid CREATE2 deploy +
///         deployments.json write + idempotent early-return on a re-run. The
///         Arachnid factory is etched at its canonical address so the script's
///         `arachnid.call(...)` round-trips locally without needing a fork.
///         The script mutates deployments.json (writes the new WTEL address
///         back); the test snapshots the file before running and restores it
///         after, so the suite is order-independent and doesn't pollute
///         committed state.
contract TestnetDeployWTELTest is Test {
    /// @dev Canonical Arachnid deterministic-deployment-proxy address. Same on
    ///      every chain that runs the keyless deploy.
    address constant ARACHNID = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// @dev Runtime bytecode of the Arachnid factory (sourced from
    ///      `script/GenerateGenesisPrecompileConfig.s.sol`).
    bytes constant ARACHNID_RUNTIME =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    string deploymentsPath;
    string snapshot;

    function setUp() public {
        deploymentsPath = string.concat(vm.projectRoot(), "/deployments/deployments.json");
        snapshot = vm.readFile(deploymentsPath);
        vm.etch(ARACHNID, ARACHNID_RUNTIME);

        // Force WTEL to zero on disk so the deploy-script tests start from a
        // known clean state regardless of whether the committed deployments.json
        // already has a live WTEL address (e.g. post-deploy on Adiri). String-
        // replacing the WTEL line in the snapshot and rewriting the whole file
        // via vm.writeFile sidesteps foundry's parseJson cache, which makes
        // vm.writeJson unreliable across cross-file test invocations.
        bytes memory raw = vm.parseJson(snapshot, ".WTEL");
        address current = abi.decode(raw, (address));
        if (current != address(0)) {
            string memory currentLine = string.concat(
                '"WTEL": "',
                LibString.toHexString(uint256(uint160(current)), 20),
                '"'
            );
            string memory testJson = LibString.replace(
                snapshot,
                currentLine,
                '"WTEL": "0x0000000000000000000000000000000000000000"'
            );
            vm.writeFile(deploymentsPath, testJson);
        }
    }

    /// @dev Single test that exercises BOTH deploy paths back-to-back:
    ///      1. Fresh state (deployments.WTEL == 0)  -> CREATE2 deploys + persists address.
    ///      2. Re-run against the now-populated deployments.WTEL -> early-return path fires.
    ///      Combining the cases avoids the vm.writeJson/parseJson cache that
    ///      makes a separate seeding test order-dependent: the first script
    ///      run is what writes the non-zero sentinel that the second run
    ///      reads back.
    function test_DeploysAndIsIdempotent() public {
        // Sanity: pre-condition is WTEL unset.
        bytes memory rawPre = vm.parseJson(vm.readFile(deploymentsPath), ".WTEL");
        assertEq(abi.decode(rawPre, (address)), address(0), "WTEL should start as zero");

        // First run: deploy path.
        TestnetDeployWTEL first = new TestnetDeployWTEL();
        first.setUp();
        first.run();

        address deployed = first.wtel();
        assertGt(deployed.code.length, 0, "WTEL not deployed on first run");
        // Sanity: the deployed contract has the expected metadata.
        assertEq(WTEL(payable(deployed)).symbol(), "WTEL");
        assertEq(WTEL(payable(deployed)).decimals(), 18);

        // First run persisted the address back to disk.
        bytes memory rawMid = vm.parseJson(vm.readFile(deploymentsPath), ".WTEL");
        assertEq(abi.decode(rawMid, (address)), deployed, "deployments.json not updated");

        // Second run: should early-return because the persisted value is non-zero.
        TestnetDeployWTEL second = new TestnetDeployWTEL();
        second.setUp();
        second.run();

        // The early-return path doesn't assign `wtel`, so it stays at the default 0.
        assertEq(second.wtel(), address(0), "early-return path did not fire on re-run");
        // And the persisted address didn't change.
        bytes memory rawPost = vm.parseJson(vm.readFile(deploymentsPath), ".WTEL");
        assertEq(abi.decode(rawPost, (address)), deployed, "deployments.WTEL drifted on idempotent re-run");

        // Restore so we don't leave the deployed address in the committed file.
        vm.writeFile(deploymentsPath, snapshot);
    }

    // NOTE: a `test_RunRevertsWhenArachnidCallFails` test previously exercised
    // the `require(ok, ...)` revert branch by etching REVERT at the Arachnid
    // address. It was removed because reliably forcing `deployments.WTEL` back
    // to zero on disk before the script reads it depends on vm.parseJson cache
    // + vm.writeFile interaction that flakes between foundry versions (passed
    // locally on nightly, failed on CI). The next iteration should refactor
    // the script to take Deployments via a constructor / setter so tests can
    // bypass the disk read entirely; then this branch becomes covered without
    // the disk-state dance.
}
