// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {GitAttestationRegistry} from "../../src/CI/GitAttestationRegistry.sol";

contract GitAttestationRegistryTest is Test {
    GitAttestationRegistry gitAttestationRegistry;
    address maintainer = address(0x123);
    address admin = address(this);

    function setUp() public {
        address[] memory maintainers = new address[](2);
        maintainers[0] = admin;
        maintainers[1] = maintainer;
        gitAttestationRegistry = new GitAttestationRegistry(4, maintainers);
    }

    function testAttestGitCommitHash() public {
        vm.startPrank(maintainer);
        bytes20 gitHash = bytes20("0xabcde");
        gitAttestationRegistry.attestGitCommitHash(gitHash, true);

        bool result = gitAttestationRegistry.gitCommitHashAttested(gitHash);
        assertTrue(result);
        vm.stopPrank();
    }

    function testSetBufferSize() public {
        vm.startPrank(admin);
        uint8 newSize = 8;
        gitAttestationRegistry.setBufferSize(newSize);

        uint8 bufferSize = gitAttestationRegistry.bufferSize();
        assertEq(bufferSize, newSize);
        vm.stopPrank();
    }

    function testResizeBuffer() public {
        vm.startPrank(maintainer);
        bytes20[] memory hashes = new bytes20[](4);
        hashes[0] = bytes20("0x11111");
        hashes[1] = bytes20("0x22222");
        hashes[2] = bytes20("0x33333");
        hashes[3] = bytes20("0x44444");

        for (uint8 i = 0; i < 4; i++) {
            gitAttestationRegistry.attestGitCommitHash(hashes[i], true);
        }

        vm.stopPrank();
        vm.startPrank(admin);

        uint8 newSize = 6;
        gitAttestationRegistry.setBufferSize(newSize);

        for (uint8 i = 0; i < 4; i++) {
            bool result = gitAttestationRegistry.gitCommitHashAttested(
                hashes[i]
            );
            assertTrue(result);
        }

        vm.stopPrank();
    }

    function testResizeBufferSmaller() public {
        vm.startPrank(maintainer);
        bytes20[] memory hashes = new bytes20[](4);
        hashes[0] = bytes20("0x11111");
        hashes[1] = bytes20("0x22222");
        hashes[2] = bytes20("0x33333");
        hashes[3] = bytes20("0x44444");

        for (uint8 i = 0; i < 4; i++) {
            gitAttestationRegistry.attestGitCommitHash(hashes[i], true);
        }

        vm.stopPrank();
        vm.startPrank(admin);

        uint8 newSize = 2;
        gitAttestationRegistry.setBufferSize(newSize);

        // Only the last two hashes should be present
        bool result1 = gitAttestationRegistry.gitCommitHashAttested(hashes[2]);
        bool result2 = gitAttestationRegistry.gitCommitHashAttested(hashes[3]);
        assertTrue(result1);
        assertTrue(result2);

        vm.stopPrank();
    }

    function testFuzzAttestAndResize(uint8 bufferSize, bytes20 gitHash) public {
        vm.assume(bufferSize > 0 && bufferSize <= 256);
        // ring buffer members initialize to bytes32(0x0) so it must be excluded. Hash collision with 0 is extremely
        // unlikely
        vm.assume(gitHash != bytes32(0x0));

        address[] memory maintainers = new address[](1);
        maintainers[0] = admin;
        GitAttestationRegistry fuzzGitAttestationRegistry = new GitAttestationRegistry(
                bufferSize,
                maintainers
            );

        vm.startPrank(admin);
        fuzzGitAttestationRegistry.attestGitCommitHash(gitHash, true);
        vm.stopPrank();

        bool result = fuzzGitAttestationRegistry.gitCommitHashAttested(gitHash);
        assertTrue(result);

        vm.startPrank(admin);
        fuzzGitAttestationRegistry.setBufferSize(bufferSize);
        vm.stopPrank();

        result = fuzzGitAttestationRegistry.gitCommitHashAttested(gitHash);
        assertTrue(result);
    }
}
