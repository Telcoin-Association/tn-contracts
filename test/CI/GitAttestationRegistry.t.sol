// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import { GitAttestationRegistry } from "../../src/CI/GitAttestationRegistry.sol";

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
            bool result = gitAttestationRegistry.gitCommitHashAttested(hashes[i]);
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
        GitAttestationRegistry fuzzGitAttestationRegistry = new GitAttestationRegistry(bufferSize, maintainers);

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

    /// @dev Fills the 4-slot buffer so `head` wraps to 0. Hashes start at 1 because the zero value
    /// means "empty".
    function _fillBuffer() internal {
        vm.startPrank(maintainer);
        for (uint8 i; i < 4; ++i) {
            gitAttestationRegistry.attestGitCommitHash(bytes20(uint160(i + 1)), true);
        }
        vm.stopPrank();
    }

    /// @notice Growing materializes the new tail slots, so the next attestation writes in bounds.
    function test_growThenAttest_doesNotPanic() public {
        _fillBuffer();

        vm.prank(admin);
        gitAttestationRegistry.setBufferSize(6);

        bytes20 fresh = bytes20(uint160(0xbeef));
        vm.prank(maintainer);
        gitAttestationRegistry.attestGitCommitHash(fresh, true);

        assertTrue(gitAttestationRegistry.gitCommitHashAttested(fresh));
    }

    /// @notice After a grow, a lookup that misses returns false; every slot in [0, bufferSize) exists.
    function test_growThenMissingLookup_returnsFalse() public {
        _fillBuffer();

        vm.prank(admin);
        gitAttestationRegistry.setBufferSize(6);

        assertFalse(gitAttestationRegistry.gitCommitHashAttested(bytes20(uint160(0xdead))));
    }

    /// @notice `ringBuffer.length` tracks `bufferSize` across a grow, so the top slot is addressable.
    function test_growMaterializesEverySlot() public {
        vm.prank(admin);
        gitAttestationRegistry.setBufferSize(6);

        assertEq(gitAttestationRegistry.bufferSize(), 6);
        (bytes20 hash_,) = gitAttestationRegistry.ringBuffer(5);
        assertEq(hash_, bytes20(0x0));
    }

    /// @notice A second grow does not revert; `head < ringBuffer.length` holds after the first.
    function test_consecutiveGrows() public {
        _fillBuffer();

        vm.startPrank(admin);
        gitAttestationRegistry.setBufferSize(6);
        gitAttestationRegistry.setBufferSize(8);
        vm.stopPrank();

        assertEq(gitAttestationRegistry.bufferSize(), 8);
    }
}
