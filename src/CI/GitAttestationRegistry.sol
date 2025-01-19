// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @dev Smart contract used to facilitate trusted CI runs across the Telcoin team
/// @notice Facilitates Telcoin's distributed source control mechanisms by bypassing the
/// sluggish Github CI workflow which takes ages to build/test remotely by allowing a limited
/// set of private key owners to attest to CI correctness locally and register git commit
/// hashes that pass CI checks in an onchain registry serving as single source of truth
contract GitAttestationRegistry is AccessControl {
    struct GitCommitHashRecord {
        bytes20 gitCommitHash;
        bool ciPassed;
    }

    event GitHashAttested(bytes20 gitCommitHash, bool ciPassed);
    event BufferSizeChanged(uint8 newSize);

    GitCommitHashRecord[] public ringBuffer;
    bytes32 public constant MAINTAINER_ROLE = keccak256("MAINTAINER_ROLE");
    uint8 public bufferSize;
    uint8 public head;

    constructor(uint8 bufferSize_, address[] memory maintainers_) {
        require(bufferSize_ > 0, "Buffer size must be greater than 0");

        bufferSize = bufferSize_;
        for (uint256 i; i < bufferSize_; ++i) {
            ringBuffer.push(GitCommitHashRecord(bytes20(0x0), false));
        }

        _grantRole(DEFAULT_ADMIN_ROLE, maintainers_[0]);
        for (uint256 i; i < maintainers_.length; ++i) {
            _grantRole(MAINTAINER_ROLE, maintainers_[i]);
        }
    }

    function attestGitCommitHash(
        bytes20 gitCommitHash,
        bool ciPassed
    ) external onlyRole(MAINTAINER_ROLE) {
        ringBuffer[head] = GitCommitHashRecord(gitCommitHash, ciPassed);
        head = (head + 1) % bufferSize;

        emit GitHashAttested(gitCommitHash, ciPassed);
    }

    function gitCommitHashAttested(
        bytes20 gitCommitHash
    ) external view returns (bool) {
        for (uint8 i = 0; i < bufferSize; i++) {
            if (ringBuffer[i].gitCommitHash == gitCommitHash) {
                return ringBuffer[i].ciPassed;
            }
        }
        return false;
    }

    function setBufferSize(
        uint8 newSize
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newSize > 0, "Buffer size cannot be 0");

        GitCommitHashRecord[] memory newBuffer = new GitCommitHashRecord[](
            newSize
        );
        uint8 itemsToCopy = bufferSize < newSize ? bufferSize : newSize;
        // calculate start index of oldest element in ring buffer
        uint8 start = (head + (bufferSize - itemsToCopy)) % bufferSize;

        for (uint8 i; i < itemsToCopy; ++i) {
            newBuffer[i] = ringBuffer[(start + i) % bufferSize];
        }

        // solidity does not support writing memory arrays directly to storage
        delete ringBuffer;
        for (uint8 i; i < itemsToCopy; ++i) {
            ringBuffer.push(newBuffer[i]);
        }

        bufferSize = newSize;
        head = itemsToCopy % newSize;

        emit BufferSizeChanged(newSize);
    }
}
