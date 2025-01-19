// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

contract KeyTestUtils {
    function _createRandomBlsPubkey(
        uint256 seed
    ) internal pure returns (bytes memory) {
        bytes32 seedHash = keccak256(abi.encode(seed));
        return abi.encodePacked(seedHash, seedHash, seedHash);
    }

    function _createRandomBlsSig(
        uint256 seed
    ) internal pure returns (bytes memory) {
        bytes32 seedHash = keccak256(abi.encode(seed));
        return
            abi.encodePacked(
                seedHash,
                keccak256(abi.encode(seedHash)),
                bytes32(0)
            );
    }

    function _createRandomED25519Pubkey(
        uint256 seed
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(seed));
    }
}
