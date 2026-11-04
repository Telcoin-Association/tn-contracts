// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";

/// @title Genesis Replay
/// @notice Replays a contract's original Ethereum deployment (its creation code sent through the
/// deterministic deployer that created it) on a fresh test chain, and reports what the
/// constructor stored. Comparing the result with the genesis etch proves the etch reproduces
/// the deployed state: the same runtime bytes at the same address, and exactly the storage
/// the generator writes
abstract contract GenesisReplay is Test {
    address internal constant ARACHNID = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// @dev Runtime code of the Arachnid deterministic deployment proxy, identical on every chain
    bytes internal constant ARACHNID_RUNTIME =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    string internal constant CANONICAL_INITCODE_DIR = "/deployments/canonical-initcode/";

    /// @dev Reads a vendored creation-code file and asserts its hash
    function _readInitcode(string memory name, bytes32 expectedHash) internal view returns (bytes memory initcode) {
        initcode = vm.parseBytes(vm.readFile(string.concat(vm.projectRoot(), CANONICAL_INITCODE_DIR, name, ".hex")));
        assertEq(keccak256(initcode), expectedHash, string.concat(name, ": vendored initcode hash mismatch"));
    }

    /// @dev Sends `salt ++ initcode` to a deterministic deployer (Arachnid proxy or Safe Singleton
    /// Factory, which share the calling convention) and returns the address it created
    function _deployThrough(address deployer, bytes32 salt, bytes memory initcode) internal returns (address created) {
        (bool ok, bytes memory ret) = deployer.call(bytes.concat(salt, initcode));
        require(ok && ret.length == 20, "deterministic deployment failed");
        created = address(bytes20(ret));
    }

    /// @dev Deploys through `deployer` while recording state, returning the created address and
    /// the final value of every storage slot the deployment wrote on `account`
    function _deployRecordingStorage(
        address deployer,
        bytes32 salt,
        bytes memory initcode,
        address account
    )
        internal
        returns (address created, bytes32[] memory slots, bytes32[] memory values)
    {
        vm.startStateDiffRecording();
        created = _deployThrough(deployer, salt, initcode);
        (slots, values) = _storageWrites(vm.stopAndReturnStateDiff(), account);
    }

    /// @dev Distinct slots written on `account`, in first-write order, with their last written value
    function _storageWrites(
        Vm.AccountAccess[] memory records,
        address account
    )
        internal
        pure
        returns (bytes32[] memory slots, bytes32[] memory values)
    {
        uint256 total;
        for (uint256 i; i < records.length; ++i) {
            total += records[i].storageAccesses.length;
        }
        slots = new bytes32[](total);
        values = new bytes32[](total);
        uint256 count;
        for (uint256 i; i < records.length; ++i) {
            Vm.StorageAccess[] memory accesses = records[i].storageAccesses;
            for (uint256 j; j < accesses.length; ++j) {
                if (accesses[j].account != account || !accesses[j].isWrite || accesses[j].reverted) continue;
                uint256 k;
                while (k < count && slots[k] != accesses[j].slot) ++k;
                if (k == count) slots[count++] = accesses[j].slot;
                values[k] = accesses[j].newValue;
            }
        }
        assembly ("memory-safe") {
            mstore(slots, count)
            mstore(values, count)
        }
    }

    /// @dev Whether `code` contains `needle` (an address baked in as an immutable or constant)
    function _containsAddress(bytes memory code, address needle) internal pure returns (bool) {
        bytes20 target = bytes20(needle);
        if (code.length < 20) return false;
        for (uint256 i; i <= code.length - 20; ++i) {
            bytes20 window;
            assembly ("memory-safe") {
                // keep the 20 high-order bytes; the rest of the loaded word is the following code
                window := and(mload(add(add(code, 0x20), i)), shl(96, sub(shl(160, 1), 1)))
            }
            if (window == target) return true;
        }
        return false;
    }
}
