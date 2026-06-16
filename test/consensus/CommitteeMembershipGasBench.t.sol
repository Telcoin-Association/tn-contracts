// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";

/// @title Committee-membership gas benchmark
/// @notice Compares the two strategies for `_updateValidatorQueue`'s exit-eligibility test: the former
/// linear scan of three committees per pending-exit validator (O(P x 3C)) vs the transient (EIP-1153)
/// membership set (O(3C + P)). These functions mirror the contract's `_isCommitteeMember` (old) and
/// `_markCommitteeMembers`/`_isCommitteeMember` (new) so the comparison isolates the algorithmic delta.
/// Worst case is measured: pending-exit validators absent from every committee, so each scan runs the
/// full committee length (and this is the realistic case, since the protocol exits a queued validator by
/// excluding it from all upcoming committees). C is swept up to the 100-member committee cap.
contract CommitteeMembershipGasBench is Test {
    bytes32 private constant NS = keccak256("bench.committee");

    function _addrs(uint256 base, uint256 n) internal pure returns (address[] memory a) {
        a = new address[](n);
        for (uint256 i; i < n; ++i) {
            a[i] = address(uint160(uint256(keccak256(abi.encode(base, i)))));
        }
    }

    /// @dev mirror of the contract's former linear committee scan
    function _scan(address v, address[] memory c) internal pure returns (bool) {
        for (uint256 i; i < c.length; ++i) {
            if (c[i] == v) return true;
        }
        return false;
    }

    /// @dev mirror of the contract's transient-set helpers
    function _mark(address[] memory c, bytes32 set) internal {
        for (uint256 i; i < c.length; ++i) {
            address m = c[i];
            assembly ("memory-safe") {
                mstore(0x00, m)
                mstore(0x20, set)
                tstore(keccak256(0x00, 0x40), 1)
            }
        }
    }

    function _isMarked(address v, bytes32 set) internal view returns (bool r) {
        assembly ("memory-safe") {
            mstore(0x00, v)
            mstore(0x20, set)
            r := tload(keccak256(0x00, 0x40))
        }
    }

    function test_gas_committeeMembership() public {
        uint256[4] memory cs = [uint256(10), 25, 50, 100];
        uint256[4] memory ps = [uint256(1), 10, 50, 100];
        uint256 scenario;
        for (uint256 ci; ci < cs.length; ++ci) {
            for (uint256 pi; pi < ps.length; ++pi) {
                uint256 C = cs[ci];
                uint256 P = ps[pi];
                ++scenario;
                bytes32 set = keccak256(abi.encode(NS, scenario));
                address[] memory c1 = _addrs(scenario * 1000 + 1, C);
                address[] memory c2 = _addrs(scenario * 1000 + 2, C);
                address[] memory c3 = _addrs(scenario * 1000 + 3, C);
                address[] memory pe = _addrs(scenario * 1000 + 9, P); // disjoint -> worst case

                // before: linear scan of three committees per pending-exit validator
                uint256 g0 = gasleft();
                uint256 stayed;
                for (uint256 i; i < P; ++i) {
                    if (_scan(pe[i], c1) || _scan(pe[i], c2) || _scan(pe[i], c3)) ++stayed;
                }
                uint256 scanGas = g0 - gasleft();

                // after: mark the three committees once, then O(1) check per pending-exit validator
                uint256 g1 = gasleft();
                _mark(c1, set);
                _mark(c2, set);
                _mark(c3, set);
                uint256 stayed2;
                for (uint256 i; i < P; ++i) {
                    if (_isMarked(pe[i], set)) ++stayed2;
                }
                uint256 transientGas = g1 - gasleft();

                assertEq(stayed, 0);
                assertEq(stayed2, 0);
                emit log_named_uint("C committee", C);
                emit log_named_uint("  P pendingExit", P);
                emit log_named_uint("    scan gas      (O(P*3C))", scanGas);
                emit log_named_uint("    transient gas (O(3C+P))", transientGas);
            }
        }
    }
}
