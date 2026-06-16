// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BLS_G1_ADDRESS } from "../../src/consensus/BlsG1.sol";

/// @dev Minimal subset of the Foundry cheatcode interface needed to place mock bytecode.
interface IBlsG1MockVm {
    function getDeployedCode(string calldata artifactPath) external returns (bytes memory runtimeBytecode);
    function etch(address target, bytes calldata newRuntimeBytecode) external;
}

/// @title BlsG1PrecompileMock
/// @notice Stand-in for the native BLS proof-of-possession precompile at `BLS_G1_ADDRESS`, used in
/// Foundry tests where the real precompile is absent. Mirrors ONLY the precompile's length gate: it
/// returns true iff the signature is 48 bytes and the pubkey is 96 bytes, and never runs the BLS
/// pairing. Real-crypto verification is covered by the Rust precompile unit/property tests and the
/// telcoin-network e2e suite; the Solidity tests here assert the registry's plumbing around it.
/// @dev Reached via DELEGATECALL from `ConsensusRegistry` (linked to `BLS_G1_ADDRESS`), so it must be
/// stateless.
contract BlsG1PrecompileMock {
    /// @dev `payable` so the value-carrying delegatecall from the payable `stake` / `delegateStake` does
    /// not trip a non-payable function's callvalue guard (delegatecall preserves `msg.value`). The real
    /// native precompile has no such guard; the forwarded value is ignored here.
    function verifyProofOfPossession(
        bytes calldata signature,
        bytes calldata pubkey,
        address
    )
        external
        payable
        returns (bool)
    {
        return signature.length == 48 && pubkey.length == 96;
    }
}

/// @title BlsG1PrecompileMockDeployed
/// @notice Test base that etches `BlsG1PrecompileMock` at `BLS_G1_ADDRESS`, so consumers linked to
/// that address (e.g. `ConsensusRegistry`) resolve their `BlsG1.verifyProofOfPossession` calls to the
/// mock. Mirrors the placement strategy of the former `BlsG1Deployed`: as a base constructor it runs
/// before an inheriting `ConsensusRegistry`'s own construction, which verifies PoPs.
/// @dev Inherits nothing so that, listed first in the inheritance list, its constructor runs first in
/// the C3 linearization (before any sibling `ConsensusRegistry` base).
abstract contract BlsG1PrecompileMockDeployed {
    IBlsG1MockVm private constant _MOCK_VM = IBlsG1MockVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    constructor() {
        _MOCK_VM.etch(BLS_G1_ADDRESS, _MOCK_VM.getDeployedCode("BlsG1PrecompileMock.sol:BlsG1PrecompileMock"));
    }
}
