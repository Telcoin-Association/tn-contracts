// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BLS_G1_ADDRESS } from "../../src/consensus/BlsG1.sol";

/// @dev Minimal subset of the Foundry cheatcode interface needed to place library bytecode.
interface IBlsG1Vm {
    function getDeployedCode(string calldata artifactPath) external returns (bytes memory runtimeBytecode);
    function etch(address target, bytes calldata newRuntimeBytecode) external;
}

/// @title BlsG1Deployed
/// @notice Test base that places the linked `BlsG1` library bytecode at its canonical
/// genesis address (`BLS_G1_ADDRESS`).
/// @dev `foundry.toml` pins `BlsG1` to `BLS_G1_ADDRESS` via `libraries`, which makes Forge link
/// consumers to that fixed address but, unlike the default behaviour, does NOT auto-deploy the
/// library there. Without code at the address every call into `BlsG1` reverts. We place it in the
/// constructor because consumers such as `ConsensusRegistry` call `BlsG1` during their own
/// constructors (run via inheritance), before any `setUp` could etch it.
/// @dev This base intentionally inherits nothing (it carries its own `vm` handle rather than
/// extending `forge-std/Test`). A shared base like `Test` would be pulled earlier in the C3
/// linearization, causing this constructor to run AFTER a sibling `ConsensusRegistry` base. With
/// no bases of its own, listing `BlsG1Deployed` first guarantees its constructor runs first.
abstract contract BlsG1Deployed {
    IBlsG1Vm private constant _BLS_VM = IBlsG1Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    constructor() {
        _BLS_VM.etch(BLS_G1_ADDRESS, _BLS_VM.getDeployedCode("BlsG1.sol:BlsG1"));
    }
}
