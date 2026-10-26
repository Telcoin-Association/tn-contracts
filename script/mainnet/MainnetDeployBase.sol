// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Script } from "forge-std/Script.sol";
import { VmSafe } from "forge-std/Vm.sol";
import { console2 } from "forge-std/console2.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { DeploymentsResolver } from "../../deployments/DeploymentsResolver.sol";

/// @title Mainnet Deploy Base
/// @notice Shared guards for the post-genesis mainnet deploy scripts under
///         `script/mainnet/deploy/`. Every script built on this base runs on its own, in
///         any order, any number of times:
///         - it refuses to run until `DeploymentsResolver.MAINNET_CHAIN_ID` is set, and
///           then only against that chain
///         - it reads `deployments-mainnet.json` explicitly rather than through
///           `DeploymentsResolver.relativePath()`, whose fallback for unknown chain ids is
///           the testnet file
///         - deterministic deploys predict their address first and skip anything that
///           already has code, so a re-run (or a front-run with identical initcode) is a
///           no-op rather than a revert
///         - the address book is written only when broadcasting, so a dry run never
///           records addresses that were not actually deployed
/// @dev Owner-gated contracts are handed to the genesis governance Safe
///      (`deployments.Safe`) inside the deploy itself. The broadcasting key only pays gas
///      and never holds a privileged role, so any funded EOA can run these scripts.
abstract contract MainnetDeployBase is Script {
    string internal constant DEPLOYMENTS_PATH = "/deployments/deployments-mainnet.json";
    string internal constant INITCODE_DIR = "/deployments/canonical-initcode/";

    Deployments internal deployments;
    /// @notice Genesis governance Safe; owner of every owner-gated contract deployed here
    address internal governance;
    /// @notice Arachnid deterministic deployment proxy (genesis-assigned)
    address internal arachnid;

    /// @notice Loads the mainnet address book and checks the chain and its genesis prerequisites
    function _loadMainnet() internal {
        uint256 expected = _expectedChainId();
        require(
            expected != 0, "MainnetDeploy: mainnet chain id not finalized; set DeploymentsResolver.MAINNET_CHAIN_ID"
        );
        require(
            block.chainid == expected,
            string.concat(
                "MainnetDeploy: connected to chain ", vm.toString(block.chainid), ", expected ", vm.toString(expected)
            )
        );

        string memory json = vm.readFile(string.concat(vm.projectRoot(), DEPLOYMENTS_PATH));
        deployments = abi.decode(vm.parseJson(json), (Deployments));

        governance = deployments.Safe;
        arachnid = deployments.ArachnidDeterministicDeployFactory;
        _requireCode(governance, "governance Safe");
        _requireCode(arachnid, "Arachnid deterministic deployment proxy");
    }

    /// @notice Chain id the script must be connected to
    /// @dev Virtual so tests can run the scripts against a local genesis replay
    function _expectedChainId() internal view virtual returns (uint256) {
        return DeploymentsResolver.MAINNET_CHAIN_ID;
    }

    /// @notice CREATE2-deploys `initcode` through the Arachnid proxy, or returns the existing
    ///         contract when the predicted address already has code
    /// @dev Must be called inside a broadcast so the proxy call becomes a transaction.
    ///      Identical initcode always lands at the same address, so an existing contract at
    ///      the predicted address is by construction the one this call would have deployed.
    function _deployDeterministic(
        bytes32 salt,
        bytes memory initcode,
        string memory label
    )
        internal
        returns (address deployed)
    {
        deployed = vm.computeCreate2Address(salt, keccak256(initcode), arachnid);
        if (deployed.code.length != 0) {
            console2.log(string.concat(label, " already deployed at"), deployed);
            return deployed;
        }

        (bool ok, bytes memory ret) = arachnid.call(bytes.concat(salt, initcode));
        require(
            ok && ret.length == 20 && address(bytes20(ret)) == deployed,
            string.concat("MainnetDeploy: CREATE2 deploy failed for ", label)
        );
        console2.log(string.concat(label, " deployed at"), deployed);
    }

    /// @notice Reads vendored canonical initcode and checks it against its pinned hash
    /// @param relativeFile Path under `deployments/canonical-initcode/`
    function _readInitcode(string memory relativeFile, bytes32 expectedHash) internal view returns (bytes memory code) {
        code = vm.parseBytes(vm.readFile(string.concat(vm.projectRoot(), INITCODE_DIR, relativeFile)));
        require(
            keccak256(code) == expectedHash,
            string.concat("MainnetDeploy: vendored initcode hash mismatch for ", relativeFile)
        );
    }

    function _requireCode(address target, string memory label) internal view {
        require(target.code.length != 0, string.concat("MainnetDeploy: no code at ", label));
    }

    /// @notice Pins runtime code for contracts whose deployed bytes are chain-independent
    function _requireCodehash(address target, bytes32 expected, string memory label) internal view {
        require(target.codehash == expected, string.concat("MainnetDeploy: unexpected runtime code for ", label));
    }

    /// @notice Writes `value` into the mainnet address book at `key`, only when broadcasting
    function _record(string memory key, address value) internal {
        if (!vm.isContext(VmSafe.ForgeContext.ScriptBroadcast)) return;
        vm.writeJson(LibString.toHexStringChecksummed(value), string.concat(vm.projectRoot(), DEPLOYMENTS_PATH), key);
    }
}
