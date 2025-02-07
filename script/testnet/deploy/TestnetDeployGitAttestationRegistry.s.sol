// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Deployments } from "../../../deployments/Deployments.sol";
import "../../../src/CI/GitAttestationRegistry.sol";

/// @dev Usage: `forge script script/deploy/TestnetDeployGitAttestationRegistry.s.sol --rpc-url $TN_RPC_URL -vvvv
/// --private-key
/// $ADMIN_PK`
contract TestnetDeployGitAttestationRegistry is Script {
    GitAttestationRegistry gitAttestationRegistry;

    address[] maintainers; // [admin, maintainer1, maintainer2]
    bytes32 gitAttestationRegistrySalt;
    uint8 bufferSize;

    Deployments deployments;
    address admin; // admin, maintainer role
    address maintainer1;
    address maintainer2;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        admin = deployments.admin;

        // populate maintainers array
        maintainer1 = 0xDe9700E89e0999854e5BFd7357a803d8FC476BB0;
        maintainer2 = 0x9F35A76bE2a3A84FF0c0A6365CD3C5CeB3a7FD97;
        maintainers.push(admin);
        maintainers.push(maintainer1);
        maintainers.push(maintainer2);

        bufferSize = 32;
        gitAttestationRegistrySalt = bytes32(keccak256("GitAttestationRegistry"));
    }

    function run() public {
        vm.startBroadcast();

        // deploy implementation
        gitAttestationRegistry = new GitAttestationRegistry{ salt: gitAttestationRegistrySalt }(bufferSize, maintainers);

        // add maintainer2's attestation wallet without affecting deploy address via constructor args
        address maintainer3 = 0x9D39C91A3f9058ee55AEb3869ce23ea6714A40cf;
        bytes32 maintainerRole = gitAttestationRegistry.MAINTAINER_ROLE();
        gitAttestationRegistry.grantRole(maintainerRole, maintainer3);

        vm.stopBroadcast();

        // asserts
        assert(gitAttestationRegistry.bufferSize() == bufferSize);
        assert(gitAttestationRegistry.hasRole(bytes32(0x0), admin)); // admin role
        assert(gitAttestationRegistry.hasRole(maintainerRole, admin));
        assert(gitAttestationRegistry.hasRole(maintainerRole, maintainer1));
        assert(gitAttestationRegistry.hasRole(maintainerRole, maintainer2));
        assert(gitAttestationRegistry.hasRole(maintainerRole, maintainer3));

        // logs
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(gitAttestationRegistry))), 20),
            dest,
            ".GitAttestationRegistry"
        );
    }
}
