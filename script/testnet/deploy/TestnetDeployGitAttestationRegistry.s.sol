// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Deployments } from "../../../deployments/Deployments.sol";
import { DeploymentsResolver } from "../../../deployments/DeploymentsResolver.sol";
import "../../../src/CI/GitAttestationRegistry.sol";

/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployGitAttestationRegistry.s.sol \
/// --rpc-url $TN_RPC_URL -vvvv --private-key $ADMIN_PK`
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
        string memory path = string.concat(root, DeploymentsResolver.relativePath());
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
        address maintainer4 = 0xC20D15aBC36d37E7e06fb8E33F27fe9263C4904f;
        bytes32 maintainerRole = gitAttestationRegistry.MAINTAINER_ROLE();
        gitAttestationRegistry.grantRole(maintainerRole, maintainer3);
        gitAttestationRegistry.grantRole(maintainerRole, maintainer4);
        gitAttestationRegistry.revokeRole(maintainerRole, maintainer2);

        vm.stopBroadcast();

        // asserts
        assert(gitAttestationRegistry.bufferSize() == bufferSize);
        assert(gitAttestationRegistry.hasRole(bytes32(0x0), admin)); // admin role
        assert(gitAttestationRegistry.hasRole(maintainerRole, admin));
        assert(gitAttestationRegistry.hasRole(maintainerRole, maintainer1));
        // maintainer2 is granted the role at construction (it is in the `maintainers` array) then
        // revoked above, so it must no longer hold the role after this script runs
        assert(!gitAttestationRegistry.hasRole(maintainerRole, maintainer2));
        assert(gitAttestationRegistry.hasRole(maintainerRole, maintainer3));
        assert(gitAttestationRegistry.hasRole(maintainerRole, maintainer4));

        // logs
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, DeploymentsResolver.relativePath());
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(gitAttestationRegistry))), 20),
            dest,
            ".GitAttestationRegistry"
        );
    }
}
