// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { StablecoinManager } from "../../src/StablecoinManager.sol";
import { Deployments } from "../../deployments/Deployments.sol";

/// @dev Usage: `forge script script/TestnetDisableStablecoin.s.sol --rpc-url $TN_RPC_URL -vvvv --private-key $ADMIN_PK`
contract TestnetDisableStablecoin is Script {
    StablecoinManager stablecoinManager;

    Deployments deployments;
    address admin; // admin, support, minter, burner role
    address[] tokensToManage;
    uint256 maxLimit;
    uint256 minLimit;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        admin = deployments.admin;

        stablecoinManager = StablecoinManager(payable(deployments.StablecoinManager));
        address[] memory enabledStables = stablecoinManager.getEnabledXYZs();
        for (uint256 i; i < enabledStables.length; ++i) {
            tokensToManage.push(enabledStables[i]);
        }
        maxLimit = type(uint256).max;
        minLimit = 1000;
    }

    function run() public {
        vm.startBroadcast();

        for (uint256 i; i < tokensToManage.length; ++i) {
            stablecoinManager.UpdateXYZ(tokensToManage[i], false, maxLimit, minLimit);
        }

        vm.stopBroadcast();

        address[] memory remainingEnabledStables = stablecoinManager.getEnabledXYZs();
        assert(remainingEnabledStables.length == 0);
    }
}
