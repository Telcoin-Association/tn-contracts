// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { StablecoinManager } from "../../src/testnet/StablecoinManager.sol";
import { Deployments } from "../../deployments/Deployments.sol";

/// @dev Usage: `forge script script/testnet/TestnetManageFaucet.s.sol \
/// --rpc-url $TN_RPC_URL -vvvv --private-key $ADMIN_PK`
contract TestnetManageFaucet is Script {
    StablecoinManager stablecoinManager;

    Deployments deployments;
    address admin; // admin, support, minter, burner role
    address[] tokensToManage;
    bool enableOrDisable; // true to enable, false to disable
    uint256 maxLimit;
    uint256 minLimit;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        admin = deployments.admin;

        /// @dev Configure for each run!
        enableOrDisable = false;

        stablecoinManager = StablecoinManager(payable(deployments.StablecoinManager));
        if (enableOrDisable == false) {
            /// @dev will disable all enabledStables. Customize accordingly
            address[] memory enabledStables = stablecoinManager.getEnabledXYZs();
            for (uint256 i; i < enabledStables.length; ++i) {
                tokensToManage.push(enabledStables[i]);
            }
        } else {
            /// @dev will enable all stablecoin XYZs. Customize accordingly
            tokensToManage.push(deployments.eXYZs.eAUD);
            tokensToManage.push(deployments.eXYZs.eCAD);
            tokensToManage.push(deployments.eXYZs.eCFA);
            tokensToManage.push(deployments.eXYZs.eCHF);
            tokensToManage.push(deployments.eXYZs.eCZK);
            tokensToManage.push(deployments.eXYZs.eDKK);
            tokensToManage.push(deployments.eXYZs.eEUR);
            tokensToManage.push(deployments.eXYZs.eGBP);
            tokensToManage.push(deployments.eXYZs.eHKD);
            tokensToManage.push(deployments.eXYZs.eHUF);
            tokensToManage.push(deployments.eXYZs.eINR);
            tokensToManage.push(deployments.eXYZs.eISK);
            tokensToManage.push(deployments.eXYZs.eJPY);
            tokensToManage.push(deployments.eXYZs.eKES);
            tokensToManage.push(deployments.eXYZs.eMXN);
            tokensToManage.push(deployments.eXYZs.eNOK);
            tokensToManage.push(deployments.eXYZs.eNZD);
            tokensToManage.push(deployments.eXYZs.eSDR);
            tokensToManage.push(deployments.eXYZs.eSEK);
            tokensToManage.push(deployments.eXYZs.eSGD);
            tokensToManage.push(deployments.eXYZs.eTRY);
            tokensToManage.push(deployments.eXYZs.eUSD);
            tokensToManage.push(deployments.eXYZs.eZAR);
        }
        maxLimit = type(uint256).max;
        minLimit = 1000;
    }

    function run() public {
        vm.startBroadcast();

        for (uint256 i; i < tokensToManage.length; ++i) {
            stablecoinManager.UpdateXYZ(tokensToManage[i], enableOrDisable, maxLimit, minLimit);
        }

        vm.stopBroadcast();

        // asserts
        address[] memory enabledStables = stablecoinManager.getEnabledXYZs();
        assert(enabledStables.length == 0); // customize accordingly
    }
}
