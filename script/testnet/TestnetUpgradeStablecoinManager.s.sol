// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { StablecoinManager } from "../../src/StablecoinManager.sol";
import { Deployments } from "../../deployments/Deployments.sol";

/// @dev Usage: `forge script script/TestnetDeployTokens.s.sol --rpc-url $TN_RPC_URL -vvvv --private-key $ADMIN_PK`
contract TestnetUpgradeStablecoinManager is Script {
    StablecoinManager newStablecoinManagerImpl;
    StablecoinManager stablecoinManager;

    bytes32 stablecoinManagerSalt; // used for both impl and proxy
    bytes upgradeCall; // optional- configure for each upgrade
    uint256 dripAmount;
    uint256 nativeDripAmount;
    uint256 lowBalanceThreshold;

    Deployments deployments;
    address admin; // admin, support, minter, burner role

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        admin = deployments.admin;
        stablecoinManager = StablecoinManager(payable(deployments.StablecoinManager));

        stablecoinManagerSalt = bytes32(bytes("StablecoinManager"));
        dripAmount = 100e6;
        nativeDripAmount = 1e18; // 1 $TEL
        lowBalanceThreshold = 10_000;
    }

    function run() public {
        vm.startBroadcast();

        // note: configure before each upgrade
        upgradeCall = "";

        // deploy new StablecoinManager impl and upgrade proxy
        newStablecoinManagerImpl = new StablecoinManager{ salt: stablecoinManagerSalt }();
        UUPSUpgradeable(payable(address(stablecoinManager))).upgradeToAndCall(
            address(newStablecoinManagerImpl), upgradeCall
        );

        vm.stopBroadcast();

        // asserts
        assert(stablecoinManager.getDripAmount() == 100e6);
        assert(stablecoinManager.getNativeDripAmount() == nativeDripAmount);
        assert(stablecoinManager.isEnabledXYZ(address(0x0)));
        assert(stablecoinManager.getEnabledXYZs().length == 0);
        assert(stablecoinManager.getEnabledXYZsWithMetadata().length == 0);
    }
}
