// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { Stablecoin } from "../../src/testnet/Stablecoin.sol";
import { Deployments } from "../../deployments/Deployments.sol";

/// @dev Usage: `forge script script/testnet/TestnetFundDeveloper.s.sol \
/// -vvvv --rpc-url $TN_RPC_URL --private-key $ADMIN_PK`
contract TestnetFundDeveloper is Script {
    // config: send $TEL and stables to the following address
    address developer = 0x6A7aE3671672D1d7dc250f60C46F14E35d383a80;
    uint256 telAmount;
    uint256 stablecoinAmount;

    Stablecoin[] stables; // 23 canonical Telcoin stablecoins

    // json source
    Deployments deployments;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        telAmount = 2_000_000_000e18;
        stablecoinAmount = 1_000_000_000e6; // stablecoin.decimals() == 6

        // populate array for iteration
        stables.push(Stablecoin(deployments.eXYZs.eAUD));
        stables.push(Stablecoin(deployments.eXYZs.eCAD));
        stables.push(Stablecoin(deployments.eXYZs.eCFA));
        stables.push(Stablecoin(deployments.eXYZs.eCHF));
        stables.push(Stablecoin(deployments.eXYZs.eCZK));
        stables.push(Stablecoin(deployments.eXYZs.eDKK));
        stables.push(Stablecoin(deployments.eXYZs.eEUR));
        stables.push(Stablecoin(deployments.eXYZs.eGBP));
        stables.push(Stablecoin(deployments.eXYZs.eHKD));
        stables.push(Stablecoin(deployments.eXYZs.eHUF));
        stables.push(Stablecoin(deployments.eXYZs.eINR));
        stables.push(Stablecoin(deployments.eXYZs.eISK));
        stables.push(Stablecoin(deployments.eXYZs.eJPY));
        stables.push(Stablecoin(deployments.eXYZs.eKES));
        stables.push(Stablecoin(deployments.eXYZs.eMXN));
        stables.push(Stablecoin(deployments.eXYZs.eNOK));
        stables.push(Stablecoin(deployments.eXYZs.eNZD));
        stables.push(Stablecoin(deployments.eXYZs.eSDR));
        stables.push(Stablecoin(deployments.eXYZs.eSEK));
        stables.push(Stablecoin(deployments.eXYZs.eSGD));
        stables.push(Stablecoin(deployments.eXYZs.eTRY));
        stables.push(Stablecoin(deployments.eXYZs.eUSD));
        stables.push(Stablecoin(deployments.eXYZs.eZAR));
    }

    function run() public {
        vm.startBroadcast(); // must be called by minter role

        // send native $TEL for gas/swaps
        (bool success,) = developer.call{ value: telAmount }("");
        require(success, "TEL transfer failed");

        // mint and transfer stables
        for (uint256 i; i < stables.length; ++i) {
            stables[i].mint(stablecoinAmount);
            stables[i].transfer(developer, stablecoinAmount);
        }

        vm.stopBroadcast();
    }
}
