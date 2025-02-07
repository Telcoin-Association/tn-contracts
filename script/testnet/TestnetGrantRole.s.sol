// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { Stablecoin } from "telcoin-contracts/contracts/stablecoin/Stablecoin.sol";
import { Deployments } from "../../deployments/Deployments.sol";

/// @dev Usage: `forge script script/TestnetGrantRole.s.sol --rpc-url $TN_RPC_URL --private-key $ADMIN_PK`
contract TestnetGrantRole is Script {
    // config: grant roles to the following addresses (faucet keys)
    address recipient0 = 0xE626Ce81714CB7777b1Bf8aD2323963fb3398ad5;
    address recipient1 = 0xB3FabBd1d2EdDE4D9Ced3CE352859CE1bebf7907;
    address recipient2 = 0xA3478861957661b2D8974D9309646A71271D98b9;
    address recipient3 = 0xE69151677E5aeC0B4fC0a94BFcAf20F6f0f975eB;
    bytes32 adminRole;
    bytes32 minterRole;
    bytes32 burnerRole;
    bytes32 supportRole;
    bytes32 blacklisterRole;

    address[] recipients; // contains addresses declared above
    Stablecoin[] stables; // 11 canonical Telcoin stablecoins

    // json source
    Deployments deployments;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        // fetch role values
        adminRole = Stablecoin(deployments.eAUD).DEFAULT_ADMIN_ROLE();
        supportRole = Stablecoin(deployments.eAUD).SUPPORT_ROLE();
        minterRole = Stablecoin(deployments.eAUD).MINTER_ROLE();
        burnerRole = Stablecoin(deployments.eAUD).BURNER_ROLE();
        blacklisterRole = Stablecoin(deployments.eAUD).BLACKLISTER_ROLE();

        // populate target arrays
        recipients.push(recipient0);
        recipients.push(recipient1);
        recipients.push(recipient2);
        recipients.push(recipient3);
        stables.push(Stablecoin(deployments.eAUD));
        stables.push(Stablecoin(deployments.eCAD));
        stables.push(Stablecoin(deployments.eCHF));
        stables.push(Stablecoin(deployments.eEUR));
        stables.push(Stablecoin(deployments.eGBP));
        stables.push(Stablecoin(deployments.eHKD));
        stables.push(Stablecoin(deployments.eJPY));
        stables.push(Stablecoin(deployments.eMXN));
        stables.push(Stablecoin(deployments.eNOK));
        stables.push(Stablecoin(deployments.eSDR));
        stables.push(Stablecoin(deployments.eSGD));
    }

    function run() public {
        vm.startBroadcast(); // must be called by admin role

        // for each stablecoin proxy contract, grant minter & burner role to all recipients
        for (uint256 i; i < stables.length; ++i) {
            for (uint256 j; j < recipients.length; ++j) {
                stables[i].grantRole(minterRole, recipients[j]);
                stables[i].grantRole(burnerRole, recipients[j]);
            }
        }

        vm.stopBroadcast();

        // asserts
        for (uint256 i; i < stables.length; ++i) {
            assert(stables[i].hasRole(adminRole, deployments.admin));

            for (uint256 j; j < recipients.length; ++j) {
                assert(stables[i].hasRole(minterRole, recipients[j]));
                assert(stables[i].hasRole(burnerRole, recipients[j]));
            }
        }
    }
}
