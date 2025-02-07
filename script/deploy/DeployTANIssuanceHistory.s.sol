// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { TANIssuanceHistory } from "../../src/issuance/TANIssuanceHistory.sol";
import { ISimplePlugin } from "../../src/interfaces/ISimplePlugin.sol";

contract DeployTANIssuanceHistory is Script {
    TANIssuanceHistory tanIssuanceHistory;

    // config
    Deployments deployments;
    IERC20 tel;
    ISimplePlugin tanIssuancePlugin;
    address owner;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        // calls `TANIssuanceHistory::increaseClaimableByBatch()`
        // owner = todo: prod owner;

        // both mocks and prod contracts use canonical TEL
        tel = IERC20(0xdF7837DE1F2Fa4631D716CF2502f8b230F1dcc32);

        // polygon mock plugin; todo: prod deployment
        // tanIssuancePlugin = ISimplePlugin(deployments.TanIssuancePlugin);
    }

    function run() public {
        vm.startBroadcast();

        // tanIssuanceHistory = new TANIssuanceHistory{ salt: bytes32(0x0) }(tanIssuancePlugin, owner);

        vm.stopBroadcast();

        // asserts
        assert(tanIssuanceHistory.tel() == tel);
        assert(tanIssuanceHistory.owner() == owner);
        assert(tanIssuanceHistory.tanIssuancePlugin() == tanIssuancePlugin);
        assert(tanIssuanceHistory.clock() == block.number);

        // logs
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(tanIssuancePlugin))), 20), dest, ".TanIssuancePlugin"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(tanIssuanceHistory))), 20), dest, ".TanIssuanceHistory"
        );
    }
}
