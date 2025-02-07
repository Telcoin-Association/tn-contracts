// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Deployments } from "../../../deployments/Deployments.sol";
import { TANIssuanceHistory } from "../../../src/issuance/TANIssuanceHistory.sol";
import { ISimplePlugin } from "../../../src/interfaces/ISimplePlugin.sol";
import { MockAmirX } from "../../../test/issuance/mocks/MockImplementations.sol";

contract TestnetDeployTANIssuanceHistory is Script {
    ISimplePlugin tanIssuancePlugin;
    MockAmirX mockAmirX;
    TANIssuanceHistory tanIssuanceHistory;

    // config
    Deployments deployments;
    IERC20 tel;
    address owner;
    address executor;
    address spoofDefiAgg;
    bytes32 salt; // create2 salt for both MockAmirX and TANIssuanceHistory

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        // calls `TANIssuanceHistory::increaseClaimableByBatch()`
        owner = deployments.admin;
        // calls `mockAmirX::defiSwap`, same as owner for simplicity
        executor = owner;
        // "TN tester" this address must hold TEL for user fee transfers
        spoofDefiAgg = 0x3DCc9a6f3A71F0A6C8C659c65558321c374E917a;

        // both mocks and prod contracts use canonical TEL
        tel = IERC20(0xdF7837DE1F2Fa4631D716CF2502f8b230F1dcc32);

        // polygon mock plugin
        tanIssuancePlugin = ISimplePlugin(0xd5ac3373187e34DFf4Fd156f8aEf9B1De5123caE);

        tanIssuanceHistory = TANIssuanceHistory(0xcAE9a3227C93905418500498F65f5d2baB235511);
    }

    function run() public {
        vm.startBroadcast();

        // as no AmirX contract explicitly for testing exists, deploy a MockAmirX
        mockAmirX = new MockAmirX{ salt: salt }(tel, executor, spoofDefiAgg);

        tanIssuanceHistory = new TANIssuanceHistory{ salt: salt }(tanIssuancePlugin, owner);

        vm.stopBroadcast();

        // asserts
        assert(tanIssuanceHistory.tel() == tel);
        assert(tanIssuanceHistory.owner() == executor);
        assert(tanIssuanceHistory.tanIssuancePlugin() == tanIssuancePlugin);
        assert(tanIssuanceHistory.clock() == block.number);

        // logs omitted for this script
    }
}
