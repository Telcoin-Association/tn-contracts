// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { AddressBytes } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/libs/AddressBytes.sol";
import { InterchainTokenService } from "@axelar-network/interchain-token-service/contracts/InterchainTokenService.sol";
import { InterchainTokenFactory } from "@axelar-network/interchain-token-service/contracts/InterchainTokenFactory.sol";
import { TokenManager } from "@axelar-network/interchain-token-service/contracts/token-manager/TokenManager.sol";
import { LibString } from "solady/utils/LibString.sol";
import { InterchainTEL } from "../src/InterchainTEL.sol";
import { Deployments, ITS } from "../deployments/Deployments.sol";
import { ITSConfig } from "../deployments/utils/ITSConfig.sol";

/// @dev Usage: `forge script script/InterchainTransfer.s.sol -vvvv`
contract InterchainTransfer is ITSConfig, Script {
    Deployments deployments;

    InterchainTokenService service;
    string destinationChain;
    address destinationAddress;
    uint256 interchainAmount;

    function setUp() public {
        string memory path = string.concat(vm.projectRoot(), "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        service = InterchainTokenService(deployments.its.InterchainTokenService);
        destinationChain = "telcoin";
        destinationAddress = owner_;
        interchainAmount = 100; // 1 TEL

        /// @dev For testnet and mainnet genesis configs, use corresponding function
        _setUpDevnetConfig(deployments.admin, deployments.sepoliaTEL, deployments.wTEL, deployments.its.InterchainTEL);
    }

    function run() public {
        vm.startBroadcast();

        service.interchainTransfer{ value: gasValue }(
            DEVNET_INTERCHAIN_TOKENID,
            destinationChain,
            AddressBytes.toBytes(destinationAddress),
            interchainAmount,
            "",
            gasValue
        );

        vm.stopBroadcast();
    }
}
