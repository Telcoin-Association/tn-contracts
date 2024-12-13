// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
// import { AxelarGateway } from "@axelar-network/axelar-cgp-solidity/contracts/AxelarGateway.sol";
import { Deployments } from "../deployments/Deployments.sol";

/// @dev Usage: `forge script script/GatewayRegisterToken.s.sol -vvvv --rpc-url $SEPOLIA_RPC_URL --private-key $PK`
contract GatewayRegisterToken is Script {
    // set configs below
    // AxelarGateway externalGateway = AxelarGateway(0xe432150cce91c13a887f7D836923d5597adD8E31);

    // eg. $TEL
    address tokenToRegister;
    string name;
    string symbol;
    uint8 decimals;
    uint256 cap;
    uint256 mintLimit;

    // json source
    Deployments deployments;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));
    }

    function run() public {
        vm.startBroadcast();

        tokenToRegister = deployments.sepoliaTEL;
        // eg. "Telcoin"
        name = ERC20(tokenToRegister).name();
        // eg. "TEL"
        symbol = ERC20(tokenToRegister).symbol();
        decimals = ERC20(tokenToRegister).decimals();

        // for an existing `TokenType.External` token, cap is unused
        cap = 0;
        mintLimit = type(uint256).max;
        bytes memory params = abi.encode(name, symbol, decimals, cap, tokenToRegister, mintLimit);

        bytes memory rawCall = abi.encodeWithSignature("deployToken(bytes,bytes32)", params, bytes32(0));
        console2.logBytes(rawCall);

        // second `bytes32` param is unused
        // externalGateway.deployToken(params, bytes32(0));

        vm.stopBroadcast();
    }
}
