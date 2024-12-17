// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
import { AxelarGateway } from "@axelar-network/axelar-cgp-solidity/contracts/AxelarGateway.sol";
import { AxelarGatewayProxy } from "@axelar-network/axelar-cgp-solidity/contracts/AxelarGatewayProxy.sol";
import { TokenDeployer } from "@axelar-network/axelar-cgp-solidity/contracts/TokenDeployer.sol";
import { Deployments } from "../deployments/Deployments.sol";

/// @dev Usage: `forge script script/TestnetDeployAxelarGateway.s.sol -vvvv --rpc-url $SEPOLIA_RPC --private-key $PK`
/// @notice Requires either updates to `solidity ^0.8.9` in fixed Axelar dependency contracts
/// or a separate Foundry environment than this one, which is pinned to `solidity 0.8.26`
contract TestnetDeployAxelarGateway is Script {
    // set configs below
    AxelarGateway externalGatewayImpl;
    AxelarGateway externalGateway;
    Auth auth;
    TokenDeployer tokenDeployer;

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

        // for sepolia scripting:
        // externalGatewayImpl = AxelarGateway(0xc1712652326E87D193Ac11910934085FF45C2F48);
        // externalGateway = AxelarGateway(0xe432150cce91c13a887f7D836923d5597adD8E31);
    }

    function run() public {
        vm.startBroadcast();

        auth = new Auth();
        tokenDeployer = new TokenDeployer();
        externalGatewayImpl = new AxelarGateway(address(auth), address(tokenDeployer));
        bytes memory dummyData = abi.encode(address(0), address(0), "");
        externalGateway = AxelarGateway(address(new AxelarGatewayProxy(address(externalGatewayImpl), dummyData)));

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

        // calls to AxelarGatewayProxy must be routed through `execute()`
        // outside of testnet this can only happen via Axelar governance
        bytes32[] memory commandIds = new bytes32[](1);
        commandIds[0] = bytes32(0); // checked if it is executed (== false)
        string[] memory commands = new string[](1);
        commands[0] = "deployToken";
        bytes[] memory executeParams = new bytes[](1);
        executeParams[0] = params;
        bytes memory data = abi.encode(11_155_111, commandIds, commands, executeParams);
        bytes memory proof = "";
        bytes memory input = abi.encode(data, proof);

        externalGateway.execute(input);

        vm.stopBroadcast();
    }
}

/// @dev Dummy auth module contract for testing while awaiting verifier whitelisting
contract Auth {
    function validateProof(bytes32 messageHash, bytes calldata proof) external returns (bool currentOperators) {
        return true;
    }

    function transferOperatorship(bytes calldata params) external { }
}
