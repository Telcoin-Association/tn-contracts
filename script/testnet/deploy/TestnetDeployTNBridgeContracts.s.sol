// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.0;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { CREATE3 } from "solady/utils/CREATE3.sol";
import { AxelarAmplifierGateway } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol";
import { AxelarAmplifierGatewayProxy } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGatewayProxy.sol";
import {
    WeightedSigner,
    WeightedSigners
} from "@axelar-network/axelar-gmp-sdk-solidity/contracts/types/WeightedMultisigTypes.sol";
import { Deployments } from "../../../deployments/Deployments.sol";

/// @dev Usage: `forge script script/deploy/TestnetDeployTNBridgeContracts.s.sol --rpc-url $TN_RPC_URL -vvvv
/// --private-key
/// $ADMIN_PK`
contract TestnetDeployTNBridgeContracts is Script {
    AxelarAmplifierGateway axelarAmplifierImpl; // (numPrevSignersToRetain, domainSeparator, minRotationDelay)
    AxelarAmplifierGateway axelarAmplifier; // (gatewayImpl, owner, setupParams)

    // CREATE3 SALT
    bytes32 gatewayImplSalt;
    bytes32 gatewayProxySalt;

    /// CONFIG
    Deployments deployments;
    address admin; // operator, owner
    uint256 previousSignersRetention;
    bytes32 domainSeparator;
    uint256 minimumRotationDelay;
    uint128 weight;
    uint128 threshold;
    bytes32 nonce;
    WeightedSigner[] signerArray;
    bytes gatewaySetupParams;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        admin = deployments.admin;

        gatewayImplSalt = keccak256("axelar-amplifier-gateway");
        gatewayProxySalt = keccak256("axelar-amplifier-gateway-proxy");

        previousSignersRetention = 16;
        string memory axelarIdForTelcoin = "telcoin"; // todo: use prod axelarId for tel
        string memory routerAddress = "router"; // todo: use prod router addr
        uint256 telChainId = block.chainid;
        // derive domain separator with schema matching mainnet axelar amplifier gateway
        domainSeparator = keccak256(abi.encodePacked(axelarIdForTelcoin, routerAddress, telChainId));

        // default rotation delay is `1 day == 86400 seconds`
        minimumRotationDelay = 86_400;

        weight = 1; // todo: use prod weight
        WeightedSigner memory signer = WeightedSigner(admin, weight); // todo: use Axelar signer
        signerArray.push(signer); // todo: use prod signers
        threshold = 1; // todo: use prod threshold
        nonce = bytes32(0x0); // todo: use prod nonce
    }

    function run() public {
        vm.startBroadcast();

        // construct contract init code for gateway impl
        bytes memory gatewayImplInitcode = bytes.concat(
            type(AxelarAmplifierGateway).creationCode,
            abi.encode(previousSignersRetention, domainSeparator, minimumRotationDelay)
        );

        // CREATE3 equivalent of `new AxelarAmplifierGateway(previousSignersRetention, domainSeparator,
        // minimumRotationDelay)`
        axelarAmplifierImpl = AxelarAmplifierGateway(CREATE3.deployDeterministic(gatewayImplInitcode, gatewayImplSalt));

        // construct contract init code for gateway proxy
        WeightedSigners memory weightedSigners = WeightedSigners(signerArray, threshold, nonce);
        WeightedSigners[] memory weightedSignersArray = new WeightedSigners[](1);
        weightedSignersArray[0] = weightedSigners;
        gatewaySetupParams = abi.encode(admin, weightedSignersArray);
        bytes memory gatewayProxyInitcode = bytes.concat(
            type(AxelarAmplifierGatewayProxy).creationCode,
            abi.encode(address(axelarAmplifierImpl), admin, gatewaySetupParams)
        );

        // CREATE3 equivalent of `new AxelarAmplifierGatewayProxy(address(axelarAmplifierImpl), admin,
        // gatewaySetupParams)`
        axelarAmplifier = AxelarAmplifierGateway(CREATE3.deployDeterministic(gatewayProxyInitcode, gatewayProxySalt));

        vm.stopBroadcast();

        // asserts
        assert(axelarAmplifier.owner() == admin);
        assert(axelarAmplifier.operator() == admin);
        assert(axelarAmplifier.implementation() == address(axelarAmplifierImpl));
        assert(axelarAmplifier.previousSignersRetention() == 16);
        assert(axelarAmplifier.domainSeparator() == domainSeparator);
        assert(axelarAmplifier.minimumRotationDelay() == minimumRotationDelay);

        // logs
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(axelarAmplifierImpl))), 20),
            dest,
            ".AxelarAmplifierGatewayImpl"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(axelarAmplifier))), 20), dest, ".AxelarAmplifierGateway"
        );
    }
}
