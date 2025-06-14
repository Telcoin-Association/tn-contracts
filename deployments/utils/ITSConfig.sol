// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import { LibString } from "solady/utils/LibString.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { Create3Deployer } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/deploy/Create3Deployer.sol";
import {
    WeightedSigner,
    WeightedSigners,
    Proof
} from "@axelar-network/axelar-gmp-sdk-solidity/contracts/types/WeightedMultisigTypes.sol";
import { AxelarAmplifierGateway } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol";
import { ITokenManagerType } from "@axelar-network/interchain-token-service/contracts/interfaces/ITokenManagerType.sol";
import { InterchainTokenService } from "@axelar-network/interchain-token-service/contracts/InterchainTokenService.sol";
import { InterchainTokenFactory } from "@axelar-network/interchain-token-service/contracts/InterchainTokenFactory.sol";
import { AddressBytes } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/libs/AddressBytes.sol";
import { ITSUtils } from "./ITSUtils.sol";

abstract contract ITSConfig is ITSUtils {
    // chain constants
    string constant ITS_HUB_CHAIN_NAME = "axelar";
    string constant ITS_HUB_ROUTING_IDENTIFIER = "hub";
    string constant ITS_HUB_ROUTER_ADDR = "axelar157hl7gpuknjmhtac2qnphuazv2yerfagva7lsu9vuj2pgn32z22qa26dk4";
    string constant TN_CHAIN_NAME = "telcoin-network";
    bytes32 constant TN_CHAINNAMEHASH = keccak256(bytes(TN_CHAIN_NAME));
    string constant MAINNET_CHAIN_NAME = "Ethereum";
    bytes32 constant MAINNET_CHAINNAMEHASH = 0x564ccaf7594d66b1eaaea24fe01f0585bf52ee70852af4eac0cc4b04711cd0e2;
    address constant MAINNET_ITS = 0xB5FB4BE02232B1bBA4dC8f81dc24C26980dE9e3C;
    address constant MAINNET_GATEWAY = 0x4F4495243837681061C4743b74B3eEdf548D56A5;
    address constant MAINNET_TEL = 0x467Bccd9d29f223BcE8043b84E8C8B282827790F;
    uint256 constant SEPOLIA_CHAINID = 11155111;
    string constant DEVNET_TN_CHAIN_NAME = "telcoin";
    bytes32 constant DEVNET_TN_CHAINNAMEHASH = keccak256(bytes(DEVNET_TN_CHAIN_NAME));
    bytes32 constant DEVNET_INTERCHAIN_TOKENID = 0x09f3c6e8754c8e269060f138d8b55526b0058b0fa258f90ae3197ee4808d23b6;
    string constant DEVNET_SEPOLIA_CHAIN_NAME = "eth-sepolia";
    bytes32 constant DEVNET_SEPOLIA_CHAINNAMEHASH = 0x24f78f6b35533491ef3d467d5e8306033cca94049b9b76db747dfc786df43f86;
    address constant DEVNET_SEPOLIA_ITS = 0x2269B93c8D8D4AfcE9786d2940F5Fcd4386Db7ff;
    address constant DEVNET_SEPOLIA_GATEWAY = 0xF128c84c3326727c3e155168daAa4C0156B87AD1;
    string constant TESTNET_TN_CHAIN_NAME = "telcoin-testnet";
    bytes32 constant TESTNET_TN_CHAINNAMEHASH = keccak256(bytes(TESTNET_TN_CHAIN_NAME));
    string constant TESTNET_SEPOLIA_CHAIN_NAME = "ethereum-sepolia";
    bytes32 constant TESTNET_SEPOLIA_CHAINNAMEHASH = 0x564ccaf7594d66b1eaaea24fe01f0585bf52ee70852af4eac0cc4b04711cd0e2;
    address constant TESTNET_SEPOLIA_ITS = 0xB5FB4BE02232B1bBA4dC8f81dc24C26980dE9e3C;
    address constant TESTNET_SEPOLIA_GATEWAY = 0xe432150cce91c13a887f7D836923d5597adD8E31;

    // message type constants; these serve as headers for ITS messages between chains
    uint256 constant MESSAGE_TYPE_INTERCHAIN_TRANSFER = 0;
    uint256 constant MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN = 1;
    // uint256 constant MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER = 2; // replaced with `linkToken() in v2.1.0`
    uint256 constant MESSAGE_TYPE_SEND_TO_HUB = 3;
    uint256 constant MESSAGE_TYPE_RECEIVE_FROM_HUB = 4;
    uint256 constant MESSAGE_TYPE_LINK_TOKEN = 5;
    uint256 constant MESSAGE_TYPE_REGISTER_TOKEN_METADATA = 6;

    // mutable fork contracts
    // Sepolia
    IERC20 sepoliaTEL;
    InterchainTokenService sepoliaITS;
    InterchainTokenFactory sepoliaITF;
    AxelarAmplifierGateway sepoliaGateway;

    uint256 public constant telTotalSupply = 100_000_000_000e18;
    /// @dev TEL genesis allocation to the governance safe for gas used to relay initial ITS bridging
    uint256 public constant governanceInitialBalance = 10e18;

    /// @dev Create3 deployment of ITS requires some deterministic addresses before deployment
    /// @dev Prefetch target addrs for constructor args is also helpful for the config setups
    function _precalculateCreate3ConstructorArgs(Create3Deployer create3Deploy, address sender) internal view returns (address precalculatedITS, address precalculatedWTEL, address precalculatedInterchainTEL) {
        precalculatedITS = create3Deploy.deployedAddress("", sender, salts.itsSalt);
        precalculatedWTEL = create3Deploy.deployedAddress("", sender, salts.wtelSalt);
        precalculatedInterchainTEL = create3Deploy.deployedAddress("", sender, salts.itelSalt);
    }

    function _setGovernanceSafeConfig() internal virtual {
        safeOwners.push(0x2358CF87e62618663E781CE52EE7a7F777aC4e65);
        safeOwners.push(0x84B0fc1Bb26212a1BfFb48F03B010FDA4aDCe3c9);
        safeOwners.push(0x707856C0089Fd59d9e686A47784d5DAd7c0784c4);
        safeOwners.push(0xfeCeE4Ab07127fFf4EE4a3BA61dF5fD7B906F84C);
        safeOwners.push(0xf5b3944629F9303fa94670B2a6611eE1b11Cd538);
        safeOwners.push(0xd7e88D492Dc992127384215b8555C9305C218299);
        safeThreshold = 3;
    }

    function _setUpDevnetConfig(address admin, address devnetTEL, address wtel, address itel) internal virtual {
        // devnet uses admin as linker and single verifier running tofnd + ampd
        linker = admin;
        address ampdVerifier = 0xCc9Cc353B765Fee36669Af494bDcdc8660402d32;

        // AxelarAmplifierGateway
        axelarId = DEVNET_TN_CHAIN_NAME;
        routerAddress = ITS_HUB_ROUTER_ADDR;
        telChainId = 0x7e1;
        domainSeparator = keccak256(abi.encodePacked(axelarId, routerAddress, telChainId));
        previousSignersRetention = 16;
        minimumRotationDelay = 86_400;
        weight = 1; 
        threshold = 1;
        nonce = bytes32(0x0);
        ampdVerifierSigners.push(ampdVerifier);
        signerArray.push(WeightedSigner(ampdVerifierSigners[0], weight));
        // in memory since nested arrays within custom Solidity structs cannot be copied to storage
        WeightedSigners memory weightedSigners = WeightedSigners(signerArray, threshold, nonce);
        WeightedSigners[] memory weightedSignersArray = new WeightedSigners[](1);
        weightedSignersArray[0] = weightedSigners;
        gatewayOperator = admin;
        gatewaySetupParams = abi.encode(gatewayOperator, weightedSignersArray);
        gatewayOwner = admin;

        // AxelarGasService
        gasCollector = admin;
        gasValue = 0.001 ether;
        gsOwner = admin;
        gsSetupParams = ""; // note: unused

        // InterchainTokenService
        itsOwner = admin;
        itsOperator = admin;
        chainName_ = DEVNET_TN_CHAIN_NAME;
        trustedChainNames.push(ITS_HUB_CHAIN_NAME); // leverage ITS hub to support remote chains
        trustedChainNames.push(DEVNET_SEPOLIA_CHAIN_NAME);
        trustedChainNames.push(DEVNET_TN_CHAIN_NAME);
        trustedAddresses.push(ITS_HUB_ROUTING_IDENTIFIER);
        trustedAddresses.push(ITS_HUB_ROUTING_IDENTIFIER);
        trustedAddresses.push(ITS_HUB_ROUTING_IDENTIFIER);
        itsSetupParams = abi.encode(itsOperator, chainName_, trustedChainNames, trustedAddresses);

        // InterchainTokenFactory
        itfOwner = admin;

        // iTEL config
        originTEL = devnetTEL;
        originChainName_ = DEVNET_SEPOLIA_CHAIN_NAME;
        symbol_ = "iTEL";
        name_ = "Interchain Telcoin";
        recoverableWindow_ = 60; // 1 minute for devnet
        owner_ = admin;
        maxToClean = uint16(300);
        baseERC20_ = wtel; 

        // iTELTokenManager config
        tmOperator = AddressBytes.toBytes(owner_);
        tokenAddress = itel;
        params = abi.encode(tmOperator, tokenAddress);

        // not used in devnet, but required to avoid reverts
        _setGovernanceSafeConfig();

        // stored for asserts
        abiEncodedWeightedSigners = abi.encode(weightedSigners);
    }

    function _setUpTestnetConfig(address governanceSafe, address admin, address testnetTEL, address wtel, address itel) internal virtual {
        _setUpDevnetConfig(admin, testnetTEL, wtel, itel);

        // overwrite select devnet configurations
        axelarId = TESTNET_TN_CHAIN_NAME;
        gatewayOwner = governanceSafe;
        itsOwner = governanceSafe;
        itfOwner = governanceSafe;
        originChainName_ = TESTNET_SEPOLIA_CHAIN_NAME;
        recoverableWindow_ = 600; // 10 minutes for testnet
        owner_ = governanceSafe;
        tmOperator = AddressBytes.toBytes(owner_);
        params = abi.encode(tmOperator, tokenAddress);

        _setGovernanceSafeConfig();
    }
}
