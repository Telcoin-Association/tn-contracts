// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { IAxelarGateway } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/interfaces/IAxelarGateway.sol";
import { AxelarAmplifierGateway } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol";
import { AxelarAmplifierGatewayProxy } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGatewayProxy.sol";
import { BaseAmplifierGateway } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/BaseAmplifierGateway.sol";
import { Message, CommandType } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/types/AmplifierGatewayTypes.sol";
import {
    WeightedSigner,
    WeightedSigners,
    Proof
} from "@axelar-network/axelar-gmp-sdk-solidity/contracts/types/WeightedMultisigTypes.sol";
import { Create3Deployer } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/deploy/Create3Deployer.sol";
import { AddressBytes } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/libs/AddressBytes.sol";
import { Create3AddressFixed } from "@axelar-network/interchain-token-service/contracts/utils/Create3AddressFixed.sol";
import { InterchainTokenService } from "@axelar-network/interchain-token-service/contracts/InterchainTokenService.sol";
import { InterchainProxy } from "@axelar-network/interchain-token-service/contracts/proxies/InterchainProxy.sol";
import { TokenManagerProxy } from "@axelar-network/interchain-token-service/contracts/proxies/TokenManagerProxy.sol";
import { InterchainTokenDeployer } from
    "@axelar-network/interchain-token-service/contracts/utils/InterchainTokenDeployer.sol";
import { InterchainTokenFactory } from "@axelar-network/interchain-token-service/contracts/InterchainTokenFactory.sol";
import { InterchainToken } from
    "@axelar-network/interchain-token-service/contracts/interchain-token/InterchainToken.sol";
import { TokenManagerDeployer } from "@axelar-network/interchain-token-service/contracts/utils/TokenManagerDeployer.sol";
import { TokenManager } from "@axelar-network/interchain-token-service/contracts/token-manager/TokenManager.sol";
import { ITokenManager } from "@axelar-network/interchain-token-service/contracts/interfaces/ITokenManager.sol";
import { ITokenManagerType } from "@axelar-network/interchain-token-service/contracts/interfaces/ITokenManagerType.sol";
import { TokenHandler } from "@axelar-network/interchain-token-service/contracts/TokenHandler.sol";
import { GatewayCaller } from "@axelar-network/interchain-token-service/contracts/utils/GatewayCaller.sol";
import { AxelarGasService } from "@axelar-network/axelar-cgp-solidity/contracts/gas-service/AxelarGasService.sol";
import { AxelarGasServiceProxy } from "../external/axelar-cgp-solidity/AxelarGasServiceProxy.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
import { WTEL } from "../src/WTEL.sol";
import { InterchainTEL } from "../src/InterchainTEL.sol";
import { Create3Utils, Salts, ImplSalts } from "../deployments/utils/Create3Utils.sol";
import { Deployments, ITS } from "../deployments/Deployments.sol";
import { ITSConfig } from "../deployments/utils/ITSConfig.sol";
import { GenesisPrecompiler } from "../deployments/genesis/GenesisPrecompiler.sol";
import { ITSGenesis } from "../deployments/genesis/ITSGenesis.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { SafeProxy } from "safe-contracts/contracts/proxies/SafeProxy.sol";

/// @title Interchain Token Service Genesis Config Generator
/// @notice Generates a yaml file comprising the storage slots and their values
/// Used by Telcoin-Network protocol to instantiate the contracts with required configuration at genesis

/// @dev Usage: `forge script script/GenerateITSGenesisConfig.s.sol -vvvv`
contract GenerateITSGenesisConfig is ITSGenesis, Script {
    Deployments deployments;
    string root;
    string dest;
    string fileName = "/deployments/genesis/its-config.yaml";

    uint64 sharedNonce = 0;
    uint256 sharedBalance = 0;
    // will be further decremented at genesis by protocol, based on initial validators stake
    uint256 iTELBalance = telTotalSupply - governanceInitialBalance;

    function setUp() public {
        root = vm.projectRoot();
        dest = string.concat(root, fileName);
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        /// @dev For testnet and mainnet genesis configs, use corresponding function
        _setUpDevnetConfig(deployments.admin, deployments.sepoliaTEL, deployments.wTEL, deployments.its.InterchainTEL);

        _setGenesisTargets(
            deployments.its,
            payable(deployments.wTEL),
            payable(deployments.its.InterchainTEL),
            deployments.its.InterchainTELTokenManager,
            payable(deployments.SafeImpl),
            deployments.SafeProxyFactory,
            payable(deployments.Safe)
        );

        // create3 contract only used for simulation; will not be instantiated at genesis
        create3 = new Create3Deployer{ salt: salts.Create3DeployerSalt }();
    }

    function run() public {
        vm.startBroadcast();

        // initialize clean yaml file
        if (vm.exists(dest)) vm.removeFile(dest);
        vm.writeLine(dest, "---"); // indicate yaml format

        // wTEL
        address simulatedWTEL = address(payable(instantiateWTEL()));
        assertFalse(yamlAppendGenesisAccount(dest, simulatedWTEL, deployments.wTEL, sharedNonce, sharedBalance));

        // iTEL before ITS to fetch token id for TokenHandler::constructor
        address simulatedInterchainTEL = address(instantiateInterchainTEL(deployments.its.InterchainTokenService));
        assertTrue(
            yamlAppendGenesisAccount(
                dest, simulatedInterchainTEL, deployments.its.InterchainTEL, sharedNonce, iTELBalance
            )
        );
        customLinkedTokenId = iTEL.interchainTokenId();

        // gateway impl (no storage)
        address simulatedGatewayImpl = address(instantiateAxelarAmplifierGatewayImpl());
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedGatewayImpl, deployments.its.AxelarAmplifierGatewayImpl, sharedNonce, sharedBalance
            )
        );
        // gateway (has storage)
        address simulatedGateway =
            address(instantiateAxelarAmplifierGateway(deployments.its.AxelarAmplifierGatewayImpl));
        assertTrue(
            yamlAppendGenesisAccount(
                dest, simulatedGateway, deployments.its.AxelarAmplifierGateway, sharedNonce, sharedBalance
            )
        );
        // token manager deployer (no storage)
        address simulatedTMD = address(instantiateTokenManagerDeployer());
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedTMD, deployments.its.TokenManagerDeployer, sharedNonce, sharedBalance
            )
        );
        // it impl (no storage)
        address simulatedITImpl = address(instantiateInterchainTokenImpl(deployments.its.InterchainTokenService));
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedITImpl, deployments.its.InterchainTokenImpl, sharedNonce, sharedBalance
            )
        );
        // itd (no storage)
        address simulatedITD = address(instantiateInterchainTokenDeployer(deployments.its.InterchainTokenImpl));
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedITD, deployments.its.InterchainTokenDeployer, sharedNonce, sharedBalance
            )
        );
        // tmImpl (no storage)
        address simulatedTMImpl = address(instantiateTokenManagerImpl(deployments.its.InterchainTokenService));
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedTMImpl, deployments.its.TokenManagerImpl, sharedNonce, sharedBalance
            )
        );
        // token handler (no storage)
        address simulatedTH = address(instantiateTokenHandler());
        assertFalse(
            yamlAppendGenesisAccount(dest, simulatedTH, deployments.its.TokenHandler, sharedNonce, sharedBalance)
        );

        // gas service (has storage)
        vm.startStateDiffRecording();
        address simulatedGSImpl = address(instantiateAxelarGasServiceImpl());
        assertFalse(
            yamlAppendGenesisAccount(dest, simulatedGSImpl, deployments.its.GasServiceImpl, sharedNonce, sharedBalance)
        );
        address simulatedGS = address(instantiateAxelarGasService(deployments.its.GasServiceImpl));
        assertTrue(yamlAppendGenesisAccount(dest, simulatedGS, deployments.its.GasService, sharedNonce, sharedBalance));

        // gateway caller (no storage)
        address simulatedGC =
            address(instantiateGatewayCaller(deployments.its.AxelarAmplifierGateway, deployments.its.GasService));
        assertFalse(
            yamlAppendGenesisAccount(dest, simulatedGC, deployments.its.GatewayCaller, sharedNonce, sharedBalance)
        );

        // its (has storage)
        address simulatedITSImpl = address(
            instantiateITSImpl(
                deployments.its.TokenManagerDeployer,
                deployments.its.InterchainTokenDeployer,
                deployments.its.AxelarAmplifierGateway,
                deployments.its.GasService,
                deployments.its.InterchainTokenFactory,
                deployments.its.TokenManagerImpl,
                deployments.its.TokenHandler,
                deployments.its.GatewayCaller
            )
        );
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedITSImpl, deployments.its.InterchainTokenServiceImpl, sharedNonce, sharedBalance
            )
        );
        address simulatedITS = address(instantiateITS(deployments.its.InterchainTokenServiceImpl));
        assertTrue(
            yamlAppendGenesisAccount(
                dest, simulatedITS, deployments.its.InterchainTokenService, sharedNonce, sharedBalance
            )
        );

        // itf (has storage)
        address simulatedITFImpl = address(instantiateITFImpl(deployments.its.InterchainTokenService));
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedITFImpl, deployments.its.InterchainTokenFactoryImpl, sharedNonce, sharedBalance
            )
        );
        address simulatedITF = address(instantiateITF(deployments.its.InterchainTokenFactoryImpl));
        assertTrue(
            yamlAppendGenesisAccount(
                dest, simulatedITF, deployments.its.InterchainTokenFactory, sharedNonce, sharedBalance
            )
        );

        // itel token manager (has storage)
        address simulatedInterchainTELTokenManager =
            address(instantiateInterchainTELTokenManager(deployments.its.InterchainTokenService, customLinkedTokenId));
        assertTrue(
            yamlAppendGenesisAccount(
                dest,
                simulatedInterchainTELTokenManager,
                deployments.its.InterchainTELTokenManager,
                sharedNonce,
                sharedBalance
            )
        );

        // safe impl (has storage)
        address simulatedSafeImpl = address(instantiateSafeImpl());
        assertTrue(yamlAppendGenesisAccount(dest, simulatedSafeImpl, deployments.SafeImpl, sharedNonce, sharedBalance));

        // safe proxy factory (no storage)
        address simulatedSafeFactory = address(instantiateSafeProxyFactory());
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedSafeFactory, deployments.SafeProxyFactory, sharedNonce, sharedBalance
            )
        );
        // governance safe (has storage)
        address simulatedSafe = address(instantiateGovernanceSafe());
        assertTrue(
            yamlAppendGenesisAccount(dest, simulatedSafe, deployments.Safe, sharedNonce, governanceInitialBalance)
        );

        vm.stopBroadcast();
    }
}
