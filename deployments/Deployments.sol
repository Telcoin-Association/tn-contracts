/// SPDX-License-Identifier MIT or Apache-2.0
pragma solidity ^0.8.26;

/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
/// therefore upper-case struct member names must come **BEFORE** lower-case ones!
struct Deployments {
    address ArachnidDeterministicDeployFactory;
    address ConsensusRegistry;
    address GitAttestationRegistry;
    address Issuance;
    address Safe;
    address SafeImpl;
    address SafeProxyFactory;
    address StablecoinImpl;
    address StablecoinManager;
    address StablecoinManagerImpl;
    address StakeManager;
    address TANIssuanceHistory;
    address TANIssuancePlugin;
    address admin;
    EXYZs eXYZs;
    ITS its;
    address optimismTEL;
    address sepoliaTEL;
    UniswapV2 uniswapV2;
    address wTEL;
}

/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
struct ITS {
    address AxelarAmplifierGateway;
    address AxelarAmplifierGatewayImpl;
    address GasService;
    address GasServiceImpl;
    address GatewayCaller;
    address InterchainTEL;
    address InterchainTELTokenManager;
    address InterchainTokenDeployer;
    address InterchainTokenFactory;
    address InterchainTokenFactoryImpl;
    address InterchainTokenImpl;
    address InterchainTokenService;
    address InterchainTokenServiceImpl;
    address TokenHandler;
    address TokenManagerDeployer;
    address TokenManagerImpl;
}

/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
struct EXYZs {
    address eAUD;
    address eCAD;
    address eCFA;
    address eCHF;
    address eCZK;
    address eDKK;
    address eEUR;
    address eGBP;
    address eHKD;
    address eHUF;
    address eINR;
    address eISK;
    address eJPY;
    address eKES;
    address eMXN;
    address eNOK;
    address eNZD;
    address eSDR;
    address eSEK;
    address eSGD;
    address eTRY;
    address eUSD;
    address eZAR;
}

/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
struct UniswapV2 {
    address UniswapV2Factory;
    address UniswapV2Router02;
    address eEUR_eAUD_Pool;
    address eEUR_eCAD_Pool;
    address eEUR_eCFA_Pool;
    address eEUR_eCHF_Pool;
    address eEUR_eCZK_Pool;
    address eEUR_eDKK_Pool;
    address eEUR_eGBP_Pool;
    address eEUR_eHKD_Pool;
    address eEUR_eHUF_Pool;
    address eEUR_eINR_Pool;
    address eEUR_eISK_Pool;
    address eEUR_eJPY_Pool;
    address eEUR_eKES_Pool;
    address eEUR_eMXN_Pool;
    address eEUR_eNOK_Pool;
    address eEUR_eNZD_Pool;
    address eEUR_eSDR_Pool;
    address eEUR_eSEK_Pool;
    address eEUR_eSGD_Pool;
    address eEUR_eTRY_Pool;
    address eEUR_eZAR_Pool;
    address eUSD_eAUD_Pool;
    address eUSD_eCAD_Pool;
    address eUSD_eCFA_Pool;
    address eUSD_eCHF_Pool;
    address eUSD_eCZK_Pool;
    address eUSD_eDKK_Pool;
    address eUSD_eEUR_Pool;
    address eUSD_eGBP_Pool;
    address eUSD_eHKD_Pool;
    address eUSD_eHUF_Pool;
    address eUSD_eINR_Pool;
    address eUSD_eISK_Pool;
    address eUSD_eJPY_Pool;
    address eUSD_eKES_Pool;
    address eUSD_eMXN_Pool;
    address eUSD_eNOK_Pool;
    address eUSD_eNZD_Pool;
    address eUSD_eSDR_Pool;
    address eUSD_eSEK_Pool;
    address eUSD_eSGD_Pool;
    address eUSD_eTRY_Pool;
    address eUSD_eZAR_Pool;
    address wTEL_eEUR_Pool;
    address wTEL_eUSD_Pool;
}
