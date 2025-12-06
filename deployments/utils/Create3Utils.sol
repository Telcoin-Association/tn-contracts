/// SPDX-License-Identifier MIT or Apache-2.0
pragma solidity ^0.8.26;

import { Create3Deployer } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/deploy/Create3Deployer.sol";
import { AxelarAmplifierGateway } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol";

/// @dev Configuration and utilities for Create3 deterministic deployments
/// @notice Used extensively for Axelar ITS contracts

struct Salts {
    /// @notice create2 salt; Create3Deployer contract must be deployed with `create2`
    bytes32 Create3DeployerSalt;
    // create3 salts
    bytes32 gatewaySalt;
    bytes32 gcSalt; 
    bytes32 gsSalt;
    bytes32 itdSalt;
    bytes32 itfSalt;
    bytes32 itsSalt;
    bytes32 thSalt;
    bytes32 tmSalt;
    bytes32 tmdSalt;
    bytes32 wtelSalt;
    bytes32 itelSalt;
    bytes32 itelTMSalt;
    bytes32 registerCustomTokenSalt;
}

/// @dev Proxy implementation salts separated into second `ImplSalts` struct for "stack too deep"
struct ImplSalts {
    bytes32 gatewayImplSalt;
    bytes32 gsImplSalt;
    bytes32 itImplSalt;
    bytes32 itfImplSalt;
    bytes32 itsImplSalt;
    bytes32 tmImplSalt;
}

abstract contract Create3Utils {

    Salts public salts = Salts({
        /// @notice create2 salt; Create3Deployer contract must be deployed with `create2`
        Create3DeployerSalt: keccak256("create3-deployer"),
        // create3 salts
        gatewaySalt: keccak256("axelar-amplifier-gateway"),
        gcSalt: keccak256("gateway-caller"),
        gsSalt: keccak256("axelar-gas-service"),
        itdSalt: keccak256("interchain-token-deployer"),
        itfSalt: keccak256("interchain-token-factory"),
        itsSalt: keccak256("interchain-token-service"),
        thSalt: keccak256("token-handler"),
        tmSalt: keccak256("token-manager"),
        tmdSalt: keccak256("token-manager-deployer"),
        wtelSalt: keccak256("wrapped-telcoin"),
        itelSalt: keccak256("interchain-telcoin"),
        itelTMSalt: keccak256("itel-token-manager"),
        registerCustomTokenSalt: keccak256("telcoin-v3")
    });

    ImplSalts public implSalts = ImplSalts({
        gatewayImplSalt: keccak256("axelar-amplifier-gateway-impl"),
        gsImplSalt: keccak256("axelar-gas-service-impl"),
        itImplSalt: keccak256("interchain-token-impl"),
        itfImplSalt: keccak256("interchain-token-factory-impl"),
        itsImplSalt: keccak256("interchain-token-service-impl"),
        tmImplSalt: keccak256("token-manager-impl")
    });


    /// @dev Deploys a contract using `CREATE3`
    function create3Deploy(
        Create3Deployer create3Deployer,
        bytes memory contractCreationCode,
        bytes memory constructorArgs,
        bytes32 salt
    ) public returns (address deployment) {
        bytes memory contractInitCode = bytes.concat(
            contractCreationCode,
            constructorArgs
        );
        return create3Deployer.deploy(contractInitCode, salt);
    }

    /// @dev Returns the expected contract deployment address using `CREATE3`
    function create3Address(Create3Deployer create3Deployer, bytes memory contractCreationCode, bytes memory constructorArgs, address sender, bytes32 salt) public view returns (address expectedDeployment) {
        bytes memory contractInitCode = bytes.concat(
            contractCreationCode,
            constructorArgs
        );
        return create3Deployer.deployedAddress(contractInitCode, sender, salt);
    }
}