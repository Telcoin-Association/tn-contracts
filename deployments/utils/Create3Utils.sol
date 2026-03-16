/// SPDX-License-Identifier MIT or Apache-2.0
pragma solidity ^0.8.26;

import { Create3Deployer } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/deploy/Create3Deployer.sol";

/// @dev Configuration and utilities for Create3 deterministic deployments

struct Salts {
    /// @notice create2 salt; Create3Deployer contract must be deployed with `create2`
    bytes32 Create3DeployerSalt;
}

abstract contract Create3Utils {

    Salts public salts = Salts({
        /// @notice create2 salt; Create3Deployer contract must be deployed with `create2`
        Create3DeployerSalt: keccak256("create3-deployer")
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
