// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Stablecoin } from "telcoin-contracts/contracts/stablecoin/Stablecoin.sol";
import { Deployments } from "../../../deployments/Deployments.sol";

/// @dev To deploy the Arachnid deterministic deployment proxy:
/// `cast send 0x3fab184622dc19b6109349b94811493bf2a45362 --value 0.01ether --rpc-url $TN_RPC_URL \
/// --private-key $ADMIN_PK`
/// `cast publish --rpc-url $TN_RPC_URL \
/// 0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222`
/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployTokens.s.sol \
/// --rpc-url $TN_RPC_URL -vvvv --private-key $ADMIN_PK`
// To verify StablecoinImpl: `forge verify-contract 0xd3930b15461fcecff57a4c9bd65abf6fa2a44307
// node_modules/telcoin-contracts/contracts/stablecoin/Stablecoin.sol:Stablecoin --rpc-url $TN_RPC_URL \
// --verifier sourcify --compiler-version 0.8.26 --num-of-optimizations 200`
// To verify Proxies: `forge verify-contract <eXYZ> \
// node_modules/@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy --rpc-url $TN_RPC_URL --verifier \
// sourcify --compiler-version 0.8.26 --num-of-optimizations 200`
contract TestnetDeployTokens is Script {

    Stablecoin stablecoinImpl;

    Deployments deployments;
    address admin; // admin, support, minter, burner role

    // shared Stablecoin creation params
    uint256 numStables;
    uint8 decimals_;
    bytes32 stablecoinSalt;
    bytes32 minterRole;
    bytes32 burnerRole;
    bytes32 supportRole;

    // specific Stablecoin creation params
    TokenMetadata[] metadatas;
    bytes32[] salts;
    bytes[] initDatas; // encoded Stablecoin.initialize() calls using metadatas

    struct TokenMetadata {
        string name;
        string symbol;
    }

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        admin = deployments.admin;

        numStables = 23;
        decimals_ = 6;

        // populate metadatas
        metadatas.push(TokenMetadata("Telcoin AUD", "eAUD"));
        metadatas.push(TokenMetadata("Telcoin CAD", "eCAD"));
        metadatas.push(TokenMetadata("Telcoin CFA", "eCFA"));
        metadatas.push(TokenMetadata("Telcoin CHF", "eCHF"));
        metadatas.push(TokenMetadata("Telcoin CZK", "eCZK"));
        metadatas.push(TokenMetadata("Telcoin DKK", "eDKK"));
        metadatas.push(TokenMetadata("Telcoin EUR", "eEUR"));
        metadatas.push(TokenMetadata("Telcoin GBP", "eGBP"));
        metadatas.push(TokenMetadata("Telcoin HKD", "eHKD"));
        metadatas.push(TokenMetadata("Telcoin HUF", "eHUF"));
        metadatas.push(TokenMetadata("Telcoin INR", "eINR"));
        metadatas.push(TokenMetadata("Telcoin ISK", "eISK"));
        metadatas.push(TokenMetadata("Telcoin JPY", "eJPY"));
        metadatas.push(TokenMetadata("Telcoin KES", "eKES"));
        metadatas.push(TokenMetadata("Telcoin MXN", "eMXN"));
        metadatas.push(TokenMetadata("Telcoin NOK", "eNOK"));
        metadatas.push(TokenMetadata("Telcoin NZD", "eNZD"));
        metadatas.push(TokenMetadata("Telcoin SDR", "eSDR"));
        metadatas.push(TokenMetadata("Telcoin SEK", "eSEK"));
        metadatas.push(TokenMetadata("Telcoin SGD", "eSGD"));
        metadatas.push(TokenMetadata("Telcoin TRY", "eTRY"));
        metadatas.push(TokenMetadata("Telcoin USD", "eUSD"));
        metadatas.push(TokenMetadata("Telcoin ZAR", "eZAR"));

        // populate deployDatas
        for (uint256 i; i < numStables; ++i) {
            TokenMetadata storage metadata = metadatas[i];
            bytes32 salt = bytes32(bytes(metadata.symbol));
            salts.push(salt);

            bytes memory initCall =
                abi.encodeWithSelector(Stablecoin.initialize.selector, metadata.name, metadata.symbol, decimals_);
            initDatas.push(initCall);
        }
    }

    function run() public {
        vm.startBroadcast();

        // deploy stablecoin impl and proxies
        stablecoinSalt = bytes32(bytes("Stablecoin"));

        /// @dev Configure as necessary for new / existing deployments
        // stablecoinImpl = new Stablecoin{ salt: stablecoinSalt }();
        stablecoinImpl = Stablecoin(deployments.StablecoinImpl);

        address[] memory deployedTokens = new address[](numStables);
        for (uint256 i; i < numStables; ++i) {
            bytes32 currentSalt = bytes32(bytes(metadatas[i].symbol));
            // leave ERC1967 initdata empty to properly set default admin role
            address stablecoin = address(new ERC1967Proxy{ salt: currentSalt }(address(stablecoinImpl), ""));
            
            /// @dev for debugging
            // bytes memory bytecode = bytes.concat(type(ERC1967Proxy).creationCode, abi.encode(address(stablecoinImpl), ""));
            // address stablecoin = computeAddress(deployments.ArachnidDeterministicDeployFactory, currentSalt, bytecode);

            // initialize manually from admin address since adminRole => msg.sender
            (bool r,) = stablecoin.call(initDatas[i]);
            require(r, "Initialization failed");

            // grant deployer minter, burner & support roles
            minterRole = Stablecoin(stablecoin).MINTER_ROLE();
            burnerRole = Stablecoin(stablecoin).BURNER_ROLE();
            supportRole = Stablecoin(stablecoin).SUPPORT_ROLE();
            Stablecoin(stablecoin).grantRole(minterRole, admin);
            Stablecoin(stablecoin).grantRole(burnerRole, admin);
            Stablecoin(stablecoin).grantRole(supportRole, admin);

            // push to array for asserts
            deployedTokens[i] = stablecoin;
        }

        vm.stopBroadcast();

        // asserts
        for (uint256 i; i < numStables; ++i) {
            TokenMetadata memory tokenMetadata = metadatas[i];

            Stablecoin token = Stablecoin(deployedTokens[i]);
            assert(keccak256(bytes(token.name())) == keccak256(bytes(tokenMetadata.name)));
            assert(keccak256(bytes(token.symbol())) == keccak256(bytes(tokenMetadata.symbol)));
            assert(token.decimals() == decimals_);
            assert(token.hasRole(token.DEFAULT_ADMIN_ROLE(), admin));
            assert(token.hasRole(minterRole, admin));
            assert(token.hasRole(burnerRole, admin));
            assert(token.hasRole(supportRole, admin));
        }

        // logs
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(stablecoinImpl))), 20), dest, ".StablecoinImpl");
        for (uint256 i; i < numStables; ++i) {
            string memory jsonKey = string.concat(".eXYZs.", Stablecoin(deployedTokens[i]).symbol());
            vm.writeJson(LibString.toHexString(uint256(uint160(deployedTokens[i])), 20), dest, jsonKey);
        }
    }

    function computeAddress(address deployer, bytes32 salt, bytes memory bytecode) public pure returns (address) {
        bytes32 addrHash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                deployer,
                salt,
                keccak256(bytecode)
            )
        );
     
        return address(uint160(uint256(addrHash)));
    }
}
