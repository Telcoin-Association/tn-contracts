// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { RecoverableWrapper } from "recoverable-wrapper/contracts/rwt/RecoverableWrapper.sol";
import { Stablecoin } from "telcoin-contracts/contracts/stablecoin/Stablecoin.sol";
import { WTEL } from "../../../src/WTEL.sol";
import { Deployments } from "../../../deployments/Deployments.sol";

/// @dev To deploy the Arachnid deterministic deployment proxy:
/// `cast send 0x3fab184622dc19b6109349b94811493bf2a45362 --value 0.01ether --rpc-url $TN_RPC_URL --private-key
/// $ADMIN_PK`
/// `cast publish --rpc-url $TN_RPC_URL
/// 0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222`
/// @dev Usage: `forge script script/deploy/TestnetDeployTokens.s.sol --rpc-url $TN_RPC_URL -vvvv --private-key
/// $ADMIN_PK`
// To verify WTEL: `forge verify-contract 0x5c78ebbcfdc8fd432c6d7581f6f8e6b82079f24a src/WTEL.sol:WTEL \
// --rpc-url $TN_RPC_URL --verifier sourcify --compiler-version 0.8.26 --num-of-optimizations 200`
// To verify StablecoinImpl: `forge verify-contract 0xd3930b15461fcecff57a4c9bd65abf6fa2a44307
// node_modules/telcoin-contracts/contracts/stablecoin/Stablecoin.sol:Stablecoin --rpc-url $TN_RPC_URL \
// --verifier sourcify --compiler-version 0.8.26 --num-of-optimizations 200`
// To verify Proxies: `forge verify-contract <eXYZ> \
// node_modules/@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy --rpc-url $TN_RPC_URL --verifier \
// sourcify --compiler-version 0.8.26 --num-of-optimizations 200`
contract TestnetDeployTokens is Script {
    WTEL wTEL;
    RecoverableWrapper rwTEL;

    Stablecoin stablecoinImpl;
    Stablecoin eAUD;
    Stablecoin eCAD;
    Stablecoin eCHF;
    Stablecoin eEUR;
    Stablecoin eGBP;
    Stablecoin eHKD;
    Stablecoin eMXN;
    Stablecoin eNOK;
    Stablecoin eJPY;
    Stablecoin eSDR;
    Stablecoin eSGD;

    Deployments deployments;
    address admin; // admin, support, minter, burner role

    bytes32 wTELsalt;

    // rwTEL constructor params
    string name_;
    string symbol_;
    uint256 recoverableWindow_;
    address governanceAddress_;
    address baseERC20_;
    uint16 maxToClean;
    bytes32 rwTELsalt;

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
        wTELsalt = bytes32(bytes("wTEL"));
        rwTELsalt = bytes32(bytes("rwTEL"));
        name_ = "Recoverable Wrapped Telcoin";
        symbol_ = "rwTEL";
        recoverableWindow_ = 86_400; // ~1 day; Telcoin Network blocktime is ~1s
        governanceAddress_ = admin; // multisig/council/DAO address in prod
        maxToClean = type(uint16).max; // gas is not expected to be an obstacle; clear all relevant storage

        numStables = 11;
        decimals_ = 6;

        // populate metadatas
        metadatas.push(TokenMetadata("Telcoin AUD", "eAUD"));
        metadatas.push(TokenMetadata("Telcoin CAD", "eCAD"));
        metadatas.push(TokenMetadata("Telcoin CHF", "eCHF"));
        metadatas.push(TokenMetadata("Telcoin EUR", "eEUR"));
        metadatas.push(TokenMetadata("Telcoin GBP", "eGBP"));
        metadatas.push(TokenMetadata("Telcoin HKD", "eHKD"));
        metadatas.push(TokenMetadata("Telcoin MXN", "eMXN"));
        metadatas.push(TokenMetadata("Telcoin NOK", "eNOK"));
        metadatas.push(TokenMetadata("Telcoin JPY", "eJPY"));
        metadatas.push(TokenMetadata("Telcoin SDR", "eSDR"));
        metadatas.push(TokenMetadata("Telcoin SGD", "eSGD"));

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

        wTEL = new WTEL{ salt: wTELsalt }();
        baseERC20_ = address(wTEL);

        rwTEL = new RecoverableWrapper{ salt: rwTELsalt }(
            name_, symbol_, recoverableWindow_, governanceAddress_, baseERC20_, maxToClean
        );

        // deploy stablecoin impl and proxies
        stablecoinSalt = bytes32(bytes("Stablecoin"));
        stablecoinImpl = new Stablecoin{ salt: stablecoinSalt }();
        address[] memory deployedTokens = new address[](numStables);
        for (uint256 i; i < numStables; ++i) {
            bytes32 currentSalt = bytes32(bytes(metadatas[i].symbol));
            // leave ERC1967 initdata empty to properly set default admin role
            address stablecoin = address(new ERC1967Proxy{ salt: currentSalt }(address(stablecoinImpl), ""));
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
        assert(rwTEL.baseToken() == address(wTEL));
        assert(rwTEL.governanceAddress() == admin);

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
        vm.writeJson(LibString.toHexString(uint256(uint160(address(wTEL))), 20), dest, ".wTEL");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(rwTEL))), 20), dest, ".rwTEL");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(stablecoinImpl))), 20), dest, ".StablecoinImpl");
        for (uint256 i; i < numStables; ++i) {
            string memory jsonKey = string.concat(".", Stablecoin(deployedTokens[i]).symbol());
            vm.writeJson(LibString.toHexString(uint256(uint160(deployedTokens[i])), 20), dest, jsonKey);
        }
    }
}
