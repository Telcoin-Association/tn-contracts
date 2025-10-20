// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { CREATE3 } from "solady/utils/CREATE3.sol";
import { IUniswapV2Factory } from "external/uniswap/interfaces/IUniswapV2Factory.sol";
import { IUniswapV2Router02 } from "external/uniswap/interfaces/IUniswapV2Router02.sol";
import { IUniswapV2Pair } from "external/uniswap/interfaces/IUniswapV2Pair.sol";
import { UniswapV2FactoryBytecode } from "external/uniswap/precompiles/UniswapV2FactoryBytecode.sol";
import { UniswapV2Router02Bytecode } from "external/uniswap/precompiles/UniswapV2Router02Bytecode.sol";
import { WTEL } from "../../../src/WTEL.sol";
import { Deployments } from "../../../deployments/Deployments.sol";

/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployUniswapV2.s.sol -vvvv \
///--rpc-url $TN_RPC_URL --private-key $ADMIN_PK`
contract TestnetDeployUniswapV2 is Script, UniswapV2FactoryBytecode, UniswapV2Router02Bytecode {
    // deploys the following:
    IUniswapV2Factory uniswapV2Factory;
    IUniswapV2Router02 uniswapV2Router02;
    IUniswapV2Pair[] pairs; // 45 pairs: 22 for eUSD, 21 for eEUR, wTEL<>eUSD, wTEL<>eEUR

    // config
    Deployments deployments;
    address wTEL;
    address feeToSetter_;
    address admin;
    bytes32 factorySalt;
    bytes32 routerSalt;
    address[] stables;
    uint256 eEURNumPairs; // 23 stables less eEUR and eUSD == 21
    uint256 eUSDNumPairs; // 23 stables less eUSD == 22

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        wTEL = deployments.wTEL;
        admin = deployments.admin;
        feeToSetter_ = admin;
        factorySalt = bytes32(bytes("UniswapV2Factory"));
        routerSalt = bytes32(bytes("UniswapV2Router02"));

        stables.push(deployments.eXYZs.eAUD);
        stables.push(deployments.eXYZs.eCAD);
        stables.push(deployments.eXYZs.eCFA);
        stables.push(deployments.eXYZs.eCHF);
        stables.push(deployments.eXYZs.eCZK);
        stables.push(deployments.eXYZs.eDKK);
        stables.push(deployments.eXYZs.eEUR);
        stables.push(deployments.eXYZs.eGBP);
        stables.push(deployments.eXYZs.eHKD);
        stables.push(deployments.eXYZs.eHUF);
        stables.push(deployments.eXYZs.eINR);
        stables.push(deployments.eXYZs.eISK);
        stables.push(deployments.eXYZs.eJPY);
        stables.push(deployments.eXYZs.eKES);
        stables.push(deployments.eXYZs.eMXN);
        stables.push(deployments.eXYZs.eNOK);
        stables.push(deployments.eXYZs.eNZD);
        stables.push(deployments.eXYZs.eSDR);
        stables.push(deployments.eXYZs.eSEK);
        stables.push(deployments.eXYZs.eSGD);
        stables.push(deployments.eXYZs.eTRY);
        stables.push(deployments.eXYZs.eUSD);
        stables.push(deployments.eXYZs.eZAR);
    }

    function run() public {
        vm.startBroadcast();

        /// @dev Customize appropriately; for existing deployments:
        // uniswapV2Factory = IUniswapV2Factory(deployments.uniswapV2.UniswapV2Factory);
        // uniswapV2Router02 = IUniswapV2Router02(deployments.uniswapV2.UniswapV2Router02);

        /// @dev Customize appropriately; for new deployments:
        // deploy v2 core contracts
        bytes memory factoryInitcode = bytes.concat(UNISWAPV2FACTORY_BYTECODE, abi.encode(feeToSetter_));
        (bool factoryRes, bytes memory factoryRet) =
            deployments.ArachnidDeterministicDeployFactory.call(bytes.concat(factorySalt, factoryInitcode));
        require(factoryRes);
        uniswapV2Factory = IUniswapV2Factory(address(bytes20(factoryRet)));

        // deploy v2 periphery contracts
        bytes memory router02Initcode = bytes.concat(
            UNISWAPV2ROUTER02_BYTECODE,
            bytes32(uint256(uint160(address(uniswapV2Factory)))),
            bytes32(uint256(uint160(wTEL)))
        );
        (bool routerRes, bytes memory routerRet) =
            deployments.ArachnidDeterministicDeployFactory.call(bytes.concat(routerSalt, router02Initcode));
        require(routerRes);
        uniswapV2Router02 = IUniswapV2Router02(address(bytes20(routerRet)));

        // deploy v2 pools for eEUR and record pairs
        for (uint256 i; i < stables.length; ++i) {
            // for eEUR pools, skip eEUR (can't be paired with self) && eUSD (deployed in last loop)
            if (stables[i] == deployments.eXYZs.eUSD || stables[i] == deployments.eXYZs.eEUR) continue;
            
            IUniswapV2Pair eEURcurrentPair =
                IUniswapV2Pair(uniswapV2Factory.createPair(deployments.eXYZs.eEUR, stables[i]));
                // or for live deployments:
                // IUniswapV2Pair(uniswapV2Factory.getPair(deployments.eXYZs.eEUR, stables[i]));
            pairs.push(eEURcurrentPair);
        }

        // deploy v2 pools for eUSD and record pairs
        for (uint256 i; i < stables.length; ++i) {
            // for eUSD pools, skip eUSD (can't be paired with self)
            if (stables[i] == deployments.eXYZs.eUSD) continue;

            IUniswapV2Pair eUSDcurrentPair =
                IUniswapV2Pair(uniswapV2Factory.createPair(deployments.eXYZs.eUSD, stables[i]));
                // or for live deployments:
                // IUniswapV2Pair(uniswapV2Factory.getPair(deployments.eXYZs.eUSD, stables[i]));
            pairs.push(eUSDcurrentPair);
        }

        // deploy wTEL pools for both eEUR and eUSD, record pairs
        IUniswapV2Pair wTELeEURPair = IUniswapV2Pair(uniswapV2Factory.createPair(wTEL, deployments.eXYZs.eEUR));
        pairs.push(wTELeEURPair);
        IUniswapV2Pair wTELeUSDPair = IUniswapV2Pair(uniswapV2Factory.createPair(wTEL, deployments.eXYZs.eUSD));
        pairs.push(wTELeUSDPair);

        // for live deployments, use existing pairs
        // IUniswapV2Pair wTELeEURPair = uniswapV2Factory.getPair(wTEL, deployments.eXYZs.eEUR);
        // pairs.push(wTELeEURPair);
        // IUniswapV2Pair wTELeUSDPair = uniswapV2Factory.getPair(wTEL, deployments.eXYZs.eUSD);
        // pairs.push(wTELeUSDPair);

        vm.stopBroadcast();

        // asserts
        assert(address(uniswapV2Factory).code.length != 0);
        assert(uniswapV2Factory.feeToSetter() == admin);
        assert(address(uniswapV2Router02).code.length != 0);
        assert(uniswapV2Router02.factory() == address(uniswapV2Factory));
        assert(uniswapV2Router02.WETH() == wTEL);

        assert(stables.length == 23);
        assert(pairs.length == 45); // 22 for eUSD pairs, 21 for eEUR pairs, wTEL<>eUSD, wTEL<>eEUR
        for (uint256 i; i < pairs.length; ++i) {
            IUniswapV2Pair currentPair = pairs[i];
            bool correctFactory = currentPair.factory() == address(uniswapV2Factory);
            assert(correctFactory);

            address token0 = currentPair.token0();
            address token1 = currentPair.token1();

            bool correctToken0;
            bool correctToken1;
            eEURNumPairs = stables.length - 2;
            eUSDNumPairs = stables.length - 1;
            if (i < eEURNumPairs) {
                // search stables array
                for (uint256 j; j < stables.length; ++j) {
                    // skip eEUR && eUSD
                    if (stables[j] == deployments.eXYZs.eEUR || stables[j] == deployments.eXYZs.eUSD) continue;

                    // should be a stable paired with eEUR; skip matches already found
                    if (!correctToken0) correctToken0 = token0 == stables[j] || token0 == deployments.eXYZs.eEUR;
                    if (!correctToken1) correctToken1 = token1 == stables[j] || token1 == deployments.eXYZs.eEUR;
                }
            } else if (i >= eEURNumPairs && i < eEURNumPairs + eUSDNumPairs) {
                // search stables array
                for (uint256 j; j < stables.length; ++j) {
                    // skip eUSD
                    if (stables[j] == deployments.eXYZs.eUSD) continue;

                    // should be a stable paired with eUSD; skip matches already found
                    if (!correctToken0) correctToken0 = token0 == stables[j] || token0 == deployments.eXYZs.eUSD;
                    if (!correctToken1) correctToken1 = token1 == stables[j] || token1 == deployments.eXYZs.eUSD;
                }
            } else {
                // last two pools are wTEL<>eEUR or wTEL<>eUSD
                if (i == pairs.length - 2) {
                    // shold be wTEL<>eEUR; skip matches already found
                    if (!correctToken0) correctToken0 = token0 == wTEL || token0 == deployments.eXYZs.eEUR;
                    if (!correctToken1) correctToken1 = token1 == wTEL || token1 == deployments.eXYZs.eEUR;
                }

                if (i == pairs.length - 1) {
                    // shold be wTEL<>eUSD; skip matches already found
                    if (!correctToken0) correctToken0 = token0 == wTEL || token0 == deployments.eXYZs.eUSD;
                    if (!correctToken1) correctToken1 = token1 == wTEL || token1 == deployments.eXYZs.eUSD;
                }
            }

            assert(correctToken0);
            assert(correctToken1);
        }

        // logs
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(uniswapV2Factory))), 20), dest, ".uniswapV2.UniswapV2Factory");
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(uniswapV2Router02))), 20), dest, ".uniswapV2.UniswapV2Router02"
        );
        vm.writeJson(LibString.toHexString(uint256(uint160(address(pairs[0]))), 20), dest, ".uniswapV2.eEUR_eAUD_Pool");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(pairs[1]))), 20), dest, ".uniswapV2.eEUR_eCAD_Pool");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(pairs[2]))), 20), dest, ".uniswapV2.eEUR_eCFA_Pool");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(pairs[3]))), 20), dest, ".uniswapV2.eEUR_eCHF_Pool");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(pairs[4]))), 20), dest, ".uniswapV2.eEUR_eCZK_Pool");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(pairs[5]))), 20), dest, ".uniswapV2.eEUR_eDKK_Pool");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(pairs[6]))), 20), dest, ".uniswapV2.eEUR_eGBP_Pool");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(pairs[7]))), 20), dest, ".uniswapV2.eEUR_eHKD_Pool");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(pairs[8]))), 20), dest, ".uniswapV2.eEUR_eHUF_Pool");
        vm.writeJson(LibString.toHexString(uint256(uint160(address(pairs[9]))), 20), dest, ".uniswapV2.eEUR_eINR_Pool");
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[10]))), 20), dest, ".uniswapV2.eEUR_eISK_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[11]))), 20), dest, ".uniswapV2.eEUR_eJPY_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[12]))), 20), dest, ".uniswapV2.eEUR_eKES_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[13]))), 20), dest, ".uniswapV2.eEUR_eMXN_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[14]))), 20), dest, ".uniswapV2.eEUR_eNOK_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[15]))), 20), dest, ".uniswapV2.eEUR_eNZD_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[16]))), 20), dest, ".uniswapV2.eEUR_eSDR_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[17]))), 20), dest, ".uniswapV2.eEUR_eSEK_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[18]))), 20), dest, ".uniswapV2.eEUR_eSGD_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[19]))), 20), dest, ".uniswapV2.eEUR_eTRY_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[20]))), 20), dest, ".uniswapV2.eEUR_eZAR_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[21]))), 20), dest, ".uniswapV2.eUSD_eAUD_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[22]))), 20), dest, ".uniswapV2.eUSD_eCAD_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[23]))), 20), dest, ".uniswapV2.eUSD_eCFA_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[24]))), 20), dest, ".uniswapV2.eUSD_eCHF_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[25]))), 20), dest, ".uniswapV2.eUSD_eCZK_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[26]))), 20), dest, ".uniswapV2.eUSD_eDKK_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[27]))), 20), dest, ".uniswapV2.eUSD_eEUR_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[28]))), 20), dest, ".uniswapV2.eUSD_eGBP_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[29]))), 20), dest, ".uniswapV2.eUSD_eHKD_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[30]))), 20), dest, ".uniswapV2.eUSD_eHUF_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[31]))), 20), dest, ".uniswapV2.eUSD_eINR_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[32]))), 20), dest, ".uniswapV2.eUSD_eISK_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[33]))), 20), dest, ".uniswapV2.eUSD_eJPY_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[34]))), 20), dest, ".uniswapV2.eUSD_eKES_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[35]))), 20), dest, ".uniswapV2.eUSD_eMXN_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[36]))), 20), dest, ".uniswapV2.eUSD_eNOK_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[37]))), 20), dest, ".uniswapV2.eUSD_eNZD_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[38]))), 20), dest, ".uniswapV2.eUSD_eSDR_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[39]))), 20), dest, ".uniswapV2.eUSD_eSEK_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[40]))), 20), dest, ".uniswapV2.eUSD_eSGD_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[41]))), 20), dest, ".uniswapV2.eUSD_eTRY_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[42]))), 20), dest, ".uniswapV2.eUSD_eZAR_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[43]))), 20), dest, ".uniswapV2.wTEL_eEUR_Pool"
        );
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(pairs[44]))), 20), dest, ".uniswapV2.wTEL_eUSD_Pool"
        );
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
