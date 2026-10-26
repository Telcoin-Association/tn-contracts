// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { console2 } from "forge-std/console2.sol";
import { UniswapV2FactoryBytecode } from "external/uniswap/precompiles/UniswapV2FactoryBytecode.sol";
import { UniswapV3FactoryBytecode } from "external/uniswap/precompiles/v3/UniswapV3Factory.sol";
import { NFTDescriptorBytecode } from "external/uniswap/precompiles/v3/NFTDescriptor.sol";
import {
    NonfungibleTokenPositionDescriptorBytecode
} from "external/uniswap/precompiles/v3/NonfungibleTokenPositionDescriptor.sol";
import { NonfungiblePositionManagerBytecode } from "external/uniswap/precompiles/v3/NonfungiblePositionManager.sol";
import { QuoterV2Bytecode } from "external/uniswap/precompiles/v3/QuoterV2.sol";
import { TickLensBytecode } from "external/uniswap/precompiles/v3/TickLens.sol";
import { SwapRouter02Bytecode } from "external/uniswap/precompiles/v3/SwapRouter02.sol";
import { MainnetDeployBase } from "../MainnetDeployBase.sol";
import { UniswapV3FactoryDeployer, IUniswapV3FactoryAdmin } from "../../utils/UniswapV3FactoryDeployer.sol";
import { UNISWAP_V2_FACTORY_SALT } from "./MainnetDeployUniswapV2.s.sol";

/// @notice Constructor-pinned getters shared by the V3 periphery contracts
interface IV3Periphery {
    function factory() external view returns (address);
    function WETH9() external view returns (address);
}

interface ISwapRouter02 {
    function factoryV2() external view returns (address);
    function positionManager() external view returns (address);
}

/// @title Deploy Uniswap V3 on Telcoin Network mainnet
///
/// @notice Deploys UniswapV3Factory and the v3-periphery contracts: NFTDescriptor,
///         NonfungibleTokenPositionDescriptor, NonfungiblePositionManager, SwapRouter02,
///         QuoterV2 and TickLens. No pools are created.
///
/// @notice The factory is created by `UniswapV3FactoryDeployer` (itself deployed through the
///         Arachnid proxy), which enables the 0.01% fee tier and transfers factory ownership to
///         the governance Safe in the same transaction. Every other contract is deployed
///         directly through the Arachnid proxy. All addresses are therefore deterministic and
///         a re-run is a no-op.
///
/// @notice Requires Uniswap V2: SwapRouter02 routes across V2 and V3 and takes the V2 factory
///         as a constructor argument. Run MainnetDeployUniswapV2 first.
///
/// @dev The vendored factory initcode is the canonical v3-core 1.0.0 build, which fixes the
///      pool init code hash at the canonical
///      0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54.
///      See external/uniswap/precompiles/v3/README.md.
///
/// @dev Usage: `forge script script/mainnet/deploy/MainnetDeployUniswapV3.s.sol -vvvv \
///      --rpc-url $TN_MAINNET_RPC_URL --private-key $DEPLOYER_PK --broadcast`
contract MainnetDeployUniswapV3 is
    MainnetDeployBase,
    UniswapV2FactoryBytecode,
    UniswapV3FactoryBytecode,
    NFTDescriptorBytecode,
    NonfungibleTokenPositionDescriptorBytecode,
    NonfungiblePositionManagerBytecode,
    QuoterV2Bytecode,
    TickLensBytecode,
    SwapRouter02Bytecode
{
    /// @notice Native currency label rendered in position NFT metadata
    bytes32 internal constant NATIVE_CURRENCY_LABEL = bytes32("TEL");

    /// @dev Byte offset of the NFTDescriptor library-link placeholder within
    ///      NonfungibleTokenPositionDescriptor's creation code (v3-periphery 1.4.4
    ///      `linkReferences`)
    uint256 internal constant DESC_LIB_LINK_OFFSET = 1681;

    bytes32 internal constant V3_FACTORY_INITCODE_HASH =
        0xa9cb11ffa1b1bf9a9a2b70b66f6a22db3e8328b37ec44e6ce602749081efdb6d;

    bytes32 internal constant FACTORY_DEPLOYER_SALT = bytes32(bytes("UniswapV3FactoryDeployer"));
    bytes32 internal constant NFT_DESCRIPTOR_SALT = bytes32(bytes("NFTDescriptor"));
    bytes32 internal constant POSITION_DESCRIPTOR_SALT = bytes32(bytes("NFTPositionDescriptor"));
    bytes32 internal constant POSITION_MANAGER_SALT = bytes32(bytes("NonfungiblePositionManager"));
    bytes32 internal constant SWAP_ROUTER_02_SALT = bytes32(bytes("SwapRouter02"));
    bytes32 internal constant QUOTER_V2_SALT = bytes32(bytes("QuoterV2"));
    bytes32 internal constant TICK_LENS_SALT = bytes32(bytes("TickLens"));

    function run() public {
        _loadMainnet();
        address wtel = deployments.WTEL;
        _requireCode(wtel, "WTEL");
        address v2Factory = _resolveV2Factory();
        _requireCode(v2Factory, "UniswapV2Factory; run MainnetDeployUniswapV2 first");
        require(
            keccak256(UNISWAPV3FACTORY_BYTECODE) == V3_FACTORY_INITCODE_HASH,
            "MainnetDeployUniswapV3: vendored factory initcode hash mismatch"
        );

        vm.startBroadcast();
        (address factory, bool factoryDeployed) = _deployFactory();
        address nftDescriptor = _deployDeterministic(NFT_DESCRIPTOR_SALT, NFTDESCRIPTOR_BYTECODE, "NFTDescriptor");
        address positionDescriptor = _deployDeterministic(
            POSITION_DESCRIPTOR_SALT,
            bytes.concat(
                _linkNFTDescriptor(NONFUNGIBLE_TOKEN_POSITION_DESCRIPTOR_BYTECODE, nftDescriptor),
                abi.encode(wtel, NATIVE_CURRENCY_LABEL)
            ),
            "NonfungibleTokenPositionDescriptor"
        );
        address positionManager = _deployDeterministic(
            POSITION_MANAGER_SALT,
            bytes.concat(NONFUNGIBLE_POSITION_MANAGER_BYTECODE, abi.encode(factory, wtel, positionDescriptor)),
            "NonfungiblePositionManager"
        );
        address swapRouter02 = _deployDeterministic(
            SWAP_ROUTER_02_SALT,
            bytes.concat(SWAP_ROUTER_02_BYTECODE, abi.encode(v2Factory, factory, positionManager, wtel)),
            "SwapRouter02"
        );
        address quoterV2 = _deployDeterministic(
            QUOTER_V2_SALT, bytes.concat(QUOTER_V2_BYTECODE, abi.encode(factory, wtel)), "QuoterV2"
        );
        address tickLens = _deployDeterministic(TICK_LENS_SALT, TICK_LENS_BYTECODE, "TickLens");
        vm.stopBroadcast();

        // a factory deployed in an earlier run may since have changed hands through governance
        if (factoryDeployed) {
            require(IUniswapV3FactoryAdmin(factory).owner() == governance, "MainnetDeployUniswapV3: factory owner");
            require(
                IUniswapV3FactoryAdmin(factory).feeAmountTickSpacing(100) == 1, "MainnetDeployUniswapV3: 0.01% tier"
            );
        }
        require(IV3Periphery(positionManager).factory() == factory, "MainnetDeployUniswapV3: NPM factory");
        require(IV3Periphery(positionManager).WETH9() == wtel, "MainnetDeployUniswapV3: NPM WETH9");
        require(IV3Periphery(swapRouter02).factory() == factory, "MainnetDeployUniswapV3: router factory");
        require(ISwapRouter02(swapRouter02).factoryV2() == v2Factory, "MainnetDeployUniswapV3: router factoryV2");
        require(ISwapRouter02(swapRouter02).positionManager() == positionManager, "MainnetDeployUniswapV3: router NPM");
        require(IV3Periphery(quoterV2).factory() == factory, "MainnetDeployUniswapV3: quoter factory");

        _record(".uniswapV3.UniswapV3Factory", factory);
        _record(".uniswapV3.NFTDescriptor", nftDescriptor);
        _record(".uniswapV3.NonfungibleTokenPositionDescriptor", positionDescriptor);
        _record(".uniswapV3.NonfungiblePositionManager", positionManager);
        _record(".uniswapV3.SwapRouter02", swapRouter02);
        _record(".uniswapV3.QuoterV2", quoterV2);
        _record(".uniswapV3.TickLens", tickLens);
    }

    /// @notice Returns the V3 factory, deploying it through `UniswapV3FactoryDeployer` if absent
    /// @dev A factory recorded in the address book wins over the predicted address, so a later
    ///      compiler change to the helper cannot cause a second factory to be deployed
    function _deployFactory() internal returns (address factory, bool deployed) {
        address recorded = deployments.uniswapV3.UniswapV3Factory;
        if (recorded != address(0) && recorded.code.length != 0) {
            console2.log("UniswapV3Factory already deployed at", recorded);
            return (recorded, false);
        }

        bytes memory deployerInitcode = bytes.concat(
            type(UniswapV3FactoryDeployer).creationCode, abi.encode(UNISWAPV3FACTORY_BYTECODE, governance)
        );
        address helper = vm.computeCreate2Address(FACTORY_DEPLOYER_SALT, keccak256(deployerInitcode), arachnid);
        factory = vm.computeCreate2Address(bytes32(0), V3_FACTORY_INITCODE_HASH, helper);
        if (factory.code.length != 0) {
            console2.log("UniswapV3Factory already deployed at", factory);
            return (factory, false);
        }

        _deployDeterministic(FACTORY_DEPLOYER_SALT, deployerInitcode, "UniswapV3FactoryDeployer");
        require(UniswapV3FactoryDeployer(helper).factory() == factory, "MainnetDeployUniswapV3: factory address");
        console2.log("UniswapV3Factory deployed at", factory);
        return (factory, true);
    }

    /// @notice The V2 factory recorded in the address book, else its deterministic address
    /// @dev Mirrors MainnetDeployUniswapV2: Arachnid proxy, UNISWAP_V2_FACTORY_SALT,
    ///      feeToSetter = governance
    function _resolveV2Factory() internal view returns (address) {
        address recorded = deployments.uniswapV2.UniswapV2Factory;
        if (recorded != address(0) && recorded.code.length != 0) return recorded;
        bytes memory initcode = bytes.concat(UNISWAPV2FACTORY_BYTECODE, abi.encode(governance));
        return vm.computeCreate2Address(UNISWAP_V2_FACTORY_SALT, keccak256(initcode), arachnid);
    }

    /// @dev Splices `lib` into `code` at DESC_LIB_LINK_OFFSET, replacing the 20 zero bytes the
    ///      vendored artifact carries in place of solc's library-link placeholder. Reverts if
    ///      those bytes are not zero, which means the offset no longer matches the artifact.
    function _linkNFTDescriptor(bytes memory code, address lib) internal pure returns (bytes memory linked) {
        require(code.length >= DESC_LIB_LINK_OFFSET + 20, "MainnetDeployUniswapV3: descriptor code too short");
        for (uint256 i; i < 20; ++i) {
            require(code[DESC_LIB_LINK_OFFSET + i] == 0, "MainnetDeployUniswapV3: descriptor link offset mismatch");
        }
        linked = bytes.concat(code);
        bytes20 libBytes = bytes20(lib);
        for (uint256 i; i < 20; ++i) {
            linked[DESC_LIB_LINK_OFFSET + i] = libBytes[i];
        }
    }
}
