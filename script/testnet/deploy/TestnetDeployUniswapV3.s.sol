// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Deployments } from "../../../deployments/Deployments.sol";
import { UniswapV3FactoryBytecode } from "external/uniswap/precompiles/v3/UniswapV3Factory.sol";
import { NFTDescriptorBytecode } from "external/uniswap/precompiles/v3/NFTDescriptor.sol";
import { NonfungibleTokenPositionDescriptorBytecode } from
    "external/uniswap/precompiles/v3/NonfungibleTokenPositionDescriptor.sol";
import { NonfungiblePositionManagerBytecode } from
    "external/uniswap/precompiles/v3/NonfungiblePositionManager.sol";
import { QuoterV2Bytecode } from "external/uniswap/precompiles/v3/QuoterV2.sol";
import { TickLensBytecode } from "external/uniswap/precompiles/v3/TickLens.sol";
import { SwapRouter02Bytecode } from "external/uniswap/precompiles/v3/SwapRouter02.sol";

/// @title Deploy Uniswap V3 (factory + periphery) on Adiri Testnet
///
/// @notice Mirrors the deploy shape of TestnetDeployUniswapV2.s.sol: pre-compiled
///         bytecode literals deployed via Arachnid CREATE2 with addresses written
///         back to `deployments/deployments.json`.
///
/// @notice Pools are NOT pre-seeded. Liquidity providers initialize pools
///         on first mint per fee tier through the swap UI. This contrasts
///         with the V2 deploy script, which proactively creates 45 pairs.
///
/// @dev Deploy order:
///        1. UniswapV3Factory                          (CREATE2, no constructor args)
///        2. NFTDescriptor (library)                   (CREATE2, no constructor args)
///        3. NonfungibleTokenPositionDescriptor        (CREATE2, args: wTEL, nativeCurrencyLabel)
///                                                     library-linked to NFTDescriptor
///        4. NonfungiblePositionManager                (CREATE2, args: factory, wTEL, descriptor)
///        5. SwapRouter02                              (CREATE2, args: factoryV2, factoryV3, NPM, wTEL)
///        6. QuoterV2                                  (CREATE2, args: factory, wTEL)
///        7. TickLens                                  (CREATE2, no constructor args)
///
/// @dev Library linking note: NonfungibleTokenPositionDescriptor's bytecode contains
///        a 20-byte placeholder for NFTDescriptor's deployed address at byte offset
///        1681 (per the v3-periphery 1.4.4 published linkReferences). We splice the
///        deployed NFTDescriptor address into that exact offset before running the
///        CREATE2 deploy.
///
/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployUniswapV3.s.sol -vvvv \
///      --rpc-url $TN_RPC_URL --private-key $ADMIN_PK --broadcast`
contract TestnetDeployUniswapV3 is
    Script,
    UniswapV3FactoryBytecode,
    NFTDescriptorBytecode,
    NonfungibleTokenPositionDescriptorBytecode,
    NonfungiblePositionManagerBytecode,
    QuoterV2Bytecode,
    TickLensBytecode,
    SwapRouter02Bytecode
{
    /// @notice Native currency label for V3 NFT metadata. Encoded as bytes32 because
    ///         that's the type the NonfungibleTokenPositionDescriptor constructor takes.
    bytes32 constant NATIVE_CURRENCY_LABEL = bytes32("TEL");

    // Byte offset of NFTDescriptor's library-link placeholder within
    // NonfungibleTokenPositionDescriptor's deploy bytecode. Pinned to
    // the v3-periphery 1.4.4 compiled artifact; if the bytecode file is
    // refreshed against a different release, re-derive this from the
    // artifact's `linkReferences` field (see the fetch script).
    uint256 constant DESC_LIB_LINK_OFFSET = 1681;

    Deployments deployments;

    // Outputs - populated during run().
    address uniswapV3Factory;
    address nftDescriptor;
    address nonfungibleTokenPositionDescriptor;
    address nonfungiblePositionManager;
    address swapRouter02;
    address quoterV2;
    address tickLens;

    // Config
    address wTEL;
    address admin;

    // Salts for the deterministic CREATE2 deployer (Arachnid). Each is a unique
    // bytes32 derived from the contract name so re-runs land at the same address.
    // _v3 suffix forces fresh CREATE2 destinations so the WTEL-aware redeploy
    // doesn't collide with prior Adiri V3 stacks (factory / NFTDescriptor /
    // TickLens have no WTEL dependency, so without a salt bump they'd hash to
    // the previously-predicted addresses). The earlier _v2 predictions baked in
    // a stale WTEL address and were never broadcast cleanly; bumping all salts
    // uniformly keeps the on-chain story coherent: every V3 contract for the
    // new stack lives at a "_v3" address consistent with the live WTEL.
    bytes32 factorySalt = bytes32(bytes("UniswapV3Factory_v3"));
    bytes32 nftDescriptorSalt = bytes32(bytes("NFTDescriptor_v3"));
    bytes32 descSalt = bytes32(bytes("NFTPositionDescriptor_v3"));
    bytes32 npmSalt = bytes32(bytes("NonfungiblePositionManager_v3"));
    bytes32 swapRouter02Salt = bytes32(bytes("SwapRouter02_v3"));
    bytes32 quoterV2Salt = bytes32(bytes("QuoterV2_v3"));
    bytes32 tickLensSalt = bytes32(bytes("TickLens_v3"));

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        wTEL = deployments.WTEL;
        admin = deployments.admin;

        require(
            wTEL != address(0) && wTEL.code.length > 0,
            "TestnetDeployUniswapV3: WTEL not deployed (or recorded address has no code); run TestnetDeployWTEL first"
        );

        // V3's SwapRouter02 takes the V2 factory as a constructor arg so a single
        // router can route across both V2 and V3 pools.
        address v2Factory = deployments.uniswapV2.UniswapV2Factory;
        require(
            v2Factory != address(0) && v2Factory.code.length > 0,
            "TestnetDeployUniswapV3: V2 factory not deployed (or recorded address has no code); run TestnetDeployUniswapV2 first"
        );
    }

    function run() public {
        // Idempotency: skip only if the V3 factory is recorded AND has code
        // on-chain. A non-zero JSON address with no on-chain code means the
        // recorded address is a stale prediction (e.g. an earlier broadcast
        // that never actually landed) - we must redeploy in that case rather
        // than treating the JSON as authoritative.
        address v3Factory = deployments.uniswapV3.UniswapV3Factory;
        if (v3Factory != address(0) && v3Factory.code.length > 0) {
            console2.log("Uniswap V3 already deployed at:", v3Factory);
            return;
        }

        vm.startBroadcast();

        address arachnid = deployments.ArachnidDeterministicDeployFactory;

        // 1. UniswapV3Factory - no constructor args.
        uniswapV3Factory = _deployCreate2(arachnid, factorySalt, UNISWAPV3FACTORY_BYTECODE);

        // 2. NFTDescriptor library - no constructor args. Must be deployed before the
        //    NonfungibleTokenPositionDescriptor that depends on it.
        nftDescriptor = _deployCreate2(arachnid, nftDescriptorSalt, NFTDESCRIPTOR_BYTECODE);

        // 3. NonfungibleTokenPositionDescriptor - constructor args: (wTEL, nativeCurrencyLabel).
        //    Library-linked to NFTDescriptor; we splice the deployed NFTDescriptor
        //    address into the bytecode placeholder before deploying.
        bytes memory descLinked = _linkNFTDescriptor(NONFUNGIBLE_TOKEN_POSITION_DESCRIPTOR_BYTECODE, nftDescriptor);
        bytes memory descInitcode =
            bytes.concat(descLinked, abi.encode(wTEL, NATIVE_CURRENCY_LABEL));
        nonfungibleTokenPositionDescriptor = _deployCreate2(arachnid, descSalt, descInitcode);

        // 4. NonfungiblePositionManager - constructor args: (factory, wTEL, descriptor).
        bytes memory npmInitcode = bytes.concat(
            NONFUNGIBLE_POSITION_MANAGER_BYTECODE,
            abi.encode(uniswapV3Factory, wTEL, nonfungibleTokenPositionDescriptor)
        );
        nonfungiblePositionManager = _deployCreate2(arachnid, npmSalt, npmInitcode);

        // 5. SwapRouter02 - constructor args: (factoryV2, factoryV3, positionManager, wTEL).
        bytes memory swapRouterInitcode = bytes.concat(
            SWAP_ROUTER_02_BYTECODE,
            abi.encode(
                deployments.uniswapV2.UniswapV2Factory,
                uniswapV3Factory,
                nonfungiblePositionManager,
                wTEL
            )
        );
        swapRouter02 = _deployCreate2(arachnid, swapRouter02Salt, swapRouterInitcode);

        // 6. QuoterV2 - constructor args: (factory, wTEL).
        bytes memory quoterInitcode =
            bytes.concat(QUOTER_V2_BYTECODE, abi.encode(uniswapV3Factory, wTEL));
        quoterV2 = _deployCreate2(arachnid, quoterV2Salt, quoterInitcode);

        // 7. TickLens - no constructor args.
        tickLens = _deployCreate2(arachnid, tickLensSalt, TICK_LENS_BYTECODE);

        vm.stopBroadcast();

        // Sanity assertions before writing back.
        assert(uniswapV3Factory.code.length != 0);
        assert(nftDescriptor.code.length != 0);
        assert(nonfungibleTokenPositionDescriptor.code.length != 0);
        assert(nonfungiblePositionManager.code.length != 0);
        assert(swapRouter02.code.length != 0);
        assert(quoterV2.code.length != 0);
        assert(tickLens.code.length != 0);

        _writeDeployments();
    }

    /// @dev Deploys arbitrary initcode through Arachnid's deterministic deployer.
    ///      Mirrors the call shape used in TestnetDeployUniswapV2.s.sol.
    function _deployCreate2(address arachnid, bytes32 salt, bytes memory initcode) internal returns (address deployed) {
        (bool ok, bytes memory ret) = arachnid.call(bytes.concat(salt, initcode));
        require(ok, "TestnetDeployUniswapV3: CREATE2 deploy failed");
        deployed = address(bytes20(ret));
    }

    /// @dev Splices `lib`'s 20-byte address into `code` at DESC_LIB_LINK_OFFSET, replacing
    ///      the linker placeholder. Returns a fresh bytes copy so the original
    ///      bytecode constant is left untouched.
    /// @dev Asserts the 20 target bytes are zero before splicing. Solc's library-link
    ///      placeholder is `__$<hex>$__`, which the fetch script scrubs to 40 zero
    ///      hex chars (20 zero bytes). If a future v3-periphery release moves the
    ///      placeholder, this guard stops a silent miscompile that would only surface
    ///      at first `tokenURI` call. To re-derive the offset, parse the artifact's
    ///      `linkReferences` field via the fetch script.
    function _linkNFTDescriptor(bytes memory code, address lib) internal pure returns (bytes memory linked) {
        require(code.length >= DESC_LIB_LINK_OFFSET + 20, "_linkNFTDescriptor: code too short");
        for (uint256 i = 0; i < 20; ++i) {
            require(
                code[DESC_LIB_LINK_OFFSET + i] == 0,
                "_linkNFTDescriptor: target bytes not zero - refresh DESC_LIB_LINK_OFFSET against current artifact linkReferences"
            );
        }
        linked = bytes.concat(code); // memory copy
        bytes20 libBytes = bytes20(lib);
        for (uint256 i = 0; i < 20; ++i) {
            linked[DESC_LIB_LINK_OFFSET + i] = libBytes[i];
        }
    }

    /// @dev Persists deployed addresses back to `deployments/deployments.json`.
    function _writeDeployments() internal {
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(_addrStr(uniswapV3Factory), dest, ".uniswapV3.UniswapV3Factory");
        vm.writeJson(_addrStr(nftDescriptor), dest, ".uniswapV3.NFTDescriptor");
        vm.writeJson(
            _addrStr(nonfungibleTokenPositionDescriptor), dest, ".uniswapV3.NonfungibleTokenPositionDescriptor"
        );
        vm.writeJson(_addrStr(nonfungiblePositionManager), dest, ".uniswapV3.NonfungiblePositionManager");
        vm.writeJson(_addrStr(swapRouter02), dest, ".uniswapV3.SwapRouter02");
        vm.writeJson(_addrStr(quoterV2), dest, ".uniswapV3.QuoterV2");
        vm.writeJson(_addrStr(tickLens), dest, ".uniswapV3.TickLens");
    }

    function _addrStr(address a) internal pure returns (string memory) {
        return LibString.toHexString(uint256(uint160(a)), 20);
    }
}
