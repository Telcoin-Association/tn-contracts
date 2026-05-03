// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Deployments } from "../../../deployments/Deployments.sol";

address constant TELCOIN_PRECOMPILE = 0x00000000000000000000000000000000000007E1;

/// @title Deploy Uniswap V3 (factory + periphery) on Adiri Testnet
///
/// @notice This script mirrors the deploy shape of TestnetDeployUniswapV2.s.sol:
///         CREATE2-deterministic deployments via Arachnid's factory, with all
///         addresses written back to `deployments/deployments.json`.
///
/// @notice V3 source is Solidity 0.7.6, which `tn-contracts` (pinned at
///         `solc = "0.8.26"`) cannot compile. We ship V3 as pre-compiled
///         bytecode literals under `external/uniswap/precompiles/v3/` and
///         deploy via Arachnid CREATE2, exactly the way V2 is shipped today.
///         See `external/uniswap/precompiles/v3/README.md` for the source
///         recipe (Uniswap release tag, optimizer settings, init-code hash)
///         that the bytecode files must match for canonical V3 pool address
///         derivation to work against this chain.
///
/// @notice Pools are NOT pre-seeded. Per the V3 / V4 design doc
///         (`script/testnet/deploy/UNISWAP_V3_V4.md`), liquidity providers
///         initialize pools on first mint per fee tier through the swap UI.
///         This contrasts with the V2 deploy script, which proactively
///         creates 45 pairs.
///
/// @dev Deploy order:
///        1. UniswapV3Factory                          (CREATE2)
///        2. NFTDescriptor (library)                   (CREATE2)
///        3. NonfungibleTokenPositionDescriptor        (CREATE2, links NFTDescriptor)
///        4. NonfungiblePositionManager                (constructor: factory, wTEL, descriptor)
///        5. SwapRouter02                              (constructor: factoryV2, factoryV3, NPM, wTEL)
///        6. QuoterV2                                  (constructor: factory, wTEL)
///        7. TickLens                                  (no constructor args)
///
/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployUniswapV3.s.sol -vvvv \
///      --rpc-url $TN_RPC_URL --private-key $ADMIN_PK --broadcast`
contract TestnetDeployUniswapV3 is Script {
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
    address telPrecompile;
    address admin;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        telPrecompile = TELCOIN_PRECOMPILE;
        admin = deployments.admin;

        // V3 needs V2's factory address for SwapRouter02's multi-version routing.
        require(
            deployments.uniswapV2.UniswapV2Factory != address(0),
            "TestnetDeployUniswapV3: V2 factory not deployed; run TestnetDeployUniswapV2 first"
        );
    }

    function run() public {
        // Idempotency: skip if already deployed. The orchestrator
        // (script/bash/deploy-testnet-infra.sh) also gates on `has_code` so
        // this is belt-and-suspenders for direct invocations.
        if (deployments.uniswapV3.UniswapV3Factory != address(0)) {
            console2.log("Uniswap V3 already deployed at:", deployments.uniswapV3.UniswapV3Factory);
            return;
        }

        // The pre-compiled V3 bytecode files live under
        // `external/uniswap/precompiles/v3/`. Until they're populated (see the
        // README in that directory for the refresh recipe), this script reverts
        // with a clear message rather than silently producing a no-op deploy.
        //
        // Once bytecode files exist, this revert is removed and replaced with
        // the CREATE2 deploys + writeJson block that follows the same shape
        // as TestnetDeployUniswapV2.s.sol.
        revert(
            "TestnetDeployUniswapV3: V3 bytecode not yet populated. See external/uniswap/precompiles/v3/README.md."
        );

        // --- Deploy block (commented until bytecode files land) ------------
        //
        // vm.startBroadcast();
        //
        // // 1. UniswapV3Factory
        // bytes memory factoryInitcode = UNISWAPV3FACTORY_BYTECODE;
        // (bool factoryRes, bytes memory factoryRet) = deployments.ArachnidDeterministicDeployFactory.call(
        //     bytes.concat(bytes32(bytes("UniswapV3Factory")), factoryInitcode)
        // );
        // require(factoryRes, "UniswapV3Factory deploy failed");
        // uniswapV3Factory = address(bytes20(factoryRet));
        //
        // // 2-7. Periphery in dependency order (NFTDescriptor library first, then
        // //      descriptor, NPM, SwapRouter02, QuoterV2, TickLens).
        //
        // vm.stopBroadcast();
        //
        // _writeDeployments();
        //
        // -------------------------------------------------------------------
    }

    /// @dev Persists deployed addresses back to `deployments/deployments.json`.
    ///      Mirrors the writeback pattern in TestnetDeployUniswapV2.s.sol.
    ///      Wired up once the deploy block above is enabled.
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
