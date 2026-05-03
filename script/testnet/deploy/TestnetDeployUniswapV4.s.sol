// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Deployments } from "../../../deployments/Deployments.sol";

address constant TELCOIN_PRECOMPILE = 0x00000000000000000000000000000000000007E1;

// Permit2's canonical universal address, deployed on every chain via Arachnid + a
// fixed salt. Identical across mainnet, every L2, and every testnet that has
// Permit2 deployed correctly. Off-chain tooling (Universal Router, position
// managers, every wallet that supports Permit2) hardcodes this address.
address constant PERMIT2_CANONICAL = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

/// @title Deploy Uniswap V4 (Permit2 + PoolManager + periphery) on Adiri Testnet
///
/// @notice V4 source is Solidity 0.8.26 - same compiler tn-contracts itself uses - so
///         V4 contracts compile from source under `lib/v4-core` and `lib/v4-periphery`,
///         no pre-compiled bytecode files needed. This contrasts with V2 and V3, both
///         of which ship as bytecode literals because their source language is older.
///
/// @notice Pools are NOT pre-seeded. Per the V3 / V4 design doc
///         (`script/testnet/deploy/UNISWAP_V3_V4.md`), liquidity providers initialize
///         V4 pools by calling `PoolManager.initialize(PoolKey, sqrtPriceX96)` and
///         then minting their first position via PositionManager. The deploy script
///         just stands up the singletons.
///
/// @dev Deploy order:
///        1. Permit2                                   (skip if at PERMIT2_CANONICAL)
///        2. PoolManager                               (singleton, takes protocol-fee controller)
///        3. PositionManager                           (constructor: poolManager, permit2, wTEL, descriptor)
///        4. UniversalRouter                           (constructor: poolManager, permit2, factoryV2,
///                                                     factoryV3, swapRouter02, positionManager, wTEL)
///
/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployUniswapV4.s.sol -vvvv \
///      --rpc-url $TN_RPC_URL --private-key $ADMIN_PK --broadcast`
contract TestnetDeployUniswapV4 is Script {
    Deployments deployments;

    // Outputs - populated during run().
    address permit2;
    address poolManager;
    address positionManager;
    address universalRouter;

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

        // V4 UniversalRouter takes the V2 + V3 factory addresses + V3 SwapRouter02 +
        // V4 PositionManager so a single router can route across every Uniswap version
        // we deploy. V4 therefore depends on both V2 and V3 being deployed first.
        require(
            deployments.uniswapV2.UniswapV2Factory != address(0),
            "TestnetDeployUniswapV4: V2 factory not deployed; run TestnetDeployUniswapV2 first"
        );
        require(
            deployments.uniswapV3.UniswapV3Factory != address(0),
            "TestnetDeployUniswapV4: V3 factory not deployed; run TestnetDeployUniswapV3 first"
        );
    }

    function run() public {
        // Idempotency: skip if already deployed. The orchestrator
        // (script/bash/deploy-testnet-infra.sh) also gates on `has_code` so this
        // is belt-and-suspenders for direct invocations.
        if (deployments.uniswapV4.PoolManager != address(0)) {
            console2.log("Uniswap V4 already deployed; PoolManager:", deployments.uniswapV4.PoolManager);
            return;
        }

        // V4 contracts compile from source under `lib/v4-core` and `lib/v4-periphery`.
        // Until those are installed via `forge install` (see
        // script/testnet/deploy/UNISWAP_V3_V4.md), this script reverts with a clear
        // message rather than silently no-op'ing.
        //
        // Once libs are installed, this revert is removed and replaced with the V4
        // deploy block below.
        revert(
            "TestnetDeployUniswapV4: V4 deps not installed. Run `forge install Uniswap/v4-core Uniswap/v4-periphery` and add remappings; see script/testnet/deploy/UNISWAP_V3_V4.md."
        );

        // --- Deploy block (commented until lib/v4-core + lib/v4-periphery land) ----
        //
        // vm.startBroadcast();
        //
        // // 1. Permit2 - skip if already deployed at the canonical address.
        // permit2 = PERMIT2_CANONICAL;
        // if (permit2.code.length == 0) {
        //     // Deploy Permit2 via Arachnid with the canonical salt so the address
        //     // matches every other chain. Bytecode comes from a Permit2 bytecode
        //     // literal under external/uniswap/precompiles/v4/.
        //     // ...
        // }
        //
        // // 2. PoolManager. Constructor takes the protocol-fee controller (typically
        // //    admin until governance hands it off to a controller contract).
        // poolManager = address(new PoolManager(admin));
        //
        // // 3. PositionManager. Constructor: poolManager, permit2, wTEL, descriptor.
        // positionManager = address(new PositionManager(...));
        //
        // // 4. UniversalRouter. Constructor takes the union of every router target.
        // universalRouter = address(new UniversalRouter(...));
        //
        // vm.stopBroadcast();
        //
        // _writeDeployments();
        //
        // ----------------------------------------------------------------------------
    }

    /// @dev Persists deployed addresses back to `deployments/deployments.json`.
    ///      Mirrors the writeback pattern in TestnetDeployUniswapV2.s.sol.
    ///      Wired up once the deploy block above is enabled.
    function _writeDeployments() internal {
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(_addrStr(permit2), dest, ".uniswapV4.Permit2");
        vm.writeJson(_addrStr(poolManager), dest, ".uniswapV4.PoolManager");
        vm.writeJson(_addrStr(positionManager), dest, ".uniswapV4.PositionManager");
        vm.writeJson(_addrStr(universalRouter), dest, ".uniswapV4.UniversalRouter");
    }

    function _addrStr(address a) internal pure returns (string memory) {
        return LibString.toHexString(uint256(uint160(a)), 20);
    }
}
