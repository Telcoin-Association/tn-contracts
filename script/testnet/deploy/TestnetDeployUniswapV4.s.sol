// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Deployments } from "../../../deployments/Deployments.sol";
import { Permit2Bytecode } from "external/uniswap/precompiles/v4/Permit2Bytecode.sol";

// V4 source imports are intentionally left commented in this commit.
// lib/v4-core and lib/v4-periphery are installed (see remappings.txt) and
// ready to compile, but the V4 codebase requires via_ir = true at the solc
// level. Enabling via_ir at tn-contracts' project level crashes solc's
// Windows binary with a native stack overflow at our 200-runs setting; the
// fix needs either a higher optimizer_runs target (v4-core itself uses
// 44_444_444), a per-path compilation_restrictions block in foundry.toml,
// or a separate FOUNDRY_PROFILE=uniswap profile. Tracked as a follow-up
// commit so the V3 bytecode work can land on its own. Once that's resolved,
// uncomment the imports + the deploy block below.
//
// import { PoolManager } from "@uniswap/v4-core/src/PoolManager.sol";
// import { IPoolManager } from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
// import { PositionManager } from "v4-periphery/src/PositionManager.sol";
// import { PositionDescriptor } from "v4-periphery/src/PositionDescriptor.sol";
// import { IPositionDescriptor } from "v4-periphery/src/interfaces/IPositionDescriptor.sol";
// import { IAllowanceTransfer } from "permit2/src/interfaces/IAllowanceTransfer.sol";
// import { IWETH9 } from "v4-periphery/src/interfaces/external/IWETH9.sol";
// import { V4Quoter } from "v4-periphery/src/lens/V4Quoter.sol";
// import { StateView } from "v4-periphery/src/lens/StateView.sol";

address constant TELCOIN_PRECOMPILE = 0x00000000000000000000000000000000000007E1;

/// @title Deploy Uniswap V4 (Permit2 + PoolManager + periphery) on Adiri Testnet
///
/// @notice V4 core + periphery compile from source under lib/v4-core and
///         lib/v4-periphery (both pinned to canonical Uniswap commits;
///         see script/testnet/deploy/UNISWAP_V3_V4.md for the recipe).
///         Permit2 ships as a pre-compiled bytecode literal because the
///         canonical universal address is recipe-pinned to a specific
///         compile output that we can't reproduce under tn-contracts'
///         0.8.26 / 200-runs settings.
///
/// @notice Pools are NOT pre-seeded. Liquidity providers initialize V4 pools
///         by calling PoolManager.initialize(PoolKey, sqrtPriceX96) and then
///         minting their first position via PositionManager. The deploy
///         script just stands up the singletons.
///
/// @dev Deploy order (when fully wired):
///        1. Permit2                                   (Arachnid CREATE2 + canonical salt + canonical bytecode)
///        2. PoolManager                               (new PoolManager(admin))
///        3. PositionDescriptor                        (new PositionDescriptor(poolManager, wTEL, "TEL"))
///        4. PositionManager                           (new PositionManager(poolManager, permit2, gasLimit, descriptor, wTEL))
///        5. V4Quoter                                  (new V4Quoter(poolManager))
///        6. StateView                                 (new StateView(poolManager))
///
/// @notice UniversalRouter is intentionally NOT deployed here. As of the
///         foundation commit, no tagged release of Uniswap/universal-router
///         supports V4 routing. Defer until Uniswap tags a release that
///         includes V4 so we can pin against a canonical mainnet release.
///
/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployUniswapV4.s.sol -vvvv \
///      --rpc-url $TN_RPC_URL --private-key $ADMIN_PK --broadcast`
contract TestnetDeployUniswapV4 is Script, Permit2Bytecode {
    /// @notice Gas limit forwarded to subscriber hooks during unsubscribe.
    ///         Mainnet PositionManager uses 300_000; we keep the same default
    ///         to mirror behavior for the swap UI.
    uint256 constant UNSUBSCRIBE_GAS_LIMIT = 300_000;

    // Native currency label for V4 NFT metadata. Same as V3.
    bytes32 constant NATIVE_CURRENCY_LABEL = bytes32("TEL");

    Deployments deployments;

    // Outputs - populated during run().
    address permit2;
    address poolManager;
    address positionDescriptor;
    address positionManager;
    address v4Quoter;
    address stateView;

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

        // V4 surface here (PoolManager, PositionManager, V4Quoter, StateView)
        // is independent of V2 and V3. Once a canonical V4-aware UniversalRouter
        // is added, it will require V2 / V3 factories at construction time and
        // a require() will be added here mirroring the V3 script's check.
    }

    function run() public {
        // Idempotency: skip if already deployed.
        if (deployments.uniswapV4.PoolManager != address(0)) {
            console2.log("Uniswap V4 already deployed; PoolManager:", deployments.uniswapV4.PoolManager);
            return;
        }

        // Source imports for V4 contracts are pending the foundry-profile work
        // (see top-of-file note). Until that lands, the deploy block below is
        // unreachable and this script reverts loudly. The orchestrator
        // (script/bash/deploy-testnet-infra.sh) gates the V4 step on
        // PERMIT2_CREATION_BYTECODE being non-empty AND lib/v4-core existing,
        // and on a fresh chain it prints a "deferred" message rather than
        // running this script.
        revert(
            "TestnetDeployUniswapV4: V4 source imports disabled until via_ir compile config is resolved. See script/testnet/deploy/UNISWAP_V3_V4.md and the top-of-file comment."
        );

        // --- Deploy block (commented while V4 source imports are disabled) -------
        //
        // vm.startBroadcast();
        //
        // // 1. Permit2 - if already at the canonical address, reuse. Otherwise
        // //    deploy via Arachnid + canonical salt + canonical bytecode.
        // if (PERMIT2_CANONICAL_ADDRESS.code.length > 0) {
        //     permit2 = PERMIT2_CANONICAL_ADDRESS;
        //     console2.log("Permit2 already at canonical address:", permit2);
        // } else {
        //     require(
        //         PERMIT2_CREATION_BYTECODE.length > 0,
        //         "Permit2 creation bytecode not populated. See external/uniswap/precompiles/v4/Permit2Bytecode.sol."
        //     );
        //     (bool ok, bytes memory ret) = deployments.ArachnidDeterministicDeployFactory.call(
        //         bytes.concat(PERMIT2_CANONICAL_SALT, PERMIT2_CREATION_BYTECODE)
        //     );
        //     require(ok, "Permit2 CREATE2 deploy failed");
        //     permit2 = address(bytes20(ret));
        //     require(
        //         permit2 == PERMIT2_CANONICAL_ADDRESS,
        //         "Permit2 deployed at non-canonical address; bytecode or salt drifted from recipe"
        //     );
        // }
        //
        // // 2. PoolManager - the V4 singleton.
        // poolManager = address(new PoolManager(admin));
        //
        // // 3. PositionDescriptor - intermediate, used by PositionManager for NFT metadata.
        // positionDescriptor = address(
        //     new PositionDescriptor(IPoolManager(poolManager), telPrecompile, NATIVE_CURRENCY_LABEL)
        // );
        //
        // // 4. PositionManager - the user-facing LP entry point.
        // positionManager = address(
        //     new PositionManager(
        //         IPoolManager(poolManager),
        //         IAllowanceTransfer(permit2),
        //         UNSUBSCRIBE_GAS_LIMIT,
        //         IPositionDescriptor(positionDescriptor),
        //         IWETH9(telPrecompile)
        //     )
        // );
        //
        // // 5. V4Quoter - off-chain quote helper.
        // v4Quoter = address(new V4Quoter(IPoolManager(poolManager)));
        //
        // // 6. StateView - read-only state accessor.
        // stateView = address(new StateView(IPoolManager(poolManager)));
        //
        // vm.stopBroadcast();
        //
        // assert(permit2.code.length != 0);
        // assert(poolManager.code.length != 0);
        // assert(positionDescriptor.code.length != 0);
        // assert(positionManager.code.length != 0);
        // assert(v4Quoter.code.length != 0);
        // assert(stateView.code.length != 0);
        //
        // _writeDeployments();
        //
        // -------------------------------------------------------------------------
    }

    /// @dev Persists deployed addresses back to `deployments/deployments.json`.
    ///      Wired up once the deploy block above is enabled.
    function _writeDeployments() internal {
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(_addrStr(permit2), dest, ".uniswapV4.Permit2");
        vm.writeJson(_addrStr(poolManager), dest, ".uniswapV4.PoolManager");
        vm.writeJson(_addrStr(positionManager), dest, ".uniswapV4.PositionManager");
        vm.writeJson(_addrStr(stateView), dest, ".uniswapV4.StateView");
        vm.writeJson(_addrStr(v4Quoter), dest, ".uniswapV4.V4Quoter");
    }

    function _addrStr(address a) internal pure returns (string memory) {
        return LibString.toHexString(uint256(uint160(a)), 20);
    }
}
