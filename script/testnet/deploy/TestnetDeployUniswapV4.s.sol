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
///        4. V4Quoter                                  (constructor: poolManager)
///        5. StateView                                 (constructor: poolManager)
///
/// @notice UniversalRouter is intentionally NOT deployed in this script. As of the
///         foundation commit, no tagged universal-router release supports V4 routing
///         (the V4-aware build lives on a non-canonical branch on Uniswap/universal-router).
///         The swap UI composes V4 swaps via direct PoolManager-unlock callbacks plus
///         V4Quoter for previews and StateView for state reads. UniversalRouter can be
///         added in a follow-up once Uniswap tags a release that includes V4.
///
/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployUniswapV4.s.sol -vvvv \
///      --rpc-url $TN_RPC_URL --private-key $ADMIN_PK --broadcast`
contract TestnetDeployUniswapV4 is Script {
    Deployments deployments;

    // Outputs - populated during run().
    address permit2;
    address poolManager;
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

        // V4 currently does not depend on V2 / V3 having been deployed first; the
        // V4 surface here (PoolManager, PositionManager, V4Quoter, StateView) is
        // independent. The swap UI cross-references V2 / V3 separately. Once a
        // canonical V4-aware UniversalRouter is added, that contract takes the
        // V2 + V3 factory + SwapRouter02 addresses and a require() will be added
        // here mirroring the V3 script's V2-factory check.
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
        //     // matches every other chain. Bytecode comes from
        //     // external/uniswap/precompiles/v4/Permit2Bytecode.sol.
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
        // // 4. V4Quoter. Off-chain quote helper (mirrors V3's QuoterV2).
        // v4Quoter = address(new V4Quoter(IPoolManager(poolManager)));
        //
        // // 5. StateView. Read-only state accessor.
        // stateView = address(new StateView(IPoolManager(poolManager)));
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
        vm.writeJson(_addrStr(stateView), dest, ".uniswapV4.StateView");
        vm.writeJson(_addrStr(v4Quoter), dest, ".uniswapV4.V4Quoter");
    }

    function _addrStr(address a) internal pure returns (string memory) {
        return LibString.toHexString(uint256(uint160(a)), 20);
    }
}
