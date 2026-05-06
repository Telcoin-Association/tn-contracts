// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Deployments } from "../../../deployments/Deployments.sol";
import { Permit2Bytecode } from "external/uniswap/precompiles/v4/Permit2Bytecode.sol";
import { PoolManagerBytecode } from "external/uniswap/precompiles/v4/PoolManager.sol";
import { PositionDescriptorBytecode } from "external/uniswap/precompiles/v4/PositionDescriptor.sol";
import { PositionManagerBytecode } from "external/uniswap/precompiles/v4/PositionManager.sol";
import { V4QuoterBytecode } from "external/uniswap/precompiles/v4/V4Quoter.sol";
import { StateViewBytecode } from "external/uniswap/precompiles/v4/StateView.sol";
import { V4SwapHelper } from "../../../src/uniswap/V4SwapHelper.sol";
import { IPoolManager } from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";

/// @title Deploy Uniswap V4 (Permit2 + PoolManager + periphery) on Adiri Testnet
///
/// @notice Same shape as TestnetDeployUniswapV2 / V3: pre-compiled bytecode
///         literals fed through Arachnid CREATE2. The bytecode files under
///         external/uniswap/precompiles/v4/ are produced by
///         script/bash/fetch-uniswap-v4-bytecode.sh, which builds the V4
///         source (lib/v4-core + lib/v4-periphery) under v4-periphery's own
///         foundry.toml (via_ir + 44M optimizer runs + per-file
///         compilation_restrictions for PositionManager and
///         PositionDescriptor) and extracts the resulting bytecode.
///
/// @notice Why not compile V4 source inside tn-contracts: V4 needs via_ir
///         and a 44M optimizer-runs target. Enabling via_ir at tn-contracts'
///         project level crashes solc's Windows binary; scoping via_ir to
///         the v4 paths via Foundry's compilation_restrictions errors with
///         "Missing profile satisfying settings restrictions" because the
///         deploy script imports types from v4-core / v4-periphery and
///         Foundry can't reconcile the script's settings with the imported
///         files' settings into a single solc invocation. Treating V4 the
///         way we treat V2, V3, and Permit2 (CREATE2-deploy of a
///         pre-compiled bytecode literal) sidesteps the compile-config
///         problem entirely while preserving canonical Uniswap mainnet
///         release behavior.
///
/// @notice Pools are NOT pre-seeded. Liquidity providers initialize V4 pools
///         by calling PoolManager.initialize(PoolKey, sqrtPriceX96) and then
///         minting their first position via PositionManager.
///
/// @dev Deploy order:
///        1. Permit2                                   (Arachnid CREATE2 + canonical salt; skip if at canonical address)
///        2. PoolManager                               (CREATE2, args: admin)
///        3. PositionDescriptor                        (CREATE2, args: poolManager, wTEL, "TEL")
///        4. PositionManager                           (CREATE2, args: poolManager, permit2, gasLimit, descriptor, wTEL)
///        5. V4Quoter                                  (CREATE2, args: poolManager)
///        6. StateView                                 (CREATE2, args: poolManager)
///
/// @notice UniversalRouter is intentionally NOT deployed here. As of the
///         foundation commit, no tagged release of Uniswap/universal-router
///         supports V4 routing.
///
/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployUniswapV4.s.sol -vvvv \
///      --rpc-url $TN_RPC_URL --private-key $ADMIN_PK --broadcast`
contract TestnetDeployUniswapV4 is
    Script,
    Permit2Bytecode,
    PoolManagerBytecode,
    PositionDescriptorBytecode,
    PositionManagerBytecode,
    V4QuoterBytecode,
    StateViewBytecode
{
    /// @notice Gas limit forwarded to subscriber hooks during unsubscribe.
    ///         Mainnet PositionManager uses 300_000.
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
    address v4SwapHelper;

    // Config
    address wTEL;
    address admin;

    // Salts for Arachnid CREATE2. Each is a unique bytes32 derived from the
    // contract name so re-runs land at the same address. _v2 suffix forces
    // fresh CREATE2 destinations so the WTEL-aware redeploy doesn't collide
    // with the legacy Adiri V4 stack (PoolManager / V4Quoter / StateView have
    // no WTEL dependency in their constructors, so without a salt bump they'd
    // hash to the existing live addresses and CREATE2 would revert on
    // already-occupied code).
    bytes32 poolManagerSalt = bytes32(bytes("PoolManager_v2"));
    bytes32 positionDescriptorSalt = bytes32(bytes("PositionDescriptor_v2"));
    bytes32 positionManagerSalt = bytes32(bytes("PositionManager_v2"));
    bytes32 v4QuoterSalt = bytes32(bytes("V4Quoter_v2"));
    bytes32 stateViewSalt = bytes32(bytes("StateView_v2"));
    bytes32 v4SwapHelperSalt = bytes32(bytes("V4SwapHelper_v2"));

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        wTEL = deployments.WTEL;
        admin = deployments.admin;

        require(
            wTEL != address(0),
            "TestnetDeployUniswapV4: WTEL not deployed; run TestnetDeployWTEL first"
        );

        // V4 surface here (PoolManager, PositionManager, V4Quoter, StateView)
        // is independent of V2 and V3. Once a canonical V4-aware
        // UniversalRouter is added, it will require V2 / V3 factories at
        // construction time and a require() will be added here.
    }

    function run() public {
        // Idempotency: if PoolManager is deployed, the V4 core stack is already
        // live. Late-added contracts (e.g. V4SwapHelper, introduced after the
        // initial V4 deploy) still need to land on the chain - run those
        // standalone instead of skipping the whole script.
        if (deployments.uniswapV4.PoolManager != address(0)) {
            if (deployments.uniswapV4.V4SwapHelper == address(0)) {
                console2.log("V4 core already deployed; running V4SwapHelper-only deploy");
                _deployV4SwapHelperOnly();
                return;
            }
            console2.log("Uniswap V4 already deployed; PoolManager:", deployments.uniswapV4.PoolManager);
            return;
        }

        vm.startBroadcast();

        address arachnid = deployments.ArachnidDeterministicDeployFactory;

        // 1. Permit2 - reuse canonical address if already there, else CREATE2.
        if (PERMIT2_CANONICAL_ADDRESS.code.length > 0) {
            permit2 = PERMIT2_CANONICAL_ADDRESS;
            console2.log("Permit2 already at canonical address:", permit2);
        } else {
            require(
                PERMIT2_CREATION_BYTECODE.length > 0,
                "TestnetDeployUniswapV4: Permit2 creation bytecode not populated. See external/uniswap/precompiles/v4/Permit2Bytecode.sol."
            );
            (bool ok, bytes memory ret) = arachnid.call(
                bytes.concat(PERMIT2_CANONICAL_SALT, PERMIT2_CREATION_BYTECODE)
            );
            require(ok, "Permit2 CREATE2 deploy failed");
            permit2 = address(bytes20(ret));
            require(
                permit2 == PERMIT2_CANONICAL_ADDRESS,
                "Permit2 deployed at non-canonical address; bytecode or salt drifted from recipe"
            );
        }

        // 2. PoolManager - constructor: admin (the protocol-fee controller).
        bytes memory pmInitcode = bytes.concat(POOL_MANAGER_BYTECODE, abi.encode(admin));
        poolManager = _create2(arachnid, poolManagerSalt, pmInitcode);

        // 3. PositionDescriptor - constructor: (poolManager, wTEL, native label).
        bytes memory descInitcode = bytes.concat(
            POSITION_DESCRIPTOR_BYTECODE, abi.encode(poolManager, wTEL, NATIVE_CURRENCY_LABEL)
        );
        positionDescriptor = _create2(arachnid, positionDescriptorSalt, descInitcode);

        // 4. PositionManager - constructor:
        //    (poolManager, permit2, unsubscribeGasLimit, descriptor, weth9).
        bytes memory posmInitcode = bytes.concat(
            POSITION_MANAGER_BYTECODE,
            abi.encode(poolManager, permit2, UNSUBSCRIBE_GAS_LIMIT, positionDescriptor, wTEL)
        );
        positionManager = _create2(arachnid, positionManagerSalt, posmInitcode);

        // 5. V4Quoter - constructor: poolManager.
        bytes memory quoterInitcode = bytes.concat(V4_QUOTER_BYTECODE, abi.encode(poolManager));
        v4Quoter = _create2(arachnid, v4QuoterSalt, quoterInitcode);

        // 6. StateView - constructor: poolManager.
        bytes memory stateViewInitcode = bytes.concat(STATE_VIEW_BYTECODE, abi.encode(poolManager));
        stateView = _create2(arachnid, stateViewSalt, stateViewInitcode);

        // 7. V4SwapHelper - mediator that lets EOAs call V4 swap. Compiled in-project
        //    (its v4-core deps are interface / value-type / TickMath / SafeCast only,
        //    none of which require via_ir), so we use type(...).creationCode rather
        //    than a hex-literal bytecode dependency.
        bytes memory helperInitcode = bytes.concat(
            type(V4SwapHelper).creationCode, abi.encode(IPoolManager(poolManager))
        );
        v4SwapHelper = _create2(arachnid, v4SwapHelperSalt, helperInitcode);

        vm.stopBroadcast();

        // Sanity assertions before writing back.
        assert(permit2.code.length != 0);
        assert(poolManager.code.length != 0);
        assert(positionDescriptor.code.length != 0);
        assert(positionManager.code.length != 0);
        assert(v4Quoter.code.length != 0);
        assert(stateView.code.length != 0);
        assert(v4SwapHelper.code.length != 0);

        _writeDeployments();
    }

    /// @dev Deploys only V4SwapHelper using the already-on-chain PoolManager
    ///      address. Used when re-running this script against a chain that
    ///      already has the original V4 core deployed but predates the helper.
    function _deployV4SwapHelperOnly() internal {
        vm.startBroadcast();
        bytes memory helperInitcode = bytes.concat(
            type(V4SwapHelper).creationCode,
            abi.encode(IPoolManager(deployments.uniswapV4.PoolManager))
        );
        v4SwapHelper = _create2(
            deployments.ArachnidDeterministicDeployFactory, v4SwapHelperSalt, helperInitcode
        );
        vm.stopBroadcast();

        assert(v4SwapHelper.code.length != 0);

        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(_addrStr(v4SwapHelper), dest, ".uniswapV4.V4SwapHelper");

        console2.log("V4SwapHelper deployed at:", v4SwapHelper);
    }

    /// @dev Deploys arbitrary initcode through Arachnid's deterministic deployer.
    function _create2(address arachnid, bytes32 salt, bytes memory initcode) internal returns (address deployed) {
        (bool ok, bytes memory ret) = arachnid.call(bytes.concat(salt, initcode));
        require(ok, "TestnetDeployUniswapV4: CREATE2 deploy failed");
        deployed = address(bytes20(ret));
    }

    /// @dev Persists deployed addresses back to deployments/deployments.json.
    ///      We deliberately don't write PositionDescriptor - it's intermediate
    ///      and the swap UI reads it via PositionManager.tokenDescriptor().
    function _writeDeployments() internal {
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(_addrStr(permit2), dest, ".uniswapV4.Permit2");
        vm.writeJson(_addrStr(poolManager), dest, ".uniswapV4.PoolManager");
        vm.writeJson(_addrStr(positionManager), dest, ".uniswapV4.PositionManager");
        vm.writeJson(_addrStr(stateView), dest, ".uniswapV4.StateView");
        vm.writeJson(_addrStr(v4Quoter), dest, ".uniswapV4.V4Quoter");
        vm.writeJson(_addrStr(v4SwapHelper), dest, ".uniswapV4.V4SwapHelper");
    }

    function _addrStr(address a) internal pure returns (string memory) {
        return LibString.toHexString(uint256(uint160(a)), 20);
    }
}
