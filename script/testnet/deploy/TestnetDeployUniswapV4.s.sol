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

address constant TELCOIN_PRECOMPILE = 0x00000000000000000000000000000000000007E1;

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
/// @notice Pools are NOT pre-seeded. Per the V3 / V4 design doc
///         (script/testnet/deploy/UNISWAP_V3_V4.md), liquidity providers
///         initialize V4 pools by calling
///         PoolManager.initialize(PoolKey, sqrtPriceX96) and then minting
///         their first position via PositionManager.
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

    // Config
    address telPrecompile;
    address admin;

    // Salts for Arachnid CREATE2. Each is a unique bytes32 derived from the
    // contract name so re-runs land at the same address.
    bytes32 poolManagerSalt = bytes32(bytes("PoolManager"));
    bytes32 positionDescriptorSalt = bytes32(bytes("PositionDescriptor"));
    bytes32 positionManagerSalt = bytes32(bytes("PositionManager"));
    bytes32 v4QuoterSalt = bytes32(bytes("V4Quoter"));
    bytes32 stateViewSalt = bytes32(bytes("StateView"));

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        telPrecompile = TELCOIN_PRECOMPILE;
        admin = deployments.admin;

        // V4 surface here (PoolManager, PositionManager, V4Quoter, StateView)
        // is independent of V2 and V3. Once a canonical V4-aware
        // UniversalRouter is added, it will require V2 / V3 factories at
        // construction time and a require() will be added here.
    }

    function run() public {
        // Idempotency: skip if already deployed.
        if (deployments.uniswapV4.PoolManager != address(0)) {
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
            POSITION_DESCRIPTOR_BYTECODE, abi.encode(poolManager, telPrecompile, NATIVE_CURRENCY_LABEL)
        );
        positionDescriptor = _create2(arachnid, positionDescriptorSalt, descInitcode);

        // 4. PositionManager - constructor:
        //    (poolManager, permit2, unsubscribeGasLimit, descriptor, weth9).
        bytes memory posmInitcode = bytes.concat(
            POSITION_MANAGER_BYTECODE,
            abi.encode(poolManager, permit2, UNSUBSCRIBE_GAS_LIMIT, positionDescriptor, telPrecompile)
        );
        positionManager = _create2(arachnid, positionManagerSalt, posmInitcode);

        // 5. V4Quoter - constructor: poolManager.
        bytes memory quoterInitcode = bytes.concat(V4_QUOTER_BYTECODE, abi.encode(poolManager));
        v4Quoter = _create2(arachnid, v4QuoterSalt, quoterInitcode);

        // 6. StateView - constructor: poolManager.
        bytes memory stateViewInitcode = bytes.concat(STATE_VIEW_BYTECODE, abi.encode(poolManager));
        stateView = _create2(arachnid, stateViewSalt, stateViewInitcode);

        vm.stopBroadcast();

        // Sanity assertions before writing back.
        assert(permit2.code.length != 0);
        assert(poolManager.code.length != 0);
        assert(positionDescriptor.code.length != 0);
        assert(positionManager.code.length != 0);
        assert(v4Quoter.code.length != 0);
        assert(stateView.code.length != 0);

        _writeDeployments();
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
    }

    function _addrStr(address a) internal pure returns (string memory) {
        return LibString.toHexString(uint256(uint160(a)), 20);
    }
}
