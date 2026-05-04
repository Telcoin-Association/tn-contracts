// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { Permit2Bytecode } from "../../external/uniswap/precompiles/v4/Permit2Bytecode.sol";
import { PoolManagerBytecode } from "../../external/uniswap/precompiles/v4/PoolManager.sol";
import { PositionDescriptorBytecode } from "../../external/uniswap/precompiles/v4/PositionDescriptor.sol";
import { PositionManagerBytecode } from "../../external/uniswap/precompiles/v4/PositionManager.sol";
import { V4QuoterBytecode } from "../../external/uniswap/precompiles/v4/V4Quoter.sol";
import { StateViewBytecode } from "../../external/uniswap/precompiles/v4/StateView.sol";
import { MockTelMintPrecompile } from "./MockTelMintPrecompile.sol";
import { Currency, PoolKey, IPoolManager, IPositionManager, IV4Quoter, IStateView } from "./IV4Test.sol";

/// @dev Local interface used only by V4IntegrationFork for the descriptor
///      lookup on a live-deployed PositionManager.
interface IPositionManagerWithDescriptor {
    function tokenDescriptor() external view returns (address);
}

/// @title Fork integration test for Uniswap V4 on Adiri
///
/// @notice Forks Adiri at the latest block, etches a `MockTelMintPrecompile`
///         at the canonical TEL_MINT precompile address (0x07e1) so the
///         local EVM can dispatch wTEL methods, then runs the same V4
///         deploy logic the testnet script executes and exercises the
///         basic post-deploy lifecycle: constructor wiring, then
///         `PoolManager.initialize` for a wTEL / eUSD pool.
///
/// @notice LP mint and swap are intentionally NOT in this test suite. V4
///         requires a callback-based interaction pattern (PositionManager
///         encodes "actions" in a Multicall-style envelope; PoolManager
///         requires `unlock` callbacks for swaps) that needs substantial
///         test-only scaffolding. Those flows will land alongside the
///         swap UI work, where the same callback shape gets encoded by
///         the front-end. The V3 fork test already proves the broader
///         "etched-mock-precompile + low-level-staticcall" approach
///         works for token interactions; V4's deploy + initialize tests
///         here validate that the V4 surface ships correctly via Arachnid
///         CREATE2.
///
/// @dev Run: `forge test --match-contract V4IntegrationFork --fork-url $TN_RPC_URL -vv`
contract V4IntegrationFork is
    Test,
    Permit2Bytecode,
    PoolManagerBytecode,
    PositionDescriptorBytecode,
    PositionManagerBytecode,
    V4QuoterBytecode,
    StateViewBytecode
{
    address constant TELCOIN_PRECOMPILE = 0x00000000000000000000000000000000000007E1;
    bytes32 constant NATIVE_CURRENCY_LABEL = bytes32("TEL");
    uint256 constant UNSUBSCRIBE_GAS_LIMIT = 300_000;

    Deployments deployments;

    // V4 deployment outputs.
    address permit2;
    address poolManager;
    address positionDescriptor;
    address positionManager;
    address v4Quoter;
    address stateView;

    // Tokens.
    address eUSD;
    address wTEL;

    address constant ADMIN = 0x588D280a2B5577042765C2aaa6f13C7A611649de;

    function setUp() public {
        // Read addresses from deployments.json.
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        eUSD = deployments.eXYZs.eUSD;
        wTEL = TELCOIN_PRECOMPILE;

        // Etch the mock at 0x07e1 so the local EVM has bytecode to execute
        // when V4 contracts call IERC20(wTEL).balanceOf etc.
        MockTelMintPrecompile mockImpl = new MockTelMintPrecompile();
        vm.etch(TELCOIN_PRECOMPILE, address(mockImpl).code);

        _deployV4();

        vm.deal(ADMIN, 1_000_000 ether);
    }

    function _deployV4() internal {
        address arachnid = deployments.ArachnidDeterministicDeployFactory;

        // 1. Permit2 - reuse if at canonical address (rare in fork), else deploy.
        if (PERMIT2_CANONICAL_ADDRESS.code.length > 0) {
            permit2 = PERMIT2_CANONICAL_ADDRESS;
        } else {
            (bool ok, bytes memory ret) = arachnid.call(
                bytes.concat(PERMIT2_CANONICAL_SALT, PERMIT2_CREATION_BYTECODE)
            );
            require(ok, "Permit2 CREATE2 failed");
            permit2 = address(bytes20(ret));
            require(permit2 == PERMIT2_CANONICAL_ADDRESS, "Permit2 non-canonical address");
        }

        // 2. PoolManager - constructor: admin (protocol-fee controller).
        poolManager = _deployOrReuse(
            deployments.uniswapV4.PoolManager,
            arachnid,
            bytes32(bytes("PoolManager")),
            bytes.concat(POOL_MANAGER_BYTECODE, abi.encode(ADMIN))
        );

        // 3. PositionDescriptor - constructor: (poolManager, wTEL, native label).
        // PositionDescriptor isn't tracked in deployments.json (it's intermediate
        // and the swap UI reads it via PositionManager.tokenDescriptor()), so
        // always deploy fresh on a clean fork. If it's already on-chain at the
        // deterministic address, _create2 reverts and we explicitly catch that
        // here by reading the on-chain address from PositionManager itself.
        if (deployments.uniswapV4.PositionManager.code.length > 0) {
            // Live PositionManager on-chain - read its descriptor so the test
            // mirrors live state instead of a fresh sub-deploy.
            positionDescriptor =
                IPositionManagerWithDescriptor(deployments.uniswapV4.PositionManager).tokenDescriptor();
        } else {
            positionDescriptor = _create2(
                arachnid,
                bytes32(bytes("PositionDescriptor")),
                bytes.concat(POSITION_DESCRIPTOR_BYTECODE, abi.encode(poolManager, wTEL, NATIVE_CURRENCY_LABEL))
            );
        }

        // 4. PositionManager - constructor:
        //    (poolManager, permit2, unsubscribeGasLimit, descriptor, weth9).
        positionManager = _deployOrReuse(
            deployments.uniswapV4.PositionManager,
            arachnid,
            bytes32(bytes("PositionManager")),
            bytes.concat(
                POSITION_MANAGER_BYTECODE,
                abi.encode(poolManager, permit2, UNSUBSCRIBE_GAS_LIMIT, positionDescriptor, wTEL)
            )
        );

        // 5. V4Quoter.
        v4Quoter = _deployOrReuse(
            deployments.uniswapV4.V4Quoter,
            arachnid,
            bytes32(bytes("V4Quoter")),
            bytes.concat(V4_QUOTER_BYTECODE, abi.encode(poolManager))
        );

        // 6. StateView.
        stateView = _deployOrReuse(
            deployments.uniswapV4.StateView,
            arachnid,
            bytes32(bytes("StateView")),
            bytes.concat(STATE_VIEW_BYTECODE, abi.encode(poolManager))
        );
    }

    function _create2(address arachnid, bytes32 salt, bytes memory initcode) internal returns (address deployed) {
        (bool ok, bytes memory ret) = arachnid.call(bytes.concat(salt, initcode));
        require(ok, "_create2 failed");
        deployed = address(bytes20(ret));
    }

    /// @dev Same self-bootstrapping shape as V3IntegrationFork: reuse on-chain
    ///      address if it exists, else CREATE2-deploy.
    function _deployOrReuse(
        address existing,
        address arachnid,
        bytes32 salt,
        bytes memory initcode
    )
        internal
        returns (address)
    {
        if (existing != address(0) && existing.code.length > 0) {
            return existing;
        }
        return _create2(arachnid, salt, initcode);
    }

    // ---------- Tests ----------

    function test_AllContractsHaveCode() public view {
        assertGt(permit2.code.length, 0, "permit2 missing code");
        assertGt(poolManager.code.length, 0, "PoolManager missing code");
        assertGt(positionDescriptor.code.length, 0, "PositionDescriptor missing code");
        assertGt(positionManager.code.length, 0, "PositionManager missing code");
        assertGt(v4Quoter.code.length, 0, "V4Quoter missing code");
        assertGt(stateView.code.length, 0, "StateView missing code");

        assertEq(permit2, PERMIT2_CANONICAL_ADDRESS, "Permit2 at canonical address");

        console2.log("Permit2:                    ", permit2);
        console2.log("PoolManager:                ", poolManager);
        console2.log("PositionDescriptor:         ", positionDescriptor);
        console2.log("PositionManager:            ", positionManager);
        console2.log("V4Quoter:                   ", v4Quoter);
        console2.log("StateView:                  ", stateView);
    }

    function test_PoolManagerOwner() public view {
        assertEq(IPoolManager(poolManager).owner(), ADMIN, "PoolManager owner");
    }

    function test_PeripheryWiring() public view {
        assertEq(IPositionManager(positionManager).poolManager(), poolManager, "PositionManager poolManager");
        assertEq(IPositionManager(positionManager).permit2(), permit2, "PositionManager permit2");
        assertEq(IV4Quoter(v4Quoter).poolManager(), poolManager, "V4Quoter poolManager");
        assertEq(IStateView(stateView).poolManager(), poolManager, "StateView poolManager");
    }

    function test_PoolManagerInitialize() public {
        // Build a PoolKey for wTEL / eUSD with no hooks at the 0.3% fee tier
        // (3000 bps with V4's 60-tick spacing, matching V3 conventions).
        // Currencies must be ordered low -> high.
        address c0 = wTEL < eUSD ? wTEL : eUSD;
        address c1 = wTEL < eUSD ? eUSD : wTEL;

        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(c0),
            currency1: Currency.wrap(c1),
            fee: 3000,
            tickSpacing: 60,
            hooks: address(0)
        });

        // 1:1 sqrtPriceX96.
        uint160 sqrtPriceX96 = 79228162514264337593543950336;

        vm.prank(ADMIN);
        int24 tick = IPoolManager(poolManager).initialize(key, sqrtPriceX96);

        // Initial tick at 1:1 should be 0 (or very close - V4 rounds based on
        // ln(price) / ln(1.0001)). For sqrtPriceX96 = 2^96, the price is exactly
        // 1, and tick is 0.
        assertEq(tick, 0, "initial tick at 1:1");

        // Verify state is queryable via StateView.
        bytes32 poolId = _toId(key);
        (uint160 actualSqrtPrice, int24 actualTick, , ) = IStateView(stateView).getSlot0(poolId);
        assertEq(actualSqrtPrice, sqrtPriceX96, "slot0 sqrtPriceX96");
        assertEq(actualTick, 0, "slot0 tick");

        uint128 liquidity = IStateView(stateView).getLiquidity(poolId);
        assertEq(liquidity, 0, "no liquidity yet");

        console2.log("V4 wTEL/eUSD pool initialized at fee=3000, tickSpacing=60, price=1:1");
    }

    /// @dev Computes the PoolId for a PoolKey. V4's PoolIdLibrary uses
    ///      keccak256(abi.encode(key)) as the canonical id.
    function _toId(PoolKey memory key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key));
    }
}
