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
import { WTEL } from "../../src/WTEL.sol";
import { V4SwapHelper } from "../../src/uniswap/V4SwapHelper.sol";
import { IPoolManager as IPoolManagerCore } from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import { Currency as CurrencyCore } from "@uniswap/v4-core/src/types/Currency.sol";
import { PoolKey as PoolKeyCore } from "@uniswap/v4-core/src/types/PoolKey.sol";
import { IHooks } from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import { Currency, PoolKey, IPoolManager, IPositionManager, IV4Quoter, IStateView } from "./IV4Test.sol";

/// @dev Local interface used only by V4IntegrationFork for the descriptor
///      lookup on a live-deployed PositionManager.
interface IPositionManagerWithDescriptor {
    function tokenDescriptor() external view returns (address);
}

/// @title Fork integration test for Uniswap V4 on Adiri
///
/// @notice Forks Adiri at the latest block, deploys WTEL + the V4 stack via
///         Arachnid CREATE2 (mirroring TestnetDeployWTEL + TestnetDeployUniswapV4),
///         and exercises the post-deploy lifecycle: constructor wiring, then
///         `PoolManager.initialize` for a wTEL / eUSD pool. wTEL is the real
///         WTEL ERC20 contract, not the legacy precompile, so no etched
///         bytecode is needed at 0x07e1.
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
    address v4SwapHelper;

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

        // Skip the entire suite when running outside a fork (e.g. CI's default
        // `forge test` without TN_RPC_URL). Without a fork neither eUSD nor
        // the Arachnid factory have on-chain code, so every cross-contract
        // call below would revert with "call to non-contract address". With
        // a fork URL, eUSD has code and the suite runs as before.
        if (eUSD.code.length == 0) {
            vm.skip(true);
            return;
        }

        // Deploy WTEL via Arachnid (or reuse if deployments.WTEL is populated),
        // then deploy V4 against it. Mirrors TestnetDeployWTEL + TestnetDeployUniswapV4.
        wTEL = _deployOrReuse(
            deployments.WTEL,
            deployments.ArachnidDeterministicDeployFactory,
            bytes32(bytes("WTEL")),
            type(WTEL).creationCode
        );

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
            bytes32(bytes("PoolManager_v2")),
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
                bytes32(bytes("PositionDescriptor_v2")),
                bytes.concat(POSITION_DESCRIPTOR_BYTECODE, abi.encode(poolManager, wTEL, NATIVE_CURRENCY_LABEL))
            );
        }

        // 4. PositionManager - constructor:
        //    (poolManager, permit2, unsubscribeGasLimit, descriptor, weth9).
        positionManager = _deployOrReuse(
            deployments.uniswapV4.PositionManager,
            arachnid,
            bytes32(bytes("PositionManager_v2")),
            bytes.concat(
                POSITION_MANAGER_BYTECODE,
                abi.encode(poolManager, permit2, UNSUBSCRIBE_GAS_LIMIT, positionDescriptor, wTEL)
            )
        );

        // 5. V4Quoter.
        v4Quoter = _deployOrReuse(
            deployments.uniswapV4.V4Quoter,
            arachnid,
            bytes32(bytes("V4Quoter_v2")),
            bytes.concat(V4_QUOTER_BYTECODE, abi.encode(poolManager))
        );

        // 6. StateView.
        stateView = _deployOrReuse(
            deployments.uniswapV4.StateView,
            arachnid,
            bytes32(bytes("StateView_v2")),
            bytes.concat(STATE_VIEW_BYTECODE, abi.encode(poolManager))
        );

        // 7. V4SwapHelper - mediator that lets EOAs call V4 swap.
        v4SwapHelper = _deployOrReuse(
            deployments.uniswapV4.V4SwapHelper,
            arachnid,
            bytes32(bytes("V4SwapHelper_v2")),
            bytes.concat(type(V4SwapHelper).creationCode, abi.encode(IPoolManagerCore(poolManager)))
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
        assertGt(v4SwapHelper.code.length, 0, "V4SwapHelper missing code");

        assertEq(permit2, PERMIT2_CANONICAL_ADDRESS, "Permit2 at canonical address");

        console2.log("Permit2:                    ", permit2);
        console2.log("PoolManager:                ", poolManager);
        console2.log("PositionDescriptor:         ", positionDescriptor);
        console2.log("PositionManager:            ", positionManager);
        console2.log("V4Quoter:                   ", v4Quoter);
        console2.log("StateView:                  ", stateView);
        console2.log("V4SwapHelper:               ", v4SwapHelper);
    }

    function test_V4SwapHelperWiring() public view {
        assertEq(
            address(V4SwapHelper(payable(v4SwapHelper)).poolManager()),
            poolManager,
            "V4SwapHelper poolManager"
        );
    }

    function test_V4SwapHelperRejectsMismatchedNativeValue() public {
        // Build a wTEL/eUSD pool key. Uses the canonical v4-core PoolKey
        // (PoolKeyCore) since that's the type the helper's ExactInputSingleParams
        // expects; the local IV4Test PoolKey is shape-identical but a distinct
        // Solidity type and isn't implicitly convertible.
        address c0 = wTEL < eUSD ? wTEL : eUSD;
        address c1 = wTEL < eUSD ? eUSD : wTEL;
        PoolKeyCore memory key = PoolKeyCore({
            currency0: CurrencyCore.wrap(c0),
            currency1: CurrencyCore.wrap(c1),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(0))
        });

        V4SwapHelper.ExactInputSingleParams memory params = V4SwapHelper.ExactInputSingleParams({
            poolKey: key,
            zeroForOne: true,
            amountIn: 1 ether,
            amountOutMinimum: 0,
            recipient: ADMIN,
            sqrtPriceLimitX96: 0,
            deadline: type(uint48).max,
            hookData: ""
        });

        // ERC-20 input (neither currency is address(0)) but we send msg.value.
        // The InvalidNativeValue guard must fire BEFORE the unlock callback runs.
        vm.deal(ADMIN, 1 ether);
        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(V4SwapHelper.InvalidNativeValue.selector, uint256(1), uint256(0))
        );
        V4SwapHelper(payable(v4SwapHelper)).exactInputSingle{ value: 1 }(params);
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
        bytes32 poolId = _toId(key);

        // Idempotent across re-runs against the same forked PoolManager: skip
        // the initialize call if a previous run already initialized this pool
        // (PoolManager throws PoolAlreadyInitialized otherwise). The post-init
        // assertions then verify slot0 against whatever price the pool was
        // initialized at (either by us this run or by a prior run / external
        // actor) - the contract-level guarantee we care about is "slot0 is
        // queryable and non-zero", not a specific price.
        (uint160 priceBefore, , , ) = IStateView(stateView).getSlot0(poolId);
        if (priceBefore == 0) {
            vm.prank(ADMIN);
            int24 tick = IPoolManager(poolManager).initialize(key, sqrtPriceX96);
            assertEq(tick, 0, "initial tick at 1:1");
            (uint160 actualSqrtPrice, int24 actualTick, , ) = IStateView(stateView).getSlot0(poolId);
            assertEq(actualSqrtPrice, sqrtPriceX96, "slot0 sqrtPriceX96 matches our init");
            assertEq(actualTick, 0, "slot0 tick matches our init");
            console2.log("V4 wTEL/eUSD pool initialized at fee=3000, tickSpacing=60, price=1:1");
        } else {
            (uint160 actualSqrtPrice, , , ) = IStateView(stateView).getSlot0(poolId);
            assertGt(actualSqrtPrice, 0, "slot0 sqrtPriceX96 readable on already-init pool");
            console2.log("V4 wTEL/eUSD pool already initialized at sqrtPriceX96 =", actualSqrtPrice);
        }
    }

    /// @dev Computes the PoolId for a PoolKey. V4's PoolIdLibrary uses
    ///      keccak256(abi.encode(key)) as the canonical id.
    function _toId(PoolKey memory key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key));
    }
}
