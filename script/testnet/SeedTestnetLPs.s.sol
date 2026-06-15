// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { DeploymentsResolver } from "../../deployments/DeploymentsResolver.sol";
import { IUniswapV2Router02 } from "external/uniswap/interfaces/IUniswapV2Router02.sol";
import { IUniswapV2Factory } from "external/uniswap/interfaces/IUniswapV2Factory.sol";
import { IUniswapV2Pair } from "external/uniswap/interfaces/IUniswapV2Pair.sol";
import { TickMath } from "@uniswap/v4-core/src/libraries/TickMath.sol";
import { LiquidityAmounts } from "v4-periphery/src/libraries/LiquidityAmounts.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { IMulticall3 } from "forge-std/interfaces/IMulticall3.sol";

/// @title Seed LP across V2/V3/V4 on Adiri using live FX rates
///
/// @notice For each of 22 eUSD/eXYZ pairs, seeds liquidity on the V2 router,
///         the V3 NonfungiblePositionManager, and the V4 PositionManager at
///         the live FX-implied price. Pre-flight: tops up admin's balance for
///         each stablecoin via the StablecoinManager faucet (one drip per
///         token, capped by the configured per-call max).
///
/// @notice Realistic ratios come from a USD-base FX feed (open.er-api.com)
///         that the bash wrapper writes to `cache/seed-testnet-lps-fx.json`. Each rate
///         is a 1e6-scaled uint - e.g. eAUD = 1_383_247 means 1 USD = 1.383247
///         AUD. We compute pool amounts and sqrt-prices off these rates so
///         each pool starts at the live price.
///
/// @notice Multicall: V3 NPM and V4 PositionManager both expose multicall.
///         All 22 V3 (createAndInit + mint) calls land in one tx via
///         NPM.multicall; same for V4 (initializePool + modifyLiquidities).
///         V2 router has no multicall - those 22 addLiquidity calls go out
///         sequentially.
///
/// @dev Run via the bash wrapper:
///        `bash script/bash/seed-testnet-lps.sh`
///      The wrapper fetches FX rates and calls this script with --broadcast.
contract SeedTestnetLPs is Script {
    // ---------- config ----------

    /// @notice Per-pool eXYZ amount, raw (6-decimal). The eUSD side is
    ///         derived per-pair as `XYZ_PER_POOL * 1e6 / rate6`. Sized to fit
    ///         the natural single-drip eUSD budget across 22 pairs * 3
    ///         protocols: 3 * sum(XYZ_PER_POOL / FX_rate) totals ~26 eUSD at
    ///         current rates, comfortably within the faucet's 100-eUSD-per-
    ///         drip cap.
    uint256 constant XYZ_PER_POOL = 1e6; // 1 of each eXYZ

    /// @notice Per-token drip request - matches the faucet's default
    ///         per-recipient `maxDripAmount`. The faucet's per-token cooldown
    ///         decides whether the drip lands; we read that upfront via
    ///         Multicall3 so we only enqueue eligible drips.
    uint256 constant DRIP_AMOUNT = 100e6;

    uint24 constant FEE = 3000; // 0.3%
    int24 constant TICK_SPACING = 60; // for fee=3000
    int24 constant TICK_LOWER = -887_220; // full-range, -MIN_TICK aligned to 60
    int24 constant TICK_UPPER = 887_220; // full-range,  MAX_TICK aligned to 60

    uint160 constant SQRT_PRICE_LOWER = 4_295_128_739; // TickMath.MIN_SQRT_PRICE for tick -887220
    uint160 constant SQRT_PRICE_UPPER = 1_461_446_703_485_210_103_287_273_052_203_988_822_378_723_970_341; // for tick 887220

    /// @notice Canonical Multicall3 address. Verified deployed on Adiri.
    address constant MULTICALL3 = 0xcA11bde05977b3631167028862bE2a173976CA11;

    /// @notice Lowest balance worth keeping post-LP per token. Drips are
    ///         skipped when admin already holds at least this much (avoids
    ///         burning faucet calls on tokens we don't need to top up).
    uint256 constant MIN_BALANCE_TARGET = 50e6; // 50 of each stablecoin

    // ---------- state ----------

    Deployments deployments;
    address admin;
    address eUSD;
    address stablecoinMgr;

    // V2
    IUniswapV2Router02 v2Router;
    IUniswapV2Factory v2Factory;

    // V3
    address v3NPM;
    address v3Factory;

    // V4
    address v4PoolManager;
    address v4PositionManager;
    address permit2;

    /// @notice One entry per non-eUSD eXYZ. `rate6` is FX rate * 1e6, where
    ///         rate6 / 1e6 = units of this currency per 1 USD.
    struct Pair {
        string symbol;
        address token;
        uint256 rate6;
    }

    Pair[] pairs;

    /// @notice Drip plan, populated by `_planDrip` ahead of broadcast.
    address[] dripTokens;
    uint256[] dripAmounts;

    // ---------- setup ----------

    function setUp() public {
        // Deployments JSON.
        string memory root = vm.projectRoot();
        string memory dPath = string.concat(root, DeploymentsResolver.relativePath());
        bytes memory data = vm.parseJson(vm.readFile(dPath));
        deployments = abi.decode(data, (Deployments));

        admin = deployments.admin;
        eUSD = deployments.eXYZs.eUSD;
        stablecoinMgr = deployments.StablecoinManager;
        v2Router = IUniswapV2Router02(deployments.uniswapV2.UniswapV2Router02);
        v2Factory = IUniswapV2Factory(deployments.uniswapV2.UniswapV2Factory);
        v3NPM = deployments.uniswapV3.NonfungiblePositionManager;
        v3Factory = deployments.uniswapV3.UniswapV3Factory;
        v4PoolManager = deployments.uniswapV4.PoolManager;
        v4PositionManager = deployments.uniswapV4.PositionManager;
        permit2 = deployments.uniswapV4.Permit2;

        // FX rates JSON (written by script/bash/seed-testnet-lps.sh).
        string memory fxPath = string.concat(root, "/cache/seed-testnet-lps-fx.json");
        string memory fxJson = vm.readFile(fxPath);

        // Build pairs[] in a fixed order that matches the FX JSON keys.
        _addPair(fxJson, "eAUD", deployments.eXYZs.eAUD);
        _addPair(fxJson, "eCAD", deployments.eXYZs.eCAD);
        _addPair(fxJson, "eCFA", deployments.eXYZs.eCFA);
        _addPair(fxJson, "eCHF", deployments.eXYZs.eCHF);
        _addPair(fxJson, "eCZK", deployments.eXYZs.eCZK);
        _addPair(fxJson, "eDKK", deployments.eXYZs.eDKK);
        _addPair(fxJson, "eEUR", deployments.eXYZs.eEUR);
        _addPair(fxJson, "eGBP", deployments.eXYZs.eGBP);
        _addPair(fxJson, "eHKD", deployments.eXYZs.eHKD);
        _addPair(fxJson, "eHUF", deployments.eXYZs.eHUF);
        _addPair(fxJson, "eINR", deployments.eXYZs.eINR);
        _addPair(fxJson, "eISK", deployments.eXYZs.eISK);
        _addPair(fxJson, "eJPY", deployments.eXYZs.eJPY);
        _addPair(fxJson, "eKES", deployments.eXYZs.eKES);
        _addPair(fxJson, "eMXN", deployments.eXYZs.eMXN);
        _addPair(fxJson, "eNOK", deployments.eXYZs.eNOK);
        _addPair(fxJson, "eNZD", deployments.eXYZs.eNZD);
        _addPair(fxJson, "eSDR", deployments.eXYZs.eSDR);
        _addPair(fxJson, "eSEK", deployments.eXYZs.eSEK);
        _addPair(fxJson, "eSGD", deployments.eXYZs.eSGD);
        _addPair(fxJson, "eTRY", deployments.eXYZs.eTRY);
        _addPair(fxJson, "eZAR", deployments.eXYZs.eZAR);

        require(pairs.length == 22, "SeedTestnetLPs: pair count mismatch");
    }

    function _addPair(string memory fxJson, string memory sym, address token) internal {
        require(token != address(0), string.concat("SeedTestnetLPs: ", sym, " not in deployments.json"));
        uint256 rate6 = vm.parseJsonUint(fxJson, string.concat(".rates.", sym));
        require(rate6 > 0, string.concat("SeedTestnetLPs: ", sym, " rate missing or zero"));
        pairs.push(Pair({ symbol: sym, token: token, rate6: rate6 }));
    }

    // ---------- run ----------

    function run() public {
        // Phase 1: pre-flight read via Multicall3 (no broadcast).
        _planDrip();

        // Phase 2: broadcast all state changes.
        vm.startBroadcast(admin);

        _executeDrip();
        _seedV2();
        _seedV3();
        _seedV4();

        vm.stopBroadcast();

        _logSummary();
    }

    // ---------- 1. faucet (read-plan-act) ----------

    /// @notice Reads admin's faucet state for all 23 stablecoins in one
    ///         Multicall3 aggregate3, then plans which drips are eligible
    ///         (cooldown elapsed, balance below `MIN_BALANCE_TARGET`). No
    ///         broadcast - pure read. We use a `staticcall` so this never
    ///         becomes a tx in the broadcast queue regardless of phase.
    function _planDrip() internal {
        console2.log("--- plan drip ---");

        uint256 nTokens = 1 + pairs.length; // eUSD + 22 eXYZ
        IMulticall3.Call3[] memory calls = new IMulticall3.Call3[](nTokens * 2);

        for (uint256 i; i < nTokens; ++i) {
            address token = i == 0 ? eUSD : pairs[i - 1].token;
            calls[2 * i] = IMulticall3.Call3({
                target: token,
                allowFailure: false,
                callData: abi.encodeWithSelector(IERC20.balanceOf.selector, admin)
            });
            calls[2 * i + 1] = IMulticall3.Call3({
                target: stablecoinMgr,
                allowFailure: false,
                callData: abi.encodeWithSelector(IFaucet.getNextEligibleDripTimestamp.selector, admin, token)
            });
        }

        (bool ok, bytes memory ret) = MULTICALL3.staticcall(
            abi.encodeWithSelector(IMulticall3.aggregate3.selector, calls)
        );
        require(ok, "SeedTestnetLPs: Multicall3 read failed");
        IMulticall3.Result[] memory results = abi.decode(ret, (IMulticall3.Result[]));

        for (uint256 i; i < nTokens; ++i) {
            address token = i == 0 ? eUSD : pairs[i - 1].token;
            string memory sym = i == 0 ? "eUSD" : pairs[i - 1].symbol;
            uint256 bal = abi.decode(results[2 * i].returnData, (uint256));
            uint256 nextEligible = abi.decode(results[2 * i + 1].returnData, (uint256));

            if (bal >= MIN_BALANCE_TARGET) {
                console2.log(string.concat("  skip ", sym, ": balance OK ="), bal);
                continue;
            }
            if (nextEligible > block.timestamp) {
                console2.log(string.concat("  skip ", sym, ": cooldown until"), nextEligible);
                continue;
            }
            dripTokens.push(token);
            dripAmounts.push(DRIP_AMOUNT);
            console2.log(string.concat("  plan ", sym, ": drip"), DRIP_AMOUNT);
        }
    }

    /// @notice Batches all eligible drips into a single Multicall3 tx.
    ///         `dripTo(recipient, ...)` checks the recipient's cooldown - not
    ///         msg.sender's - so calling it from the Multicall3 contract
    ///         credits admin and respects admin's per-recipient state.
    function _executeDrip() internal {
        if (dripTokens.length == 0) {
            console2.log("--- drip: nothing to do ---");
            return;
        }
        console2.log("--- drip: batching", dripTokens.length, "drips via Multicall3 ---");

        IMulticall3.Call3[] memory calls = new IMulticall3.Call3[](dripTokens.length);
        for (uint256 i; i < dripTokens.length; ++i) {
            calls[i] = IMulticall3.Call3({
                target: stablecoinMgr,
                allowFailure: false,
                callData: abi.encodeWithSelector(
                    IFaucet.dripTo.selector, admin, dripTokens[i], dripAmounts[i]
                )
            });
        }
        IMulticall3(MULTICALL3).aggregate3(calls);
    }

    // ---------- 2. V2 ----------

    /// @notice For each pair: skip if pool already has reserves; else
    ///         approve eUSD + eXYZ to the router (max, idempotent at
    ///         allowance level) and call addLiquidity at FX-implied amounts.
    function _seedV2() internal {
        console2.log("--- V2 ---");
        // Approve eUSD once.
        IERC20(eUSD).approve(address(v2Router), type(uint256).max);

        for (uint256 i; i < pairs.length; ++i) {
            Pair memory p = pairs[i];
            address pool = v2Factory.getPair(eUSD, p.token);
            if (pool == address(0)) {
                console2.log("  skip", p.symbol, ": pair missing in factory");
                continue;
            }
            (uint112 r0, uint112 r1,) = IUniswapV2Pair(pool).getReserves();
            if (r0 > 0 || r1 > 0) {
                console2.log("  skip", p.symbol, ": already has reserves");
                continue;
            }

            uint256 xyzAmt = XYZ_PER_POOL;
            uint256 usdAmt = (xyzAmt * 1e6) / p.rate6;

            IERC20(p.token).approve(address(v2Router), type(uint256).max);
            v2Router.addLiquidity(
                eUSD,
                p.token,
                usdAmt,
                xyzAmt,
                0,
                0,
                admin,
                block.timestamp + 1800
            );
            console2.log("  V2 LP    ", p.symbol);
        }
    }

    // ---------- 3. V3 (one multicall per pair) ----------

    /// @notice Per pair: one NPM.multicall combining createAndInitialize +
    ///         mint. Splitting per-pair (rather than one giant 22-pair
    ///         multicall) keeps each tx well under the chain's block gas
    ///         limit; pool init alone is ~4.5M gas plus ~0.5M for the mint.
    function _seedV3() internal {
        console2.log("--- V3 ---");
        IERC20(eUSD).approve(v3NPM, type(uint256).max);

        uint256 deadline = block.timestamp + 1800;
        bytes[] memory perPair = new bytes[](2);

        for (uint256 i; i < pairs.length; ++i) {
            Pair memory p = pairs[i];
            IERC20(p.token).approve(v3NPM, type(uint256).max);

            (address t0, address t1, uint256 a0, uint256 a1, uint160 sqrtPriceX96) = _amountsAndPrice(p);

            perPair[0] = abi.encodeWithSelector(
                INPM.createAndInitializePoolIfNecessary.selector, t0, t1, FEE, sqrtPriceX96
            );
            INPM.MintParams memory mp = INPM.MintParams({
                token0: t0,
                token1: t1,
                fee: FEE,
                tickLower: TICK_LOWER,
                tickUpper: TICK_UPPER,
                amount0Desired: a0,
                amount1Desired: a1,
                amount0Min: 0,
                amount1Min: 0,
                recipient: admin,
                deadline: deadline
            });
            perPair[1] = abi.encodeWithSelector(INPM.mint.selector, mp);

            IMulticall(v3NPM).multicall(perPair);
            console2.log("  V3 LP    ", p.symbol);
        }
    }

    // ---------- 4. V4 (one multicall per pair) ----------

    /// @notice V4 LP requires Permit2-mediated transfers. Per token:
    ///           1. ERC20.approve(token, Permit2, max) - one tx per token
    ///           2. Permit2.approve(token, PositionManager, max, expiration) -
    ///              one tx per token (Permit2's own allowance ledger).
    ///         Then for each pair we send one PositionManager.multicall
    ///         combining initializePool + modifyLiquidities. Per-pair
    ///         (rather than 22-in-one) keeps each tx under the block gas
    ///         limit.
    function _seedV4() internal {
        console2.log("--- V4 ---");
        // Step A: token -> Permit2 ERC20 approvals.
        IERC20(eUSD).approve(permit2, type(uint256).max);
        for (uint256 i; i < pairs.length; ++i) {
            IERC20(pairs[i].token).approve(permit2, type(uint256).max);
        }
        // Step B: Permit2 -> PositionManager allowances. Permit2 caps amount
        // at uint160 and uses an expiration timestamp.
        uint48 expiration = uint48(block.timestamp + 365 days);
        IPermit2(permit2).approve(eUSD, v4PositionManager, type(uint160).max, expiration);
        for (uint256 i; i < pairs.length; ++i) {
            IPermit2(permit2).approve(pairs[i].token, v4PositionManager, type(uint160).max, expiration);
        }

        // Step C: per-pair multicall(initializePool, modifyLiquidities).
        bytes[] memory perPair = new bytes[](2);
        uint256 deadline = block.timestamp + 1800;

        for (uint256 i; i < pairs.length; ++i) {
            Pair memory p = pairs[i];

            (address t0, address t1, uint256 a0, uint256 a1, uint160 sqrtPriceX96) = _amountsAndPrice(p);

            PoolKey memory key = PoolKey({
                currency0: t0,
                currency1: t1,
                fee: FEE,
                tickSpacing: TICK_SPACING,
                hooks: address(0)
            });

            perPair[0] = abi.encodeWithSelector(
                IV4PositionManager.initializePool.selector, key, sqrtPriceX96
            );

            // Compute liquidity from amounts at full-range bounds.
            uint128 liquidity = LiquidityAmounts.getLiquidityForAmounts(
                sqrtPriceX96, SQRT_PRICE_LOWER, SQRT_PRICE_UPPER, a0, a1
            );

            // Encode actions: MINT_POSITION + SETTLE_PAIR.
            // Action constants from v4-periphery/src/libraries/Actions.sol.
            bytes memory actions = abi.encodePacked(uint8(0x02), uint8(0x0d));
            bytes[] memory params = new bytes[](2);
            params[0] = abi.encode(
                key,
                TICK_LOWER,
                TICK_UPPER,
                uint256(liquidity),
                uint128(a0 + a0 / 100), // 1% slack
                uint128(a1 + a1 / 100),
                admin,
                bytes("") // hookData
            );
            params[1] = abi.encode(t0, t1);
            bytes memory unlockData = abi.encode(actions, params);

            perPair[1] = abi.encodeWithSelector(
                IV4PositionManager.modifyLiquidities.selector, unlockData, deadline
            );

            IMulticall(v4PositionManager).multicall(perPair);
            console2.log("  V4 LP    ", p.symbol);
        }
    }

    // ---------- helpers ----------

    /// @notice Sorts (eUSD, eXYZ) by address and returns the desired raw
    ///         token amounts for a 5-eXYZ pool plus the matching sqrtPriceX96.
    function _amountsAndPrice(Pair memory p)
        internal
        view
        returns (address t0, address t1, uint256 amt0, uint256 amt1, uint160 sqrtPriceX96)
    {
        uint256 xyzAmt = XYZ_PER_POOL;
        uint256 usdAmt = (xyzAmt * 1e6) / p.rate6;

        if (eUSD < p.token) {
            t0 = eUSD;
            t1 = p.token;
            amt0 = usdAmt;
            amt1 = xyzAmt;
        } else {
            t0 = p.token;
            t1 = eUSD;
            amt0 = xyzAmt;
            amt1 = usdAmt;
        }

        // sqrtPriceX96 = sqrt((amt1 << 192) / amt0).
        // Both amounts <= 30e6 so (amt1 << 192) <= ~1.9e65, fits in uint256.
        uint256 ratioQ192 = (amt1 << 192) / amt0;
        sqrtPriceX96 = uint160(FixedPointMathLib.sqrt(ratioQ192));
    }

    function _logSummary() internal view {
        console2.log("--- post-seed admin balances ---");
        console2.log("  eUSD :", IERC20(eUSD).balanceOf(admin));
        for (uint256 i; i < pairs.length; ++i) {
            console2.log(string.concat("  ", pairs[i].symbol, " :"), IERC20(pairs[i].token).balanceOf(admin));
        }
    }
}

// ---------- minimal interfaces (kept inline to avoid coupling to test files) ----------

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IFaucet {
    function dripTo(address recipient, address token, uint256 amount) external;
    function getNextEligibleDripTimestamp(address recipient, address token) external view returns (uint256);
}

interface IMulticall {
    function multicall(bytes[] calldata data) external returns (bytes[] memory);
}

interface INPM {
    struct MintParams {
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
    }

    function createAndInitializePoolIfNecessary(
        address token0,
        address token1,
        uint24 fee,
        uint160 sqrtPriceX96
    )
        external
        payable
        returns (address);

    function mint(MintParams calldata params)
        external
        payable
        returns (uint256, uint128, uint256, uint256);
}

interface IPermit2 {
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
}

struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

interface IV4PositionManager {
    function initializePool(PoolKey calldata key, uint160 sqrtPriceX96) external payable returns (int24);
    function modifyLiquidities(bytes calldata unlockData, uint256 deadline) external payable;
}
