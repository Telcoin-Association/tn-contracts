// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { console2 } from "forge-std/console2.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { UniswapV3FactoryBytecode } from "../../external/uniswap/precompiles/v3/UniswapV3Factory.sol";
import { NFTDescriptorBytecode } from "../../external/uniswap/precompiles/v3/NFTDescriptor.sol";
import { NonfungibleTokenPositionDescriptorBytecode } from
    "../../external/uniswap/precompiles/v3/NonfungibleTokenPositionDescriptor.sol";
import { NonfungiblePositionManagerBytecode } from
    "../../external/uniswap/precompiles/v3/NonfungiblePositionManager.sol";
import { QuoterV2Bytecode } from "../../external/uniswap/precompiles/v3/QuoterV2.sol";
import { TickLensBytecode } from "../../external/uniswap/precompiles/v3/TickLens.sol";
import { SwapRouter02Bytecode } from "../../external/uniswap/precompiles/v3/SwapRouter02.sol";
import { WTEL } from "../../src/WTEL.sol";
import {
    IUniswapV3Factory,
    IUniswapV3Pool,
    INonfungiblePositionManager,
    ISwapRouter02,
    IERC20Min
} from "./IV3Test.sol";

/// @title Fork integration test for Uniswap V3 on Adiri
///
/// @notice Forks Adiri at the latest block, deploys WTEL + the V3 stack via
///         Arachnid CREATE2 (mirroring TestnetDeployWTEL + TestnetDeployUniswapV3),
///         and exercises the full LP-create + LP-mint + swap lifecycle against
///         the real wrapped-native contract. WTEL is funded by ADMIN's native
///         balance via `deposit()` so LP / swap flows have wrapped tokens to
///         move; no precompile-mock etching is needed because every wTEL
///         interaction now resolves to plain ERC20 calls on the deployed WTEL
///         contract.
///
/// @dev Run: `forge test --match-contract V3IntegrationFork --fork-url $TN_RPC_URL -vv`
///      A live RPC URL is required; the test does not function under unit-test mode.
///      No transactions are broadcast - this is pure simulation against the fork.
contract V3IntegrationFork is
    Test,
    UniswapV3FactoryBytecode,
    NFTDescriptorBytecode,
    NonfungibleTokenPositionDescriptorBytecode,
    NonfungiblePositionManagerBytecode,
    QuoterV2Bytecode,
    TickLensBytecode,
    SwapRouter02Bytecode
{
    bytes32 constant NATIVE_CURRENCY_LABEL = bytes32("TEL");
    uint256 constant DESC_LIB_LINK_OFFSET = 1681;

    Deployments deployments;

    // V3 deployment outputs.
    address uniswapV3Factory;
    address nftDescriptor;
    address nonfungibleTokenPositionDescriptor;
    address nonfungiblePositionManager;
    address swapRouter02;
    address quoterV2;
    address tickLens;

    // Test accounts. The fork inherits Adiri's actual eUSD contract; we use
    // Foundry's `deal` cheatcode to grant balances rather than running through
    // the StablecoinManager faucet.
    address constant ADMIN = 0x588D280a2B5577042765C2aaa6f13C7A611649de;

    // Tokens (read from the fork's deployments.json snapshot).
    address eUSD;
    address wTEL;

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
        // then deploy V3 against it. Mirrors TestnetDeployWTEL + TestnetDeployUniswapV3.
        wTEL = _deployOrReuse(
            deployments.WTEL,
            deployments.ArachnidDeterministicDeployFactory,
            bytes32(bytes("WTEL")),
            type(WTEL).creationCode
        );

        _deployV3();

        // Fund the admin with native TEL + eUSD, then wrap a chunk so LP / swap
        // tests have a positive WTEL balance to move.
        vm.deal(ADMIN, 1_000_000 ether);
        deal(eUSD, ADMIN, 1_000_000 * 10 ** IERC20Min(eUSD).decimals());
        vm.prank(ADMIN);
        WTEL(payable(wTEL)).deposit{ value: 500_000 ether }();
    }

    /// @dev Self-bootstrapping deploy: if the address is already populated in
    ///      `deployments.json` AND has on-chain code at fork time, reuse it
    ///      instead of trying to redeploy via Arachnid (which would revert on
    ///      address-collision). This makes the same test work both pre-deploy
    ///      (deploys fresh on a chain that doesn't yet have V3) and post-deploy
    ///      (validates against the live on-chain V3).
    function _deployV3() internal {
        address arachnid = deployments.ArachnidDeterministicDeployFactory;

        // 1. UniswapV3Factory
        uniswapV3Factory = _deployOrReuse(
            deployments.uniswapV3.UniswapV3Factory,
            arachnid,
            bytes32(bytes("UniswapV3Factory_v2")),
            UNISWAPV3FACTORY_BYTECODE
        );

        // 2. NFTDescriptor library
        nftDescriptor = _deployOrReuse(
            deployments.uniswapV3.NFTDescriptor,
            arachnid,
            bytes32(bytes("NFTDescriptor_v2")),
            NFTDESCRIPTOR_BYTECODE
        );

        // 3. NonfungibleTokenPositionDescriptor (library-linked to NFTDescriptor).
        bytes memory descLinked = _linkNFTDescriptor(NONFUNGIBLE_TOKEN_POSITION_DESCRIPTOR_BYTECODE, nftDescriptor);
        bytes memory descInitcode = bytes.concat(descLinked, abi.encode(wTEL, NATIVE_CURRENCY_LABEL));
        nonfungibleTokenPositionDescriptor = _deployOrReuse(
            deployments.uniswapV3.NonfungibleTokenPositionDescriptor,
            arachnid,
            bytes32(bytes("NFTPositionDescriptor_v2")),
            descInitcode
        );

        // 4. NonfungiblePositionManager(_factory, _WETH9, _tokenDescriptor)
        bytes memory npmInitcode = bytes.concat(
            NONFUNGIBLE_POSITION_MANAGER_BYTECODE,
            abi.encode(uniswapV3Factory, wTEL, nonfungibleTokenPositionDescriptor)
        );
        nonfungiblePositionManager = _deployOrReuse(
            deployments.uniswapV3.NonfungiblePositionManager,
            arachnid,
            bytes32(bytes("NonfungiblePositionManager_v2")),
            npmInitcode
        );

        // 5. SwapRouter02(_factoryV2, _factoryV3, _positionManager, _WETH9)
        bytes memory swapRouterInitcode = bytes.concat(
            SWAP_ROUTER_02_BYTECODE,
            abi.encode(deployments.uniswapV2.UniswapV2Factory, uniswapV3Factory, nonfungiblePositionManager, wTEL)
        );
        swapRouter02 = _deployOrReuse(
            deployments.uniswapV3.SwapRouter02,
            arachnid,
            bytes32(bytes("SwapRouter02_v2")),
            swapRouterInitcode
        );

        // 6. QuoterV2(_factory, _WETH9)
        bytes memory quoterInitcode = bytes.concat(QUOTER_V2_BYTECODE, abi.encode(uniswapV3Factory, wTEL));
        quoterV2 = _deployOrReuse(
            deployments.uniswapV3.QuoterV2,
            arachnid,
            bytes32(bytes("QuoterV2_v2")),
            quoterInitcode
        );

        // 7. TickLens
        tickLens = _deployOrReuse(
            deployments.uniswapV3.TickLens,
            arachnid,
            bytes32(bytes("TickLens_v2")),
            TICK_LENS_BYTECODE
        );
    }

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

    function _create2(address arachnid, bytes32 salt, bytes memory initcode) internal returns (address deployed) {
        (bool ok, bytes memory ret) = arachnid.call(bytes.concat(salt, initcode));
        require(ok, "_create2 failed");
        deployed = address(bytes20(ret));
    }

    function _linkNFTDescriptor(bytes memory code, address lib) internal pure returns (bytes memory linked) {
        require(code.length >= DESC_LIB_LINK_OFFSET + 20, "code too short");
        linked = bytes.concat(code);
        bytes20 libBytes = bytes20(lib);
        for (uint256 i = 0; i < 20; ++i) {
            linked[DESC_LIB_LINK_OFFSET + i] = libBytes[i];
        }
    }

    // ---------- Tests ----------

    function test_AllContractsHaveCode() public view {
        assertGt(uniswapV3Factory.code.length, 0, "factory missing code");
        assertGt(nftDescriptor.code.length, 0, "NFTDescriptor missing code");
        assertGt(nonfungibleTokenPositionDescriptor.code.length, 0, "descriptor missing code");
        assertGt(nonfungiblePositionManager.code.length, 0, "NPM missing code");
        assertGt(swapRouter02.code.length, 0, "SwapRouter02 missing code");
        assertGt(quoterV2.code.length, 0, "QuoterV2 missing code");
        assertGt(tickLens.code.length, 0, "TickLens missing code");
        console2.log("UniswapV3Factory:                   ", uniswapV3Factory);
        console2.log("NFTDescriptor:                      ", nftDescriptor);
        console2.log("NonfungibleTokenPositionDescriptor: ", nonfungibleTokenPositionDescriptor);
        console2.log("NonfungiblePositionManager:         ", nonfungiblePositionManager);
        console2.log("SwapRouter02:                       ", swapRouter02);
        console2.log("QuoterV2:                           ", quoterV2);
        console2.log("TickLens:                           ", tickLens);
    }

    function test_NPMConstructorWiringIsCorrect() public view {
        INonfungiblePositionManager npm = INonfungiblePositionManager(nonfungiblePositionManager);
        assertEq(npm.factory(), uniswapV3Factory, "NPM factory");
        assertEq(npm.WETH9(), wTEL, "NPM WETH9");
    }

    function test_SwapRouter02ConstructorWiringIsCorrect() public view {
        ISwapRouter02 r = ISwapRouter02(swapRouter02);
        assertEq(r.factory(), uniswapV3Factory, "router factory");
        assertEq(r.WETH9(), wTEL, "router WETH9");
    }

    function test_CreateAndInitWtelEusdPool() public {
        // Use the 0.3% fee tier as a reasonable default for testnet.
        uint24 fee = 3000;

        // Sort tokens to match V3's tokenA < tokenB convention.
        (address token0, address token1) = wTEL < eUSD ? (wTEL, eUSD) : (eUSD, wTEL);

        // 1:1 price for the initial sqrtPriceX96 (Q96). The actual price
        // doesn't matter for this test - we're verifying the create + init
        // path works at all against the etched mock precompile.
        uint160 sqrtPriceX96 = 79228162514264337593543950336; // sqrt(1) * 2^96

        vm.prank(ADMIN);
        address pool = INonfungiblePositionManager(nonfungiblePositionManager).createAndInitializePoolIfNecessary(
            token0, token1, fee, sqrtPriceX96
        );

        assertGt(pool.code.length, 0, "pool not deployed");
        assertEq(IUniswapV3Factory(uniswapV3Factory).getPool(token0, token1, fee), pool, "factory mapping");
        assertEq(IUniswapV3Pool(pool).token0(), token0, "pool token0");
        assertEq(IUniswapV3Pool(pool).token1(), token1, "pool token1");
        assertEq(IUniswapV3Pool(pool).fee(), fee, "pool fee");

        (uint160 actualSqrtPrice,,,,,,) = IUniswapV3Pool(pool).slot0();
        assertEq(actualSqrtPrice, sqrtPriceX96, "pool initialized price");
    }

    function test_MintLpWtelEusd() public {
        // Pre-conditions for LP mint: pool exists + admin has wTEL + eUSD + has approved NPM.
        uint24 fee = 3000;
        (address token0, address token1) = wTEL < eUSD ? (wTEL, eUSD) : (eUSD, wTEL);
        uint160 sqrtPriceX96 = 79228162514264337593543950336;

        vm.startPrank(ADMIN);
        INonfungiblePositionManager(nonfungiblePositionManager).createAndInitializePoolIfNecessary(
            token0, token1, fee, sqrtPriceX96
        );

        // Approve NPM to pull both tokens. wTEL works through the etched mock;
        // eUSD is the real eUSD contract from the fork.
        IERC20Min(wTEL).approve(nonfungiblePositionManager, type(uint256).max);
        IERC20Min(eUSD).approve(nonfungiblePositionManager, type(uint256).max);

        // Full-range LP mint. Tick spacing for fee=3000 is 60; full range
        // ticks are -887272 / 887272, but they must be multiples of 60.
        // -887220 and 887220 are the canonical full-range bounds for 60-spacing.
        int24 tickLower = -887220;
        int24 tickUpper = 887220;

        // Provide 1000 of each token (in their respective decimals).
        uint256 amount0Desired = token0 == eUSD ? 1000 * 10 ** IERC20Min(eUSD).decimals() : 1000 ether;
        uint256 amount1Desired = token1 == eUSD ? 1000 * 10 ** IERC20Min(eUSD).decimals() : 1000 ether;

        INonfungiblePositionManager.MintParams memory params = INonfungiblePositionManager.MintParams({
            token0: token0,
            token1: token1,
            fee: fee,
            tickLower: tickLower,
            tickUpper: tickUpper,
            amount0Desired: amount0Desired,
            amount1Desired: amount1Desired,
            amount0Min: 0,
            amount1Min: 0,
            recipient: ADMIN,
            deadline: block.timestamp + 600
        });

        (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1) =
            INonfungiblePositionManager(nonfungiblePositionManager).mint(params);

        vm.stopPrank();

        assertGt(tokenId, 0, "tokenId issued");
        assertGt(liquidity, 0, "liquidity minted");
        assertGt(amount0, 0, "amount0 deposited");
        assertGt(amount1, 0, "amount1 deposited");

        console2.log("LP minted: tokenId=%d liquidity=%d", tokenId, liquidity);
        console2.log("amount0=%d amount1=%d", amount0, amount1);
    }

    function test_SwapWtelForEusd() public {
        // Reuses the LP mint setup, then performs a swap.
        test_MintLpWtelEusd();

        uint24 fee = 3000;

        uint256 wtelBefore = IERC20Min(wTEL).balanceOf(ADMIN);
        uint256 eusdBefore = IERC20Min(eUSD).balanceOf(ADMIN);

        vm.startPrank(ADMIN);
        IERC20Min(wTEL).approve(swapRouter02, type(uint256).max);

        ISwapRouter02.ExactInputSingleParams memory params = ISwapRouter02.ExactInputSingleParams({
            tokenIn: wTEL,
            tokenOut: eUSD,
            fee: fee,
            recipient: ADMIN,
            amountIn: 10 ether, // 10 wTEL
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });

        uint256 amountOut = ISwapRouter02(swapRouter02).exactInputSingle(params);
        vm.stopPrank();

        uint256 wtelAfter = IERC20Min(wTEL).balanceOf(ADMIN);
        uint256 eusdAfter = IERC20Min(eUSD).balanceOf(ADMIN);

        assertLt(wtelAfter, wtelBefore, "wTEL spent");
        assertGt(eusdAfter, eusdBefore, "eUSD received");
        assertEq(eusdAfter - eusdBefore, amountOut, "received matches return");
        console2.log("swap: spent %d wTEL, received %d eUSD", wtelBefore - wtelAfter, amountOut);
    }
}
