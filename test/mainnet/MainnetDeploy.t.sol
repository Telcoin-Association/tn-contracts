// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { DeploymentsResolver } from "../../deployments/DeploymentsResolver.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { MainnetDeploySafeV130 } from "../../script/mainnet/deploy/MainnetDeploySafeV130.s.sol";
import { MainnetDeployEntryPoint } from "../../script/mainnet/deploy/MainnetDeployEntryPoint.s.sol";
import { MainnetDeployCreateX } from "../../script/mainnet/deploy/MainnetDeployCreateX.s.sol";
import { MainnetDeployPermit2 } from "../../script/mainnet/deploy/MainnetDeployPermit2.s.sol";
import { MainnetDeployUniswapV2 } from "../../script/mainnet/deploy/MainnetDeployUniswapV2.s.sol";
import { MainnetDeployUniswapV3 } from "../../script/mainnet/deploy/MainnetDeployUniswapV3.s.sol";
import { IUniswapV3FactoryAdmin } from "../../script/utils/UniswapV3FactoryDeployer.sol";
import { IUniswapV2Factory } from "external/uniswap/interfaces/IUniswapV2Factory.sol";
import { UniswapV2FactoryBytecode } from "external/uniswap/precompiles/UniswapV2FactoryBytecode.sol";

// Harnesses accept the local test chain in place of the (not yet finalized) mainnet chain id

contract SafeV130Harness is MainnetDeploySafeV130 {
    function _expectedChainId() internal view override returns (uint256) {
        return block.chainid;
    }
}

contract EntryPointHarness is MainnetDeployEntryPoint {
    function _expectedChainId() internal view override returns (uint256) {
        return block.chainid;
    }
}

contract CreateXHarness is MainnetDeployCreateX {
    function _expectedChainId() internal view override returns (uint256) {
        return block.chainid;
    }
}

contract Permit2Harness is MainnetDeployPermit2 {
    function _expectedChainId() internal view override returns (uint256) {
        return block.chainid;
    }
}

contract UniswapV2Harness is MainnetDeployUniswapV2 {
    function _expectedChainId() internal view override returns (uint256) {
        return block.chainid;
    }
}

contract UniswapV3Harness is MainnetDeployUniswapV3 {
    function _expectedChainId() internal view override returns (uint256) {
        return block.chainid;
    }
}

contract WrongChainHarness is MainnetDeployPermit2 {
    function _expectedChainId() internal view override returns (uint256) {
        return block.chainid + 1;
    }
}

interface IGnosisSafeProxyFactoryV130 {
    function createProxyWithNonce(
        address singleton,
        bytes memory initializer,
        uint256 saltNonce
    )
        external
        returns (address proxy);
}

interface IGnosisSafeV130 {
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    )
        external;
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function VERSION() external view returns (string memory);
}

interface IUniswapV3PoolFactory {
    function createPool(address tokenA, address tokenB, uint24 fee) external returns (address pool);
}

/// @title Mainnet post-genesis deploy scripts
/// @notice Runs every script under script/mainnet/deploy/ against a replay of mainnet genesis:
///         each one alone from a fresh state, then again to prove a re-run sends nothing, then
///         end-to-end checks that the deployed contracts produce canonical cross-chain addresses
contract MainnetDeployTest is Test {
    /// @dev Runtime code of the Arachnid deterministic deployment proxy, identical on every chain
    bytes constant ARACHNID_RUNTIME =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    /// @dev forge-std's default broadcaster for `vm.startBroadcast()` without arguments
    address constant BROADCASTER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38;

    Deployments deployments;

    function setUp() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/deployments/deployments-mainnet.json"));
        deployments = abi.decode(vm.parseJson(json), (Deployments));

        // genesis state the scripts depend on: the governance Safe (and the v1.4.1 Safe
        // contracts it runs on), WTEL, and the Arachnid proxy
        GenerateGenesisPrecompileConfig genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiateSafeImpl();
        genesis.instantiateSafeL2();
        genesis.instantiateSafeProxyFactory();
        genesis.instantiateCompatibilityFallbackHandler();
        genesis.instantiateGovernanceSafe();
        genesis.instantiateWTEL();
        vm.etch(deployments.ArachnidDeterministicDeployFactory, ARACHNID_RUNTIME);

        vm.deal(BROADCASTER, 10 ether);
    }

    // ---------------------------------------------------------------------------------------
    // Guards
    // ---------------------------------------------------------------------------------------

    function test_refusesUntilMainnetChainIdIsSet() public {
        MainnetDeployPermit2 script = new MainnetDeployPermit2();
        if (DeploymentsResolver.MAINNET_CHAIN_ID == 0) {
            vm.expectRevert(
                bytes("MainnetDeploy: mainnet chain id not finalized; set DeploymentsResolver.MAINNET_CHAIN_ID")
            );
        } else {
            vm.chainId(DeploymentsResolver.MAINNET_CHAIN_ID + 1);
            vm.expectRevert();
        }
        script.run();
    }

    function test_refusesWrongChain() public {
        WrongChainHarness script = new WrongChainHarness();
        vm.expectRevert();
        script.run();
    }

    function test_dryRunDoesNotWriteAddressBook() public {
        bytes32 before = keccak256(bytes(vm.readFile(_mainnetJsonPath())));
        new Permit2Harness().run();
        assertEq(keccak256(bytes(vm.readFile(_mainnetJsonPath()))), before);
    }

    // ---------------------------------------------------------------------------------------
    // Safe v1.3.0
    // ---------------------------------------------------------------------------------------

    function test_safeV130_factoryWaitsForLiveSingletons() public {
        SafeV130Harness script = new SafeV130Harness();

        // first run on a fresh chain: everything but the factory
        script.run();
        assertGt(0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552.code.length, 0, "GnosisSafe");
        assertGt(0x3E5c63644E683549055b9Be8653de26E0B4CD36E.code.length, 0, "GnosisSafeL2");
        assertGt(0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4.code.length, 0, "fallback handler");
        assertGt(0x59AD6735bCd8152B84860Cb256dD9e96b85F69Da.code.length, 0, "SimulateTxAccessor");
        assertEq(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2.code.length, 0, "factory must wait");

        // second run sees live singletons and deploys the factory
        script.run();
        assertGt(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2.code.length, 0, "factory");

        // third run is a no-op
        uint64 nonce = vm.getNonce(BROADCASTER);
        script.run();
        assertEq(vm.getNonce(BROADCASTER), nonce, "re-run sent transactions");
    }

    /// @notice Replays the 2022 Polygon creation of the v1.3.0 Safe 0x583D...90B2 from its
    ///         original parameters and lands at the same address
    function test_safeV130_reproducesCrossChainSafe() public {
        SafeV130Harness script = new SafeV130Harness();
        script.run();
        script.run();

        address[] memory owners = new address[](1);
        owners[0] = 0x707856C0089Fd59d9e686A47784d5DAd7c0784c4;
        bytes memory initializer = abi.encodeCall(
            IGnosisSafeV130.setup,
            (owners, 1, address(0), "", 0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4, address(0), 0, payable(address(0)))
        );
        address proxy = IGnosisSafeProxyFactoryV130(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2)
            .createProxyWithNonce(0x3E5c63644E683549055b9Be8653de26E0B4CD36E, initializer, 1_650_316_736_569);

        assertEq(proxy, 0x583D596b0a79C0e83C87851eA9FB1A91e80290B2);
        assertEq(IGnosisSafeV130(proxy).getThreshold(), 1);
        assertEq(IGnosisSafeV130(proxy).getOwners()[0], owners[0]);
        assertEq(IGnosisSafeV130(proxy).VERSION(), "1.3.0");
    }

    // ---------------------------------------------------------------------------------------
    // ERC-4337
    // ---------------------------------------------------------------------------------------

    function test_entryPoint_deploysCanonicalAndIsIdempotent() public {
        EntryPointHarness script = new EntryPointHarness();
        script.run();
        assertGt(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789.code.length, 0, "EntryPoint v0.6");
        assertGt(0x0000000071727De22E5E9d8BAf0edAc6f37da032.code.length, 0, "EntryPoint v0.7");
        assertGt(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108.code.length, 0, "EntryPoint v0.8");

        uint64 nonce = vm.getNonce(BROADCASTER);
        script.run();
        assertEq(vm.getNonce(BROADCASTER), nonce, "re-run sent transactions");
    }

    // ---------------------------------------------------------------------------------------
    // CreateX
    // ---------------------------------------------------------------------------------------

    function test_createX_landsAtCanonicalAddressFromPresignedTx() public {
        address createX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
        CreateXHarness script = new CreateXHarness();
        script.run();
        assertEq(createX.codehash, 0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f);
        assertEq(vm.getNonce(0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5), 1);

        uint64 nonce = vm.getNonce(BROADCASTER);
        script.run();
        assertEq(vm.getNonce(BROADCASTER), nonce, "re-run sent transactions");
    }

    function test_createX_refusesWhenDeployerNonceSpent() public {
        vm.setNonce(0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5, 1);
        CreateXHarness script = new CreateXHarness();
        vm.expectRevert(
            bytes("MainnetDeployCreateX: CreateX deployer nonce 0 already spent; canonical address unreachable")
        );
        script.run();
    }

    // ---------------------------------------------------------------------------------------
    // Permit2
    // ---------------------------------------------------------------------------------------

    function test_permit2_deploysCanonicalAndIsIdempotent() public {
        Permit2Harness script = new Permit2Harness();
        script.run();
        assertGt(0x000000000022D473030F116dDEE9F6B43aC78BA3.code.length, 0);

        uint64 nonce = vm.getNonce(BROADCASTER);
        script.run();
        assertEq(vm.getNonce(BROADCASTER), nonce, "re-run sent transactions");
    }

    // ---------------------------------------------------------------------------------------
    // Uniswap
    // ---------------------------------------------------------------------------------------

    function test_uniswapV2_governanceFeeSetterAndCanonicalPairHash() public {
        UniswapV2Harness script = new UniswapV2Harness();
        script.run();
        address factory = _v2Factory();
        assertEq(IUniswapV2Factory(factory).feeToSetter(), deployments.Safe);
        assertEq(IUniswapV2Factory(factory).feeTo(), address(0));

        (address token0, address token1) = (address(0x1111), address(0x2222));
        address pair = IUniswapV2Factory(factory).createPair(token0, token1);
        assertEq(
            pair,
            vm.computeCreate2Address(
                keccak256(abi.encodePacked(token0, token1)),
                0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f,
                factory
            ),
            "pair init code hash is not canonical"
        );

        uint64 nonce = vm.getNonce(BROADCASTER);
        script.run();
        assertEq(vm.getNonce(BROADCASTER), nonce, "re-run sent transactions");
    }

    function test_uniswapV3_requiresV2() public {
        UniswapV3Harness script = _uniswapV3Harness();
        vm.expectRevert(bytes("MainnetDeploy: no code at UniswapV2Factory; run MainnetDeployUniswapV2 first"));
        script.run();
    }

    function test_uniswapV3_governanceOwnedFactoryAndCanonicalPoolHash() public {
        new UniswapV2Harness().run();
        UniswapV3Harness script = _uniswapV3Harness();

        vm.recordLogs();
        script.run();
        address factory = _v3FactoryFromLogs();

        IUniswapV3FactoryAdmin admin = IUniswapV3FactoryAdmin(factory);
        assertEq(admin.owner(), deployments.Safe, "factory owner");
        assertEq(admin.feeAmountTickSpacing(100), 1);
        assertEq(admin.feeAmountTickSpacing(500), 10);
        assertEq(admin.feeAmountTickSpacing(3000), 60);
        assertEq(admin.feeAmountTickSpacing(10_000), 200);

        (address token0, address token1) = (address(0x1111), address(0x2222));
        address pool = IUniswapV3PoolFactory(factory).createPool(token0, token1, 3000);
        assertEq(
            pool,
            vm.computeCreate2Address(
                keccak256(abi.encode(token0, token1, uint24(3000))),
                0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54,
                factory
            ),
            "pool init code hash is not canonical"
        );

        uint64 nonce = vm.getNonce(BROADCASTER);
        script.run();
        assertEq(vm.getNonce(BROADCASTER), nonce, "re-run sent transactions");
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    /// @dev The V3 script embeds the full V3 bytecode set and exceeds the EIP-170 runtime size
    ///      limit, which forge script does not enforce but `new` in a test does
    function _uniswapV3Harness() internal returns (UniswapV3Harness script) {
        address at = makeAddr("UniswapV3Harness");
        deployCodeTo("MainnetDeploy.t.sol:UniswapV3Harness", at);
        script = UniswapV3Harness(at);
    }

    function _v2Factory() internal returns (address) {
        bytes memory initcode =
            bytes.concat(new UniswapV2FactoryBytecode().UNISWAPV2FACTORY_BYTECODE(), abi.encode(deployments.Safe));
        return vm.computeCreate2Address(
            bytes32(bytes("UniswapV2Factory")), keccak256(initcode), deployments.ArachnidDeterministicDeployFactory
        );
    }

    /// @dev UniswapV3Factory emits OwnerChanged(oldOwner, newOwner) on construction and on
    ///      setOwner; the emitter of those logs is the factory
    function _v3FactoryFromLogs() internal returns (address factory) {
        bytes32 ownerChanged = keccak256("OwnerChanged(address,address)");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == ownerChanged) return logs[i].emitter;
        }
        revert("no UniswapV3Factory OwnerChanged log");
    }

    function _mainnetJsonPath() internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/deployments/deployments-mainnet.json");
    }
}
