// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { DeploymentsResolver } from "../../deployments/DeploymentsResolver.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { MainnetDeployUniswapV2 } from "../../script/mainnet/deploy/MainnetDeployUniswapV2.s.sol";
import { MainnetDeployUniswapV3 } from "../../script/mainnet/deploy/MainnetDeployUniswapV3.s.sol";
import { IUniswapV3FactoryAdmin } from "../../script/utils/UniswapV3FactoryDeployer.sol";
import { IUniswapV2Factory } from "external/uniswap/interfaces/IUniswapV2Factory.sol";
import { UniswapV2FactoryBytecode } from "external/uniswap/precompiles/UniswapV2FactoryBytecode.sol";

// Harnesses accept the local test chain in place of the (not yet finalized) mainnet chain id

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

contract WrongChainHarness is MainnetDeployUniswapV2 {
    function _expectedChainId() internal view override returns (uint256) {
        return block.chainid + 1;
    }
}

interface IUniswapV3PoolFactory {
    function createPool(address tokenA, address tokenB, uint24 fee) external returns (address pool);
}

/// @title Mainnet post-genesis deploy scripts
/// @notice Runs every script under script/mainnet/deploy/ against a replay of mainnet genesis:
///         each one alone from a fresh state, then again to prove a re-run sends nothing, then
///         end-to-end checks that the deployed factories produce canonical pair and pool
///         addresses
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
        MainnetDeployUniswapV2 script = new MainnetDeployUniswapV2();
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
        new UniswapV2Harness().run();
        assertEq(keccak256(bytes(vm.readFile(_mainnetJsonPath()))), before);
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
