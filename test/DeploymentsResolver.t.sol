// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { Deployments } from "../deployments/Deployments.sol";
import { DeploymentsResolver } from "../deployments/DeploymentsResolver.sol";

/// @title Deployments Resolver Test
/// @notice Locks in the chain-id to deployments-file mapping and guards both
/// json files against schema drift: `abi.decode` of `vm.parseJson` output
/// requires every struct key present and lexicographically ordered, so a
/// missing or misplaced key in either file fails these tests at decode time
contract DeploymentsResolverTest is Test {
    function test_relativePathByChainId() public {
        vm.chainId(DeploymentsResolver.DEVNET_CHAIN_ID);
        assertEq(DeploymentsResolver.relativePath(), "/deployments/deployments-devnet.json");

        vm.chainId(DeploymentsResolver.TESTNET_CHAIN_ID);
        assertEq(DeploymentsResolver.relativePath(), "/deployments/deployments-testnet.json");

        // unknown chain ids (local simulations, tests) fall back to the testnet file
        vm.chainId(31_337);
        assertEq(DeploymentsResolver.relativePath(), "/deployments/deployments-testnet.json");
    }

    function test_devnetJsonMatchesDeploymentsSchema() public view {
        Deployments memory devnet = _load("/deployments/deployments-devnet.json");
        Deployments memory testnet = _load("/deployments/deployments-testnet.json");

        // genesis-assigned addresses are identical across networks because every
        // network shares the same genesis configuration
        assertEq(devnet.ArachnidDeterministicDeployFactory, testnet.ArachnidDeterministicDeployFactory);
        assertEq(devnet.ConsensusRegistry, testnet.ConsensusRegistry);
        assertEq(devnet.Issuance, testnet.Issuance);
        assertEq(devnet.Safe, testnet.Safe);
        assertEq(devnet.SafeImpl, testnet.SafeImpl);
        assertEq(devnet.SafeProxyFactory, testnet.SafeProxyFactory);
        assertEq(devnet.StakeManager, testnet.StakeManager);
        assertEq(devnet.WorkerConfigs, testnet.WorkerConfigs);
        assertEq(devnet.magicAddresses.BLS_G1_LIBRARY, testnet.magicAddresses.BLS_G1_LIBRARY);
        assertEq(devnet.magicAddresses.NATIVE_TOKEN_POINTER, testnet.magicAddresses.NATIVE_TOKEN_POINTER);
        assertEq(devnet.magicAddresses.TEL_MINT_PRECOMPILE, testnet.magicAddresses.TEL_MINT_PRECOMPILE);

        // Permit2 lands at its canonical address on any chain (Arachnid + canonical salt)
        assertEq(devnet.uniswapV4.Permit2, testnet.uniswapV4.Permit2);

        // script-deployed addresses are intentionally NOT asserted: devnet resets
        // zero them and each deploy-pipeline run repopulates them, so their values
        // are live deployment records rather than invariants
    }

    /// @notice The mainnet file is the genesis source of truth consumed by
    /// GenerateGenesisPrecompileConfig: genesis-assigned keys only, everything
    /// script-deployed (including admin and Permit2) zeroed until actually deployed
    function test_mainnetJsonIsStrictlyGenesisAssigned() public view {
        Deployments memory mainnet = _load("/deployments/deployments-mainnet.json");
        Deployments memory testnet = _load("/deployments/deployments-testnet.json");

        // genesis-assigned addresses are identical on every network
        assertEq(mainnet.ArachnidDeterministicDeployFactory, testnet.ArachnidDeterministicDeployFactory);
        assertEq(mainnet.ConsensusRegistry, testnet.ConsensusRegistry);
        assertEq(mainnet.Issuance, testnet.Issuance);
        assertEq(mainnet.Safe, testnet.Safe);
        assertEq(mainnet.SafeImpl, testnet.SafeImpl);
        assertEq(mainnet.SafeProxyFactory, testnet.SafeProxyFactory);
        assertEq(mainnet.StakeManager, testnet.StakeManager);
        assertEq(mainnet.WorkerConfigs, testnet.WorkerConfigs);
        assertEq(mainnet.magicAddresses.BLS_G1_LIBRARY, testnet.magicAddresses.BLS_G1_LIBRARY);
        assertEq(mainnet.magicAddresses.NATIVE_TOKEN_POINTER, testnet.magicAddresses.NATIVE_TOKEN_POINTER);
        assertEq(mainnet.magicAddresses.TEL_MINT_PRECOMPILE, testnet.magicAddresses.TEL_MINT_PRECOMPILE);

        // nothing aspirational: non-genesis keys stay zeroed until deployed for real
        assertEq(mainnet.admin, address(0));
        assertEq(mainnet.uniswapV4.Permit2, address(0));
        assertEq(mainnet.WTEL, address(0));
        assertEq(mainnet.StablecoinImpl, address(0));
        assertEq(mainnet.StablecoinManager, address(0));
        assertEq(mainnet.GitAttestationRegistry, address(0));
        assertEq(mainnet.eXYZs.eUSD, address(0));
        assertEq(mainnet.uniswapV2.UniswapV2Factory, address(0));
        assertEq(mainnet.uniswapV3.UniswapV3Factory, address(0));
        assertEq(mainnet.uniswapV4.PoolManager, address(0));
    }

    function _load(string memory relativePath) internal view returns (Deployments memory) {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), relativePath));
        return abi.decode(vm.parseJson(json), (Deployments));
    }
}
