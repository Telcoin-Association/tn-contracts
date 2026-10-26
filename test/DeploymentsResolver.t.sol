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

        // WTEL is genesis-assigned at its vanity address. Live testnet and devnet
        // predate the genesis entry and keep their pre-genesis CREATE2 deployments
        // until their next regenesis/reset, so WTEL is the one genesis key that is
        // temporarily not identical across the network files
        assertEq(mainnet.WTEL, 0x00000000000000000000000000000000000037E1);

        // nothing aspirational: non-genesis keys stay zeroed until deployed for real
        assertEq(mainnet.admin, address(0));
        assertEq(mainnet.uniswapV4.Permit2, address(0));
        assertEq(mainnet.StablecoinImpl, address(0));
        assertEq(mainnet.StablecoinManager, address(0));
        assertEq(mainnet.GitAttestationRegistry, address(0));
        assertEq(mainnet.eXYZs.eUSD, address(0));
        assertEq(mainnet.uniswapV2.UniswapV2Factory, address(0));
        assertEq(mainnet.uniswapV3.UniswapV3Factory, address(0));
        assertEq(mainnet.uniswapV4.PoolManager, address(0));
        assertEq(mainnet.CreateX, address(0));
        assertEq(mainnet.erc4337.EntryPointV06, address(0));
        assertEq(mainnet.erc4337.EntryPointV07, address(0));
        assertEq(mainnet.erc4337.EntryPointV08, address(0));
        assertEq(mainnet.safeV130.GnosisSafeProxyFactory, address(0));
    }

    /// @notice The post-genesis contracts already live on testnet are recorded at their
    /// canonical cross-chain addresses, the same ones the mainnet scripts deploy to
    function test_testnetCanonicalPostGenesisAddresses() public view {
        Deployments memory testnet = _load("/deployments/deployments-testnet.json");

        assertEq(testnet.CreateX, 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);
        assertEq(testnet.erc4337.EntryPointV07, 0x0000000071727De22E5E9d8BAf0edAc6f37da032);
        assertEq(testnet.safeV130.GnosisSafe, 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552);
        assertEq(testnet.safeV130.GnosisSafeL2, 0x3E5c63644E683549055b9Be8653de26E0B4CD36E);
        assertEq(testnet.safeV130.GnosisSafeProxyFactory, 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2);
        assertEq(testnet.safeV130.CompatibilityFallbackHandler, 0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4);
        assertEq(testnet.safeV130.MultiSend, 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761);
        assertEq(testnet.safeV130.MultiSendCallOnly, 0x40A2aCCbd92BCA938b02010E17A5b8929b49130D);
        assertEq(testnet.safeV130.SignMessageLib, 0xA65387F16B013cf2Af4605Ad8aA5ec25a2cbA3a2);
        assertEq(testnet.safeV130.CreateCall, 0x7cbB62EaA69F79e6873cD1ecB2392971036cFAa4);
        assertEq(testnet.safeV130.SimulateTxAccessor, 0x59AD6735bCd8152B84860Cb256dD9e96b85F69Da);
    }

    function _load(string memory relativePath) internal view returns (Deployments memory) {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), relativePath));
        return abi.decode(vm.parseJson(json), (Deployments));
    }
}
