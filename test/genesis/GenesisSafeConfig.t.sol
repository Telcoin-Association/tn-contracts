// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { CompatibilityFallbackHandler } from "safe-contracts/contracts/handler/CompatibilityFallbackHandler.sol";
import { TokenCallbackHandler } from "safe-contracts/contracts/handler/TokenCallbackHandler.sol";

/// @title Genesis Safe Config Test
/// @notice Replays the genesis precompile simulation and verifies the resulting Safe
/// infrastructure state: the CompatibilityFallbackHandler is deployed at its canonical
/// address, the governance safe references it, and fallback dispatch through the
/// proxy -> singleton -> handler chain works end to end
contract GenesisSafeConfigTest is Test {
    /// @dev Mirrors `FallbackManager.FALLBACK_HANDLER_STORAGE_SLOT`
    bytes32 constant FALLBACK_HANDLER_STORAGE_SLOT = keccak256("fallback_manager.handler.address");
    /// @dev Mirrors `CompatibilityFallbackHandler.SAFE_MSG_TYPEHASH`
    bytes32 constant SAFE_MSG_TYPEHASH = keccak256("SafeMessage(bytes message)");

    Deployments deployments;
    Safe governanceSafe;
    SafeProxyFactory safeProxyFactory;
    address safeImpl;
    address fallbackHandler;

    function setUp() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/deployments/deployments-mainnet.json"));
        deployments = abi.decode(vm.parseJson(json), (Deployments));

        // replay the genesis simulation; copies code + storage onto the deployments addresses
        GenerateGenesisPrecompileConfig genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiateSafeImpl();
        genesis.instantiateSafeProxyFactory();
        genesis.instantiateCompatibilityFallbackHandler();
        genesis.instantiateGovernanceSafe();

        governanceSafe = Safe(payable(deployments.Safe));
        safeProxyFactory = SafeProxyFactory(deployments.SafeProxyFactory);
        safeImpl = deployments.SafeImpl;
        fallbackHandler = deployments.CompatibilityFallbackHandler;
    }

    function test_fallbackHandlerDeployedAtCanonicalAddress() public view {
        // canonical Safe v1.4.1 CompatibilityFallbackHandler address, identical across EVM chains
        assertEq(fallbackHandler, 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99);
        assertTrue(fallbackHandler.code.length > 0);
    }

    function test_governanceSafeReferencesFallbackHandler() public view {
        bytes32 raw = vm.load(address(governanceSafe), FALLBACK_HANDLER_STORAGE_SLOT);
        assertEq(address(uint160(uint256(raw))), fallbackHandler);

        // sanity check the rest of the genesis safe config
        assertEq(governanceSafe.getThreshold(), 3);
        assertEq(governanceSafe.getOwners().length, 7);
    }

    /// @notice Calls handler functions on the governance safe address itself, proving the
    /// proxy -> singleton fallback -> handler dispatch chain works with the genesis state
    function test_governanceSafeFallbackDispatch() public view {
        CompatibilityFallbackHandler viaSafe = CompatibilityFallbackHandler(address(governanceSafe));

        // token callbacks resolve through the fallback handler
        assertEq(
            viaSafe.onERC721Received(address(0xBEEF), address(0xCAFE), 1, ""),
            TokenCallbackHandler.onERC721Received.selector
        );

        // EIP-712 safe message hash computed by the handler in the safe's context
        bytes memory message = "telcoin network genesis";
        bytes32 expected = keccak256(
            abi.encodePacked(
                bytes1(0x19),
                bytes1(0x01),
                governanceSafe.domainSeparator(),
                keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message)))
            )
        );
        assertEq(viaSafe.getMessageHash(message), expected);
    }

    /// @notice Safes created post-genesis through the factory get the handler when the
    /// initializer references it; Safe tooling (protocol-kit SDK, Safe{Wallet} UI) injects
    /// the canonical handler address by default when the caller does not specify one
    function test_factoryCreatedSafeUsesFallbackHandler() public {
        Safe newSafe = _createSafeViaFactory(fallbackHandler, 1);

        bytes32 raw = vm.load(address(newSafe), FALLBACK_HANDLER_STORAGE_SLOT);
        assertEq(address(uint160(uint256(raw))), fallbackHandler);

        // fallback dispatch works on the freshly created safe
        CompatibilityFallbackHandler viaSafe = CompatibilityFallbackHandler(address(newSafe));
        assertEq(
            viaSafe.onERC1155Received(address(0), address(0), 0, 0, ""),
            TokenCallbackHandler.onERC1155Received.selector
        );
    }

    /// @notice Documents that the canonical Safe contracts have no contract-level default:
    /// a setup call passing the zero address yields a safe with no fallback handler
    function test_factoryCreatedSafeWithoutHandlerHasNone() public {
        Safe bareSafe = _createSafeViaFactory(address(0), 2);

        assertEq(vm.load(address(bareSafe), FALLBACK_HANDLER_STORAGE_SLOT), bytes32(0));
    }

    function _createSafeViaFactory(address handler, uint256 saltNonce) internal returns (Safe) {
        address[] memory owners = new address[](1);
        owners[0] = address(0xA11CE);
        bytes memory setupData = abi.encodeCall(
            Safe.setup, (owners, 1, address(0), "", handler, address(0), 0, payable(address(0)))
        );
        return Safe(payable(address(safeProxyFactory.createProxyWithNonce(safeImpl, setupData, saltNonce))));
    }
}
