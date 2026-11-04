// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { GenesisERC4337Base, IEntryPointV07, PackedUserOperation } from "./GenesisERC4337Parity.t.sol";

/// @dev The safe-modules `modules/4337` v0.3.0 surface the tests use; the source is not vendored
/// under `lib/`
interface ISafe4337Module {
    function SUPPORTED_ENTRYPOINT() external view returns (address);
    function domainSeparator() external view returns (bytes32);
    function getOperationHash(PackedUserOperation calldata userOp) external view returns (bytes32);
    function executeUserOp(address to, uint256 value, bytes memory data, uint8 operation) external;
}

interface ISafeModuleSetup {
    function enableModules(address[] calldata modules) external;
}

/// @title Genesis Safe 4337 Module Parity Test
/// @notice Proves the genesis Safe4337Module and SafeModuleSetup (safe-modules `modules/4337`
/// v0.3.0) are byte-exact with Ethereum and that together with the genesis Safe v1.4.1 suite
/// and EntryPoint v0.7 they run a Safe as an ERC-4337 account on a chain other than Ethereum:
/// the Safe is created by the user operation's `initCode` with the module enabled and set as
/// its fallback handler, then executes the operation it validated by its owner's signature
contract GenesisSafe4337ParityTest is GenesisERC4337Base {
    address constant SAFE_4337_MODULE = 0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226;
    address constant SAFE_MODULE_SETUP = 0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47;
    address constant SAFE_L2_SINGLETON = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;
    address constant SAFE_PROXY_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;

    /// @dev `keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")`
    bytes32 constant MODULE_DOMAIN_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    uint256 constant SALT_NONCE = 4337;

    function setUp() public {
        _replayGenesis();
        genesis.instantiateSafeL2();
        genesis.instantiateSafeProxyFactory();
        genesis.instantiateSafe4337Module();
    }

    function test_canonicalCodehashes() public view {
        assertEq(SAFE_4337_MODULE.codehash, 0x2aea997c4e3cf0e2f333025372e219abcfde81c21fc2f8fb066414a5685dd3e0);
        assertEq(SAFE_MODULE_SETUP.codehash, 0xaf2d170bb766d2773c3fa88717f5b3599827478074d3767d1dee55e5c2f3fbcb);
    }

    function test_boundToEntryPointV07() public view {
        assertEq(ISafe4337Module(SAFE_4337_MODULE).SUPPORTED_ENTRYPOINT(), ENTRY_POINT_V07);
    }

    /// @notice v0.3.0 computes its domain separator from `block.chainid` on every call
    function test_domainSeparatorUsesTheLiveChainId() public {
        uint256[2] memory chainIds = [uint256(1), TN_CHAIN_ID];
        for (uint256 i; i < chainIds.length; ++i) {
            vm.chainId(chainIds[i]);
            assertEq(
                ISafe4337Module(SAFE_4337_MODULE).domainSeparator(),
                keccak256(abi.encode(MODULE_DOMAIN_TYPEHASH, chainIds[i], SAFE_4337_MODULE))
            );
        }
    }

    function test_safeRunsAUserOperation() public {
        vm.chainId(TN_CHAIN_ID);
        PackedUserOperation memory op = _safeUserOp();
        vm.deal(op.sender, 1 ether);
        op.signature = _safeOpSignature(ISafe4337Module(SAFE_4337_MODULE).getOperationHash(op));

        _handleOps(ENTRY_POINT_V07, op);

        Safe safe = Safe(payable(op.sender));
        assertGt(op.sender.code.length, 0, "Safe not created by initCode");
        assertTrue(safe.isModuleEnabled(SAFE_4337_MODULE));
        assertEq(safe.getOwners()[0], vm.addr(OWNER_KEY));
        assertEq(RECIPIENT.balance, 0.1 ether);
        assertGt(BENEFICIARY.balance, 0, "bundler not compensated");
        assertEq(IEntryPointV07(ENTRY_POINT_V07).getNonce(op.sender, 0), 1);
    }

    /// @notice A SafeOp signed under Ethereum's domain does not validate on TN
    function test_ethereumSafeOpDoesNotReplay() public {
        PackedUserOperation memory op = _safeUserOp();
        vm.deal(op.sender, 1 ether);
        vm.chainId(1);
        op.signature = _safeOpSignature(ISafe4337Module(SAFE_4337_MODULE).getOperationHash(op));

        vm.chainId(TN_CHAIN_ID);
        vm.expectRevert(abi.encodeWithSignature("FailedOp(uint256,string)", 0, "AA24 signature error"));
        _handleOps(ENTRY_POINT_V07, op);
    }

    function test_yamlCarriesSafe4337Module() public view {
        string memory yaml = _genesisYaml();
        _assertYamlAccount(yaml, SAFE_4337_MODULE, "safe-4337-v0.3.0/Safe4337Module", 1);
        _assertYamlAccount(yaml, SAFE_MODULE_SETUP, "safe-4337-v0.3.0/SafeModuleSetup", 1);
    }

    /// @dev The standard 4337 Safe setup: one owner, SafeModuleSetup enabling the module during
    /// `setup`, and the module as fallback handler so the Safe answers `validateUserOp`
    function _initializer() internal view returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = vm.addr(OWNER_KEY);
        address[] memory modules = new address[](1);
        modules[0] = SAFE_4337_MODULE;
        return abi.encodeCall(
            Safe.setup,
            (
                owners,
                1,
                SAFE_MODULE_SETUP,
                abi.encodeCall(ISafeModuleSetup.enableModules, (modules)),
                SAFE_4337_MODULE,
                address(0),
                0,
                payable(address(0))
            )
        );
    }

    function _safeUserOp() internal view returns (PackedUserOperation memory op) {
        bytes memory initializer = _initializer();
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), SALT_NONCE));
        bytes memory deploymentData = abi.encodePacked(
            SafeProxyFactory(SAFE_PROXY_FACTORY).proxyCreationCode(), uint256(uint160(SAFE_L2_SINGLETON))
        );
        op.sender = vm.computeCreate2Address(salt, keccak256(deploymentData), SAFE_PROXY_FACTORY);
        op.initCode = abi.encodePacked(
            SAFE_PROXY_FACTORY,
            abi.encodeCall(SafeProxyFactory.createProxyWithNonce, (SAFE_L2_SINGLETON, initializer, SALT_NONCE))
        );
        op.callData = abi.encodeCall(ISafe4337Module.executeUserOp, (RECIPIENT, 0.1 ether, "", 0));
        op.accountGasLimits = bytes32((VERIFICATION_GAS_LIMIT << 128) | CALL_GAS_LIMIT);
        op.preVerificationGas = PRE_VERIFICATION_GAS;
        op.gasFees = bytes32((MAX_FEE_PER_GAS << 128) | MAX_FEE_PER_GAS);
        // validAfter and validUntil (both 0: no time bounds) prefix the owner signatures
        op.signature = abi.encodePacked(uint48(0), uint48(0));
    }

    /// @dev `validAfter ++ validUntil ++` the owner's ECDSA signature over the SafeOp hash
    function _safeOpSignature(bytes32 operationHash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, operationHash);
        return abi.encodePacked(uint48(0), uint48(0), r, s, v);
    }
}
