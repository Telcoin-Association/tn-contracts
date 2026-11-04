// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { GenesisERC4337Base, IEntryPointV07, PackedUserOperation } from "./GenesisERC4337Parity.t.sol";

interface IEntryPointV08 {
    function senderCreator() external view returns (address);
    function getDomainSeparatorV4() external view returns (bytes32);
}

interface ISenderCreatorV08 {
    function entryPoint() external view returns (address);
}

/// @title Genesis EntryPoint v0.8 Parity Test
/// @notice Proves the genesis EntryPoint v0.8 and its SenderCreator are byte-exact with
/// Ethereum and behave correctly on a chain other than Ethereum. v0.8 hashes user operations
/// under EIP-712 and caches the chain-1 domain separator as an immutable at construction, so
/// the Ethereum bytes carry chain id 1; it rebuilds the separator from `block.chainid`
/// whenever that differs, which these tests prove on the Adiri chain id. v0.8 keeps its
/// reentrancy guard in transient storage, so genesis gives it no storage
contract GenesisEntryPointV08ParityTest is GenesisERC4337Base {
    bytes32 constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant PACKED_USEROP_TYPEHASH = keccak256(
        "PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)"
    );
    /// @dev The domain separator EntryPoint v0.8 returns on Ethereum mainnet
    bytes32 constant ETHEREUM_DOMAIN_SEPARATOR = 0x1cb06c861549b538545a86964847e07ba0bcd7699008fe569947aabf7d4dc16a;

    function setUp() public {
        _replayGenesis();
    }

    function test_canonicalCodehashes() public view {
        assertEq(ENTRY_POINT_V08.codehash, ENTRY_POINT_V08_CODEHASH);
        assertEq(SENDER_CREATOR_V08.codehash, SENDER_CREATOR_V08_CODEHASH);
    }

    function test_noStorageAndLinkedSenderCreator() public view {
        assertEq(uint256(vm.load(ENTRY_POINT_V08, REENTRANCY_STATUS_SLOT)), 0);
        assertEq(IEntryPointV08(ENTRY_POINT_V08).senderCreator(), SENDER_CREATOR_V08);
        assertEq(ISenderCreatorV08(SENDER_CREATOR_V08).entryPoint(), ENTRY_POINT_V08);
        assertEq(vm.computeCreateAddress(ENTRY_POINT_V08, 1), SENDER_CREATOR_V08);
    }

    /// @notice On chain 1 the cached separator is served; on any other chain it is rebuilt for
    /// that chain, so a TN user operation hash never equals Ethereum's
    function test_domainSeparatorFollowsTheChain() public {
        vm.chainId(1);
        assertEq(IEntryPointV08(ENTRY_POINT_V08).getDomainSeparatorV4(), ETHEREUM_DOMAIN_SEPARATOR);
        assertEq(IEntryPointV08(ENTRY_POINT_V08).getDomainSeparatorV4(), _domainSeparator(1));

        vm.chainId(TN_CHAIN_ID);
        assertEq(IEntryPointV08(ENTRY_POINT_V08).getDomainSeparatorV4(), _domainSeparator(TN_CHAIN_ID));
        assertTrue(_domainSeparator(TN_CHAIN_ID) != ETHEREUM_DOMAIN_SEPARATOR);
    }

    function test_userOpHashIsEip712UnderTheLiveChainId() public {
        PackedUserOperation memory op = _packedUserOp(ENTRY_POINT_V08);
        uint256[2] memory chainIds = [uint256(1), TN_CHAIN_ID];
        for (uint256 i; i < chainIds.length; ++i) {
            vm.chainId(chainIds[i]);
            bytes32 structHash = keccak256(
                abi.encode(
                    PACKED_USEROP_TYPEHASH,
                    op.sender,
                    op.nonce,
                    keccak256(op.initCode),
                    keccak256(op.callData),
                    op.accountGasLimits,
                    op.preVerificationGas,
                    op.gasFees,
                    keccak256(op.paymasterAndData)
                )
            );
            assertEq(
                IEntryPointV07(ENTRY_POINT_V08).getUserOpHash(op),
                keccak256(abi.encodePacked("\x19\x01", _domainSeparator(chainIds[i]), structHash))
            );
        }
    }

    /// @notice A real signed user operation on the TN chain id: the account is created through the
    /// SenderCreator (whose baked `entryPoint` must match the caller), validated and executed
    function test_handleOpsV08() public {
        vm.chainId(TN_CHAIN_ID);
        PackedUserOperation memory op = _packedUserOp(ENTRY_POINT_V08);
        vm.deal(op.sender, 1 ether);
        op.signature = _signature(IEntryPointV07(ENTRY_POINT_V08).getUserOpHash(op));

        _handleOps(ENTRY_POINT_V08, op);

        assertGt(op.sender.code.length, 0, "account not created through the SenderCreator");
        assertEq(RECIPIENT.balance, 0.1 ether);
        assertGt(BENEFICIARY.balance, 0, "bundler not compensated");
        assertEq(IEntryPointV07(ENTRY_POINT_V08).getNonce(op.sender, 0), 1);
    }

    /// @notice An operation signed over Ethereum's hash does not validate on TN
    function test_ethereumSignatureDoesNotReplay() public {
        PackedUserOperation memory op = _packedUserOp(ENTRY_POINT_V08);
        vm.deal(op.sender, 1 ether);
        vm.chainId(1);
        op.signature = _signature(IEntryPointV07(ENTRY_POINT_V08).getUserOpHash(op));

        vm.chainId(TN_CHAIN_ID);
        vm.expectRevert(abi.encodeWithSignature("FailedOp(uint256,string)", 0, "AA24 signature error"));
        _handleOps(ENTRY_POINT_V08, op);
    }

    /// @notice The committed genesis yaml carries the EntryPoint at nonce 2 and its SenderCreator
    /// at nonce 1, neither with storage
    function test_yamlCarriesEntryPointV08() public view {
        string memory yaml = _genesisYaml();
        _assertYamlAccount(yaml, ENTRY_POINT_V08, "erc4337/EntryPointV08", 2);
        _assertYamlAccount(yaml, SENDER_CREATOR_V08, "erc4337/SenderCreatorV08", 1);
    }

    function _domainSeparator(uint256 chainId) internal pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("ERC4337"), keccak256("1"), chainId, ENTRY_POINT_V08));
    }
}

/// @title Genesis EntryPoint v0.8 Replay Test
/// @notice Replays the Ethereum deployment through the Arachnid proxy with the canonical salt.
/// Under chain id 1 it reproduces the genesis bytes exactly, with the EntryPoint at nonce 2 and
/// no storage. Under the TN chain id the same creation code bakes a different cached domain
/// separator, which is why genesis carries the Ethereum bytes and relies on the rebuild above
contract GenesisEntryPointV08ReplayTest is GenesisERC4337Base {
    bytes32 constant SALT = 0x0a59dbff790c23c976a548690c27297883cc66b4c67024f9117b0238995e35e9;
    bytes32 constant INITCODE_HASH = 0x2a7c999e10f113d5f71f2abb9069a95091852afbd016309139559b9e47bb59dd;

    function setUp() public {
        vm.etch(ARACHNID, ARACHNID_RUNTIME);
    }

    function test_ethereumCreationReproducesGenesisState() public {
        vm.chainId(1);
        (address created, bytes32[] memory slots,) = _deployRecordingStorage(
            ARACHNID, SALT, _readInitcode("erc4337/EntryPointV08", INITCODE_HASH), ENTRY_POINT_V08
        );
        assertEq(created, ENTRY_POINT_V08);
        assertEq(created.codehash, ENTRY_POINT_V08_CODEHASH);
        assertEq(SENDER_CREATOR_V08.codehash, SENDER_CREATOR_V08_CODEHASH);
        assertEq(vm.getNonce(ENTRY_POINT_V08), 2);
        assertEq(slots.length, 0, "constructor wrote storage");
    }

    function test_nativeDeploymentWouldBakeTheChainId() public {
        vm.chainId(TN_CHAIN_ID);
        address created = _deployThrough(ARACHNID, SALT, _readInitcode("erc4337/EntryPointV08", INITCODE_HASH));
        assertEq(created, ENTRY_POINT_V08, "the address does not depend on the chain");
        assertTrue(created.codehash != ENTRY_POINT_V08_CODEHASH, "runtime bytes do");
        assertEq(SENDER_CREATOR_V08.codehash, SENDER_CREATOR_V08_CODEHASH);
    }
}
