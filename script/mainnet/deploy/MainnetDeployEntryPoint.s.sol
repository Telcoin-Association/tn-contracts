// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { MainnetDeployBase } from "../MainnetDeployBase.sol";

interface IEntryPointV08 {
    function senderCreator() external view returns (address);
}

/// @title Deploy the ERC-4337 EntryPoint singletons on Telcoin Network mainnet
///
/// @notice Deploys EntryPoint v0.6, v0.7 and v0.8 at their canonical cross-chain addresses by
///         replaying their original Ethereum deployments through the Arachnid proxy with the
///         canonical salts. Smart accounts, paymasters and bundlers hardcode these addresses,
///         so they must match every other chain exactly. v0.6 serves the smart accounts still
///         built against it, v0.7 is the current mainstream version and v0.8 adds EIP-7702
///         support.
///
/// @notice Each EntryPoint creates its SenderCreator helper in its constructor; the helper's
///         address and code are checked alongside the EntryPoint.
///
/// @dev EntryPoint v0.8 inherits EIP-712 with the chain id and domain separator fixed at
///      construction, so its runtime bytes differ per chain. It is verified by address (which
///      pins the initcode) rather than by runtime hash. v0.6, v0.7 and every SenderCreator
///      carry no chain-dependent bytes and are pinned to their Ethereum runtime hashes.
///
/// @dev Vendored initcode and its provenance: deployments/canonical-initcode/README.md
///
/// @dev Usage: `forge script script/mainnet/deploy/MainnetDeployEntryPoint.s.sol -vvvv \
///      --rpc-url $TN_MAINNET_RPC_URL --private-key $DEPLOYER_PK --broadcast`
contract MainnetDeployEntryPoint is MainnetDeployBase {
    address internal constant ENTRY_POINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    bytes32 internal constant ENTRY_POINT_V06_SALT = bytes32(0);
    bytes32 internal constant ENTRY_POINT_V06_INITCODE_HASH =
        0x7af81bb089cbbd117f52b96bebd684df6da9f4085c8d924358272f2506fe836b;
    bytes32 internal constant ENTRY_POINT_V06_RUNTIME_HASH =
        0xc93c806e738300b5357ecdc2e971d6438d34d8e4e17b99b758b1f9cac91c8e70;
    address internal constant SENDER_CREATOR_V06 = 0x7fc98430eAEdbb6070B35B39D798725049088348;
    bytes32 internal constant SENDER_CREATOR_V06_RUNTIME_HASH =
        0xae818091eaaf1b6175ee41472359a689f3823d0908a41e2e5c4ad508f2fc04a3;

    address internal constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    bytes32 internal constant ENTRY_POINT_V07_SALT = 0x90d8084deab30c2a37c45e8d47f49f2f7965183cb6990a98943ef94940681de3;
    bytes32 internal constant ENTRY_POINT_V07_INITCODE_HASH =
        0x30516d9cdbeabfaf62ea32d081a10ee3b95b92e5549cfc86353bbe85741c1404;
    bytes32 internal constant ENTRY_POINT_V07_RUNTIME_HASH =
        0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58;
    address internal constant SENDER_CREATOR_V07 = 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C;
    bytes32 internal constant SENDER_CREATOR_V07_RUNTIME_HASH =
        0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689;

    address internal constant ENTRY_POINT_V08 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    bytes32 internal constant ENTRY_POINT_V08_SALT = 0x0a59dbff790c23c976a548690c27297883cc66b4c67024f9117b0238995e35e9;
    bytes32 internal constant ENTRY_POINT_V08_INITCODE_HASH =
        0x2a7c999e10f113d5f71f2abb9069a95091852afbd016309139559b9e47bb59dd;
    address internal constant SENDER_CREATOR_V08 = 0x449ED7C3e6Fee6a97311d4b55475DF59C44AdD33;
    bytes32 internal constant SENDER_CREATOR_V08_RUNTIME_HASH =
        0xc69a1b3a000d570bc86eb096ee63a9014a17951ad616d720882ec61432b00fcf;

    function run() public {
        _loadMainnet();

        bytes memory v06 = _readInitcode("erc4337/EntryPointV06.hex", ENTRY_POINT_V06_INITCODE_HASH);
        bytes memory v07 = _readInitcode("erc4337/EntryPointV07.hex", ENTRY_POINT_V07_INITCODE_HASH);
        bytes memory v08 = _readInitcode("erc4337/EntryPointV08.hex", ENTRY_POINT_V08_INITCODE_HASH);

        vm.startBroadcast();
        address entryPointV06 = _deployDeterministic(ENTRY_POINT_V06_SALT, v06, "EntryPoint v0.6");
        address entryPointV07 = _deployDeterministic(ENTRY_POINT_V07_SALT, v07, "EntryPoint v0.7");
        address entryPointV08 = _deployDeterministic(ENTRY_POINT_V08_SALT, v08, "EntryPoint v0.8");
        vm.stopBroadcast();

        require(entryPointV06 == ENTRY_POINT_V06, "MainnetDeployEntryPoint: non-canonical v0.6 address");
        _requireCodehash(entryPointV06, ENTRY_POINT_V06_RUNTIME_HASH, "EntryPoint v0.6");
        _requireCodehash(SENDER_CREATOR_V06, SENDER_CREATOR_V06_RUNTIME_HASH, "EntryPoint v0.6 SenderCreator");

        require(entryPointV07 == ENTRY_POINT_V07, "MainnetDeployEntryPoint: non-canonical v0.7 address");
        _requireCodehash(entryPointV07, ENTRY_POINT_V07_RUNTIME_HASH, "EntryPoint v0.7");
        _requireCodehash(SENDER_CREATOR_V07, SENDER_CREATOR_V07_RUNTIME_HASH, "EntryPoint v0.7 SenderCreator");

        require(entryPointV08 == ENTRY_POINT_V08, "MainnetDeployEntryPoint: non-canonical v0.8 address");
        require(
            IEntryPointV08(entryPointV08).senderCreator() == SENDER_CREATOR_V08,
            "MainnetDeployEntryPoint: unexpected v0.8 SenderCreator"
        );
        _requireCodehash(SENDER_CREATOR_V08, SENDER_CREATOR_V08_RUNTIME_HASH, "EntryPoint v0.8 SenderCreator");

        _record(".erc4337.EntryPointV06", entryPointV06);
        _record(".erc4337.EntryPointV07", entryPointV07);
        _record(".erc4337.EntryPointV08", entryPointV08);
    }
}
