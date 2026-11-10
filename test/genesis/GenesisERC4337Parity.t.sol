// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { DeploymentsResolver } from "../../deployments/DeploymentsResolver.sol";
import { GenesisYamlAssertions } from "./GenesisYamlAssertions.sol";
import { GenesisReplay } from "./GenesisReplay.sol";

/// @dev EntryPoint v0.6 `UserOperation`
struct UserOperationV06 {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

/// @dev EntryPoint v0.7 and v0.8 `PackedUserOperation`
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @dev The EntryPoint surface the tests use; the source is not vendored under `lib/`
interface IEntryPointV06 {
    function handleOps(UserOperationV06[] calldata ops, address payable beneficiary) external;
    function getUserOpHash(UserOperationV06 calldata userOp) external view returns (bytes32);
    function depositTo(address account) external payable;
    function balanceOf(address account) external view returns (uint256);
    function getNonce(address sender, uint192 key) external view returns (uint256);
}

interface IEntryPointV07 {
    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);
    function depositTo(address account) external payable;
    function balanceOf(address account) external view returns (uint256);
    function getNonce(address sender, uint192 key) external view returns (uint256);
}

/// @dev Minimal ERC-4337 account: one ECDSA owner signing the EntryPoint's userOpHash
abstract contract TestAccountBase {
    address public immutable entryPoint;
    address public immutable owner;

    constructor(address entryPoint_, address owner_) {
        entryPoint = entryPoint_;
        owner = owner_;
    }

    receive() external payable { }

    function execute(address to, uint256 value) external {
        require(msg.sender == entryPoint, "TestAccount: caller is not the entry point");
        (bool ok,) = to.call{ value: value }("");
        require(ok, "TestAccount: call failed");
    }

    function _validate(
        bytes32 userOpHash,
        bytes calldata signature,
        uint256 missingAccountFunds
    )
        internal
        returns (uint256 validationData)
    {
        require(msg.sender == entryPoint, "TestAccount: caller is not the entry point");
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        validationData = ecrecover(userOpHash, v, r, s) == owner ? 0 : 1;
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{ value: missingAccountFunds }("");
            ok;
        }
    }
}

contract TestAccountV06 is TestAccountBase {
    constructor(address entryPoint_, address owner_) TestAccountBase(entryPoint_, owner_) { }

    function validateUserOp(
        UserOperationV06 calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        returns (uint256)
    {
        return _validate(userOpHash, userOp.signature, missingAccountFunds);
    }
}

/// @dev Serves EntryPoint v0.7 and v0.8, which share `PackedUserOperation` and `IAccount`
contract TestAccountV07 is TestAccountBase {
    constructor(address entryPoint_, address owner_) TestAccountBase(entryPoint_, owner_) { }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        returns (uint256)
    {
        return _validate(userOpHash, userOp.signature, missingAccountFunds);
    }
}

/// @dev Account factory an EntryPoint's SenderCreator calls for a user operation's `initCode`
contract TestAccountFactory {
    function createAccountV06(address entryPoint, address owner) external returns (address) {
        return address(new TestAccountV06{ salt: bytes32(0) }(entryPoint, owner));
    }

    function createAccountV07(address entryPoint, address owner) external returns (address) {
        return address(new TestAccountV07{ salt: bytes32(0) }(entryPoint, owner));
    }
}

/// @dev Addresses, user-operation builders and signing shared by the ERC-4337 parity tests
abstract contract GenesisERC4337Base is GenesisYamlAssertions, GenesisReplay {
    address constant ENTRY_POINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address constant SENDER_CREATOR_V06 = 0x7fc98430eAEdbb6070B35B39D798725049088348;
    address constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant SENDER_CREATOR_V07 = 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C;
    address constant ENTRY_POINT_V08 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address constant SENDER_CREATOR_V08 = 0x449ED7C3e6Fee6a97311d4b55475DF59C44AdD33;

    bytes32 constant ENTRY_POINT_V06_CODEHASH = 0xc93c806e738300b5357ecdc2e971d6438d34d8e4e17b99b758b1f9cac91c8e70;
    bytes32 constant SENDER_CREATOR_V06_CODEHASH = 0xae818091eaaf1b6175ee41472359a689f3823d0908a41e2e5c4ad508f2fc04a3;
    bytes32 constant ENTRY_POINT_V07_CODEHASH = 0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58;
    bytes32 constant SENDER_CREATOR_V07_CODEHASH = 0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689;
    bytes32 constant ENTRY_POINT_V08_CODEHASH = 0x44e632a24c6f2600cbd5b5b8b4c2d372359112c8b5774297f5fd0a9e64f11f86;
    bytes32 constant SENDER_CREATOR_V08_CODEHASH = 0xc69a1b3a000d570bc86eb096ee63a9014a17951ad616d720882ec61432b00fcf;

    /// @dev OpenZeppelin `ReentrancyGuard._status` in EntryPoint v0.6 and v0.7
    bytes32 constant REENTRANCY_STATUS_SLOT = bytes32(uint256(2));

    /// @dev Stands in for Telcoin Network: the Adiri chain id, any id other than Ethereum's 1
    uint256 constant TN_CHAIN_ID = DeploymentsResolver.TESTNET_CHAIN_ID;

    uint256 constant OWNER_KEY = 0xA11CE;
    address payable constant BENEFICIARY = payable(address(0xB0B));
    address constant RECIPIENT = address(0xCAFE);

    uint256 constant VERIFICATION_GAS_LIMIT = 1_000_000;
    uint256 constant CALL_GAS_LIMIT = 100_000;
    uint256 constant PRE_VERIFICATION_GAS = 50_000;
    uint256 constant MAX_FEE_PER_GAS = 1 gwei;

    GenerateGenesisPrecompileConfig genesis;
    TestAccountFactory accountFactory;

    function _replayGenesis() internal {
        genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiateEntryPoints();
        accountFactory = new TestAccountFactory();
    }

    function _predictAccountV07(address entryPoint) internal view returns (address) {
        bytes memory initcode =
            bytes.concat(type(TestAccountV07).creationCode, abi.encode(entryPoint, vm.addr(OWNER_KEY)));
        return vm.computeCreate2Address(bytes32(0), keccak256(initcode), address(accountFactory));
    }

    /// @dev A first user operation that creates the account through `initCode` and sends
    /// `RECIPIENT` 0.1 ether; unsigned
    function _packedUserOp(address entryPoint) internal view returns (PackedUserOperation memory op) {
        op.sender = _predictAccountV07(entryPoint);
        op.initCode = abi.encodePacked(
            address(accountFactory),
            abi.encodeCall(TestAccountFactory.createAccountV07, (entryPoint, vm.addr(OWNER_KEY)))
        );
        op.callData = abi.encodeCall(TestAccountBase.execute, (RECIPIENT, 0.1 ether));
        op.accountGasLimits = bytes32((VERIFICATION_GAS_LIMIT << 128) | CALL_GAS_LIMIT);
        op.preVerificationGas = PRE_VERIFICATION_GAS;
        op.gasFees = bytes32((MAX_FEE_PER_GAS << 128) | MAX_FEE_PER_GAS);
    }

    function _signature(bytes32 userOpHash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, userOpHash);
        return abi.encode(r, s, v);
    }

    /// @dev EntryPoint v0.7 `UserOperationLib.encode`
    function _packedUserOpStructHash(PackedUserOperation memory op) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
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
    }

    function _handleOps(address entryPoint, PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        IEntryPointV07(entryPoint).handleOps(ops, BENEFICIARY);
    }
}

/// @title Genesis ERC-4337 Parity Test (EntryPoint v0.6 and v0.7)
/// @notice Proves the genesis EntryPoint v0.6 and v0.7 and their SenderCreators are byte-exact
/// with Ethereum, carry their constructors' reentrancy-guard state, and run a real signed user
/// operation (account creation through the SenderCreator, then a value transfer) on a chain
/// other than Ethereum. EntryPoint v0.8 has its own file
contract GenesisERC4337ParityTest is GenesisERC4337Base {
    function setUp() public {
        _replayGenesis();
    }

    function test_canonicalCodehashes() public view {
        assertEq(ENTRY_POINT_V06.codehash, ENTRY_POINT_V06_CODEHASH);
        assertEq(SENDER_CREATOR_V06.codehash, SENDER_CREATOR_V06_CODEHASH);
        assertEq(ENTRY_POINT_V07.codehash, ENTRY_POINT_V07_CODEHASH);
        assertEq(SENDER_CREATOR_V07.codehash, SENDER_CREATOR_V07_CODEHASH);
    }

    function test_reentrancyGuardStartsNotEntered() public view {
        assertEq(uint256(vm.load(ENTRY_POINT_V06, REENTRANCY_STATUS_SLOT)), 1);
        assertEq(uint256(vm.load(ENTRY_POINT_V07, REENTRANCY_STATUS_SLOT)), 1);
    }

    /// @notice Each EntryPoint calls the SenderCreator its constructor created, through an
    /// address baked into its runtime, so that address must hold that exact SenderCreator
    function test_entryPointsBakeTheirSenderCreator() public view {
        assertTrue(_containsAddress(ENTRY_POINT_V06.code, SENDER_CREATOR_V06));
        assertTrue(_containsAddress(ENTRY_POINT_V07.code, SENDER_CREATOR_V07));
        assertEq(vm.computeCreateAddress(ENTRY_POINT_V06, 1), SENDER_CREATOR_V06);
        assertEq(vm.computeCreateAddress(ENTRY_POINT_V07, 1), SENDER_CREATOR_V07);
    }

    function test_depositsAndNonces() public {
        address account = makeAddr("account");
        IEntryPointV06(ENTRY_POINT_V06).depositTo{ value: 1 ether }(account);
        IEntryPointV07(ENTRY_POINT_V07).depositTo{ value: 2 ether }(account);
        assertEq(IEntryPointV06(ENTRY_POINT_V06).balanceOf(account), 1 ether);
        assertEq(IEntryPointV07(ENTRY_POINT_V07).balanceOf(account), 2 ether);
        assertEq(ENTRY_POINT_V06.balance, 1 ether);
        assertEq(ENTRY_POINT_V07.balance, 2 ether);
        assertEq(IEntryPointV06(ENTRY_POINT_V06).getNonce(account, 0), 0);
        assertEq(IEntryPointV07(ENTRY_POINT_V07).getNonce(account, 7), uint256(7) << 64);
    }

    /// @notice v0.6 and v0.7 bind the userOpHash to `block.chainid` at call time, so the same
    /// bytes produce chain-specific hashes
    function test_userOpHashUsesTheLiveChainId() public {
        PackedUserOperation memory op = _packedUserOp(ENTRY_POINT_V07);
        UserOperationV06 memory opV06 = _userOpV06();

        vm.chainId(TN_CHAIN_ID);
        assertEq(
            IEntryPointV07(ENTRY_POINT_V07).getUserOpHash(op),
            keccak256(abi.encode(_packedUserOpStructHash(op), ENTRY_POINT_V07, TN_CHAIN_ID))
        );
        assertEq(
            IEntryPointV06(ENTRY_POINT_V06).getUserOpHash(opV06),
            keccak256(abi.encode(_userOpV06StructHash(opV06), ENTRY_POINT_V06, TN_CHAIN_ID))
        );
        bytes32 tnHash = IEntryPointV07(ENTRY_POINT_V07).getUserOpHash(op);

        vm.chainId(1);
        assertTrue(IEntryPointV07(ENTRY_POINT_V07).getUserOpHash(op) != tnHash);
    }

    function test_handleOpsV06() public {
        vm.chainId(TN_CHAIN_ID);
        UserOperationV06 memory op = _userOpV06();
        vm.deal(op.sender, 1 ether);
        op.signature = _signature(IEntryPointV06(ENTRY_POINT_V06).getUserOpHash(op));

        UserOperationV06[] memory ops = new UserOperationV06[](1);
        ops[0] = op;
        IEntryPointV06(ENTRY_POINT_V06).handleOps(ops, BENEFICIARY);

        assertGt(op.sender.code.length, 0, "account not created through the SenderCreator");
        assertEq(RECIPIENT.balance, 0.1 ether);
        assertGt(BENEFICIARY.balance, 0, "bundler not compensated");
        assertEq(IEntryPointV06(ENTRY_POINT_V06).getNonce(op.sender, 0), 1);
        assertEq(uint256(vm.load(ENTRY_POINT_V06, REENTRANCY_STATUS_SLOT)), 1);
    }

    function test_handleOpsV07() public {
        vm.chainId(TN_CHAIN_ID);
        PackedUserOperation memory op = _packedUserOp(ENTRY_POINT_V07);
        vm.deal(op.sender, 1 ether);
        op.signature = _signature(IEntryPointV07(ENTRY_POINT_V07).getUserOpHash(op));

        _handleOps(ENTRY_POINT_V07, op);

        assertGt(op.sender.code.length, 0, "account not created through the SenderCreator");
        assertEq(RECIPIENT.balance, 0.1 ether);
        assertGt(BENEFICIARY.balance, 0, "bundler not compensated");
        assertEq(IEntryPointV07(ENTRY_POINT_V07).getNonce(op.sender, 0), 1);
        assertEq(uint256(vm.load(ENTRY_POINT_V07, REENTRANCY_STATUS_SLOT)), 1);
    }

    /// @notice The committed genesis yaml carries both EntryPoints at nonce 2 with their guard
    /// slot, and both SenderCreators at nonce 1 without storage
    function test_yamlCarriesEntryPointsV06V07() public view {
        string memory yaml = _genesisYaml();
        bytes32[] memory slots = new bytes32[](1);
        bytes32[] memory values = new bytes32[](1);
        slots[0] = REENTRANCY_STATUS_SLOT;
        values[0] = bytes32(uint256(1));

        uint256 v06At = _assertYamlAccount(yaml, ENTRY_POINT_V06, "erc4337/EntryPointV06", 2, slots, values);
        assertEq(
            _yamlLineAt(yaml, v06At),
            '"0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789": # erc-4337 entrypoint v0.6 (nonce 2: its constructor CREATEd the sender creator at nonce 1)'
        );
        _assertYamlAccount(yaml, SENDER_CREATOR_V06, "erc4337/SenderCreatorV06", 1);
        _assertYamlAccount(yaml, ENTRY_POINT_V07, "erc4337/EntryPointV07", 2, slots, values);
        _assertYamlAccount(yaml, SENDER_CREATOR_V07, "erc4337/SenderCreatorV07", 1);
    }

    function _userOpV06() internal view returns (UserOperationV06 memory op) {
        bytes memory initcode =
            bytes.concat(type(TestAccountV06).creationCode, abi.encode(ENTRY_POINT_V06, vm.addr(OWNER_KEY)));
        op.sender = vm.computeCreate2Address(bytes32(0), keccak256(initcode), address(accountFactory));
        op.initCode = abi.encodePacked(
            address(accountFactory),
            abi.encodeCall(TestAccountFactory.createAccountV06, (ENTRY_POINT_V06, vm.addr(OWNER_KEY)))
        );
        op.callData = abi.encodeCall(TestAccountBase.execute, (RECIPIENT, 0.1 ether));
        op.callGasLimit = CALL_GAS_LIMIT;
        op.verificationGasLimit = VERIFICATION_GAS_LIMIT;
        op.preVerificationGas = PRE_VERIFICATION_GAS;
        op.maxFeePerGas = MAX_FEE_PER_GAS;
        op.maxPriorityFeePerGas = MAX_FEE_PER_GAS;
    }

    /// @dev EntryPoint v0.6 `UserOperationLib.pack`
    function _userOpV06StructHash(UserOperationV06 memory op) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                op.sender,
                op.nonce,
                keccak256(op.initCode),
                keccak256(op.callData),
                op.callGasLimit,
                op.verificationGasLimit,
                op.preVerificationGas,
                op.maxFeePerGas,
                op.maxPriorityFeePerGas,
                keccak256(op.paymasterAndData)
            )
        );
    }
}

/// @title Genesis ERC-4337 Replay Test (EntryPoint v0.6 and v0.7)
/// @notice Replays both EntryPoints' Ethereum deployments through the Arachnid proxy with their
/// canonical salts and checks the result against the genesis etch: the same EntryPoint and
/// SenderCreator bytes at the same addresses, the EntryPoint at nonce 2, and no storage but
/// the guard's `NOT_ENTERED`. Both runtimes are chain independent, so this runs on the default
/// test chain
contract GenesisERC4337ReplayTest is GenesisERC4337Base {
    function setUp() public {
        vm.etch(ARACHNID, ARACHNID_RUNTIME);
    }

    function test_ethereumCreationReproducesGenesisStateV06() public {
        _assertReplay(
            "erc4337/EntryPointV06",
            0x7af81bb089cbbd117f52b96bebd684df6da9f4085c8d924358272f2506fe836b,
            bytes32(0),
            ENTRY_POINT_V06,
            ENTRY_POINT_V06_CODEHASH,
            SENDER_CREATOR_V06,
            SENDER_CREATOR_V06_CODEHASH
        );
    }

    function test_ethereumCreationReproducesGenesisStateV07() public {
        _assertReplay(
            "erc4337/EntryPointV07",
            0x30516d9cdbeabfaf62ea32d081a10ee3b95b92e5549cfc86353bbe85741c1404,
            0x90d8084deab30c2a37c45e8d47f49f2f7965183cb6990a98943ef94940681de3,
            ENTRY_POINT_V07,
            ENTRY_POINT_V07_CODEHASH,
            SENDER_CREATOR_V07,
            SENDER_CREATOR_V07_CODEHASH
        );
    }

    function _assertReplay(
        string memory name,
        bytes32 initcodeHash,
        bytes32 salt,
        address entryPoint,
        bytes32 entryPointCodehash,
        address senderCreator,
        bytes32 senderCreatorCodehash
    )
        internal
    {
        (address created, bytes32[] memory slots, bytes32[] memory values) =
            _deployRecordingStorage(ARACHNID, salt, _readInitcode(name, initcodeHash), entryPoint);
        assertEq(created, entryPoint);
        assertEq(created.codehash, entryPointCodehash);
        assertEq(senderCreator.codehash, senderCreatorCodehash);
        assertEq(vm.getNonce(entryPoint), 2);
        assertEq(slots.length, 1);
        assertEq(slots[0], REENTRANCY_STATUS_SLOT);
        assertEq(values[0], bytes32(uint256(1)));
    }
}
