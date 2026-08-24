// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { Enum } from "safe-contracts/contracts/common/Enum.sol";

/// @title Genesis Safe Canonical Parity Test
/// @notice Proves the genesis Safe suite is byte-exact canonical Safe v1.4.1 and that
/// counterfactual (multichain) Safe creations land at the SAME address on TN as on
/// Ethereum/Sepolia/Base. This is the property the previous compile-from-source genesis
/// broke: `createProxyWithNonce` derives the proxy address via CREATE2 over the
/// factory's embedded proxy creation code, so only the canonical factory bytes
/// reproduce canonical addresses.
contract GenesisSafeCanonicalParityTest is Test {
    // canonical Safe v1.4.1 suite addresses (identical on all EVM chains)
    address constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address constant SAFE_L2_SINGLETON = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;
    address constant SAFE_PROXY_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;
    address constant SAFE_FALLBACK_HANDLER = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;
    address constant SAFE_TO_L2_SETUP = 0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54;
    address constant SAFE_MULTI_SEND = 0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526;
    address constant SAFE_MULTI_SEND_CALL_ONLY = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address constant SAFE_SIGN_MESSAGE_LIB = 0xd53cd0aB83D845Ac265BE939c57F53AD838012c9;
    address constant SAFE_CREATE_CALL = 0x9b35Af71d77eaf8d7e40252370304687390A1A52;
    address constant SAFE_SIMULATE_TX_ACCESSOR = 0x3d4BA2E0884aa488718476ca2FB8Efc291A46199;
    address constant SAFE_SINGLETON_FACTORY = 0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7;

    /// @dev Real-world cross-chain test vector: the Telcoin governance/deployer Safe
    /// created via Safe{Wallet} with identical calldata on Ethereum mainnet
    /// (tx 0x966371ac8db7315b5b60b322e0aadaa708f065246c950576287c8cfe81a52b1f) and
    /// Sepolia (tx 0x4bb8bc16bd5e8763511b902495ebbf1a0664c0ef530043f9b5b5aa7e719e42e0),
    /// landing at the same counterfactual address on both. A canonical genesis must
    /// reproduce it; the previous recompiled factory yielded
    /// 0xd778877AfA8A2E67312ECc80F7804Df91d9b9852 and reverted GS002.
    address constant EXPECTED_MULTICHAIN_SAFE = 0x6012dBcb4350Ab297FeB7f96D4d86258062aeB03;

    /// @dev setup(owners[8], threshold=2, to=SafeToL2Setup, data=setupToL2(SafeL2),
    /// fallbackHandler=CompatibilityFallbackHandler, 0, 0, 0x5afe...) — byte-exact
    /// initializer from the mainnet/Sepolia creations above
    bytes constant MULTICHAIN_SAFE_INITIALIZER =
        hex"b63e800d00000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000bd89a1ce4dde368ffab0ec35506eece0b1ffdc540000000000000000000000000000000000000000000000000000000000000220000000000000000000000000fd0732dc9e303f09fcef3a7388ad10a83459ec99000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005afe7a11e70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000eb75f4e9f27b6075889fb57f00e70d462ea21c6f000000000000000000000000b5dfe3a88c77a885362a9616405eaabb5e0db2800000000000000000000000003329025a40607910695ee5ea2dff1ca492ced7d2000000000000000000000000f4bf633596879bb4cb75a83ed02e77ec502a30530000000000000000000000004e7a820d4528f7a0d16085d4b89dd5bb8b2500ff000000000000000000000000a8868d99fad907b6daa637783c84456b92111b39000000000000000000000000dc96ea6f55b52112bc4f4a0db0518690d2d0001e000000000000000000000000ca5d258b2337999a064ec541aa23ed9abe1527e50000000000000000000000000000000000000000000000000000000000000024fe51f64300000000000000000000000029fcb43b46531bca003ddc8fcb67ffe91900c76200000000000000000000000000000000000000000000000000000000";

    /// @dev Mirrors `FallbackManager.FALLBACK_HANDLER_STORAGE_SLOT`
    bytes32 constant FALLBACK_HANDLER_STORAGE_SLOT = keccak256("fallback_manager.handler.address");

    function setUp() public {
        // replay the genesis simulation; etches canonical code + storage at the canonical addresses
        GenerateGenesisPrecompileConfig genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiateSafeImpl();
        genesis.instantiateSafeL2();
        genesis.instantiateSafeProxyFactory();
        genesis.instantiateCompatibilityFallbackHandler();
        genesis.instantiateSafeToL2Setup();
        genesis.instantiateMultiSend();
        genesis.instantiateMultiSendCallOnly();
        genesis.instantiateSignMessageLib();
        genesis.instantiateCreateCall();
        genesis.instantiateSimulateTxAccessor();
        genesis.instantiateSafeSingletonFactory();
    }

    /// @notice Every genesis Safe contract is byte-exact with the canonical Ethereum
    /// mainnet deployment (hashes cross-verified against Sepolia and Base; see
    /// deployments/genesis/canonical-bytecode/README.md)
    function test_canonicalCodehashes() public view {
        assertEq(SAFE_SINGLETON.codehash, 0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4);
        assertEq(SAFE_L2_SINGLETON.codehash, 0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff);
        assertEq(SAFE_PROXY_FACTORY.codehash, 0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317);
        assertEq(SAFE_FALLBACK_HANDLER.codehash, 0x7c6007a5d711cea8dfd5d91f5940ec29c7f200fe511eb1fc1397b367af3c42f9);
        assertEq(SAFE_TO_L2_SETUP.codehash, 0x2f25df28caf984366ee584e13241707e85dcd5a6ea0c14267928dafc1fd6274b);
        assertEq(SAFE_MULTI_SEND.codehash, 0x0e4f7fc66550a322d1e7688e181b75e217e662a4f3f4d6a29b22bc61217c4b77);
        assertEq(
            SAFE_MULTI_SEND_CALL_ONLY.codehash, 0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939
        );
        assertEq(SAFE_SIGN_MESSAGE_LIB.codehash, 0x525c754a46b79e05543a59bb61e8de3c9eee0d955a59352409cbe67ea1077528);
        assertEq(SAFE_CREATE_CALL.codehash, 0x2b3060c55fcb8275653e99ad511a71f67ba76934ed66a7d74d6e68b52afff889);
        assertEq(
            SAFE_SIMULATE_TX_ACCESSOR.codehash, 0x91f82615581fc73b190b83d72e883608b25e392f72322035df1b13d51766cf8d
        );
        assertEq(
            SAFE_SINGLETON_FACTORY.codehash, 0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989
        );
    }

    /// @notice The end-to-end parity property: replaying a real multichain Safe
    /// creation against the genesis state reproduces its Ethereum/Sepolia address
    /// exactly, and the resulting Safe is fully configured
    function test_counterfactualSafeAddressParity() public {
        address proxy = address(
            SafeProxyFactory(SAFE_PROXY_FACTORY).createProxyWithNonce(SAFE_SINGLETON, MULTICHAIN_SAFE_INITIALIZER, 0)
        );
        assertEq(proxy, EXPECTED_MULTICHAIN_SAFE);

        Safe safe = Safe(payable(proxy));
        assertEq(safe.getThreshold(), 2);
        assertEq(safe.getOwners().length, 8);
        // SafeToL2Setup switched the singleton to SafeL2 (block.chainid != 1),
        // matching the created Safe's state on every non-mainnet canonical chain
        assertEq(address(uint160(uint256(vm.load(proxy, bytes32(0))))), SAFE_L2_SINGLETON);
        // fallback handler wired
        assertEq(
            address(uint160(uint256(vm.load(proxy, FALLBACK_HANDLER_STORAGE_SLOT)))), SAFE_FALLBACK_HANDLER
        );
    }

    /// @notice The etched singletons replicate their constructors' `threshold = 1`
    /// storage, so nobody can hijack a singleton by calling `setup` on it directly
    function test_singletonsCannotBeSetup() public {
        address[] memory owners = new address[](1);
        owners[0] = address(0xBAD);

        vm.expectRevert(bytes("GS200"));
        Safe(payable(SAFE_SINGLETON)).setup(
            owners, 1, address(0), "", address(0), address(0), 0, payable(address(0))
        );

        vm.expectRevert(bytes("GS200"));
        Safe(payable(SAFE_L2_SINGLETON)).setup(
            owners, 1, address(0), "", address(0), address(0), 0, payable(address(0))
        );
    }

    /// @notice MultiSendCallOnly executes batched calls when delegatecalled from a Safe
    /// context — smoke test that the etched library bytecode is functional
    function test_multiSendCallOnlyFunctional() public {
        // deploy a quick 1-of-1 safe via the canonical factory
        address[] memory owners = new address[](1);
        uint256 ownerKey = 0xA11CE;
        owners[0] = vm.addr(ownerKey);
        bytes memory setupData = abi.encodeCall(
            Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)))
        );
        Safe safe =
            Safe(payable(address(SafeProxyFactory(SAFE_PROXY_FACTORY).createProxyWithNonce(SAFE_SINGLETON, setupData, 1))));

        // batch: two value transfers via MultiSendCallOnly delegatecall
        vm.deal(address(safe), 3 ether);
        bytes memory multiSendData = abi.encodeWithSignature(
            "multiSend(bytes)",
            abi.encodePacked(
                abi.encodePacked(uint8(0), address(0xD00D), uint256(1 ether), uint256(0), ""),
                abi.encodePacked(uint8(0), address(0xF00D), uint256(2 ether), uint256(0), "")
            )
        );

        assertTrue(_execDelegatecallViaSafe(safe, ownerKey, SAFE_MULTI_SEND_CALL_ONLY, multiSendData));
        assertEq(address(0xD00D).balance, 1 ether);
        assertEq(address(0xF00D).balance, 2 ether);
    }

    function _execDelegatecallViaSafe(Safe safe, uint256 ownerKey, address to, bytes memory data)
        internal
        returns (bool)
    {
        bytes32 txHash =
            safe.getTransactionHash(to, 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), address(0), 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, txHash);
        return safe.execTransaction(
            to, 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(r, s, v)
        );
    }
}
