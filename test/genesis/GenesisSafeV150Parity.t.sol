// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { LibString } from "solady/utils/LibString.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { GenesisYamlAssertions } from "./GenesisYamlAssertions.sol";
import { GenesisReplay } from "./GenesisReplay.sol";

/// @dev Safe v1.5.0 ABI used by the tests. The v1.5.0 source is not vendored under `lib/`
/// (`lib/safe-contracts` is v1.4.1); `operation` is `Enum.Operation` (0 call, 1 delegatecall)
interface ISafeV150 {
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
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    )
        external
        payable
        returns (bool success);
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce
    )
        external
        view
        returns (bytes32);
    function nonce() external view returns (uint256);
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function VERSION() external view returns (string memory);
}

interface ISafeProxyFactoryV150 {
    function createProxyWithNonce(
        address singleton,
        bytes memory initializer,
        uint256 saltNonce
    )
        external
        returns (address proxy);
    function proxyCreationCode() external pure returns (bytes memory);
}

/// @dev Entry points of the v1.5.0 libraries the tests call
interface ISafeV150Libs {
    function setupToL2(address l2Singleton) external;
    function multiSend(bytes memory transactions) external payable;
    function simulate(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation
    )
        external
        returns (uint256 estimate, bool success, bytes memory returnData);
    function migrateL2Singleton() external;
}

/// @dev Addresses, hashes, Safe helpers and the genesis replay shared by the Safe v1.5.0 parity tests
abstract contract GenesisSafeV150Base is GenesisYamlAssertions, GenesisReplay {
    struct Component {
        string name;
        address target;
        bytes32 initcodeHash;
        bytes32 runtimeHash;
        /// @dev How many times the runtime bakes its own address
        uint256 selfReferences;
    }

    address constant SAFE_V150_SINGLETON = 0xFf51A5898e281Db6DfC7855790607438dF2ca44b;
    address constant SAFE_V150_L2_SINGLETON = 0xEdd160fEBBD92E350D4D398fb636302fccd67C7e;
    address constant SAFE_V150_PROXY_FACTORY = 0x14F2982D601c9458F93bd70B218933A6f8165e7b;
    address constant SAFE_V150_FALLBACK_HANDLER = 0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4;
    address constant SAFE_V150_TOKEN_CALLBACK_HANDLER = 0x54e86d004d71a8D2112ec75FaCE57D730b0433F3;
    address constant SAFE_V150_EXTENSIBLE_FALLBACK_HANDLER = 0x85a8ca358D388530ad0fB95D0cb89Dd44Fc242c3;
    address constant SAFE_V150_TO_L2_SETUP = 0x900C7589200010D6C6eCaaE5B06EBe653bc2D82a;
    address constant SAFE_V150_MULTI_SEND = 0x218543288004CD07832472D464648173c77D7eB7;
    address constant SAFE_V150_MULTI_SEND_CALL_ONLY = 0xA83c336B20401Af773B6219BA5027174338D1836;
    address constant SAFE_V150_SIGN_MESSAGE_LIB = 0x4FfeF8222648872B3dE295Ba1e49110E61f5b5aa;
    address constant SAFE_V150_CREATE_CALL = 0x2Ef5ECfbea521449E4De05EDB1ce63B75eDA90B4;
    address constant SAFE_V150_SIMULATE_TX_ACCESSOR = 0x07EfA797c55B5DdE3698d876b277aBb6B893654C;
    address constant SAFE_V150_MIGRATION = 0x6439e7ABD8Bb915A5263094784C5CF561c4172AC;
    address constant SAFE_SINGLETON_FACTORY = 0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7;

    /// @dev keccak256 of `safe-v1.5.0/SafeProxy.hex`, the runtime of every proxy the factory creates
    bytes32 constant SAFE_V150_PROXY_CODEHASH = 0x4e381985ca68b3e5d27b4425fa581c19cf33146d3f887a3cfca96f55528ea46f;
    /// @dev keccak256 of `proxyCreationCode()` as the factory returns it on Ethereum, Base and Sepolia
    bytes32 constant SAFE_V150_PROXY_CREATION_CODE_HASH =
        0x941b3e88811b2f33b8e26783c7407d2e978404581a21c9f07abf2cad9cb87e12;

    /// @dev `OwnerManager.threshold`; the singleton constructors set it to 1
    bytes32 constant THRESHOLD_SLOT = bytes32(uint256(4));
    /// @dev `FallbackManager.FALLBACK_HANDLER_STORAGE_SLOT`, unchanged since v1.3.0
    bytes32 constant FALLBACK_HANDLER_STORAGE_SLOT = keccak256("fallback_manager.handler.address");

    uint8 constant CALL = 0;
    uint8 constant DELEGATECALL = 1;
    uint256 constant OWNER_KEY = 0xA11CE;

    GenerateGenesisPrecompileConfig genesis;

    /// @dev Etches the v1.5.0 suite exactly as genesis does
    function _replayGenesis() internal {
        genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiateSafeV150Suite();
    }

    function _initializer(address owner, address to, bytes memory data) internal pure returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        return abi.encodeCall(
            ISafeV150.setup, (owners, 1, to, data, SAFE_V150_FALLBACK_HANDLER, address(0), 0, payable(address(0)))
        );
    }

    /// @dev A 1-of-1 Safe owned by `OWNER_KEY`
    function _createSafe(address singleton, uint256 saltNonce) internal returns (ISafeV150) {
        return ISafeV150(
            ISafeProxyFactoryV150(SAFE_V150_PROXY_FACTORY)
                .createProxyWithNonce(singleton, _initializer(vm.addr(OWNER_KEY), address(0), ""), saltNonce)
        );
    }

    /// @dev Executes a zero-value transaction signed by `OWNER_KEY` at the Safe's current nonce
    function _exec(ISafeV150 safe, address to, bytes memory data, uint8 operation) internal returns (bool) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, _txHash(safe, to, data, operation));
        return safe.execTransaction(
            to, 0, data, operation, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(r, s, v)
        );
    }

    function _txHash(ISafeV150 safe, address to, bytes memory data, uint8 operation) internal view returns (bytes32) {
        return safe.getTransactionHash(to, 0, data, operation, 0, 0, 0, address(0), address(0), safe.nonce());
    }

    function _singleton(address proxy) internal view returns (address) {
        return address(uint160(uint256(vm.load(proxy, bytes32(0)))));
    }

    function _vendoredRuntime(string memory name) internal view returns (bytes memory) {
        return vm.parseBytes(
            vm.readFile(string.concat(vm.projectRoot(), CANONICAL_BYTECODE_DIR, "safe-v1.5.0/", name, ".hex"))
        );
    }

    function _initcode(Component memory c) internal view returns (bytes memory) {
        return _readInitcode(string.concat("safe-v1.5.0/", c.name), c.initcodeHash);
    }

    /// @dev Replaces every occurrence of `from` in `code` with `to`, in place, and returns how many
    function _replaceAddress(bytes memory code, address from, address to) internal pure returns (uint256 replaced) {
        bytes20 needle = bytes20(from);
        bytes20 replacement = bytes20(to);
        for (uint256 i; i + 20 <= code.length; ++i) {
            bytes20 window;
            assembly ("memory-safe") {
                window := and(mload(add(add(code, 0x20), i)), shl(96, sub(shl(160, 1), 1)))
            }
            if (window != needle) continue;
            for (uint256 j; j < 20; ++j) {
                code[i + j] = replacement[j];
            }
            ++replaced;
        }
    }

    /// @dev The 13 contracts of the v1.5.0 `canonical` registry. The two singletons come first, and
    /// SafeMigration comes last because its constructor requires both singletons and the fallback
    /// handler to have code
    function _components() internal pure returns (Component[13] memory) {
        return [
            Component(
                "Safe",
                SAFE_V150_SINGLETON,
                0x3c32e7eb3961c145eef8620b24e8b829e6d2062a5730629d6169319f29fc1d07,
                0xdda019cbd7c867a533a2a86e5c53434fdc50b13122b5a5ddb4a8df61b31c20f2,
                0
            ),
            Component(
                "SafeL2",
                SAFE_V150_L2_SINGLETON,
                0x4784b1a3de5d71a416f0f5d987aef075f63287002bd2de704a9e68e57ffee658,
                0x180193227186ccb85316c94db1f0d156ed932b14712cfaac78901899178572dc,
                0
            ),
            Component(
                "SafeProxyFactory",
                SAFE_V150_PROXY_FACTORY,
                0xd8803696e4c627ba4cab33cfab2625cf66c88f218c017306e392fcf88cc4e0c6,
                0x967dae4cda22b0c9ef7f31b010bdc1ceb0af9904b0c3dc060b5302e4c18a4529,
                0
            ),
            Component(
                "CompatibilityFallbackHandler",
                SAFE_V150_FALLBACK_HANDLER,
                0xe7213ad39e55911aa31c9d631addd737170d46e9074db5a5cf60fc3f78d6e1c1,
                0x3c6a85bcf7b563daa624b884b4e9a1b9fa5371edde7be945d998071a48f28bbc,
                0
            ),
            Component(
                "TokenCallbackHandler",
                SAFE_V150_TOKEN_CALLBACK_HANDLER,
                0xabaed42c0b2d8612d844777555608d819901cfeab4e294b0030ea970a6097e24,
                0xcbc723172700efa52cc33ee26c7fc7e284edc8097f9dc307857fe525fec98cd8,
                0
            ),
            Component(
                "ExtensibleFallbackHandler",
                SAFE_V150_EXTENSIBLE_FALLBACK_HANDLER,
                0xc71c1171c056d3f4ae6b3bc8db52704dc11752e2c4473c014fdecf1b001a1348,
                0xba5bafdfba82e226b6dc8ae29bedf5026bd854ab4bee00128ca322717a5f2acf,
                0
            ),
            Component(
                "SafeToL2Setup",
                SAFE_V150_TO_L2_SETUP,
                0xa20a5a96e47e6fe2e691c672028b1ef01deefdce4bf88a458f9749e56ab42b12,
                0xf6034d841bcbff8912aa55526b0f1609212536aaf60bb16f5e8a269a4ab38f18,
                1
            ),
            Component(
                "MultiSend",
                SAFE_V150_MULTI_SEND,
                0x835a047eeb2db05847f2a0a80740fc993ff782957d2db7e093289244c3890df3,
                0xca1147a12963172a93910c5cb2bfa5ad0e941c7f03fc7eb017dd06a8ea4e5604,
                1
            ),
            Component(
                "MultiSendCallOnly",
                SAFE_V150_MULTI_SEND_CALL_ONLY,
                0xc59d60d5dc7475d074dd19c49e892a39432d2bbe4cee98002d094240f6a619af,
                0xcdbdcec38d2f1c7d961b0029ff8416b7e86e9974d6f0e9c9580c7d17fcfb6663,
                0
            ),
            Component(
                "SignMessageLib",
                SAFE_V150_SIGN_MESSAGE_LIB,
                0x3bea4df2be1715fc6acb31d39a0f87215f9eed4972ace7936b3f6939a3b5ed7d,
                0xd61840855da008da59a00fc03fb71455b4f70bdca1f56f9504f072ed8d90c50e,
                0
            ),
            Component(
                "CreateCall",
                SAFE_V150_CREATE_CALL,
                0x075bef57cac49bbfdac62bcd02d8ec78ebd7aa747f0387b98e2afce08ceec9c8,
                0x6b7d8d29bdf7004c4617d95041923774f3f7e74b056bff55c1861c9ec92ce54f,
                0
            ),
            Component(
                "SimulateTxAccessor",
                SAFE_V150_SIMULATE_TX_ACCESSOR,
                0x9fb40cd276a52c1d53843216c79fdd90be05eeb37ec0600bc4ca12f913835335,
                0x706db4bb6151f75a5b3845724174e201c59046dfbe65b4e5909ad4b88f8f752d,
                1
            ),
            Component(
                "SafeMigration",
                SAFE_V150_MIGRATION,
                0xd40853463d2e6bbdd66743fe4d2605ade11f6ce0c8d89f5f30f9f0fb4f10c4dd,
                0x52d7472fa02c3a574544f9b5a4ed4c7777e4e3315217e368926b51e1cc6014ea,
                5
            )
        ];
    }
}

/// @title Genesis Safe v1.5.0 Parity Test
/// @notice Proves the genesis Safe v1.5.0 suite is byte-exact with the safe-deployments v1.5.0
/// registry, that the four contracts baking their own address enforce it where genesis puts them,
/// that a counterfactual Safe created through the genesis factory lands at the address Ethereum's
/// proxy creation code gives it, and that the committed yaml carries all 13 accounts
contract GenesisSafeV150ParityTest is GenesisSafeV150Base {
    /// @dev Emitted by SafeToL2Setup and SafeMigration when they swap a Safe's singleton
    event ChangedMasterCopy(address singleton);

    function setUp() public {
        _replayGenesis();
    }

    /// @notice Every address holds exactly its vendored runtime, whose keccak256 is the registry's
    /// `codeHash`
    function test_canonicalCodehashes() public view {
        Component[13] memory components = _components();
        for (uint256 i; i < components.length; ++i) {
            Component memory c = components[i];
            assertEq(c.target.codehash, c.runtimeHash, c.name);
            assertEq(keccak256(c.target.code), keccak256(_vendoredRuntime(c.name)), c.name);
        }
    }

    /// @notice Both singletons carry their constructor's `threshold = 1`, so neither can be
    /// claimed by calling `setup` on it directly
    function test_singletonsCannotBeSetup() public {
        address[2] memory singletons = [SAFE_V150_SINGLETON, SAFE_V150_L2_SINGLETON];
        address[] memory owners = new address[](1);
        owners[0] = address(0xBAD);
        for (uint256 i; i < singletons.length; ++i) {
            assertEq(uint256(vm.load(singletons[i], THRESHOLD_SLOT)), 1);
            vm.expectRevert(bytes("GS200"));
            ISafeV150(singletons[i]).setup(owners, 1, address(0), "", address(0), address(0), 0, payable(0));
        }
    }

    /// @notice SafeToL2Setup, MultiSend, SimulateTxAccessor and SafeMigration compare the address
    /// they run at with the one baked into their bytes to refuse direct calls. At their canonical
    /// addresses the guard holds; the same bytes anywhere else let a direct call through
    function test_selfReferencingContractsAreDelegatecallOnly() public {
        vm.expectRevert(bytes("SafeToL2Setup should only be called via delegatecall"));
        ISafeV150Libs(SAFE_V150_TO_L2_SETUP).setupToL2(SAFE_V150_L2_SINGLETON);
        vm.expectRevert(bytes("MultiSend should only be called via delegatecall"));
        ISafeV150Libs(SAFE_V150_MULTI_SEND).multiSend("");
        vm.expectRevert(bytes("SimulateTxAccessor should only be called via delegatecall"));
        ISafeV150Libs(SAFE_V150_SIMULATE_TX_ACCESSOR).simulate(address(0), 0, "", CALL);
        vm.expectRevert(bytes("Migration should only be called via delegatecall"));
        ISafeV150Libs(SAFE_V150_MIGRATION).migrateL2Singleton();

        // negative control: MultiSend's bytes at another address accept a direct call
        address elsewhere = address(0xBEEF);
        vm.etch(elsewhere, SAFE_V150_MULTI_SEND.code);
        ISafeV150Libs(elsewhere).multiSend("");
    }

    /// @notice A multichain Safe created through the genesis factory on the L1 singleton, with
    /// SafeToL2Setup in its initializer, lands at the CREATE2 address over Ethereum's proxy
    /// creation code, carries the vendored proxy runtime, and is switched onto SafeL2 because
    /// the chain is not Ethereum
    function test_counterfactualSafeLandsOnSafeL2() public {
        ISafeProxyFactoryV150 factory = ISafeProxyFactoryV150(SAFE_V150_PROXY_FACTORY);
        bytes memory proxyCreationCode = factory.proxyCreationCode();
        assertEq(keccak256(proxyCreationCode), SAFE_V150_PROXY_CREATION_CODE_HASH);

        bytes memory initializer = _initializer(
            vm.addr(OWNER_KEY), SAFE_V150_TO_L2_SETUP, abi.encodeCall(ISafeV150Libs.setupToL2, (SAFE_V150_L2_SINGLETON))
        );
        uint256 saltNonce = 7;
        address proxy = factory.createProxyWithNonce(SAFE_V150_SINGLETON, initializer, saltNonce);

        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        bytes32 deploymentHash = keccak256(abi.encodePacked(proxyCreationCode, uint256(uint160(SAFE_V150_SINGLETON))));
        assertEq(proxy, vm.computeCreate2Address(salt, deploymentHash, SAFE_V150_PROXY_FACTORY));
        assertEq(proxy.codehash, SAFE_V150_PROXY_CODEHASH);
        assertEq(keccak256(proxy.code), keccak256(_vendoredRuntime("SafeProxy")));

        ISafeV150 safe = ISafeV150(proxy);
        assertEq(safe.VERSION(), "1.5.0");
        assertEq(safe.getThreshold(), 1);
        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], vm.addr(OWNER_KEY));
        assertEq(_singleton(proxy), SAFE_V150_L2_SINGLETON);
        assertEq(address(uint160(uint256(vm.load(proxy, FALLBACK_HANDLER_STORAGE_SLOT)))), SAFE_V150_FALLBACK_HANDLER);
    }

    /// @notice MultiSend and MultiSendCallOnly execute a batch when a v1.5.0 Safe delegatecalls them
    function test_multiSendBatchesThroughASafe() public {
        ISafeV150 safe = _createSafe(SAFE_V150_L2_SINGLETON, 0);
        vm.deal(address(safe), 6 ether);
        address[2] memory libs = [SAFE_V150_MULTI_SEND, SAFE_V150_MULTI_SEND_CALL_ONLY];
        for (uint256 i; i < libs.length; ++i) {
            address a = address(uint160(0xD00D + i));
            address b = address(uint160(0xF00D + i));
            bytes memory batch = abi.encodePacked(
                abi.encodePacked(CALL, a, uint256(1 ether), uint256(0), ""),
                abi.encodePacked(CALL, b, uint256(2 ether), uint256(0), "")
            );
            assertTrue(_exec(safe, libs[i], abi.encodeCall(ISafeV150Libs.multiSend, (batch)), DELEGATECALL));
            assertEq(a.balance, 1 ether);
            assertEq(b.balance, 2 ether);
        }
    }

    /// @notice SafeMigration moves a v1.5.0 L1 Safe onto SafeL2: its baked singleton address
    /// resolves to the genesis SafeL2
    function test_safeMigrationMigratesL1SafeToL2() public {
        ISafeV150 safe = _createSafe(SAFE_V150_SINGLETON, 1);
        assertEq(_singleton(address(safe)), SAFE_V150_SINGLETON);

        vm.expectEmit(address(safe));
        emit ChangedMasterCopy(SAFE_V150_L2_SINGLETON);
        assertTrue(_exec(safe, SAFE_V150_MIGRATION, abi.encodeCall(ISafeV150Libs.migrateL2Singleton, ()), DELEGATECALL));
        assertEq(_singleton(address(safe)), SAFE_V150_L2_SINGLETON);
    }

    /// @notice The committed genesis yaml carries all 13 accounts byte-exact at nonce 1, the two
    /// singletons with their `threshold` slot and the other 11 with no storage
    function test_yamlCarriesSafeV150Suite() public view {
        string memory yaml = _genesisYaml();
        bytes32[] memory slots = new bytes32[](1);
        bytes32[] memory values = new bytes32[](1);
        slots[0] = THRESHOLD_SLOT;
        values[0] = bytes32(uint256(1));

        Component[13] memory components = _components();
        for (uint256 i; i < components.length; ++i) {
            Component memory c = components[i];
            string memory name = string.concat("safe-v1.5.0/", c.name);
            if (i < 2) {
                _assertYamlAccount(yaml, c.target, name, 1, slots, values);
            } else {
                _assertYamlAccount(yaml, c.target, name, 1);
            }
        }
        uint256 l2At = LibString.indexOf(yaml, '"0xedd160febbd92e350d4d398fb636302fccd67c7e":');
        assertEq(_yamlLineAt(yaml, l2At), '"0xedd160febbd92e350d4d398fb636302fccd67c7e": # safe v1.5.0 l2 impl');
    }
}

/// @title Genesis Safe v1.5.0 Replay Test
/// @notice Replays the suite's Ethereum deployments (the vendored creation code through the Safe
/// Singleton Factory, salt 0) on a chain that has only the factory, and checks the result against
/// what genesis etches: the same bytes at the same addresses, nonce 1, and no storage but the
/// singletons' `threshold = 1`. With another salt the same creation code shows which bytes depend
/// on where they are deployed
contract GenesisSafeV150ReplayTest is GenesisSafeV150Base {
    function setUp() public {
        genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiateSafeSingletonFactory();
    }

    function test_ethereumCreationReproducesGenesisState() public {
        Component[13] memory components = _components();
        for (uint256 i; i < components.length; ++i) {
            Component memory c = components[i];
            (address created, bytes32[] memory slots, bytes32[] memory values) =
                _deployRecordingStorage(SAFE_SINGLETON_FACTORY, bytes32(0), _initcode(c), c.target);

            assertEq(created, c.target, c.name);
            assertEq(created.codehash, c.runtimeHash, c.name);
            assertEq(vm.getNonce(created), 1, c.name);
            if (i < 2) {
                // the singletons: exactly `threshold = 1`
                assertEq(slots.length, 1, c.name);
                assertEq(slots[0], THRESHOLD_SLOT, c.name);
                assertEq(values[0], bytes32(uint256(1)), c.name);
            } else {
                assertEq(slots.length, 0, string.concat(c.name, ": constructor wrote storage"));
            }
        }
    }

    /// @notice Deployed with salt 1, nine of the contracts come out byte-identical to the vendored
    /// runtime, and the other four differ from it in exactly their own address: once each for
    /// SafeToL2Setup, MultiSend and SimulateTxAccessor, five times for SafeMigration. The
    /// vendored bytes of those four are therefore correct only at their canonical addresses,
    /// and genesis puts them there
    function test_selfReferencesPinTheCanonicalAddress() public {
        // SafeMigration's constructor requires the v1.5.0 singletons and fallback handler to have code
        genesis.instantiateSafeV150Suite();

        Component[13] memory components = _components();
        for (uint256 i; i < components.length; ++i) {
            Component memory c = components[i];
            assertEq(_containsAddress(c.target.code, c.target), c.selfReferences != 0, c.name);

            address created = _deployThrough(SAFE_SINGLETON_FACTORY, bytes32(uint256(1)), _initcode(c));
            assertTrue(created != c.target, c.name);
            bytes memory code = created.code;
            assertEq(keccak256(code) == c.runtimeHash, c.selfReferences == 0, c.name);
            assertEq(_replaceAddress(code, created, c.target), c.selfReferences, c.name);
            assertEq(keccak256(code), c.runtimeHash, c.name);
        }
    }
}
