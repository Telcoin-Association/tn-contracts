// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { GenesisYamlAssertions } from "./GenesisYamlAssertions.sol";
import { GenesisReplay } from "./GenesisReplay.sol";

/// @dev Safe v1.3.0 ABI used by the tests. The v1.3.0 source is not vendored under `lib/`
/// (`lib/safe-contracts` is v1.4.1); `operation` is `Enum.Operation` (0 call, 1 delegatecall)
interface IGnosisSafeV130 {
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

interface IGnosisSafeProxyFactoryV130 {
    function createProxyWithNonce(
        address singleton,
        bytes memory initializer,
        uint256 saltNonce
    )
        external
        returns (address proxy);
}

/// @dev Addresses, Safe helpers and the genesis replay shared by the Safe v1.3.0 parity tests
abstract contract GenesisSafeV130Base is GenesisYamlAssertions, GenesisReplay {
    address constant SAFE_V130_SINGLETON = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;
    address constant SAFE_V130_L2_SINGLETON = 0x3E5c63644E683549055b9Be8653de26E0B4CD36E;
    address constant SAFE_V130_EIP155_SINGLETON = 0x69f4D1788e39c87893C980c06EdF4b7f686e2938;
    address constant SAFE_V130_EIP155_L2_SINGLETON = 0xfb1bffC9d739B8D520DaF37dF666da4C687191EA;
    address constant SAFE_V130_PROXY_FACTORY = 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2;
    address constant SAFE_V130_FALLBACK_HANDLER = 0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4;
    address constant SAFE_V130_MULTI_SEND = 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761;
    address constant SAFE_V130_EIP155_MULTI_SEND = 0x998739BFdAAdde7C933B942a68053933098f9EDa;
    address constant SAFE_V130_MULTI_SEND_CALL_ONLY = 0x40A2aCCbd92BCA938b02010E17A5b8929b49130D;
    address constant SAFE_V130_EIP155_MULTI_SEND_CALL_ONLY = 0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B;
    address constant SAFE_V130_SIGN_MESSAGE_LIB = 0xA65387F16B013cf2Af4605Ad8aA5ec25a2cbA3a2;
    address constant SAFE_V130_CREATE_CALL = 0x7cbB62EaA69F79e6873cD1ecB2392971036cFAa4;
    address constant SAFE_V130_SIMULATE_TX_ACCESSOR = 0x59AD6735bCd8152B84860Cb256dD9e96b85F69Da;

    /// @dev Not in genesis: the eip155 proxy factory anyone can deploy through the Safe Singleton
    /// Factory, safely now that its singletons exist from genesis
    address constant SAFE_V130_EIP155_PROXY_FACTORY = 0xC22834581EbC8527d974F8a1c97E1bEA4EF910BC;
    address constant SAFE_SINGLETON_FACTORY = 0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7;

    bytes32 constant SAFE_V130_CODEHASH = 0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e;
    bytes32 constant SAFE_V130_L2_CODEHASH = 0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f;
    bytes32 constant SAFE_V130_PROXY_FACTORY_CODEHASH =
        0x337d7f54be11b6ed55fef7b667ea5488db53db8320a05d1146aa4bd169a39a9b;

    /// @dev `OwnerManager.threshold`; the singleton constructors set it to 1
    bytes32 constant THRESHOLD_SLOT = bytes32(uint256(4));
    /// @dev `FallbackManager.FALLBACK_HANDLER_STORAGE_SLOT`, unchanged since v1.3.0
    bytes32 constant FALLBACK_HANDLER_STORAGE_SLOT = keccak256("fallback_manager.handler.address");

    uint8 constant CALL = 0;
    uint8 constant DELEGATECALL = 1;
    uint256 constant OWNER_KEY = 0xA11CE;

    GenerateGenesisPrecompileConfig genesis;

    /// @dev Etches the v1.3.0 suite and the Safe Singleton Factory exactly as genesis does
    function _replayGenesis() internal {
        genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiateSafeV130Suite();
        genesis.instantiateSafeSingletonFactory();
    }

    function _initializer(address owner) internal pure returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        return abi.encodeCall(
            IGnosisSafeV130.setup,
            (owners, 1, address(0), "", SAFE_V130_FALLBACK_HANDLER, address(0), 0, payable(address(0)))
        );
    }

    /// @dev A 1-of-1 Safe owned by `OWNER_KEY`
    function _createSafe(address factory, address singleton, uint256 saltNonce) internal returns (IGnosisSafeV130) {
        return IGnosisSafeV130(
            IGnosisSafeProxyFactoryV130(factory)
                .createProxyWithNonce(singleton, _initializer(vm.addr(OWNER_KEY)), saltNonce)
        );
    }

    /// @dev Executes a zero-value transaction signed by `OWNER_KEY` at the Safe's current nonce
    function _exec(IGnosisSafeV130 safe, address to, bytes memory data, uint8 operation) internal returns (bool) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, _txHash(safe, to, data, operation));
        return safe.execTransaction(
            to, 0, data, operation, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(r, s, v)
        );
    }

    function _txHash(
        IGnosisSafeV130 safe,
        address to,
        bytes memory data,
        uint8 operation
    )
        internal
        view
        returns (bytes32)
    {
        return safe.getTransactionHash(to, 0, data, operation, 0, 0, 0, address(0), address(0), safe.nonce());
    }

    function _singleton(address proxy) internal view returns (address) {
        return address(uint160(uint256(vm.load(proxy, bytes32(0)))));
    }
}

/// @title Genesis Safe v1.3.0 Parity Test
/// @notice Proves the genesis Safe v1.3.0 core (both singletons at their canonical and eip155
/// addresses, the proxy factory and the fallback handler) is byte-exact with Ethereum, that a
/// real cross-chain v1.3.0 Safe lands at its Polygon address on TN, and that no v1.3.0 proxy
/// can be created unowned. That last property is why the singletons are in genesis: the
/// v1.3.0 factories never check that the singleton has code, and anyone can deploy them
contract GenesisSafeV130ParityTest is GenesisSafeV130Base {
    /// @dev The Polygon Safe 0x583D...90B2, created in 2022 through the canonical v1.3.0
    /// factory on GnosisSafeL2 with this owner, the v1.3.0 fallback handler and this salt nonce
    address constant POLYGON_SAFE = 0x583D596b0a79C0e83C87851eA9FB1A91e80290B2;
    address constant POLYGON_SAFE_OWNER = 0x707856C0089Fd59d9e686A47784d5DAd7c0784c4;
    uint256 constant POLYGON_SAFE_SALT_NONCE = 1_650_316_736_569;

    function setUp() public {
        _replayGenesis();
    }

    function test_canonicalCodehashes() public view {
        assertEq(SAFE_V130_SINGLETON.codehash, SAFE_V130_CODEHASH);
        assertEq(SAFE_V130_EIP155_SINGLETON.codehash, SAFE_V130_CODEHASH);
        assertEq(SAFE_V130_L2_SINGLETON.codehash, SAFE_V130_L2_CODEHASH);
        assertEq(SAFE_V130_EIP155_L2_SINGLETON.codehash, SAFE_V130_L2_CODEHASH);
        assertEq(SAFE_V130_PROXY_FACTORY.codehash, SAFE_V130_PROXY_FACTORY_CODEHASH);
        assertEq(
            SAFE_V130_FALLBACK_HANDLER.codehash, 0x03e69f7ce809e81687c69b19a7d7cca45b6d551ffdec73d9bb87178476de1abf
        );
    }

    /// @notice All four singletons carry their constructor's `threshold = 1`, so none can be
    /// claimed by calling `setup` on it directly
    function test_singletonsCannotBeSetup() public {
        address[4] memory singletons =
            [SAFE_V130_SINGLETON, SAFE_V130_L2_SINGLETON, SAFE_V130_EIP155_SINGLETON, SAFE_V130_EIP155_L2_SINGLETON];
        address[] memory owners = new address[](1);
        owners[0] = address(0xBAD);
        for (uint256 i; i < singletons.length; ++i) {
            assertEq(uint256(vm.load(singletons[i], THRESHOLD_SLOT)), 1);
            vm.expectRevert(bytes("GS200"));
            IGnosisSafeV130(singletons[i]).setup(owners, 1, address(0), "", address(0), address(0), 0, payable(0));
        }
    }

    /// @notice Replaying the Polygon creation against the genesis state reproduces its address
    /// and configuration, as it would on Ethereum or any other chain with the canonical suite
    function test_reproducesPolygonSafe() public {
        address proxy = IGnosisSafeProxyFactoryV130(SAFE_V130_PROXY_FACTORY)
            .createProxyWithNonce(SAFE_V130_L2_SINGLETON, _initializer(POLYGON_SAFE_OWNER), POLYGON_SAFE_SALT_NONCE);

        assertEq(proxy, POLYGON_SAFE);
        IGnosisSafeV130 safe = IGnosisSafeV130(proxy);
        assertEq(safe.getThreshold(), 1);
        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], POLYGON_SAFE_OWNER);
        assertEq(safe.VERSION(), "1.3.0");
        assertEq(_singleton(proxy), SAFE_V130_L2_SINGLETON);
        assertEq(address(uint160(uint256(vm.load(proxy, FALLBACK_HANDLER_STORAGE_SLOT)))), SAFE_V130_FALLBACK_HANDLER);
    }

    /// @notice With the singletons in genesis, a proxy is set up in the transaction that creates
    /// it, and nobody can set it up again
    function test_proxyIsOwnedFromCreation() public {
        IGnosisSafeV130 safe = _createSafe(SAFE_V130_PROXY_FACTORY, SAFE_V130_L2_SINGLETON, 7);
        assertEq(safe.getThreshold(), 1);
        assertEq(safe.getOwners()[0], vm.addr(OWNER_KEY));

        address[] memory attacker = new address[](1);
        attacker[0] = address(0xBAD);
        vm.expectRevert(bytes("GS200"));
        safe.setup(attacker, 1, address(0), "", address(0), address(0), 0, payable(0));
    }

    /// @notice Negative control for the property above: against an empty singleton (the state a
    /// chain without these singletons in genesis starts from) the factory still creates the
    /// proxy, the initializer runs against no code, and the proxy sits at the victim's address
    /// unowned until someone calls `setup`. The legitimate creation then fails for good
    function test_emptySingletonWouldLeaveProxyUnowned() public {
        bytes memory singletonCode = SAFE_V130_L2_SINGLETON.code;
        vm.etch(SAFE_V130_L2_SINGLETON, "");

        IGnosisSafeProxyFactoryV130 factory = IGnosisSafeProxyFactoryV130(SAFE_V130_PROXY_FACTORY);
        address proxy = factory.createProxyWithNonce(
            SAFE_V130_L2_SINGLETON, _initializer(POLYGON_SAFE_OWNER), POLYGON_SAFE_SALT_NONCE
        );
        assertEq(proxy, POLYGON_SAFE);
        assertEq(uint256(vm.load(proxy, THRESHOLD_SLOT)), 0, "setup ran against an empty singleton");

        // once the singleton has code, the first caller of `setup` owns the victim's address
        vm.etch(SAFE_V130_L2_SINGLETON, singletonCode);
        address[] memory attacker = new address[](1);
        attacker[0] = address(0xBAD);
        IGnosisSafeV130(proxy).setup(attacker, 1, address(0), "", address(0), address(0), 0, payable(0));
        assertEq(IGnosisSafeV130(proxy).getOwners()[0], address(0xBAD));

        vm.expectRevert(bytes("Create2 call failed"));
        factory.createProxyWithNonce(SAFE_V130_L2_SINGLETON, _initializer(POLYGON_SAFE_OWNER), POLYGON_SAFE_SALT_NONCE);
    }

    /// @notice The eip155 suite works the same way: its factory, deployed permissionlessly through
    /// the genesis Safe Singleton Factory from the canonical creation code, lands at its known
    /// address with the canonical factory bytes and creates owned proxies on the eip155 singletons
    function test_eip155FactoryDeploysThroughSingletonFactory() public {
        bytes memory factoryInitcode = _readInitcode(
            "safe-v1.3.0/GnosisSafeProxyFactory", 0x13d77c68fe7529013a9a57a295a785084b80e3d6ae9358c7f334752e0c8615f4
        );
        address factory = _deployThrough(SAFE_SINGLETON_FACTORY, bytes32(0), factoryInitcode);
        assertEq(factory, SAFE_V130_EIP155_PROXY_FACTORY);
        assertEq(factory.codehash, SAFE_V130_PROXY_FACTORY_CODEHASH);

        IGnosisSafeV130 safe = _createSafe(factory, SAFE_V130_EIP155_L2_SINGLETON, 0);
        assertEq(safe.getThreshold(), 1);
        assertEq(safe.getOwners()[0], vm.addr(OWNER_KEY));
        assertEq(safe.VERSION(), "1.3.0");
        assertEq(_singleton(address(safe)), SAFE_V130_EIP155_L2_SINGLETON);
    }

    /// @notice The committed genesis yaml carries the six core accounts byte-exact, the four
    /// singletons with their `threshold` slot
    function test_yamlCarriesSafeV130Core() public view {
        string memory yaml = _genesisYaml();
        bytes32[] memory slots = new bytes32[](1);
        bytes32[] memory values = new bytes32[](1);
        slots[0] = THRESHOLD_SLOT;
        values[0] = bytes32(uint256(1));

        _assertYamlAccount(yaml, SAFE_V130_SINGLETON, "safe-v1.3.0/GnosisSafe", 1, slots, values);
        _assertYamlAccount(yaml, SAFE_V130_L2_SINGLETON, "safe-v1.3.0/GnosisSafeL2", 1, slots, values);
        uint256 eip155At =
            _assertYamlAccount(yaml, SAFE_V130_EIP155_SINGLETON, "safe-v1.3.0/GnosisSafe", 1, slots, values);
        assertEq(
            _yamlLineAt(yaml, eip155At),
            '"0x69f4d1788e39c87893c980c06edf4b7f686e2938": # safe v1.3.0 impl (eip155 address)'
        );
        _assertYamlAccount(yaml, SAFE_V130_EIP155_L2_SINGLETON, "safe-v1.3.0/GnosisSafeL2", 1, slots, values);
        _assertYamlAccount(yaml, SAFE_V130_PROXY_FACTORY, "safe-v1.3.0/GnosisSafeProxyFactory", 1);
        _assertYamlAccount(yaml, SAFE_V130_FALLBACK_HANDLER, "safe-v1.3.0/CompatibilityFallbackHandler", 1);
    }
}

/// @title Genesis Safe v1.3.0 Replay Test
/// @notice Replays the suite's Ethereum deployments (the vendored creation code through the
/// Arachnid proxy, salt 0) on a chain that has only the deterministic deployers, and checks the
/// result against what genesis etches: the same bytes at the same addresses, and no storage but
/// the singletons' `threshold = 1`. Sending the same creation code through the Safe Singleton
/// Factory produces the eip155 copies
contract GenesisSafeV130ReplayTest is GenesisSafeV130Base {
    struct Component {
        string name;
        address target;
        bytes32 initcodeHash;
        bytes32 runtimeHash;
    }

    function setUp() public {
        vm.etch(ARACHNID, ARACHNID_RUNTIME);
        genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiateSafeSingletonFactory();
    }

    function test_ethereumCreationReproducesGenesisState() public {
        Component[9] memory components = _components();
        for (uint256 i; i < components.length; ++i) {
            Component memory c = components[i];
            bytes memory initcode = _readInitcode(string.concat("safe-v1.3.0/", c.name), c.initcodeHash);
            (address created, bytes32[] memory slots, bytes32[] memory values) =
                _deployRecordingStorage(ARACHNID, bytes32(0), initcode, c.target);

            assertEq(created, c.target, c.name);
            assertEq(created.codehash, c.runtimeHash, c.name);
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

    function test_eip155CopiesComeFromTheSameCreationCode() public {
        Component[9] memory components = _components();
        address[4] memory eip155Targets = [
            SAFE_V130_EIP155_SINGLETON,
            SAFE_V130_EIP155_L2_SINGLETON,
            SAFE_V130_EIP155_MULTI_SEND,
            SAFE_V130_EIP155_MULTI_SEND_CALL_ONLY
        ];
        // GnosisSafe, GnosisSafeL2, MultiSend, MultiSendCallOnly
        uint256[4] memory componentIndex = [uint256(0), 1, 3, 4];
        bytes32[4] memory runtimeHashes = [
            SAFE_V130_CODEHASH,
            SAFE_V130_L2_CODEHASH,
            bytes32(0x81db0e4afdf5178583537b58c5ad403bd47a4ac7f9bde2442ef3e341d433126a),
            components[4].runtimeHash
        ];
        for (uint256 i; i < eip155Targets.length; ++i) {
            Component memory c = components[componentIndex[i]];
            bytes memory initcode = _readInitcode(string.concat("safe-v1.3.0/", c.name), c.initcodeHash);
            address created = _deployThrough(SAFE_SINGLETON_FACTORY, bytes32(0), initcode);
            assertEq(created, eip155Targets[i], c.name);
            assertEq(created.codehash, runtimeHashes[i], c.name);
        }
    }

    /// @dev The two singletons come first
    function _components() internal pure returns (Component[9] memory) {
        return [
            Component(
                "GnosisSafe",
                SAFE_V130_SINGLETON,
                0x30632ce72e4de7408243bfe08d3359ce0f494543f08c113cc4d4232282bf6c6c,
                SAFE_V130_CODEHASH
            ),
            Component(
                "GnosisSafeL2",
                SAFE_V130_L2_SINGLETON,
                0x49f30800a6ac5996a48b80c47ff20f19f8728812498a2a7fe75a14864fab6438,
                SAFE_V130_L2_CODEHASH
            ),
            Component(
                "CompatibilityFallbackHandler",
                SAFE_V130_FALLBACK_HANDLER,
                0x272190de126b4577e187d9f00b9ca5daeae76d771965d734876891a51f9c43d8,
                0x03e69f7ce809e81687c69b19a7d7cca45b6d551ffdec73d9bb87178476de1abf
            ),
            Component(
                "MultiSend",
                SAFE_V130_MULTI_SEND,
                0x319ec670832dc89915c70968563439764e1f45db07ce205115fef547c4d7a7ba,
                0x0208282bd262360d0320862c5ac70f375f5ed3b9d89a83a615b4d398415bdc83
            ),
            Component(
                "MultiSendCallOnly",
                SAFE_V130_MULTI_SEND_CALL_ONLY,
                0x35e699c3e43ec3e03a101730ab916c5e540893eaaf806451e929d138c3ff53b7,
                0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad
            ),
            Component(
                "SignMessageLib",
                SAFE_V130_SIGN_MESSAGE_LIB,
                0xf351650cab7419d02a85bc577276cc69272ea9ba117a56f599039531d1689962,
                0x3ac65dea3cc9dd0d7b7b800f834e3d73415b4e944bb94555c3e4a08fb137e918
            ),
            Component(
                "CreateCall",
                SAFE_V130_CREATE_CALL,
                0x81b71c6ca3958124fc3f1368afb83eff85b35d12725f55c65360842a19119e35,
                0x8155d988823a4f6f1bcbc76a64af8e510c4ce68819290d43cf24956bd24dee82
            ),
            Component(
                "SimulateTxAccessor",
                SAFE_V130_SIMULATE_TX_ACCESSOR,
                0xe5993412e711df6cc93d867252a993881b9e5ba1f9458be7b69e27499b52e232,
                0xb3fb9763869f2c09a2ac5a425d2dd6060bf7ef46b3899049d71a711e71e00f04
            ),
            Component(
                "GnosisSafeProxyFactory",
                SAFE_V130_PROXY_FACTORY,
                0x13d77c68fe7529013a9a57a295a785084b80e3d6ae9358c7f334752e0c8615f4,
                SAFE_V130_PROXY_FACTORY_CODEHASH
            )
        ];
    }
}
