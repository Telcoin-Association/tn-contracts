// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { Base64 } from "solady/utils/Base64.sol";
import { LibString } from "solady/utils/LibString.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { Enum } from "safe-contracts/contracts/common/Enum.sol";

/// @dev Minimal ABI of safe-modules `modules/passkey` v0.2.1. The module source is not
/// vendored under `lib/`; every selector declared below was checked present in the
/// dispatch table of the vendored runtime bytecode, and the tests exercise each one.
/// `uint176` is the ABI type of the module's `P256.Verifiers` user-defined value type:
/// the low 160 bits are a fallback verifier contract, the next 16 bits a precompile address
interface ISafeWebAuthnSignerFactory {
    function SINGLETON() external view returns (address);
    function getSigner(uint256 x, uint256 y, uint176 verifiers) external view returns (address signer);
    function createSigner(uint256 x, uint256 y, uint176 verifiers) external returns (address signer);
    function isValidSignatureForSigner(
        bytes32 message,
        bytes calldata signature,
        uint256 x,
        uint256 y,
        uint176 verifiers
    )
        external
        view
        returns (bytes4 magicValue);
}

/// @dev Signer proxy -> `SafeWebAuthnSignerSingleton`: the ERC-1271 entry point and the
/// legacy one Safe v1.4.1 `checkNSignatures` calls, which verifies `keccak256(data)`
interface ISafeWebAuthnSigner {
    function isValidSignature(bytes32 message, bytes calldata signature) external view returns (bytes4);
    function isValidSignature(bytes calldata data, bytes calldata signature) external view returns (bytes4);
}

interface ISafeWebAuthnSharedSigner {
    struct Signer {
        uint256 x;
        uint256 y;
        uint176 verifiers;
    }

    function SIGNER_SLOT() external view returns (uint256);
    function getConfiguration(address account) external view returns (Signer memory signer);
    function configure(Signer calldata signer) external;
    function isValidSignature(bytes32 message, bytes calldata signature) external view returns (bytes4);
}

/// @title Genesis Passkey Parity Test
/// @notice Proves the genesis Safe passkey module (safe-modules `modules/passkey` v0.2.1)
/// and its P-256 verifiers are byte-exact with Ethereum/Polygon/Base and that a passkey
/// signer lands at the SAME address on TN as on those chains. A signer is a CREATE2 proxy
/// whose address depends only on the factory bytes, the singleton address, the public key
/// and the `verifiers` word, so `getSigner` returning the mainnet-derived vector below is the
/// cross-chain parity proof. The test EVM is `prague` (foundry.toml), which like TN today has
/// no P-256 precompile at 0x100, so every verification here runs the Daimo or FCL fallback.
contract GenesisPasskeyParityTest is Test {
    address constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address constant SAFE_PROXY_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;

    address constant SAFE_WEBAUTHN_SIGNER_FACTORY = 0x1d31F259eE307358a26dFb23EB365939E8641195;
    address constant SAFE_WEBAUTHN_SIGNER_SINGLETON = 0x4E27b51350e6c2083EE19011120F50DAfEc5CA50;
    address constant DAIMO_P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
    address constant FCL_P256_VERIFIER = 0xA86e0054C51E4894D88762a017ECc5E5235f5DBA;
    address constant SAFE_WEBAUTHN_SHARED_SIGNER = 0x94a4F6affBd8975951142c3999aEAB7ecee555c2;

    /// @dev EIP-7951 / RIP-7212 P256VERIFY address; absent on prague and on TN
    address constant P256_PRECOMPILE = address(0x100);

    /// @dev `uint176((0x0100 << 160) | DaimoP256Verifier)`: precompile first, Daimo fallback.
    /// The `verifiers` word the wallet configures on every chain
    uint176 constant VERIFIERS_PRECOMPILE_THEN_DAIMO = 0x0100c2b78104907F722DABAc4C69f826a522B2754De4;

    /// @dev Test-only P-256 key; the scalar is public by design (it proves parity, never custody):
    /// `sha256("telcoin.ta-wallet.passkey.kat.v1") mod (n-1) + 1`
    uint256 constant KAT_SCALAR = 0x4b9cc252c01aaa0057ed58ae8f4cc36c8380d004d985e7dc25295f746b805bee;
    uint256 constant KAT_X = 0xf5d108bb9838b2bac8a669810dce5127f0cf14c3ae3a6f8a489e4be497b480af;
    uint256 constant KAT_Y = 0x3da80e382c83e3ed9dfce8947561d6c77f3bcb3bf4ede3eeb6a33969e1f61d78;

    /// @dev `factory.getSigner(KAT_X, KAT_Y, VERIFIERS_PRECOMPILE_THEN_DAIMO)` measured against
    /// the live Ethereum mainnet factory (identical on Polygon and Base)
    address constant KAT_SIGNER = 0x6Cd91Ee70b6C57389e278421fCfC5d11343aCb24;
    /// @dev Same key with `verifiers` = Daimo only: a different `verifiers` word moves the address
    address constant KAT_SIGNER_DAIMO_ONLY = 0x43D54CBC3F277807AA2ED446FF1De71084a506b4;

    /// @dev `sha256("telcoin.ta-wallet.p256.kat.v1") ‖ r ‖ s ‖ KAT_X ‖ KAT_Y`, the 160-byte
    /// P256VERIFY input shared by the precompile and both fallback verifiers
    bytes constant P256_KAT_INPUT =
        hex"a0ae60e65926270c6a25506e37bcfa8f020fefe50c2e790b2b551cc20c33bea5050c346091c5808fad4f9417cb9e5a6e49343e539c65c4802d2c90462b56bf3a04a094e9add23b4178d014ce5375519c324d2fcb84166b5205f86edde61abe5ff5d108bb9838b2bac8a669810dce5127f0cf14c3ae3a6f8a489e4be497b480af3da80e382c83e3ed9dfce8947561d6c77f3bcb3bf4ede3eeb6a33969e1f61d78";

    /// @dev P-256 group order, for low-s normalization
    uint256 constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    /// @dev WebAuthn authenticator flags: user present (0x01) | user verified (0x04). The
    /// singleton requires user verification
    bytes1 constant FLAGS_UP_UV = 0x05;
    /// @dev Everything after `"challenge":"…",` in the client data JSON; not checked on chain
    string constant CLIENT_DATA_FIELDS = '"origin":"https://parity.test"';

    bytes4 constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 constant LEGACY_ERC1271_MAGIC_VALUE = 0x20c13b0b;

    event Created(address indexed signer, uint256 x, uint256 y, uint176 verifiers);

    ISafeWebAuthnSignerFactory factory = ISafeWebAuthnSignerFactory(SAFE_WEBAUTHN_SIGNER_FACTORY);

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
        genesis.instantiateSafeMigration();
        genesis.instantiateSafeToL2Migration();
        genesis.instantiateSafeWebAuthnSignerFactory();
        genesis.instantiateSafeWebAuthnSignerSingleton();
        genesis.instantiateDaimoP256Verifier();
        genesis.instantiateFCLP256Verifier();
        genesis.instantiateSafeWebAuthnSharedSigner();
    }

    /// @notice Every passkey-module contract is byte-exact with the canonical deployment
    /// (hashes and sizes as in deployments/genesis/canonical-bytecode/README.md)
    function test_passkeyCodehashes() public view {
        assertEq(
            SAFE_WEBAUTHN_SIGNER_FACTORY.codehash, 0x655b1f71eedf5aa223c8a7f5fc70f140a6475259a030829bc731642e181e4853
        );
        assertEq(
            SAFE_WEBAUTHN_SIGNER_SINGLETON.codehash, 0x2f10c1deb6dc4c1756da418188d9a5c46ebb9c63080bc7906512f5e8539b2aff
        );
        assertEq(DAIMO_P256_VERIFIER.codehash, 0x3cd725b6ba67b40b7979190c41a015e82cf21e098eb61832ba623f8538bab7fc);
        assertEq(FCL_P256_VERIFIER.codehash, 0xa493dea44e0b8e3b88da6da9fe4447abeefef94ab58ae0b2e001504a38203e80);
        assertEq(
            SAFE_WEBAUTHN_SHARED_SIGNER.codehash, 0xeaa32d0280053e2feea48a7c3fa15a535cd07c23ff60c9469cfa1999533e9332
        );

        assertEq(SAFE_WEBAUTHN_SIGNER_FACTORY.code.length, 2143);
        assertEq(SAFE_WEBAUTHN_SIGNER_SINGLETON.code.length, 2246);
        assertEq(DAIMO_P256_VERIFIER.code.length, 3537);
        assertEq(FCL_P256_VERIFIER.code.length, 5770);
        assertEq(SAFE_WEBAUTHN_SHARED_SIGNER.code.length, 2954);
    }

    /// @notice The factory's baked `SINGLETON` immutable resolves to the genesis singleton
    function test_factorySingleton() public view {
        assertEq(factory.SINGLETON(), SAFE_WEBAUTHN_SIGNER_SINGLETON);
    }

    /// @notice The cross-chain parity property: the signer address for the KAT key with the
    /// wallet's precompile-first `verifiers` equals the value the live mainnet factory returns
    function test_getSignerParity() public view {
        (uint256 x, uint256 y) = vm.publicKeyP256(KAT_SCALAR);
        assertEq(x, KAT_X);
        assertEq(y, KAT_Y);

        assertEq(factory.getSigner(KAT_X, KAT_Y, VERIFIERS_PRECOMPILE_THEN_DAIMO), KAT_SIGNER);
        // negative control: the `verifiers` word is part of the CREATE2 salt input
        assertEq(factory.getSigner(KAT_X, KAT_Y, uint176(uint160(DAIMO_P256_VERIFIER))), KAT_SIGNER_DAIMO_ONLY);
    }

    /// @notice `createSigner` deploys the signer proxy at the `getSigner` address and is
    /// idempotent: a second call returns the same address without reverting or emitting
    function test_createSignerIdempotent() public {
        assertEq(KAT_SIGNER.code.length, 0);

        vm.expectEmit(true, true, true, true, SAFE_WEBAUTHN_SIGNER_FACTORY);
        emit Created(KAT_SIGNER, KAT_X, KAT_Y, VERIFIERS_PRECOMPILE_THEN_DAIMO);
        address signer = factory.createSigner(KAT_X, KAT_Y, VERIFIERS_PRECOMPILE_THEN_DAIMO);
        assertEq(signer, KAT_SIGNER);
        assertEq(signer.code.length, 236);
        bytes32 proxyCodehash = signer.codehash;

        vm.recordLogs();
        assertEq(factory.createSigner(KAT_X, KAT_Y, VERIFIERS_PRECOMPILE_THEN_DAIMO), KAT_SIGNER);
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(signer.codehash, proxyCodehash);
    }

    /// @notice No P-256 precompile on this EVM (as on TN): 0x100 has no code and returns
    /// empty data even for a valid vector, while both fallback verifiers accept it and
    /// Daimo rejects a corrupted one
    function test_p256PrecompileAbsentFallbacksVerify() public view {
        assertEq(P256_PRECOMPILE.code.length, 0);
        (bool ok, bytes memory ret) = P256_PRECOMPILE.staticcall(P256_KAT_INPUT);
        assertTrue(ok);
        assertEq(ret.length, 0);

        (ok, ret) = DAIMO_P256_VERIFIER.staticcall(P256_KAT_INPUT);
        assertTrue(ok);
        assertEq(ret, abi.encode(uint256(1)));
        (ok, ret) = FCL_P256_VERIFIER.staticcall(P256_KAT_INPUT);
        assertTrue(ok);
        assertEq(ret, abi.encode(uint256(1)));

        // negative control: flip one nibble of r
        bytes memory corrupted = P256_KAT_INPUT;
        corrupted[63] = bytes1(uint8(corrupted[63]) ^ 0x01);
        (ok, ret) = DAIMO_P256_VERIFIER.staticcall(corrupted);
        assertTrue(ok);
        assertEq(ret, abi.encode(uint256(0)));
        (ok, ret) = P256_PRECOMPILE.staticcall(corrupted);
        assertTrue(ok);
        assertEq(ret.length, 0);
    }

    /// @notice A real WebAuthn assertion over a 32-byte challenge validates through the
    /// factory with the wallet's precompile-first `verifiers`: the precompile call returns
    /// empty and the Daimo fallback accepts
    function test_isValidSignatureForSignerDaimoFallback() public view {
        bytes32 challenge = keccak256("safeTxHash-style challenge");
        bytes memory signature = _webAuthnSignature(challenge, FLAGS_UP_UV);

        assertEq(
            factory.isValidSignatureForSigner(challenge, signature, KAT_X, KAT_Y, VERIFIERS_PRECOMPILE_THEN_DAIMO),
            ERC1271_MAGIC_VALUE
        );

        // the challenge is bound: the same assertion fails for any other message
        assertEq(
            factory.isValidSignatureForSigner(
                bytes32(uint256(challenge) ^ 1), signature, KAT_X, KAT_Y, VERIFIERS_PRECOMPILE_THEN_DAIMO
            ),
            bytes4(0)
        );
        // user verification is required
        assertEq(
            factory.isValidSignatureForSigner(
                challenge, _webAuthnSignature(challenge, 0x01), KAT_X, KAT_Y, VERIFIERS_PRECOMPILE_THEN_DAIMO
            ),
            bytes4(0)
        );
        // precompile-only `verifiers` cannot verify on a chain without the precompile
        assertEq(
            factory.isValidSignatureForSigner(challenge, signature, KAT_X, KAT_Y, uint176(0x0100) << 160), bytes4(0)
        );
    }

    /// @notice The same assertion validates through `FCLP256Verifier` as the only verifier
    function test_isValidSignatureForSignerFcl() public view {
        bytes32 challenge = keccak256("safeTxHash-style challenge");
        assertEq(
            factory.isValidSignatureForSigner(
                challenge, _webAuthnSignature(challenge, FLAGS_UP_UV), KAT_X, KAT_Y, uint176(uint160(FCL_P256_VERIFIER))
            ),
            ERC1271_MAGIC_VALUE
        );
    }

    /// @notice The deployed signer proxy forwards to the singleton: both ERC-1271 entry
    /// points accept the assertion, the legacy one over `keccak256(data)`
    function test_signerProxyValidatesSignature() public {
        address signer = factory.createSigner(KAT_X, KAT_Y, VERIFIERS_PRECOMPILE_THEN_DAIMO);
        bytes memory data = "safe transaction data";
        bytes32 challenge = keccak256(data);
        bytes memory signature = _webAuthnSignature(challenge, FLAGS_UP_UV);

        assertEq(ISafeWebAuthnSigner(signer).isValidSignature(challenge, signature), ERC1271_MAGIC_VALUE);
        assertEq(ISafeWebAuthnSigner(signer).isValidSignature(data, signature), LEGACY_ERC1271_MAGIC_VALUE);
    }

    /// @notice End to end on genesis state: a canonical Safe owned only by a passkey signer
    /// executes a transaction authorized by a WebAuthn assertion whose challenge is the
    /// safeTxHash, verified through the Daimo fallback
    function test_safeWithPasskeyOwnerExecutes() public {
        address signer = factory.createSigner(KAT_X, KAT_Y, VERIFIERS_PRECOMPILE_THEN_DAIMO);
        address[] memory owners = new address[](1);
        owners[0] = signer;
        Safe safe = _createSafe(owners, 7);
        vm.deal(address(safe), 1 ether);

        address to = address(0xBEEF);
        bytes32 safeTxHash = safe.getTransactionHash(
            to, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );
        bytes memory webAuthnSignature = _webAuthnSignature(safeTxHash, FLAGS_UP_UV);
        // Safe contract signature: r = owner, s = offset of the dynamic part, v = 0
        bytes memory signatures = abi.encodePacked(
            uint256(uint160(signer)), uint256(65), uint8(0), uint256(webAuthnSignature.length), webAuthnSignature
        );

        assertTrue(
            safe.execTransaction(
                to, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures
            )
        );
        assertEq(to.balance, 1 ether);
        assertEq(safe.nonce(), 1);
    }

    /// @notice `SafeWebAuthnSharedSigner` round trip: its baked `address(this)` guard
    /// rejects a direct `configure`, a Safe delegatecall stores the key in the Safe's own
    /// storage, `getConfiguration` reads it back, and the shared signer then validates an
    /// assertion on that Safe's behalf
    function test_sharedSignerConfigureRoundTrip() public {
        ISafeWebAuthnSharedSigner sharedSigner = ISafeWebAuthnSharedSigner(SAFE_WEBAUTHN_SHARED_SIGNER);
        ISafeWebAuthnSharedSigner.Signer memory key =
            ISafeWebAuthnSharedSigner.Signer({ x: KAT_X, y: KAT_Y, verifiers: VERIFIERS_PRECOMPILE_THEN_DAIMO });

        // delegatecall-only: proves the baked self address is the canonical one
        vm.expectRevert();
        sharedSigner.configure(key);

        uint256 ownerKey = 0xA11CE;
        address[] memory owners = new address[](1);
        owners[0] = vm.addr(ownerKey);
        Safe safe = _createSafe(owners, 8);

        ISafeWebAuthnSharedSigner.Signer memory unset = sharedSigner.getConfiguration(address(safe));
        assertEq(unset.x, 0);
        assertEq(unset.y, 0);
        assertEq(unset.verifiers, 0);

        assertTrue(
            _execDelegatecallViaSafe(
                safe, ownerKey, SAFE_WEBAUTHN_SHARED_SIGNER, abi.encodeCall(ISafeWebAuthnSharedSigner.configure, (key))
            )
        );

        ISafeWebAuthnSharedSigner.Signer memory stored = sharedSigner.getConfiguration(address(safe));
        assertEq(stored.x, KAT_X);
        assertEq(stored.y, KAT_Y);
        assertEq(stored.verifiers, VERIFIERS_PRECOMPILE_THEN_DAIMO);
        assertEq(uint256(vm.load(address(safe), bytes32(sharedSigner.SIGNER_SLOT()))), KAT_X);

        // the shared signer reads the caller's configuration
        bytes32 challenge = keccak256("shared signer challenge");
        bytes memory signature = _webAuthnSignature(challenge, FLAGS_UP_UV);
        vm.prank(address(safe));
        assertEq(sharedSigner.isValidSignature(challenge, signature), ERC1271_MAGIC_VALUE);
        // an unconfigured caller gets no magic value
        assertEq(sharedSigner.isValidSignature(challenge, signature), bytes4(0));
    }

    /// @notice The committed genesis yaml carries the five accounts byte-exact: canonical
    /// address, nonce (2 for the factory, 1 otherwise), zero balance, the vendored runtime
    /// bytes, and no storage
    function test_yamlCarriesPasskeyAccounts() public view {
        string memory yaml = vm.readFile(string.concat(vm.projectRoot(), "/deployments/genesis/precompile-config.yaml"));

        uint256 factoryLine = _assertYamlAccount(yaml, SAFE_WEBAUTHN_SIGNER_FACTORY, "SafeWebAuthnSignerFactory", 2);
        string memory factoryComment = LibString.slice(yaml, factoryLine, LibString.indexOf(yaml, "\n", factoryLine));
        assertTrue(LibString.contains(factoryComment, "its constructor CREATEd the singleton at nonce 1"));

        _assertYamlAccount(yaml, SAFE_WEBAUTHN_SIGNER_SINGLETON, "SafeWebAuthnSignerSingleton", 1);
        _assertYamlAccount(yaml, DAIMO_P256_VERIFIER, "DaimoP256Verifier", 1);
        _assertYamlAccount(yaml, FCL_P256_VERIFIER, "FCLP256Verifier", 1);
        _assertYamlAccount(yaml, SAFE_WEBAUTHN_SHARED_SIGNER, "SafeWebAuthnSharedSigner", 1);
    }

    /// @dev Asserts `account` appears exactly once as a yaml key, followed by exactly
    /// `nonce`, `balance: 0` and the vendored `<name>.hex` bytes, and that the next line
    /// opens another account (no `storage:` block). Returns the key line's offset
    function _assertYamlAccount(
        string memory yaml,
        address account,
        string memory name,
        uint256 nonce
    )
        internal
        view
        returns (uint256 keyAt)
    {
        string memory key = string.concat('"', LibString.toHexString(account), '":');
        keyAt = LibString.indexOf(yaml, key);
        assertTrue(keyAt != LibString.NOT_FOUND, string.concat(name, ": missing from yaml"));
        assertEq(
            LibString.indexOf(yaml, key, keyAt + 1), LibString.NOT_FOUND, string.concat(name, ": duplicated in yaml")
        );

        string memory code =
            vm.readFile(string.concat(vm.projectRoot(), "/deployments/genesis/canonical-bytecode/", name, ".hex"));
        string memory body = string.concat("\n  nonce: ", vm.toString(nonce), "\n  balance: 0\n  code: ", code, '\n"');
        uint256 eol = LibString.indexOf(yaml, "\n", keyAt);
        assertEq(LibString.slice(yaml, eol, eol + bytes(body).length), body, string.concat(name, ": yaml entry"));
    }

    /// @dev Builds the `abi.encode(authenticatorData, clientDataFields, r, s)` signature the
    /// passkey module verifies: authenticatorData = rpIdHash ‖ flags ‖ signCount, the
    /// signed digest is `sha256(authenticatorData ‖ sha256(clientDataJSON))` where
    /// clientDataJSON = `{"type":"webauthn.get","challenge":"<base64url(challenge)>",` ++
    /// fields ++ `}`. Signed with the KAT key; s is normalized to low-s
    function _webAuthnSignature(bytes32 challenge, bytes1 flags) internal pure returns (bytes memory) {
        bytes memory authenticatorData = abi.encodePacked(sha256("parity.test"), flags, uint32(1));
        bytes memory clientDataJson = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"',
            Base64.encode(abi.encodePacked(challenge), true, true),
            '",',
            CLIENT_DATA_FIELDS,
            "}"
        );
        bytes32 digest = sha256(abi.encodePacked(authenticatorData, sha256(clientDataJson)));
        (bytes32 r, bytes32 s) = vm.signP256(KAT_SCALAR, digest);
        uint256 lowS = uint256(s) > P256_N / 2 ? P256_N - uint256(s) : uint256(s);
        return abi.encode(authenticatorData, CLIENT_DATA_FIELDS, uint256(r), lowS);
    }

    function _execDelegatecallViaSafe(
        Safe safe,
        uint256 ownerKey,
        address to,
        bytes memory data
    )
        internal
        returns (bool)
    {
        // first transaction of a fresh Safe: nonce 0
        bytes32 txHash =
            safe.getTransactionHash(to, 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), address(0), 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, txHash);
        return safe.execTransaction(
            to,
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            abi.encodePacked(r, s, v)
        );
    }

    function _createSafe(address[] memory owners, uint256 saltNonce) internal returns (Safe) {
        bytes memory setupData =
            abi.encodeCall(Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0))));
        SafeProxyFactory proxyFactory = SafeProxyFactory(SAFE_PROXY_FACTORY);
        return Safe(payable(address(proxyFactory.createProxyWithNonce(SAFE_SINGLETON, setupData, saltNonce))));
    }
}
