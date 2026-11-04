// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { GenesisSafeV130Base, IGnosisSafeV130 } from "./GenesisSafeV130Parity.t.sol";

/// @dev v1.3.0 CompatibilityFallbackHandler entry point reached through a Safe's fallback
interface IGnosisSafeV130Handler {
    function isValidSignature(bytes calldata data, bytes calldata signature) external view returns (bytes4);
}

interface IGnosisSafeV130Libs {
    function multiSend(bytes memory transactions) external payable;
    function signMessage(bytes calldata data) external;
    function performCreate(uint256 value, bytes memory deploymentData) external returns (address newContract);
    function simulate(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation
    )
        external
        returns (uint256 estimate, bool success, bytes memory returnData);
}

contract CreateCallTarget {
    function ping() external pure returns (uint256) {
        return 42;
    }
}

/// @title Genesis Safe v1.3.0 Libraries Parity Test
/// @notice Proves the seven genesis v1.3.0 libraries (MultiSend and MultiSendCallOnly at their
/// canonical and eip155 addresses, SignMessageLib, CreateCall, SimulateTxAccessor) are
/// byte-exact with Ethereum and work when a v1.3.0 Safe delegatecalls them
contract GenesisSafeV130LibsParityTest is GenesisSafeV130Base {
    /// @dev v1.3.0 `EIP1271_MAGIC_VALUE`, returned by `isValidSignature(bytes,bytes)`
    bytes4 constant LEGACY_EIP1271_MAGIC_VALUE = 0x20c13b0b;

    IGnosisSafeV130 safe;

    function setUp() public {
        _replayGenesis();
        safe = _createSafe(SAFE_V130_PROXY_FACTORY, SAFE_V130_L2_SINGLETON, 0);
        vm.deal(address(safe), 10 ether);
    }

    function test_libCodehashes() public view {
        assertEq(SAFE_V130_MULTI_SEND.codehash, 0x0208282bd262360d0320862c5ac70f375f5ed3b9d89a83a615b4d398415bdc83);
        assertEq(
            SAFE_V130_EIP155_MULTI_SEND.codehash, 0x81db0e4afdf5178583537b58c5ad403bd47a4ac7f9bde2442ef3e341d433126a
        );
        assertEq(
            SAFE_V130_MULTI_SEND_CALL_ONLY.codehash, 0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad
        );
        assertEq(
            SAFE_V130_EIP155_MULTI_SEND_CALL_ONLY.codehash,
            0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad
        );
        assertEq(
            SAFE_V130_SIGN_MESSAGE_LIB.codehash, 0x3ac65dea3cc9dd0d7b7b800f834e3d73415b4e944bb94555c3e4a08fb137e918
        );
        assertEq(SAFE_V130_CREATE_CALL.codehash, 0x8155d988823a4f6f1bcbc76a64af8e510c4ce68819290d43cf24956bd24dee82);
        assertEq(
            SAFE_V130_SIMULATE_TX_ACCESSOR.codehash, 0xb3fb9763869f2c09a2ac5a425d2dd6060bf7ef46b3899049d71a711e71e00f04
        );
    }

    /// @notice MultiSend bakes its own address (`multisendSingleton`), and that is the only
    /// difference between its two copies
    function test_multiSendCopiesDifferOnlyInTheirOwnAddress() public view {
        bytes memory canonical = SAFE_V130_MULTI_SEND.code;
        bytes memory eip155 = SAFE_V130_EIP155_MULTI_SEND.code;
        assertEq(canonical.length, eip155.length);

        bytes20 from = bytes20(SAFE_V130_MULTI_SEND);
        bytes20 to = bytes20(SAFE_V130_EIP155_MULTI_SEND);
        uint256 replaced;
        for (uint256 i; i + 20 <= canonical.length; ++i) {
            bool matches = true;
            for (uint256 j; j < 20 && matches; ++j) {
                matches = canonical[i + j] == from[j];
            }
            if (!matches) continue;
            for (uint256 j; j < 20; ++j) {
                canonical[i + j] = to[j];
            }
            ++replaced;
        }
        assertGt(replaced, 0, "MultiSend does not embed its own address");
        assertEq(keccak256(canonical), keccak256(eip155), "copies differ beyond the baked address");
    }

    /// @notice Each MultiSend copy refuses direct calls (its baked address must equal the address
    /// it runs at) and executes a batch when a Safe delegatecalls it
    function test_multiSendIsDelegatecallOnlyAndBatches() public {
        address[2] memory copies = [SAFE_V130_MULTI_SEND, SAFE_V130_EIP155_MULTI_SEND];
        for (uint256 i; i < copies.length; ++i) {
            bytes memory batch = _transferBatch(address(uint160(0xD00D + i)), address(uint160(0xF00D + i)));

            vm.expectRevert(bytes("MultiSend should only be called via delegatecall"));
            IGnosisSafeV130Libs(copies[i]).multiSend(batch);

            assertTrue(_exec(safe, copies[i], abi.encodeCall(IGnosisSafeV130Libs.multiSend, (batch)), DELEGATECALL));
            assertEq(address(uint160(0xD00D + i)).balance, 1 ether);
            assertEq(address(uint160(0xF00D + i)).balance, 2 ether);
        }
    }

    function test_multiSendCallOnlyBatchesThroughBothCopies() public {
        address[2] memory copies = [SAFE_V130_MULTI_SEND_CALL_ONLY, SAFE_V130_EIP155_MULTI_SEND_CALL_ONLY];
        for (uint256 i; i < copies.length; ++i) {
            bytes memory batch = _transferBatch(address(uint160(0xBEE0 + i)), address(uint160(0xCAFE + i)));
            assertTrue(_exec(safe, copies[i], abi.encodeCall(IGnosisSafeV130Libs.multiSend, (batch)), DELEGATECALL));
            assertEq(address(uint160(0xBEE0 + i)).balance, 1 ether);
            assertEq(address(uint160(0xCAFE + i)).balance, 2 ether);
        }
    }

    /// @notice SignMessageLib marks a message signed in the Safe's storage, and the v1.3.0
    /// fallback handler then validates it under EIP-1271 with an empty signature
    function test_signMessageLibAndFallbackHandler() public {
        bytes memory message = "telcoin network genesis";
        assertTrue(
            _exec(
                safe,
                SAFE_V130_SIGN_MESSAGE_LIB,
                abi.encodeCall(IGnosisSafeV130Libs.signMessage, (message)),
                DELEGATECALL
            )
        );
        assertEq(IGnosisSafeV130Handler(address(safe)).isValidSignature(message, ""), LEGACY_EIP1271_MAGIC_VALUE);
    }

    /// @notice CreateCall deploys from the Safe's own account when delegatecalled, at the CREATE
    /// address of the Safe's nonce
    function test_createCallDeploysFromTheSafe() public {
        address expected = vm.computeCreateAddress(address(safe), vm.getNonce(address(safe)));
        bytes memory data = abi.encodeCall(IGnosisSafeV130Libs.performCreate, (0, type(CreateCallTarget).creationCode));
        assertTrue(_exec(safe, SAFE_V130_CREATE_CALL, data, DELEGATECALL));
        assertEq(CreateCallTarget(expected).ping(), 42);
    }

    /// @notice SimulateTxAccessor bakes its own address and refuses direct calls
    function test_simulateTxAccessorIsDelegatecallOnly() public {
        vm.expectRevert(bytes("SimulateTxAccessor should only be called via delegatecall"));
        IGnosisSafeV130Libs(SAFE_V130_SIMULATE_TX_ACCESSOR).simulate(address(0), 0, "", CALL);
    }

    /// @notice The committed genesis yaml carries the seven library accounts byte-exact, with no
    /// storage
    function test_yamlCarriesSafeV130Libs() public view {
        string memory yaml = _genesisYaml();
        _assertYamlAccount(yaml, SAFE_V130_MULTI_SEND, "safe-v1.3.0/MultiSend", 1);
        _assertYamlAccount(yaml, SAFE_V130_EIP155_MULTI_SEND, "safe-v1.3.0/MultiSend.eip155", 1);
        _assertYamlAccount(yaml, SAFE_V130_MULTI_SEND_CALL_ONLY, "safe-v1.3.0/MultiSendCallOnly", 1);
        _assertYamlAccount(yaml, SAFE_V130_EIP155_MULTI_SEND_CALL_ONLY, "safe-v1.3.0/MultiSendCallOnly", 1);
        _assertYamlAccount(yaml, SAFE_V130_SIGN_MESSAGE_LIB, "safe-v1.3.0/SignMessageLib", 1);
        _assertYamlAccount(yaml, SAFE_V130_CREATE_CALL, "safe-v1.3.0/CreateCall", 1);
        _assertYamlAccount(yaml, SAFE_V130_SIMULATE_TX_ACCESSOR, "safe-v1.3.0/SimulateTxAccessor", 1);
    }

    /// @dev Two value transfers in MultiSend's packed encoding
    function _transferBatch(address a, address b) internal pure returns (bytes memory) {
        return abi.encodePacked(
            abi.encodePacked(CALL, a, uint256(1 ether), uint256(0), ""),
            abi.encodePacked(CALL, b, uint256(2 ether), uint256(0), "")
        );
    }
}
