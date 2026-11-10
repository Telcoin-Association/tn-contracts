// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { DeploymentsResolver } from "../../deployments/DeploymentsResolver.sol";
import { GenesisYamlAssertions } from "./GenesisYamlAssertions.sol";

/// @dev The CreateX surface the tests use; the source is not vendored under `lib/`
interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address newContract);
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) external view returns (address);
    function deployCreate3(bytes32 salt, bytes memory initCode) external payable returns (address newContract);
    function computeCreate3Address(bytes32 salt) external view returns (address);
}

contract CreateXTarget {
    uint256 public immutable value;

    constructor(uint256 value_) {
        value = value_;
    }
}

/// @title Genesis CreateX Parity Test
/// @notice Proves the genesis CreateX is byte-exact with Ethereum and lands CREATE2 and CREATE3
/// deployments where its own `compute*` functions (and the CREATE2 formula) predict. CreateX
/// runs every caller salt through `_guard` first: a salt whose first 20 bytes are the caller and
/// whose 21st byte is 0x00 becomes `keccak256(abi.encode(caller, salt))`, the same on every
/// chain; with 0x01 the chain id is mixed in as well
contract GenesisCreateXParityTest is GenesisYamlAssertions {
    address constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
    address constant CREATEX_DEPLOYER = 0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5;
    bytes32 constant CREATEX_CODEHASH = 0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f;

    /// @dev Stands in for Telcoin Network: the Adiri chain id, any id other than Ethereum's 1
    uint256 constant TN_CHAIN_ID = DeploymentsResolver.TESTNET_CHAIN_ID;

    function setUp() public {
        GenerateGenesisPrecompileConfig genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiateCreateX();
    }

    function test_canonicalCodehash() public view {
        assertEq(CREATEX.codehash, CREATEX_CODEHASH);
    }

    /// @notice CreateX bakes its own address (`_SELF`), so the bytes are valid only here
    function test_bakesItsOwnAddress() public view {
        bytes memory code = CREATEX.code;
        bool found;
        for (uint256 i; i + 20 <= code.length && !found; ++i) {
            bytes20 window;
            assembly ("memory-safe") {
                window := and(mload(add(add(code, 0x20), i)), shl(96, sub(shl(160, 1), 1)))
            }
            found = window == bytes20(CREATEX);
        }
        assertTrue(found);
    }

    function test_deployCreate2LandsWherePredicted() public {
        bytes32 salt = _permissionedSalt(0x00, 1);
        bytes memory initCode = bytes.concat(type(CreateXTarget).creationCode, abi.encode(uint256(7)));
        bytes32 guardedSalt = keccak256(abi.encode(address(this), salt));

        address predicted = vm.computeCreate2Address(guardedSalt, keccak256(initCode), CREATEX);
        assertEq(ICreateX(CREATEX).computeCreate2Address(guardedSalt, keccak256(initCode)), predicted);

        address deployed = ICreateX(CREATEX).deployCreate2(salt, initCode);
        assertEq(deployed, predicted);
        assertEq(CreateXTarget(deployed).value(), 7);
    }

    /// @notice With cross-chain redeploy protection the guarded salt, and so the address, follow
    /// the live chain id
    function test_crossChainProtectedSaltUsesTheLiveChainId() public {
        vm.chainId(TN_CHAIN_ID);
        bytes32 salt = _permissionedSalt(0x01, 2);
        bytes memory initCode = bytes.concat(type(CreateXTarget).creationCode, abi.encode(uint256(8)));

        bytes32 tnSalt = keccak256(abi.encode(address(this), TN_CHAIN_ID, salt));
        bytes32 ethereumSalt = keccak256(abi.encode(address(this), uint256(1), salt));
        address deployed = ICreateX(CREATEX).deployCreate2(salt, initCode);
        assertEq(deployed, vm.computeCreate2Address(tnSalt, keccak256(initCode), CREATEX));
        assertTrue(deployed != vm.computeCreate2Address(ethereumSalt, keccak256(initCode), CREATEX));
    }

    function test_deployCreate3LandsWherePredicted() public {
        bytes32 salt = _permissionedSalt(0x00, 3);
        bytes32 guardedSalt = keccak256(abi.encode(address(this), salt));
        address predicted = ICreateX(CREATEX).computeCreate3Address(guardedSalt);

        address deployed = ICreateX(CREATEX)
            .deployCreate3(salt, bytes.concat(type(CreateXTarget).creationCode, abi.encode(uint256(9))));
        assertEq(deployed, predicted);
        assertEq(CreateXTarget(deployed).value(), 9);
    }

    /// @notice The committed genesis yaml carries CreateX at nonce 1 without storage, and its
    /// presigned deployment's signer at nonce 1 so that transaction counts as spent
    function test_yamlCarriesCreateXAndSpentDeployer() public view {
        string memory yaml = _genesisYaml();
        _assertYamlAccount(yaml, CREATEX, "createx/CreateX", 1);
        _assertYamlSpentDeployer(yaml, CREATEX_DEPLOYER, CREATEX);
    }

    /// @dev Salt whose first 20 bytes are this contract (permissioned deploy), byte 21 is the
    /// cross-chain redeploy protection flag, and the rest is `entropy`
    function _permissionedSalt(bytes1 crossChainFlag, uint88 entropy) internal view returns (bytes32) {
        return bytes32(abi.encodePacked(address(this), crossChainFlag, entropy));
    }
}
