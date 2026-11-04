// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
import { Permit2Bytecode } from "external/uniswap/precompiles/v4/Permit2Bytecode.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { DeploymentsResolver } from "../../deployments/DeploymentsResolver.sol";
import { GenesisYamlAssertions } from "./GenesisYamlAssertions.sol";
import { GenesisReplay } from "./GenesisReplay.sol";

/// @dev The Permit2 `AllowanceTransfer` surface the tests use
interface IPermit2 {
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
    function allowance(
        address user,
        address token,
        address spender
    )
        external
        view
        returns (uint160 amount, uint48 expiration, uint48 nonce);
    function permit(address owner, PermitSingle memory permitSingle, bytes calldata signature) external;
    function transferFrom(address from, address to, uint160 amount, address token) external;
}

contract Permit2TestToken is ERC20 {
    function name() public pure override returns (string memory) {
        return "Permit2 Test Token";
    }

    function symbol() public pure override returns (string memory) {
        return "P2T";
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Addresses and EIP-712 helpers shared by the Permit2 parity tests
abstract contract GenesisPermit2Base is GenesisYamlAssertions, GenesisReplay {
    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    bytes32 constant PERMIT2_CODEHASH = 0xc67d1657868aa5146eaf24fb879fb1fdec3d2d493b3683a61c9c2f4fb2851131;

    /// @dev The domain separator Permit2 returns on Ethereum mainnet
    bytes32 constant ETHEREUM_DOMAIN_SEPARATOR = 0x866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28;

    bytes32 constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    bytes32 constant PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");
    bytes32 constant PERMIT_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    /// @dev Stands in for Telcoin Network: the Adiri chain id, any id other than Ethereum's 1
    uint256 constant TN_CHAIN_ID = DeploymentsResolver.TESTNET_CHAIN_ID;

    function _domainSeparator(uint256 chainId) internal pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("Permit2"), chainId, PERMIT2));
    }
}

/// @title Genesis Permit2 Parity Test
/// @notice Proves the genesis Permit2 is byte-exact with Ethereum and works on a chain other
/// than Ethereum. Its bytes cache chain id 1 and Ethereum's domain separator as immutables;
/// `DOMAIN_SEPARATOR()` rebuilds the separator from `block.chainid` whenever that differs, so
/// a permit signed for the TN chain id is accepted there and one signed for Ethereum is not
contract GenesisPermit2ParityTest is GenesisPermit2Base {
    uint256 constant OWNER_KEY = 0xA11CE;
    address constant SPENDER = address(0x5BE7);

    Permit2TestToken token;
    address owner;

    function setUp() public {
        GenerateGenesisPrecompileConfig genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiatePermit2();

        token = new Permit2TestToken();
        owner = vm.addr(OWNER_KEY);
        token.mint(owner, 100 ether);
        vm.prank(owner);
        token.approve(PERMIT2, type(uint256).max);
    }

    function test_canonicalCodehash() public view {
        assertEq(PERMIT2.codehash, PERMIT2_CODEHASH);
    }

    function test_domainSeparatorFollowsTheChain() public {
        vm.chainId(1);
        assertEq(IPermit2(PERMIT2).DOMAIN_SEPARATOR(), ETHEREUM_DOMAIN_SEPARATOR);
        assertEq(_domainSeparator(1), ETHEREUM_DOMAIN_SEPARATOR);

        vm.chainId(TN_CHAIN_ID);
        assertEq(IPermit2(PERMIT2).DOMAIN_SEPARATOR(), _domainSeparator(TN_CHAIN_ID));
        assertTrue(IPermit2(PERMIT2).DOMAIN_SEPARATOR() != ETHEREUM_DOMAIN_SEPARATOR);
    }

    function test_approveAndTransferFrom() public {
        uint48 expiration = uint48(block.timestamp + 1 days);
        vm.prank(owner);
        IPermit2(PERMIT2).approve(address(token), SPENDER, 5 ether, expiration);

        (uint160 amount, uint48 storedExpiration, uint48 nonce) =
            IPermit2(PERMIT2).allowance(owner, address(token), SPENDER);
        assertEq(amount, 5 ether);
        assertEq(storedExpiration, expiration);
        assertEq(nonce, 0);

        vm.prank(SPENDER);
        IPermit2(PERMIT2).transferFrom(owner, SPENDER, 2 ether, address(token));
        assertEq(token.balanceOf(SPENDER), 2 ether);
    }

    function test_permitSignedForTheLiveChain() public {
        vm.chainId(TN_CHAIN_ID);
        IPermit2.PermitSingle memory permitSingle = _permitSingle();
        IPermit2(PERMIT2).permit(owner, permitSingle, _sign(permitSingle, _domainSeparator(TN_CHAIN_ID)));

        (uint160 amount,, uint48 nonce) = IPermit2(PERMIT2).allowance(owner, address(token), SPENDER);
        assertEq(amount, 3 ether);
        assertEq(nonce, 1);

        vm.prank(SPENDER);
        IPermit2(PERMIT2).transferFrom(owner, SPENDER, 3 ether, address(token));
        assertEq(token.balanceOf(SPENDER), 3 ether);
    }

    function test_ethereumPermitDoesNotReplay() public {
        vm.chainId(TN_CHAIN_ID);
        IPermit2.PermitSingle memory permitSingle = _permitSingle();
        bytes memory signature = _sign(permitSingle, ETHEREUM_DOMAIN_SEPARATOR);
        vm.expectRevert(bytes4(keccak256("InvalidSigner()")));
        IPermit2(PERMIT2).permit(owner, permitSingle, signature);
    }

    function test_yamlCarriesPermit2() public view {
        _assertYamlAccount(_genesisYaml(), PERMIT2, "permit2/Permit2", 1);
    }

    function _permitSingle() internal view returns (IPermit2.PermitSingle memory) {
        return IPermit2.PermitSingle({
            details: IPermit2.PermitDetails({
                token: address(token), amount: 3 ether, expiration: uint48(block.timestamp + 1 days), nonce: 0
            }),
            spender: SPENDER,
            sigDeadline: block.timestamp + 1 hours
        });
    }

    function _sign(
        IPermit2.PermitSingle memory permitSingle,
        bytes32 domainSeparator
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_SINGLE_TYPEHASH,
                keccak256(abi.encode(PERMIT_DETAILS_TYPEHASH, permitSingle.details)),
                permitSingle.spender,
                permitSingle.sigDeadline
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(OWNER_KEY, keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash)));
        return abi.encodePacked(r, s, v);
    }
}

/// @title Genesis Permit2 Replay Test
/// @notice Replays the canonical deployment (the vendored creation code through the Arachnid
/// proxy with the canonical salt) under chain id 1: it reproduces the genesis bytes and writes
/// no storage
contract GenesisPermit2ReplayTest is GenesisPermit2Base, Permit2Bytecode {
    function setUp() public {
        vm.etch(ARACHNID, ARACHNID_RUNTIME);
    }

    function test_ethereumCreationReproducesGenesisState() public {
        vm.chainId(1);
        (address created, bytes32[] memory slots,) =
            _deployRecordingStorage(ARACHNID, PERMIT2_CANONICAL_SALT, PERMIT2_CREATION_BYTECODE, PERMIT2);
        assertEq(created, PERMIT2);
        assertEq(created.codehash, PERMIT2_CODEHASH);
        assertEq(slots.length, 0, "constructor wrote storage");
    }
}
