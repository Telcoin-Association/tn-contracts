// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Deployments } from "../../../deployments/Deployments.sol";
import { DeploymentsResolver } from "../../../deployments/DeploymentsResolver.sol";
import { WTEL } from "../../../src/WTEL.sol";

/// @title Deploy WTEL (canonical-shape wrapped TEL) on Adiri Testnet
///
/// @notice WTEL is the wrapped-native ERC20 the Uniswap V2 / V3 / V4 stacks
///         consume at their `_WETH9` constructor arg. Constructor takes no
///         arguments, so the deploy is a single Arachnid CREATE2 call against
///         `type(WTEL).creationCode`. Idempotent on re-run.
///
/// @dev Must run before TestnetDeployUniswapV2 / V3 / V4 - those scripts
///      `require(deployments.WTEL != address(0))` and consume the same value
///      as the wrapped-native arg they previously fed `TELCOIN_PRECOMPILE`.
///
/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployWTEL.s.sol -vvvv \
///      --rpc-url $TN_RPC_URL --private-key $ADMIN_PK --broadcast`
contract TestnetDeployWTEL is Script {
    Deployments deployments;

    /// @notice Populated by run() after a successful CREATE2 deploy. Public so
    ///         tests can read the deployed address back.
    address public wtel;
    bytes32 salt = bytes32(bytes("WTEL"));

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, DeploymentsResolver.relativePath());
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));
    }

    function run() public {
        // Idempotency: skip only if WTEL is recorded AND has code on-chain.
        // A non-zero JSON address with no on-chain code means the recorded
        // address is a stale prediction (e.g. an initcode that no longer
        // matches current source) - we must redeploy in that case rather
        // than treating the JSON as authoritative.
        if (deployments.WTEL != address(0) && deployments.WTEL.code.length > 0) {
            console2.log("WTEL already deployed at:", deployments.WTEL);
            return;
        }

        vm.startBroadcast();

        address arachnid = deployments.ArachnidDeterministicDeployFactory;
        bytes memory initcode = type(WTEL).creationCode;
        (bool ok, bytes memory ret) = arachnid.call(bytes.concat(salt, initcode));
        require(ok, "TestnetDeployWTEL: CREATE2 deploy failed");
        wtel = address(bytes20(ret));

        vm.stopBroadcast();

        assert(wtel.code.length != 0);

        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, DeploymentsResolver.relativePath());
        vm.writeJson(LibString.toHexString(uint256(uint160(wtel)), 20), dest, ".WTEL");

        console2.log("WTEL deployed at:", wtel);
    }
}
