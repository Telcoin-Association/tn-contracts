// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { IUniswapV2Factory } from "external/uniswap/interfaces/IUniswapV2Factory.sol";
import { IUniswapV2Router02 } from "external/uniswap/interfaces/IUniswapV2Router02.sol";
import { UniswapV2FactoryBytecode } from "external/uniswap/precompiles/UniswapV2FactoryBytecode.sol";
import { UniswapV2Router02Bytecode } from "external/uniswap/precompiles/UniswapV2Router02Bytecode.sol";
import { MainnetDeployBase } from "../MainnetDeployBase.sol";

/// @dev File-level so the V3 script derives the V2 factory address from the same recipe
bytes32 constant UNISWAP_V2_FACTORY_SALT = bytes32(bytes("UniswapV2Factory"));
bytes32 constant UNISWAP_V2_ROUTER_SALT = bytes32(bytes("UniswapV2Router02"));

/// @title Deploy Uniswap V2 on Telcoin Network mainnet
///
/// @notice Deploys the canonical UniswapV2Factory and UniswapV2Router02 through the Arachnid
///         proxy. No pairs are created: pairs are permissionless and get created by whoever
///         first provides liquidity.
///
/// @notice The factory's `feeToSetter` is the governance Safe from construction, so protocol
///         fees can only ever be switched on by governance. The router wraps native TEL through
///         the genesis WTEL.
///
/// @dev The factory's runtime bytes are byte-identical to Ethereum's canonical factory
///      (feeToSetter lives in storage), which also fixes the pair init code hash at the
///      canonical 0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f.
///
/// @dev Usage: `forge script script/mainnet/deploy/MainnetDeployUniswapV2.s.sol -vvvv \
///      --rpc-url $TN_MAINNET_RPC_URL --private-key $DEPLOYER_PK --broadcast`
contract MainnetDeployUniswapV2 is MainnetDeployBase, UniswapV2FactoryBytecode, UniswapV2Router02Bytecode {
    /// @dev Runtime hash of Ethereum's canonical UniswapV2Factory (0x5C69bEe7...aA6f)
    bytes32 internal constant FACTORY_RUNTIME_HASH = 0xbab145d02e7005f0d84c6c1639d39b799b0ea16df99ebbdaf5a14d9da820b4e0;

    function run() public {
        _loadMainnet();
        address wtel = deployments.WTEL;
        _requireCode(wtel, "WTEL");

        bytes memory factoryInitcode = bytes.concat(UNISWAPV2FACTORY_BYTECODE, abi.encode(governance));

        vm.startBroadcast();
        address factory = _deployDeterministic(UNISWAP_V2_FACTORY_SALT, factoryInitcode, "UniswapV2Factory");
        address router = _deployDeterministic(
            UNISWAP_V2_ROUTER_SALT,
            bytes.concat(UNISWAPV2ROUTER02_BYTECODE, abi.encode(factory, wtel)),
            "UniswapV2Router02"
        );
        vm.stopBroadcast();

        _requireCodehash(factory, FACTORY_RUNTIME_HASH, "UniswapV2Factory");
        require(IUniswapV2Factory(factory).feeToSetter() == governance, "MainnetDeployUniswapV2: feeToSetter");
        require(IUniswapV2Router02(router).factory() == factory, "MainnetDeployUniswapV2: router factory");
        require(IUniswapV2Router02(router).WETH() == wtel, "MainnetDeployUniswapV2: router WETH");

        _record(".uniswapV2.UniswapV2Factory", factory);
        _record(".uniswapV2.UniswapV2Router02", router);
    }
}
