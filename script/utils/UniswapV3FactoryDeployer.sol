// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

/// @notice Owner-gated surface of UniswapV3Factory used at deployment
interface IUniswapV3FactoryAdmin {
    function owner() external view returns (address);
    function feeAmountTickSpacing(uint24 fee) external view returns (int24);
    function enableFeeAmount(uint24 fee, int24 tickSpacing) external;
    function setOwner(address owner) external;
}

/// @title Uniswap V3 Factory Deployer
/// @notice One-shot helper that deploys UniswapV3Factory, enables the 0.01% fee tier and hands
///         factory ownership to `owner`, all inside its own constructor.
/// @dev UniswapV3Factory assigns `owner = msg.sender` in its constructor. Deployed directly
///      through the Arachnid proxy, the proxy would become the permanent owner and fee tiers and
///      protocol fees could never be managed. Deployed from an externally owned account, the
///      factory's address would depend on that account's nonce and the account would briefly
///      own it. This helper is itself deployed through the Arachnid proxy and CREATE2-deploys the
///      factory with salt 0, so the factory address is deterministic, and ownership reaches
///      `owner` in the same transaction that creates the factory. After construction the helper
///      holds no privileges; it only exposes the factory address.
/// @dev The 0.01% tier (fee 100, tick spacing 1) matches the tiers live on Ethereum's canonical
///      factory alongside the constructor's built-in 0.05%, 0.3% and 1% tiers.
contract UniswapV3FactoryDeployer {
    /// @notice The UniswapV3Factory this helper deployed
    address public immutable factory;

    constructor(bytes memory factoryInitcode, address owner) {
        address deployed;
        assembly ("memory-safe") {
            deployed := create2(0, add(factoryInitcode, 0x20), mload(factoryInitcode), 0)
        }
        require(deployed != address(0), "UniswapV3FactoryDeployer: factory deploy failed");

        IUniswapV3FactoryAdmin(deployed).enableFeeAmount(100, 1);
        IUniswapV3FactoryAdmin(deployed).setOwner(owner);
        factory = deployed;
    }
}
