// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { console2 } from "forge-std/console2.sol";
import { MainnetDeployBase } from "../MainnetDeployBase.sol";

/// @title Deploy CreateX on Telcoin Network mainnet
///
/// @notice Lands CreateX at its canonical cross-chain address
///         0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed by broadcasting CreateX's own presigned
///         deployment transaction. That transaction is pre-EIP-155 (no chain id), signed by the
///         CreateX deployer 0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5 at nonce 0, so it is
///         valid on any chain that accepts unprotected legacy transactions, as Telcoin Network
///         does.
///
/// @notice The script first tops the deployer up to the transaction's fixed maximum cost
///         (3,000,000 gas at 100 gwei = 0.3 TEL), then broadcasts the raw transaction. Gas the
///         deployment does not use stays with the CreateX deployer, an account nobody here
///         controls (about 0.04 TEL).
///
/// @notice If the deployer's nonce 0 has been spent on anything else, the canonical address is
///         unreachable for good; the script stops rather than deploy CreateX elsewhere.
///
/// @dev Vendored transaction and its provenance: deployments/canonical-initcode/README.md
///
/// @dev Usage: `forge script script/mainnet/deploy/MainnetDeployCreateX.s.sol -vvvv \
///      --rpc-url $TN_MAINNET_RPC_URL --private-key $DEPLOYER_PK --broadcast`
contract MainnetDeployCreateX is MainnetDeployBase {
    address internal constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
    address internal constant CREATEX_DEPLOYER = 0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5;
    bytes32 internal constant CREATEX_RUNTIME_HASH = 0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f;
    /// @dev keccak256 of the RLP-encoded signed transaction, the upstream 3M-gas-limit variant
    bytes32 internal constant PRESIGNED_TX_HASH = 0xb6274b80bc7cda162df89894c7748a5cb7ba2eaa6004183c41a1837c3b072f1e;
    uint256 internal constant PRESIGNED_GAS_PRICE = 100 gwei;
    uint256 internal constant PRESIGNED_GAS_LIMIT = 3_000_000;

    function run() public {
        _loadMainnet();

        if (CREATEX.code.length != 0) {
            _requireCodehash(CREATEX, CREATEX_RUNTIME_HASH, "CreateX");
            console2.log("CreateX already deployed at", CREATEX);
            _record(".CreateX", CREATEX);
            return;
        }

        require(
            vm.getNonce(CREATEX_DEPLOYER) == 0,
            "MainnetDeployCreateX: CreateX deployer nonce 0 already spent; canonical address unreachable"
        );
        require(block.basefee <= PRESIGNED_GAS_PRICE, "MainnetDeployCreateX: base fee above the presigned gas price");

        bytes memory presigned = _readInitcode("createx/CreateX.presigned.hex", PRESIGNED_TX_HASH);

        uint256 maxCost = PRESIGNED_GAS_LIMIT * PRESIGNED_GAS_PRICE;
        uint256 balance = CREATEX_DEPLOYER.balance;
        if (balance < maxCost) {
            vm.startBroadcast();
            (bool funded,) = CREATEX_DEPLOYER.call{ value: maxCost - balance }("");
            require(funded, "MainnetDeployCreateX: funding the CreateX deployer failed");
            vm.stopBroadcast();
        }

        vm.broadcastRawTransaction(presigned);

        _requireCodehash(CREATEX, CREATEX_RUNTIME_HASH, "CreateX");
        console2.log("CreateX deployed at", CREATEX);
        _record(".CreateX", CREATEX);
    }
}
