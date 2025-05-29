// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import { Record } from "recoverable-wrapper/contracts/util/RecordUtil.sol";

interface IInterchainTEL {
    event Minted(address indexed to, uint256 indexed nativeAmount);
    event Burned(address indexed from, uint256 indexed nativeAmount);
    event RemainderTransferFailed(address indexed to, uint256 amount);
    event GovernanceTransferStarted(address indexed currentGovernance, address indexed pendingGovernance);
    event GovernanceTransferred(address indexed previousGovernance, address indexed newGovernance);

    error OnlyTokenManager(address manager);
    error OnlyBaseToken(address wTEL);
    error PermitWrapFailed(address to, uint256 amount);
    error MintFailed(address to, uint256 amount);
    error BurnFailed(address from, uint256 amount);
    error InvalidAmount(uint256 nativeAmount);

    /// @notice Convenience function for users to wrap native TEL directly to iTEL in one tx
    /// @dev InterchainTEL performs WETH9 deposit on behalf of caller so they need not hold wTEL or make approval
    function doubleWrap() external payable;

    /// @notice Convenience function for users to wrap wTEL to iTEL in one tx without approval
    /// @dev Explicitly allows malleable signatures for optionality. Malleability is handled
    /// by abstracting signature reusability away via stateful nonce within the EIP-712 structhash
    function permitWrap(address owner, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;

    /// @notice Fetches the account's outstanding unsettled records
    /// @dev Intended as a convenience function only, eg for frontends. Does not prevent
    /// reverts arising from unbounded storage access
    function unsettledRecords(address account) external view returns (Record[] memory);

    /// @notice Returns the create3 salt used by ITS for TokenManager deployment
    /// @dev This salt is used to deploy/derive TokenManagers for both Ethereum and TN
    /// @dev ITS uses `interchainTokenId()` as the create3 salt used to deploy TokenManagers
    function tokenManagerCreate3Salt() external view returns (bytes32);

    /// @notice Returns the unique salt required for InterchainTEL ITS integration
    /// @dev Equivalent to `InterchainTokenFactory::linkedTokenDeploySalt()`
    function linkedTokenDeploySalt() external view returns (bytes32);

    /// @notice Returns the ITS TokenManager address for InterchainTEL, derived via create3
    /// @dev ITS uses `interchainTokenId()` as the create3 salt used to deploy TokenManagers
    function tokenManagerAddress() external view returns (address);

    /// @notice Required by Axelar ITS to complete interchain transfers during payload processing
    /// of `MESSAGE_TYPE_INTERCHAIN_TRANSFER` headers, which delegatecalls `TokenHandler::giveToken()`
    function isMinter(address addr) external view returns (bool);

    /// @notice InterchainTEL implementation for ITS Token Manager's mint API
    /// @dev Mints native TEL to `to` using converted native amount handled by Axelar Hub
    /// @dev Axelar Hub decimal handling info can be found here:
    /// https://github.com/axelarnetwork/axelar-amplifier/blob/aa956eed0bb48b3b14d20fdc6b93deb129c02bea/contracts/interchain-token-service/src/contract/execute/mod.rs#L260
    function mint(address to, uint256 originAmount) external;

    /// @notice InterchainTEL implementation for ITS Token Manager's burn API
    /// @dev Burns InterchainTEL out of `from`'s settled (recoverable) balance, collecting the unwrapped native TEL
    /// and forwarding unusable truncated remainders to the governance address before forwarding to Axelar
    /// @dev Axelar Hub destination chain decimal truncation can be found here:
    /// https://github.com/axelarnetwork/axelar-amplifier/blob/aa956eed0bb48b3b14d20fdc6b93deb129c02bea/contracts/interchain-token-service/src/contract/execute/interceptors.rs#L228
    function burn(address from, uint256 nativeAmount) external;

    /// @dev Starts the Governance transfer of the contract to a new account. Replaces pending governance if one exists
    /// @notice Setting `newGovernance` to the zero address is allowed; this cancels a pending governance transfer.
    /// @notice Impl of OZ 5.1.0 `Ownable2Step` for `RecoverableWrapper::governanceAddress` to avoid forking
    function transferGovernance(address newGovernanceAddress) external;

    /// @dev Transfers RecoverableWrapper governance authority to `newGovernance`, deletes pending governance
    /// @notice Impl of OZ 5.1.0 `Ownable2Step` for `RecoverableWrapper::governanceAddress` to avoid forking
    function acceptGovernance() external;
}
