// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { IStakeManager } from "../interfaces/IStakeManager.sol";
import { Issuance } from "./Issuance.sol";

/**
 * @title StakeManager
 * @author Telcoin Association
 * @notice A Telcoin Contract
 *
 * @notice This abstract contract provides modular management of consensus validator stake
 * @dev Designed for inheritance by the ConsensusRegistry
 */
abstract contract StakeManager is ERC721, EIP712, IStakeManager {
    address payable public issuance;
    uint24 public totalSupply;
    uint8 public stakeVersion;
    mapping(uint8 => StakeConfig) internal versions;
    mapping(address => uint256) internal stakeInfo;
    mapping(address => Delegation) internal delegations;

    /// @dev Validators that unstake are permanently ejected by setting their index to `UNSTAKED`
    /// @notice Rejoining requires re-onboarding with new validator address, tokenId, stake, & index
    uint256 internal constant UNSTAKED = type(uint160).max;

    /// @dev EIP-712 typed struct hash used to enable delegated proof of stake
    bytes32 DELEGATION_TYPEHASH = keccak256(
        "Delegation(bytes32 blsPubkeyHash,address validatorAddress,address delegator,uint8 validatorVersion,uint64 nonce)"
    );

    constructor(string memory name, string memory symbol) ERC721(name, symbol) { }

    /// @inheritdoc IStakeManager
    function stake(bytes calldata blsPubkey) external payable virtual;

    /// @inheritdoc IStakeManager
    function delegateStake(
        bytes calldata blsPubkey,
        address validatorAddress,
        bytes calldata validatorSig
    )
        external
        payable
        virtual;

    /// @inheritdoc IStakeManager
    function claimStakeRewards(address ecsdaPubkey) external virtual;

    /// @inheritdoc IStakeManager
    function unstake(address validatorAddress) external virtual;

    /// @inheritdoc IStakeManager
    function getRewards(address validatorAddress) public view virtual returns (uint256);

    /// @inheritdoc IStakeManager
    function getStakeInfo(address validatorAddress) public view virtual returns (uint256) {
        return stakeInfo[validatorAddress];
    }

    /// @inheritdoc IStakeManager
    function stakeConfig(uint8 version) public view virtual returns (StakeConfig memory) {
        return versions[version];
    }

    /// @inheritdoc IStakeManager
    function getCurrentStakeConfig() public view returns (StakeConfig memory) {
        return versions[stakeVersion];
    }

    /// @inheritdoc IStakeManager
    function upgradeStakeVersion(StakeConfig calldata config) external virtual returns (uint8);

    /// @inheritdoc IStakeManager
    function allocateIssuance() external payable virtual override;

    /// @inheritdoc IStakeManager
    function delegationDigest(
        bytes memory blsPubkey,
        address validatorAddress,
        address delegator
    )
        external
        view
        override
        returns (bytes32)
    {
        _checkConsensusNFTOwner(validatorAddress);
        uint64 nonce = delegations[validatorAddress].nonce;
        bytes32 blsPubkeyHash = keccak256(blsPubkey);
        bytes32 structHash =
            keccak256(abi.encode(DELEGATION_TYPEHASH, blsPubkeyHash, validatorAddress, delegator, stakeVersion, nonce));

        return _hashTypedData(structHash);
    }

    /**
     *
     *   ERC721
     *
     */

    /// @dev The StakeManager's ERC721 ledger serves a permissioning role over validators, requiring
    /// Telcoin governance to approve each node operator and manually issue them a `ConsensusNFT`
    /// @param to Refers to the struct member `ValidatorInfo.validatorAddress` in `IConsensusRegistry`
    /// @notice tokenId Will be `uint160(to)` which must be less than `UNSTAKED` and nonzero
    /// @notice Access-gated in ConsensusRegistry to its owner, which is a Telcoin governance address
    function mint(address to) external virtual;

    /// @dev In the case of malicious or erroneous node operator behavior, governance can use this function
    /// to burn a validator's `ConsensusNFT` and immediately eject from consensus committees if applicable
    /// @param from Refers to the struct member `ValidatorInfo.validatorAddress` in `IConsensusRegistry`
    /// @notice `from` will be marked `UNSTAKED` so the validator address cannot be reused
    /// @dev Intended for sparing use; only reverts if burning results in empty committee
    function burn(address from) external virtual;

    /// @notice Consensus NFTs are soulbound to validators and cannot be transferred unless burned
    function transferFrom(
        address,
        /* from */
        address,
        /* to */
        uint256 /* tokenId */
    )
        public
        virtual
        override
    {
        revert NotTransferable();
    }

    /// @notice Wouldn't do anything because transfers are disabled but explicitly disallow anyway
    function approve(address, /*to*/ uint256 /*tokenId*/ ) public virtual override {
        revert NotTransferable();
    }

    /// @notice Read-only mechanism, not yet live
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        _requireOwned(tokenId);

        return _baseURI();
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return ""; // TEL svg
    }

    /**
     *
     *   internals
     *
     */
    function _claimStakeRewards(
        address validatorAddress,
        address recipient,
        uint8 validatorVersion
    )
        internal
        virtual
        returns (uint256)
    {
        // check rewards are claimable and send via the InterchainTEL contract
        uint256 rewards = _checkRewards(validatorAddress, validatorVersion);
        stakeInfo[validatorAddress] -= rewards;
        Issuance(issuance).distributeStakeReward(recipient, rewards);

        return rewards;
    }

    function _unstake(
        address validatorAddress,
        address recipient,
        uint8 validatorVersion
    )
        internal
        virtual
        returns (uint256)
    {
        // wipe existing stakeInfo and burn the token
        uint256 bal = stakeInfo[validatorAddress];
        stakeInfo[validatorAddress] = 0;
        if (--totalSupply == 0) revert InvalidSupply();
        _burn(_getTokenId(validatorAddress));

        // forward stake to recipient through Issuance
        uint256 stakeAmt = versions[validatorVersion].stakeAmount;
        uint256 rewards = _getRewards(validatorAddress, stakeAmt);
        Issuance(issuance).distributeStakeReward{ value: bal }(recipient, rewards);

        // if slashed, consolidate remainder on the Issuance contract
        if (bal < stakeAmt) {
            (bool r,) = issuance.call{ value: stakeAmt - bal }("");
            r;
        }

        return bal + rewards;
    }

    function _checkRewards(address validatorAddress, uint8 validatorVersion) internal virtual returns (uint256) {
        uint256 initialStake = versions[validatorVersion].stakeAmount;
        uint256 rewards = _getRewards(validatorAddress, initialStake);

        if (rewards == 0 || rewards < versions[validatorVersion].minWithdrawAmount) {
            revert InsufficientRewards(rewards);
        }

        return rewards;
    }

    function _checkStakeValue(uint256 value, uint8 version) internal virtual returns (uint256) {
        if (value != versions[version].stakeAmount) revert InvalidStakeAmount(value);

        return uint256(value);
    }

    function _getRewards(address validatorAddress, uint256 initialStake) internal view virtual returns (uint256) {
        uint256 balance = stakeInfo[validatorAddress];
        uint256 rewards = balance > initialStake ? balance - initialStake : 0;

        return rewards;
    }

    /// @dev Identifies the validator's rewards recipient, ie the stake originator
    /// @return _ Returns the validator's delegator if one exists, else the validator itself
    function _getRecipient(address validatorAddress) internal view returns (address) {
        Delegation storage delegation = delegations[validatorAddress];
        address recipient = delegation.delegator;
        if (recipient == address(0x0)) recipient = validatorAddress;

        return recipient;
    }

    /// @dev Reverts if provided claimant isn't the existing delegation entry keyed under `validatorAddress`
    function _checkKnownDelegation(address validatorAddress, address claimant) internal view returns (address) {
        address delegator = delegations[validatorAddress].delegator;
        if (claimant != delegator) revert NotDelegator(claimant);

        return delegator;
    }

    /// @dev Reverts if the provided address doesn't correspond to an existing `tokenId` owned by `validatorAddress`
    function _checkConsensusNFTOwner(address validatorAddress) internal view{
        uint256 tokenId = _getTokenId(validatorAddress);
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
    }

    function _getTokenId(address validatorAddress) internal view returns (uint256) {
        return uint256(uint160(validatorAddress));
    }

    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        if (tokenId == 0 || tokenId >= UNSTAKED) revert InvalidTokenId(tokenId);
        return _ownerOf(tokenId) != address(0);
    }

    function _domainNameAndVersion() internal view virtual override returns (string memory, string memory) {
        return ("Telcoin StakeManager", "1");
    }
}
