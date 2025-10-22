// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { ERC721Enumerable } from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import { Base64 } from "@openzeppelin/contracts/utils/Base64.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { IStakeManager } from "../interfaces/IStakeManager.sol";
import { Issuance } from "./Issuance.sol";
import { BlsG1 } from "./BlsG1.sol";

/**
 * @title StakeManager
 * @author Telcoin Association
 * @notice A Telcoin Contract
 *
 * @notice This abstract contract provides modular management of consensus validator stake
 * @dev Designed for inheritance by the ConsensusRegistry
 */
abstract contract StakeManager is ERC721Enumerable, EIP712, IStakeManager {
    mapping(uint8 => StakeConfig) internal versions;
    mapping(address => uint256) internal balances;
    mapping(address => Delegation) internal delegations;
    uint8 internal stakeVersion;

    /// @dev Instantiated by the protocol as a precompile
    address payable public constant issuance = payable(0x07A07A07A07A07a07A07A07a07a07A07a07a07A0);

    /// @dev EIP-712 typed struct hash used to enable delegated proof of stake
    bytes32 constant DELEGATION_TYPEHASH = keccak256(
        "Delegation(bytes32 blsPubkeyHash,address validatorAddress,address delegator,uint8 validatorVersion,uint64 nonce)"
    );

    /// @dev ConsensusNFT SVG is stored onchain and is constant across all tokenId URIs
    string constant SVG =
        '<svg width="79" height="80" viewBox="0 0 79 80" fill="none" xmlns="http://www.w3.org/2000/svg"> <mask id="mask0_849_3417" style="mask-type:alpha" maskUnits="userSpaceOnUse" x="0" y="0" width="79" height="80"> <rect width="78.005" height="80" fill="#C4C4C4"/> </mask> <g mask="url(#mask0_849_3417)"> <rect x="17.9546" y="18.3545" width="42.2943" height="43.2918" fill="white"/> <path d="M74.2369 21.9892C76.6908 24.0315 78.2389 28.2577 77.6979 31.3733L72.4166 61.3253C71.866 64.4475 68.9592 67.8798 65.9629 68.9612L37.1947 79.3344C34.1984 80.4157 29.7421 79.6299 27.2964 77.589L3.811 58.0021C1.35708 55.9598 -0.19238 51.7417 0.358148 48.6195L5.63951 18.6674C6.19004 15.5452 9.09687 12.1129 12.0932 11.0316L40.8599 0.666453C43.8562 -0.414857 48.3125 0.370909 50.7583 2.4118L74.2369 21.9892ZM49.7645 35.4369L50.9364 29.3513L39.9517 29.3687L41.516 21.3424L37.9583 21.3424C37.9583 21.3424 34.6328 27.2901 27.3006 30.2019L26.2899 35.4503L31.0936 35.46C31.0936 35.46 29.4674 43.0029 28.9316 45.7854C27.5677 52.8682 30.9806 57.8939 36.2281 57.8939C38.8606 57.8939 41.817 57.8939 45.0972 57.8939L46.6524 51.1666C46.2742 51.1666 43.8013 51.1666 39.2336 51.1666C35.9364 51.1666 36.1099 49.3189 36.7431 46.0305L38.7838 35.4333L49.7645 35.4369Z" fill="#14C8FF"/> </g> </svg>';

    constructor(string memory name, string memory symbol) ERC721(name, symbol) { }

    /// @inheritdoc IStakeManager
    function stake(
        bytes calldata blsPubkey,
        BlsG1.ProofOfPossession calldata proofOfPossession
    )
        external
        payable
        virtual;

    /// @inheritdoc IStakeManager
    function delegateStake(
        bytes calldata blsPubkey,
        BlsG1.ProofOfPossession calldata proofOfPossession,
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
    function getBalanceBreakdown(address validatorAddress) public view virtual returns (uint256, uint256, uint256);

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

    /**
     *
     *   ERC721
     *
     */

    /// @dev The StakeManager's ERC721 ledger serves a permissioning role over validators, requiring
    /// Telcoin governance to approve each node operator and manually issue them a `ConsensusNFT`
    /// @param to Refers to the struct member `ValidatorInfo.validatorAddress` in `IConsensusRegistry`
    /// @notice For each mintee, `tokenId == uint160(to)`
    /// @notice Access-gated in ConsensusRegistry to its owner, which is a Telcoin governance address
    function mint(address to) external virtual;

    /// @dev In the case of malicious or erroneous node operator behavior, governance can use this function
    /// to burn a validator's `ConsensusNFT` and immediately eject from consensus committees if applicable
    /// @param from Refers to the struct member `ValidatorInfo.validatorAddress` in `IConsensusRegistry`
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
        override(ERC721, IERC721)
    {
        revert NotTransferable();
    }

    /// @notice Wouldn't do anything because transfers are disabled but explicitly disallow anyway
    function approve(
        address,
        /*to*/
        uint256 /*tokenId*/
    )
        public
        virtual
        override(ERC721, IERC721)
    {
        revert NotTransferable();
    }

    /// @notice Wouldn't do anything because transfers are disabled but explicitly disallow anyway
    function setApprovalForAll(
        address,
        /*operator*/
        bool /*approved*/
    )
        public
        virtual
        override(ERC721, IERC721)
    {
        revert NotTransferable();
    }

    /// @notice Read-only mechanism, not yet live
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        _requireOwned(tokenId);

        string memory json = Base64.encode(
            bytes(
                string.concat(
                    '{"name": "Telcoin-Network ConsensusNFT',
                    Strings.toChecksumHexString(address(uint160(tokenId))),
                    '", "description": "ERC721 NFT whose ownership ledger represents the permissioned whitelist for validators", "image": "',
                    _baseURI(),
                    '"}'
                )
            )
        );

        return string.concat("data:application/json;base64,", json);
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return string.concat("data:image/svg+xml;base64,", Base64.encode(bytes(SVG)));
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
        // check rewards are claimable and send via the Issuance contract
        uint256 rewards = _checkRewards(validatorAddress, validatorVersion);
        balances[validatorAddress] -= rewards;
        Issuance(issuance).distributeStakeReward(recipient, rewards);

        return rewards;
    }

    function _unstake(address validatorAddress, address recipient) internal virtual returns (uint256) {
        _burn(_getTokenId(validatorAddress));
        if (totalSupply() == 0) revert InvalidSupply();

        (uint256 bal, uint256 stakeAmt, uint256 rewards) = getBalanceBreakdown(validatorAddress);
        // zero outstanding balance implies burn context, no further action needed- ledgers are already settled
        if (bal == 0) return bal;

        // otherwise wipe existing balance & identify the amount of stake due to recipient
        balances[validatorAddress] = 0;
        uint256 unstakeAmt;
        if (bal >= stakeAmt) {
            // recipient is entitled to full initial stake amount and any outstanding rewards
            unstakeAmt = stakeAmt;
        } else {
            // recipient has been slashed below initial stake; only outstanding bal will be sent
            unstakeAmt = bal;
            // consolidate slashed stake remainder on the Issuance contract, repurposed for future rewards
            (bool r,) = issuance.call{ value: stakeAmt - bal }("");
            r;
        }

        // debit `unstakeAmt` due to recipient from this contract balance, debit rewards from Issuance balance
        Issuance(issuance).distributeStakeReward{ value: unstakeAmt }(recipient, rewards);

        return unstakeAmt + rewards;
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
        uint256 balance = balances[validatorAddress];
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

    /// @dev Reverts if the provided address doesn't correspond to an existing `tokenId` owned by `validatorAddress`
    function _checkConsensusNFTOwner(address validatorAddress) internal view returns (uint256) {
        uint256 tokenId = _getTokenId(validatorAddress);
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
        if (ownerOf(tokenId) != validatorAddress) revert RequiresConsensusNFT();

        return tokenId;
    }

    function _getTokenId(address validatorAddress) internal pure returns (uint256) {
        return uint160(validatorAddress);
    }

    function _getAddress(uint256 tokenId) internal pure returns (address) {
        return address(uint160(tokenId));
    }

    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        if (tokenId == 0 || tokenId >= type(uint160).max) revert InvalidTokenId(tokenId);
        return _ownerOf(tokenId) != address(0);
    }

    function _domainNameAndVersion() internal view virtual override returns (string memory, string memory) {
        return ("Telcoin StakeManager", "1");
    }
}
