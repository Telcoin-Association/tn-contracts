// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import {StakeInfo} from "./IStakeManager.sol";

/**
 * @title ConsensusRegistry Interface
 * @author Telcoin Association
 * @notice A Telcoin Contract
 *
 * @notice This contract provides the interface for the Telcoin ConsensusRegistry smart contract
 * @dev This contract should be deployed to a predefined system address for use with system calls
 */
interface IConsensusRegistry {
    /*
ConsensusRegistry storage layout for genesis
| Name               | Type                          | Slot                                                               | Offset | Bytes |
|--------------------|-------------------------------|--------------------------------------------------------------------|--------|-------|
| _paused            | bool                          | 0xcd5ed15c6e187e77e9aee88184c21f4f2182ab5827cb3b7e07fbedcd63f03300 | 0      | 1     |
| _owner             | address                       | 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300 | 12     | 20    |
|--------------------|-------------------------------|--------------------------------------------------------------------|--------|-------|
| rwTEL              | address                       | 0x0636e6890fec58b60f710b53efa0ef8de81ca2fddce7e46303a60c9d416c7400 | 12     | 20    |
| stakeAmount        | uint256                       | 0x0636e6890fec58b60f710b53efa0ef8de81ca2fddce7e46303a60c9d416c7401 | 0      | 32    |
| minWithdrawAmount  | uint256                       | 0x0636e6890fec58b60f710b53efa0ef8de81ca2fddce7e46303a60c9d416c7402 | 0      | 32    |
| stakeInfo          | mapping(address => StakeInfo) | 0x0636e6890fec58b60f710b53efa0ef8de81ca2fddce7e46303a60c9d416c7403 | 0      | s     |
|--------------------|-------------------------------|--------------------------------------------------------------------|--------|-------|
| _name              | string                        | 0x80bb2b638cc20bc4d0a60d66940f3ab4a00c1d7b313497ca82fb0b4ab0079300 | 0      | 31    |
| _symbol            | string                        | 0x80bb2b638cc20bc4d0a60d66940f3ab4a00c1d7b313497ca82fb0b4ab0079301 | 0      | 31    |
| _owners            | mapping(uint256 => address)   | 0x80bb2b638cc20bc4d0a60d66940f3ab4a00c1d7b313497ca82fb0b4ab0079302 | 0      | o     |
| _balances          | mapping(address => uint256)   | 0x80bb2b638cc20bc4d0a60d66940f3ab4a00c1d7b313497ca82fb0b4ab0079303 | 0      | b     |
| _tokenApprovals    | mapping(address => uint256)   | 0x80bb2b638cc20bc4d0a60d66940f3ab4a00c1d7b313497ca82fb0b4ab0079304 | 0      | ta    |
| _operatorApprovals | mapping(address => uint256)   | 0x80bb2b638cc20bc4d0a60d66940f3ab4a00c1d7b313497ca82fb0b4ab0079305 | 0      | oa    |
|--------------------|-------------------------------|--------------------------------------------------------------------|--------|-------|
| currentEpoch       | uint32                        | 0xaf33537d204b7c8488a91ad2a40f2c043712bad394401b7dd7bd4cb801f23100 | 0      | 4     |
| epochPointer       | uint8                         | 0xaf33537d204b7c8488a91ad2a40f2c043712bad394401b7dd7bd4cb801f23100 | 4      | 1     |
| epochInfo          | EpochInfo[0]                  | 0xaf33537d204b7c8488a91ad2a40f2c043712bad394401b7dd7bd4cb801f23101 | 0      | x     |
| futureEpochInfo    | FutureEpochInfo[0]            | 0xaf33537d204b7c8488a91ad2a40f2c043712bad394401b7dd7bd4cb801f23102 | 0      | y     |
| validators         | ValidatorInfo[]               | 0xaf33537d204b7c8488a91ad2a40f2c043712bad394401b7dd7bd4cb801f23103 | 0      | z     |

Storage locations for dynamic variables
- `stakeInfo` content (s) begins at slot `0x3b2018e21a7d1a934ee474879a6c46622c725c81fe1ab37a62fbdda1c85e54e4`
- `_name` comprises the following in slot `0x3b2018e21a7d1a934ee474879a6c46622c725c81fe1ab37a62fbdda1c85e54e4`
    - 31 bytes of content `"ConsensusNFT" == 0x436f6e73656e7375734e4654` and 1 byte for content length (12 == 0x0c)
- `_symbol` comprises the following in slot `0x3b2018e21a7d1a934ee474879a6c46622c725c81fe1ab37a62fbdda1c85e54e4`
    - 31 bytes of content `"CNFT" == 0x434e4654` and 1 byte for content length (4 == 0x04)
- `_owners` content (o) begins at slot `0xc59ee7f367a669c2b95c44d4fc46cac58e831d2567849aee0be2ad13d39d52cf`
- `_balances` content (b) begins at slot `0x16ba8a225c41cb03f9a77bfc5b418e9160dc43575312005d8c81f0bd330b3027`
- `_tokenApprovals` content (ta) begins at slot `0xd885219e08c56b96b65bd58819c48ecf6d3dc77d238ea09abae06bf5e59c88fd`
- `_operatorApprovals` content (oa) begins at slot `0xac257f7b51b503ba5377632679403cf33f043c21f94b6a842d6b049c3d330efb`
// - `epochInfo` (x) begins at slot `0x52b83978e270fcd9af6931f8a7e99a1b79dc8a7aea355d6241834b19e0a0ec39` as contiguous static array
// - `futureEpochInfo` (y) begins at slot `0x3e15a0612117eb21841fac9ea1ce6cd116a911fe4c91a9c367a82cd0c3d79718` as contiguous static array
- `validators` (z) begins at slot `0x96a201c8a417846842c79be2cd1e33440471871a6cf94b34c8f286aaeb24ad6b` as abi-encoded
representation
*/

    /// @custom:storage-location erc7201:telcoin.storage.ConsensusRegistry
    struct ConsensusRegistryStorage {
        uint32 currentEpoch;
        uint8 epochPointer;
        EpochInfo[4] epochInfo;
        FutureEpochInfo[4] futureEpochInfo;
        ValidatorInfo[] validators;
        uint256 numGenesisValidators;
    }

    struct ValidatorInfo {
        bytes blsPubkey; // BLS public key is 48 bytes long; BLS proofs are 96 bytes
        bytes32 ed25519Pubkey;
        address ecdsaPubkey;
        uint32 activationEpoch; // uint32 provides ~22000yr for 160s epochs (5s rounds)
        uint32 exitEpoch;
        uint24 validatorIndex;
        ValidatorStatus currentStatus;
    }

    struct EpochInfo {
        address[] committee;
        uint64 blockHeight;
    }

    /// @dev Used to populate a separate ring buffer to prevent overflow conditions when writing future state
    struct FutureEpochInfo {
        address[] committee;
    }

    error LowLevelCallFailure();
    error InvalidBLSPubkey();
    error InvalidEd25519Pubkey();
    error InvalidECDSAPubkey();
    error InvalidProof();
    error InitializerArityMismatch();
    error InvalidCommitteeSize(
        uint256 minCommitteeSize,
        uint256 providedCommitteeSize
    );
    error CommitteeRequirement(address ecdsaPubkey);
    error NotValidator(address ecdsaPubkey);
    error AlreadyDefined(address ecdsaPubkey);
    error InvalidTokenId(uint256 tokenId);
    error InvalidStatus(ValidatorStatus status);
    error InvalidIndex(uint24 validatorIndex);
    error InvalidEpoch(uint32 epoch);

    event ValidatorPendingActivation(ValidatorInfo validator);
    event ValidatorActivated(ValidatorInfo validator);
    event ValidatorPendingExit(ValidatorInfo validator);
    event ValidatorExited(ValidatorInfo validator);
    event NewEpoch(EpochInfo epoch);
    event RewardsClaimed(address claimant, uint256 rewards);

    enum ValidatorStatus {
        Undefined,
        PendingActivation,
        Active,
        PendingExit,
        Exited
    }

    /// @notice Voting Validator Committee changes once every epoch (== 32 rounds)
    /// @notice Can only be called in a `syscall` context, at the end of an epoch
    /// @dev Accepts the committee of voting validators for 2 epochs in the future
    /// @param newCommittee The future validator committee for 2 epochs after
    /// the current one is finalized; ie `$.currentEpoch + 3` (this func increments `currentEpoch`)
    function concludeEpoch(address[] calldata newCommittee) external;

    /// @dev Issues an exit request for a validator to be ejected from the active validator set
    /// @notice Reverts if the caller would cause the network to lose BFT by exiting
    /// @notice Caller must be a validator with `ValidatorStatus.Active` status
    function exit() external;

    /// @dev Issues a rejoin request for an exited validator to reactivate
    /// @notice Caller must be a validator with `ValidatorStatus.Exited` status
    /// @param blsPubkey Callers may provide a new BLS key if they wish to update it
    /// @param ed25519Pubkey Callers may provide a new ED25519 key if they wish to update it
    function rejoin(bytes calldata blsPubkey, bytes32 ed25519Pubkey) external;

    /// @dev Returns the current epoch
    function getCurrentEpoch() external view returns (uint32);

    /// @dev Returns information about the provided epoch. Only four latest & two future epochs are stored
    /// @notice When querying for future epochs, `blockHeight` will be 0 as they are not yet known
    function getEpochInfo(
        uint32 epoch
    ) external view returns (EpochInfo memory currentEpochInfo);

    /// @dev Returns an array of `ValidatorInfo` structs that match the provided status for this epoch
    function getValidators(
        ValidatorStatus status
    ) external view returns (ValidatorInfo[] memory);

    /// @dev Fetches the `validatorIndex` for a given validator address
    /// @notice A returned `validatorIndex` value of `0` is invalid and indicates
    /// that the given address is not a known validator's ECDSA externalkey
    function getValidatorIndex(
        address ecdsaPubkey
    ) external view returns (uint24 validatorIndex);

    /// @dev Fetches the `ValidatorInfo` for a given validator index
    /// @notice To enable checks against storage slots initialized to zero by the EVM, `validatorIndex` cannot be `0`
    function getValidatorByIndex(
        uint24 validatorIndex
    ) external view returns (ValidatorInfo memory validator);
}
