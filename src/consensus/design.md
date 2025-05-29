Consensus Registry

#### ConsensusNFT Whitelist

To join Telcoin Network as a validator, node operators first must be approved by Telcoin governance. Once approved, validators will be issued a `ConsensusNFT` serving as a permissioned validator whitelist. Only the contract owner, an address managed by Telcoin governance, can issue these NFTs via `ConsensusRegistry::mint()`

The ERC721 `tokenId` of each validator's token serves as their validator uid. TokenIDS can be reused after burned when a validator retires, but validator addresses can never be reused after exit.

# ConsensusRegistry Design

The `ConsensusRegistry` contract is a core component of the Telcoin Network, designed to manage the validator lifecycle, staking mechanisms, and historical epoch data.

## Validator Permissioning via ConsensusNFT

- **Governance Approval**: Validators are mobile network operators vetted through Telcoin governance, which mints a `ConsensusNFT` on the StakeManager to the validator's address.
- **Validator Representation**: Each validator is represented by a `ValidatorInfo` struct, optimized for storage efficiency.
- **NFT Characteristics**:
  - There are roughly 700 MNOs in the world, so the validator set will be small and current storage gas cost limits provide plenty of leeway before an update is required
  - Supports up to (type(uint24).max - 1) validators, with the maximum tokenID reserved as an `UNSTAKED` flag.
  - TokenIDs are generally minted in ascending order, but previously burned tokenIDs can be reminted to avoid gaps
  - ConsensusNFTs are non-transferable and do not yet implement `TokenURI`, which will be finalized during pilot and likely be a simple TEL logo svg.

## Consensus Mechanisms

### System Calls

The Telcoin Network leverages Bullshark and Narwhal protocols, enabling nodes to build blocks in parallel. Epochs are delineated by timestamps rather than block numbers.

At the epoch boundary, the protocol performs gasless system calls to the ConsensusRegistry to update its state with epoch, validator, and rewards information. System call logic is abstracted into the `SystemCallable` module.

- **Epoch Conclusion (`concludeEpoch()`)**: Finalizes the previous epoch, updates the voting committee and validator set, and stores new epoch information. Validator committees are protocol-managed and stored historically and for future epochs using ring buffers.
- **Rewards Tracking (`applyIncentives()`)**: Increments staking rewards based on validator performance and stake. Must be called before slashing and epoch conclusion.
- **Slashing (`applySlashes()`)**: Decrements validators' stakes as penalties. This is not live yet but has a preliminary implementation.

## Staking and Delegation

- **Configurable Stake Amounts**: Stake amounts are configurable to support iterative adjustments in early phases based on node operator feedback and protocol updates.
- **Stake Versions**: Records are kept of validators joining under different versions for accurate stake tracking and weighted reward calculation
- **Issuance Contract**: Accepts TEL for rewards distribution, using TEL "burnt" for epoch rewards. For simplicity, the Issuance contract offloads accounting to the EVM native ledger.
- **Delegation**: DPOS is currently supported though expected to be used sparingly for delegators and validators with ongoing offchain relationships or agreements.
- **Delegation Rewards**: Delegators receive all stake rewards and the staked balance upon unstaking, so schemas for splitting stake rewards between validator and delegator are assumed to be agreed upon offchain by those parties and settled externally to the protocol

## Rewards and Issuance

- **Rewards Claiming**: Pull-only claim flow to avoid reverts during critical consensus logic.
- **Rewards Sourcing**: During the MNO pilot, consensus block rewards are funded by the TAO in a subsidized growth phase.
- **Balance Tracking** Validator balances use a uint256 ledger which represents outstanding balance in full, including both stake and any accrued rewards.
