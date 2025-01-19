# Telcoin Network Bridging Security

## Reporting a Vulnerability

If you discover a security vulnerability, please email [`security@telcoin.org`](mailto:security@telcoin.org).
We will **acknowledge** your report within 48 hours and provide a timeline for investigation.

## Background

Cross chain bridging bears notoriety for security breaches arising from the dozens of bridge-related exploits in the few years since developers began exploring cross chain messaging systems to power blockchain bridges.

While bridging is a young concept (~5 years at most), cross-chain security considerations generally boil down to the friction between differing protocol implementations. Being positioned between protocol edges, bridges must securely translate messages between blockchains with different consensus workings, execution VMs, messaging standards, cryptographic key primitives, and programming languages. Bridge exploits have historically taken advantage of mistakes in translation of these data flows between protocol boundaries.

## Axelar Network solution

Using the Telcoin ERC20 token on Ethereum and Polygon as the native token on Telcoin-Network requires a comprehensive cross chain bridging system, so significant effort has been devoted to devising and securing our setup. Axelar Network, a Cosmos blockchain providing protocolized cross chain messaging infrastructure, was chosen to fill this role for multiple reasons:

- Axelar Network is at the forefront of cross chain communication and is battle tested, securing billions of crypto capital flowing across chain boundaries of major networks like Ethereum, BNB, Sui, Arbitrum, Optimism, Cosmos, and others.
- Axelar has protocolized cross chain communication, enabling generalized message passing in a fully automated and structured way between blockchains. This provides composability one step above many other cross chain products like Thorchain which only provide custom integrations of specific tokens
- Axelar Network is decentralized, utilizing distributed networks of two types of consensus entities: Axelar validator nodes which agnostically run the protocol and verifier nodes which validate execution on integrated external chains

## Bridging Components

![img](https://i.imgur.com/0tvOXdu.png)

From a security standpoint, Telcoin Network bridging is constituted of four component categories. These must be examined for a comprehensive understanding of bridge security.

### Gateway and Executable Contracts

##### Security implications: CRITICAL

To integrate with Axelar, Telcoin Network's execution layer uses an external gateway contract and executable contract: the AxelarAmplifierGateway and the RWTEL module, respectively.

#### External Gateway "AxelarAmplifierGateway.sol"

The external gateway serves as the EVM entrypoint and exit point for cross-chain messages. It is vital that this contract is secure to maintain the lock-release relationship between tokens on Telcoin Network and external chains.

To bolster this contract's security posture, Telcoin Network uses the canonical audited and battle-tested Axelar implementation without any changes.

#### RWTEL Executable "AxelarGMPExecutable.sol"

The RWTEL executable contract communicates with the external gateway to lock and release native $TEL tokens. It is vital that this contract is secure to handle the movement of native $TEL as part of validated bridge messages.

To bolster this contract's security posture, the contract enforces strict invariant conditions under which $TEL may be released:

- $TEL can only be burned (locked) after a 24 hour settlement period, meaning that any attacker cannot send $TEL off of Telcoin Network until 24 hours have passed for any received $TEL. This is enforced by Circle Research's `RecoverableWrapper`
- $TEL can only be minted (released) as a result of incoming bridge transactions validated by Axelar Network verifiers. This is enforced by a call to the Axelar external gateway
- $TEL bridge transactions that fail execution by the RWTEL module for any reason do not revert and instead emit a failure event. This way, failed transactions can not get stuck or be re-attempted and must be resubmitted as a new message on the source chain (which will be re-validated by Axelar verifiers)
- $TEL minting occurs as part of the simplest low-level call available within the EVM, represented and decoded from the following Solidity struct which is designed to mirror a protocol transaction:

```solidity
/// @dev Designed for AxelarGMPExecutable's required implementation of `_execute()`
struct ExtCall {
    address target;
    uint256 value;
    bytes data;
}
```

### Relayers

##### Security implications: MEDIUM

Relayers are offchain components that handle the transfer of cross-chain messages between chains. In Axelar's architecture, relayers can be run permissionlessly by anyone; Axelar even offers their own relayers as a paid service.

There are two types of relayer used for Telcoin Network bridging:

1. The Subscriber’s job is to guarantee that every protocol event on the Amplifier chain is detected and successfully relayed to Axelar Network using the GMP API as an entrypoint. It does not make use of a private key to custody or move funds. It simply relays information from the external gateway and thus bears no security risk itself.

2. The Includer’s job is to guarantee that bridge messages which have been verified by Axelar Network are delivered to the destination external gateway as well as executed via transactions. This relayer possesses a private key to transact, which requires it to custody enough funds for gas. As such, a compromise of the Includer would result in loss of these gas funds, which would normally be relatively trivial.

The Telcoin-Network Includer's security posture is bolstered by use of Foundry's cutting-edge AES-512 encrypted keystores that require access to both the keystore and its password for signing. This keystore can be easily rotated.

### GMP API

##### Security implications: LOW

The Axelar GMP API is one of Axelar's main offerings which abstracts away most of Axelar Network's internals by performing a series of CosmWasm transactions under the hood that push bridge messages through various verification steps. These verifications are codified by smart contracts deployed on the Axelar blockchain and [are discussed in-depth here](https://forum.telcoin.org/t/light-clients-independent-verification/296/6?u=robriks).

This flow is very important to TN bridging, however it is entirely implemented by Axelar thus the security considerations are bolstered by their audits and security posture. By integrating with GMP API, Telcoin-Network benefits from Axelar's existing work on their internal security and provides developers with a simple push & pull interface to the Axelar Chain. Further, most chains integrated with Axelar use this same component so a vulnerability here would incentivize attackers to prioritize bigger bridge pots than ours, such as Ethereum GMP messages.

### Verifiers

##### Security implications: CRITICAL

To validate cross-chain messages within the Axelar chain, whitelisted services called `verifiers` check new messages against their source chain's finality via RPC to quorum-vote on whether the messages were indeed emitted by the source chain's gateway within a block that has reached finality. To do so, the TN verifiers themselves run a copy of a Telcoin Network Non-Voting Validator "NVV" client to track TN's execution and consensus.

Because verifiers are the entities responsible for reaching quorum on whether bridge messages are valid and final, they possess a similar security implication to the RWTEL module. In short, the verifiers are responsible for validating bridge messages from a consensus-standpoint, whereas the RWTEL module is responsible for carrying out those validated bridge messages from the execution-standpoint.

## Telcoin Network System Contract Audit Scope

| File                                | Logic Contracts                                     | Interfaces                            | nSLOC          |
| ----------------------------------- | --------------------------------------------------- | ------------------------------------- | -------------- |
| src/RWTEL.sol                       | 1 (RWTEL)                                           | 1 (IRWTEL)                            | 141            |
| src/consensus/ConsensusRegistry.sol | 3 (ConsensusRegistry, StakeManager, SystemCallable) | 2 (IConsensusRegistry, IStakeManager) | (600, 150, 21) |
| node/src/relay/Includer.ts          | 0 (Offchain Relayer)                                | 0 (Offchain component)                | 300            |

The ConsensusRegistry smart contract, a system contract critical to the Telcoin-Network protocol's consensus, is invoked at the execution client level at epoch boundaries. For this reason, the protocol logic invoking the ConsensusRegistry via system call should thus be audited in tandem with the contract. The telcoin-network repository files involved with regard to system calls are listed below:

| File                                 | nSLOC |
| ------------------------------------ | ----- |
| crates/engine/src/lib.rs             | 295   |
| crates/engine/src/payload_builder.ts | 534   |

### Dependencies (audited)

RWTEL:

- [RecoverableWrapper](./node_modules/recoverable-wrapper/contracts/rwt/RecoverableWrapper.sol)
- [AxelarGMPExecutable](./node_modules/@axelar-network/axelar-gmp-sdk-solidity/contracts/executable/AxelarGMPExecutable.sol)
- [UUPSUpgradeable](./node_modules/@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol)
- [Ownable](./node_modules/solady/src/auth/Ownable.sol)

ConsensusRegistry:

- [PausableUpgradeable](./node_modules/@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol)
- [OwnableUpgradeable](./node_modules/@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol)
- [UUPSUpgradeable](./node_modules/@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol)
- [ERC721Upgradeable](./node_modules/@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol)

### Documentation

##### For developers and auditors, please note that this codebase adheres to [the SolidityLang NatSpec guidelines](https://docs.soliditylang.org/en/latest/natspec-format.html), meaning documentation for each contract is best viewed in its interface file. For example, to learn about the RWTEL module you should consult the IRWTEL interface and likewise, for info about the ConsensusRegistry, see IConsensusRegistry.sol.

##### Please also note that while these contracts are still a work in progress, documentation is limited to the repo's READMEs and forum posts from developers. Once finalized but still preceding audit, tn-contracts system documentation will be hosted on a standard rust-lang/mdbook.

- An overview of Telcoin Network's main smart contracts is documented in the [tn-contracts NodeJS subdirectory README](./node/src/README.md)

- ConsensusRegistry system design is documented in the [tn-contracts README](./README.md#consensusregistry) and there is some more system design discussion in [this Telcoin Forum post](https://forum.telcoin.org/t/validator-onboarding-staking-consensusregistry/364/2?u=robriks)

- RWTEL system design is likewise documented in the [tn-contracts README](./README.md#rwtel-module)

- Offchain relayer system design is documented in the [tn-contracts NodeJS subdirectory's relay README](./node/src/relay/README.md)
