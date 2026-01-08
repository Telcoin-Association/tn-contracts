# Telcoin Network Bridging Security

## Reporting a Vulnerability

If you discover a security vulnerability, please email [`security@telcoin.org`](mailto:security@telcoin.org).
We will **acknowledge** your report within 48 hours and provide a timeline for investigation.

## Background

Cross-chain bridging is notorious for security breaches, arising from numerous bridge-related exploits since developers began exploring cross-chain messaging systems to power blockchain bridges. Bridging involves translating messages between different blockchains with varying consensus mechanisms, execution environments, messaging standards, cryptographic key primitives, and programming languages. Exploits have historically taken advantage of mistakes in the translation of these data flows across protocol boundaries.

## Axelar Network solution

Using the Telcoin ERC20 token on Ethereum and Polygon as the native token on Telcoin-Network requires a comprehensive cross chain bridging system. Axelar Network's Interchain Token Service protocol was chosen to fill this role for multiple reasons:

- Axelar Network is at the forefront of cross chain communication and is battle tested, securing billions of crypto capital flowing across chain boundaries of major networks like Ethereum, BNB, Sui, Arbitrum, Optimism, Cosmos, and others.
- Axelar has protocolized cross chain communication, enabling generalized message passing in a structured way between blockchains. This enhances composability compared to other cross-chain products that offer custom integrations of specific tokens.
- Axelar Network is decentralized, utilizing distributed networks of two types of consensus entities: Axelar validator nodes which agnostically run the protocol and verifier nodes which validate execution on integrated external chains

## Bridging Components

From a security standpoint, Telcoin Network bridging consists of several components that must be examined for comprehensive security:

### Axelar Interchain Token Service and Interchain TEL

##### Security implications: CRITICAL

To integrate with Axelar, Telcoin Network's execution layer employs a custom implementation of the TEL token designed for use with the Interchain Token Service (ITS).

#### Interchain Token Service (ITS)

The Interchain Token Service enables interchain functionality by supporting bridging to any Axelar-supported chain. To bolster security posture, Telcoin Network uses canonical audited and battle-tested Axelar ITS v2.1.0 implementations as precompiles without modifications.

For more information on ITS, refer to [this design document](./src/its-design.md)

#### InterchainTEL

The InterchainTEL executable contract communicates with the external gateway to lock and release native $TEL tokens. It is vital that this contract is secure to handle the movement of $TEL for inbound and outbound bridge messages.

To bolster this contract's security posture, the contract enforces the expected ITS invariant as well as two main TN-specific invariant conditions:

- Only its `TokenManager` can access the ITS `mint()` and `burn()` functions, during interchain transfers
- $TEL can only be minted (released) as a result of incoming bridge transactions validated by Axelar Network verifiers. This is enforced by a call to the Axelar external gateway which is pre-authorized using weighted verifier signatures

For more information on InterchainTEL, refer to [this design document](./src/design.md)

### Relayers

##### Security implications: LOW

Relayers are offchain components that handle the transfer of cross-chain messages between chains. In Axelar's architecture, relayers can be run permissionlessly by anyone; Axelar even offers their own relayers as a paid service.

There are two types of relayer used for Telcoin Network bridging:

1. The Subscriber’s job is to guarantee that every protocol event on the Amplifier chain is detected and successfully relayed to Axelar Network using the GMP API as an entrypoint. It does not make use of a private key to custody or move funds. It simply relays information from the external gateway and thus bears no security risk itself.

2. The Includer’s job is to guarantee that bridge messages which have been verified by Axelar Network are delivered to the destination external gateway as well as executed via transactions. This relayer possesses a private key to transact, which requires it to custody enough funds for gas. As such, a compromise of the Includer would result in loss of these gas funds, which would normally be relatively trivial.

More information about the relayers can be found [in this readme](./node/src/relay/README.md)

### GMP API

##### Security implications: LOW

The Axelar GMP API abstracts away most of Axelar Network's internals by performing a series of CosmWasm transactions that push bridge messages through various verification steps. These verifications are codified by smart contracts deployed on the Axelar blockchain, which we do not fork for our Interchain Token Service integration.

Examples for bypassing GMP API and manually performing each of the Axelar Network transactions which it handles by GMP API can be found in [this directory](./node/src/relay/devnet/). Manual relaying through Axelar in this way is only expected to be used for devnet.

The GMP API flow is crucial to TN bridging, but it is entirely implemented by Axelar. The security considerations are supported by Axelar's audits and security posture. By integrating with the GMP API, Telcoin-Network benefits from Axelar's existing work on internal security and provides developers with a simple interface to the Axelar Chain.

More information about the GMP API can be found [in this readme](./node/src/relay/README.md)

### Verifiers

##### Security implications: CRITICAL

To validate cross-chain messages within the Axelar chain, whitelisted services called `verifiers` check new messages against their source chain's finality via RPC to quorum-vote on whether the messages were indeed emitted by the source chain's gateway within a block that has reached finality. To do so, the TN verifiers themselves run a Telcoin Network Observer client to track TN's execution and consensus.

Because verifiers are the entities responsible for reaching quorum on whether bridge messages are valid and final, they possess a similar security implication to the InterchainTEL module. In short, the verifiers are responsible for validating bridge messages from a consensus-standpoint, whereas the InterchainTEL module is responsible for carrying out those validated bridge messages from the execution-standpoint.

For more information on the verifier client, refer to [the Telcoin-Network protocol itself](https://github.com/Telcoin-Association/telcoin-network) and the Axelar [tofnd](https://github.com/axelarnetwork/tofnd) + [ampd verifier](https://github.com/axelarnetwork/axelar-amplifier/tree/main/ampd) repositories.

## Telcoin Network System Contract Audit Scope

| File                                | Logic Contracts                                     | Interfaces                            | nSLOC |
| ----------------------------------- | --------------------------------------------------- | ------------------------------------- | ----- |
| src/InterchainTEL.sol               | 1 (InterchainTEL)                                   | 1 (IInterchainTEL)                    | 393   |
| src/WTEL.sol                        | 1 (WTEL)                                            | 0                                     | 17    |
| src/consensus/ConsensusRegistry.sol | 3 (ConsensusRegistry, StakeManager, SystemCallable) | 2 (IConsensusRegistry, IStakeManager) | 1011  |
| src/Issuance.sol                    | 1 (Issuance)                                        | 0                                     | 47    |

### Other auditor notes:

One dependency contracts used required compiler version updates to be used:

- `external/axelar-cgp-solidity/AxelarGasServiceProxy.sol` from 0.8.9 to ^0.8.0

ConsensusRegistry validator vector in storage is structured around a relatively low count ~700 MNOs in the world, if we onboarded them all it would be a good problem to have. This can be optimized via eg SSTORE2 or merkleization so suggestions are welcome but not a priority atm

ConsensusRegistry and ITEL are both instantiated as precompiles at genesis, with ConsensusRegistry configuration created in memory via system call for validator data availability and with InterchainTEL precompiled & its storage slots recorded. The initial balance between the two contracts at genesis together sums up to the total TEL supply on TN.

### Documentation

##### For developers and auditors, please note that this codebase adheres to [the SolidityLang NatSpec guidelines](https://docs.soliditylang.org/en/latest/natspec-format.html), meaning documentation for each contract is best viewed in its interface file. For example, to learn about the InterchainTEL module you should consult the IInterchainTEL interface and likewise, for info about the ConsensusRegistry, see IConsensusRegistry.sol.
