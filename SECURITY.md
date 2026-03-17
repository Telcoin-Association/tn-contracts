# Telcoin Network Bridging Security

## Reporting a Vulnerability

If you discover a security vulnerability, please email [`security@telcoin.org`](mailto:security@telcoin.org).
We will **acknowledge** your report within 48 hours and provide a timeline for investigation.

## Background

Cross-chain bridging is notorious for security breaches, arising from numerous bridge-related exploits since developers began exploring cross-chain messaging systems to power blockchain bridges. Bridging involves translating messages between different blockchains with varying consensus mechanisms, execution environments, messaging standards, cryptographic key primitives, and programming languages. Exploits have historically taken advantage of mistakes in the translation of these data flows across protocol boundaries.

## TEL Native ERC20 Precompile

Telcoin Network exposes TEL as a native ERC20 precompile at `0x00000000000000000000000000000000000007e1`. The precompile uses a unified balance model where `balanceOf(account)` returns the native account balance directly — no wrapping needed. It supports the full ERC20 interface plus governance-gated `mint`, `claim`, and `burn` functions.

For more information, refer to [the TEL precompile](https://github.com/telcoin-association/telcon-network).

## Bridging

Cross-chain TEL bridging is being migrated to LayerZero. Details are out of scope for this document.

## Telcoin Network System Contract Audit Scope

| File                                | Logic Contracts                                     | Interfaces                            | nSLOC |
| ----------------------------------- | --------------------------------------------------- | ------------------------------------- | ----- |
| src/consensus/ConsensusRegistry.sol | 3 (ConsensusRegistry, StakeManager, SystemCallable) | 2 (IConsensusRegistry, IStakeManager) | 1011  |
| src/Issuance.sol                    | 1 (Issuance)                                        | 0                                     | 47    |

ConsensusRegistry validator vector in storage is structured around a relatively low count ~700 MNOs in the world, if we onboarded them all it would be a good problem to have. This can be optimized via eg SSTORE2 or merkleization so suggestions are welcome but not a priority atm

### Documentation

##### For developers and auditors, please note that this codebase adheres to [the SolidityLang NatSpec guidelines](https://docs.soliditylang.org/en/latest/natspec-format.html), meaning documentation for each contract is best viewed in its interface file. For example, for info about the ConsensusRegistry, see IConsensusRegistry.sol.
