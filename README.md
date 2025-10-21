# Telcoin Network Smart Contracts

## Overview

This Telcoin Network smart contracts repository contains various system and standard contracts that play crucial roles for the Telcoin Network, including the **InterchainTEL** token precompile and the **ConsensusRegistry** system contract.

## Get Started

This repository does not use Foundry git submodules due to dependencies that do not properly support them. Instead of the `lib` directory, all dependencies are kept in `node_modules`

Requires Node version >= 22, which can be installed like so:

`nvm install 22`

And then install using `npm`, note that `yarn` will throw an error because the yarn package manager has removed Circle Research's `RecoverableWrapper`.

`npm install`

To build the smart contracts:

`forge b`

To run the smart contract tests, which will run for a bit to fuzz thoroughly, use:

`forge test`

The fork tests will require you to add a Sepolia and Telcoin-Network RPC url to the .env file.

## ConsensusRegistry Contract

### Overview

The ConsensusRegistry system contract serves as a single onchain source of truth for consensus-related items which need to be easily accessible across all TN nodes.

It plays a pivotal role in maintaining the integrity and functionality of the network by:

1. **Managing the ConsensusNFT Whitelist**: Facilitating the onboarding of new validators who must obtain a `ConsensusNFT` through Telcoin governance.
2. **Overseeing TEL Staking Mechanisms**: Handling the locking of stakes for governance-approved validators, as well as tracking, distributing, and slashing rewards for validation services.
3. **Managing the Active Validator Set**: Processing validators through activation and exit queues.
4. **Storing Historical Epoch Information**: Recording epoch block heights and voting validator committees, which are predetermined and stored for future epochs.

### Key Features

- **ConsensusNFT Whitelist**: Ensures only approved validators can participate in the network by issuing non-transferable NFTs.
- **Validator Lifecycle Management**: Handles the activation, operation, and exit of validators in an efficient manner.
- **Epoch Management**: Utilizes system calls to maintain up-to-date contract state at the end of each epoch through `concludeEpoch()`.
- **Rewards and Slashing**: Implements mechanisms for distributing staking rewards and applying penalties.

### Validator Onboarding

Below, we follow the general lifecycle of a new validator in roughly chronological order.

1. **Approval and Whitelisting**: Gain approval from Telcoin governance and receive a `ConsensusNFT`.

2. **Staking**: After receiving a `ConsensusNFT`, validators must secure their participation by staking the required amount of TEL tokens. This can be done by calling the `stake()` function, where the validator or a delegator provides the validator BLS public key and address.

3. **Initiating Activation**: Once staked, validators can enter the pending activation queue by calling the `activate()` function. This sets their status to `PendingActivation`, with their activation epoch designated as the next epoch.

4. **Activation**: At the end of each epoch, the protocol system calls `concludeEpoch()`, processing the `PendingActivation` queue. Validators with `PendingActivation` status are transitioned to the `Active` state, allowing them to begin their duties in the network.

5. **Exit Requests**: Active validators may choose to retire by calling the `exit()` function, which places them in the exit queue where they remain active and eligible for selection in voter committees until their exit is finalized.

6. - **Protocol-Determined Exit**: The protocol manages exit finalization. A validator is fully exited after being excluded from voter committees for two consecutive epochs handled at the epoch boundary during the `concludeEpoch()` system call. This is a permissioned transition of the validator from `PendingExit` to `Exited` status, at which point the validator becomes eligible for unstaking after waiting one additional epoch.

7. **Unstaking**: Validators that have elapsed one full epoch in the `Exited` state (or their delegators) may call the `unstake()` function to reclaim the original stake and any accrued rewards. This process burns the `ConsensusNFT`, releasing the stake and rewards. Once unstaked, the validator's address enters an `UNSTAKED` state, making the retirement irreversible. To rejoin the network, a new `ConsensusNFT` must be obtained, and a new validator address must be used.

This detailed lifecycle ensures that validators are properly integrated into the Telcoin Network, maintaining the integrity and reliability of the network's consensus mechanism. For further technical details, refer to the [consensus/design.md](./design.md) file.

## InterchainTEL

### Overview

The InterchainTEL module is a crucial component of the Telcoin Network, facilitating the seamless conversion between Ethereum's ERC20 TEL and Telcoin Network's native TEL gas currency. This module is integral to the network's interchain bridging flow.

### Key Features

- **Axelar Interchain Token Service**: Utilizes Axelar's Interchain Token Service (ITS) to manage interchain conversions, integrated as system precompiles in the protocol.
- **Custom Implementation**: The InterchainTEL token contract is a custom implementation that handles minting and burning of TEL as part of the interchain bridging process.
- **Security Measures**: Implements Circle Research's recoverable wrapper utility to enforce a timelock on outbound TEL bridging, ensuring legitimate sourcing of TEL.

### Interchain Bridging Process

- **Inbound Conversion**: Native TEL is minted on Telcoin Network when TEL is locked or burned on a remote chain.
- **Outbound Bridging**: TEL is double-wrapped to iTEL for bridging to remote chains, with only settled balances being eligible for bridging.

### Native TEL at Genesis

At network genesis, the total supply of TEL, adjusted for the initial validator set's stake, is allocated to the InterchainTEL module.

For more detailed information, please refer to the [design.md](./design.md) file.

## Get Involved

We welcome contributions and feedback from the community. If you're interested in contributing to the Telcoin Network, please refer to our contribution guidelines and join our discussions on governance and protocol improvements.

## License

This project is licensed under Apache or MIT License - see the LICENSE files for details.
