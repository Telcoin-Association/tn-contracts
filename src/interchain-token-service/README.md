# Axelar Interchain Token Service overview

The Axelar Interchain Token Service enables new and existing tokens to gain interchain functionality, supporting bridging to any Axelar-supported EVM-compatible chain.

Bridging tokens via the Axelar ITS connects numerous chains by passing bridge messages through a series of validation steps on Axelar Network, which is a Cosmos IBC chain secured by decentralized consensus. Unlike older cross-chain bridges which generally implement bespoke relayer logic directly between two chains, ITS messages are relayed to Axelar Network where they are internally routed through its central hub to validate the message's origin, veracity, and conformity to the target chain's expectations.

After an ITS message is issued from a source chain and relayed to the Axelar Network hub, it is processed by a set of verification contracts specific to the target chain. If the message passes all validation checks, including the source chain's finality and that the message references a known token ID supported by both source and destination chains,

## Interchain Token IDs

ITS protocolizes interchain operability by assigning each token a standardized `interchainTokenId` which serves as a fixed UID across chains. `InterchainTEL` uses the custom-link interchain token id type; more on this later.

ITS leverages determinism to achieve statelessness, never storing any token IDs or addresses in contract storage. Instead, ITS core contracts are written to bytecode and peripheral contracts like supported tokens and their corresponding `TokenManagers` are recalculated in memory for each interchain call. This is achieved because of the following invariants:

- the `InterchainTokenService` core contract (and all core contracts) are deployed deterministically to the same address on all EVM chains
- all interchain messages route between `InterchainTokenService` contracts on supported origin and destination chains. This means ITS messages originate from and arrive to the same deterministic deployment address
- interchain token IDs are deterministically derived and immutable once registered
- interchain token IDs serve as the `create3` salt for the token's corresponding `TokenManager` contract, resulting in a deterministic address.

These deterministic invariants make the token and its `TokenManager`'s type immutable. Ie, a token and its manager that registered as `LOCK_RELEASE` cannot be changed because reattempting the deployment with `create3(tokenID)` will fail on attempting to overwrite the existing `TokenManager`'s contract bytecode.

## Interchain Token ID Types

The interchain token ID for a given token can be derived in one of three ways, each suiting a different need. These three mutually-exclusive categories are as follows:

1. Native Interchain Tokens
2. Canonical Interchain Tokens
3. Custom-linked Interchain Tokens

Telcoin-Network has selected option 3 to best suit our needs spanning interchain decimals conversion and minting/burning native gas currency.

## Telcoin <> Axelar Interchain Token Service integration via precompiles

Because Telcoin-Network uses Telcoin as native gas currency and Telcoin originates from Ethereum mainnet as an ERC20, the Interchain Token Service suite of smart contracts are integrated to Telcoin-Network protocol as system precompiles.

In addition to the ITS core precompiles, Telcoin-Network's interchain TEL contract `InterchainTEL` and its corresponding token manager proxy are also incorporated to the protocol as genesis precompiles. The `InterchainTELTokenManager` alone is allowed to perform mints and can only do so as part of a ITS bridge transaction verified on the source chain, ie Ethereum. This maintains the 1-to-1 integrity of the current canonical TEL token on Ethereum.

To comply with ITS, both InterchainTEL and its accompanying `MINT_BURN` TokenManagerProxy are deployed to the Interchain Token Service's expected `create3` addresses by using the same custom-linked interchain `linkedTokenDeploySalt` and `tokenId` derived by registering Ethereum TEL as a custom-linked interchain token. The plan for enabling `InterchainTEL` to flow from Ethereum at genesis using the precompiles is as follows:

1. Declare TEL on Ethereum as an ITS custom-linked token: `InterchainTokenService::registerTokenMetadata()`
2. Declare TEL on Telcoin Network as a corresponding ITS custom-linked token by pre-signing the corresponding `InterchainTokenService::MESSAGE_TYPE_REGISTER_TOKEN_METADATA` message on TelcoinNetwork using TN verifier keys and feeding them into the TN voting verifier before TN genesis.

- This instructs the Axelar Hub that `InterchainTEL` is ready to be linked even though the network hasn't begun yet, as well as stores the token metadata (ie decimals) in the hub so that it handles decimal conversion across chains.

3. Once registered, perform the TEL link to TN on Ethereum pre-genesis using `InterchainTokenFactory::linkToken()`.

- Normally the resulting `MESSAGE_TYPE_LINK_TOKEN` would be delivered to the TN gateway however that step is only used to deploy the TEL token manager which is already pre-configured and instantiated as a precompile so it can be obviated.

4. Launch Telcoin Network with all required ITS contracts as genesis precompiles, configured with Axelar requirements.

- A genesis system call is the network's first transaction, delivering a queued TEL bridge tx payload to the gateway and executing it which delivers `0x7e1` TEL to a relayer address which then can then use it for gas to begin processing TEL bridged from Ethereum. The TEL amount provided to the relayer must have been burned on the source chain to maintain the fixed TEL total supply.

For more information about InterchainTEL, refer to the [root README](../../README.md).

### Token ID Specifics

##### Native interchain tokens

- do not support pre-existing token contracts
- must be deployed with interchain support from the get go
- deployments share all attributes on all EVM networks, including: same address, `NATIVE_INTERCHAIN` type, and `MINT_BURN` token managers

`interchainTokenId = keccak256(abi.encode(PREFIX_INTERCHAIN_TOKEN_ID, sender, salt));`

##### Canonical interchain tokens

- designate a single pre-existing token as "canonical" on its origin chain
- no wrapping needed
- corresponding interchain deployments on all remote chains other than the original share the same address, `NATIVE_INTERCHAIN` type, and `MINT_BURN` token managers
- not upgradeable

```solidity
interchainTokenDeploySalt = keccak256(abi.encode(PREFIX_CANONICAL_TOKEN_SALT, chainNameHash, tokenAddress));
canonicalTokenId = keccak256(abi.encode(PREFIX_INTERCHAIN_TOKEN_ID, address(0x0), interchainTokenDeploySalt));
```

##### Custom-Linked interchain tokens

- register and link any number of pre-existing tokens
- no wrapping needed
- interchain token ID derived from the first token registered
- linked pre-existing tokens use `LOCK_UNLOCK` token managers, new token deployments on new chains use `MINT_BURN` token managers
- new corresponding interchain deployments on remote chains would undergo the same linking process and should be deployed with create2 to share the same address, specified token + token manager type

```solidity
linkedTokenDeploySalt = keccak256(abi.encode(PREFIX_CUSTOM_TOKEN_SALT, chainNameHash, deployer, salt));
linkedTokenId = keccak256(abi.encode(PREFIX_INTERCHAIN_TOKEN_ID, address(0x0), linkedTokenDeploySalt));`
```

InterchainTEL uses the custom-linked interchain token ID, which is originally derived on Ethereum before TN genesis. The linked token ID can then be used when deploying ITS TEL contracts to new chains.
