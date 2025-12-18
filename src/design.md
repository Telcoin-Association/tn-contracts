# InterchainTEL Design

## Background

- **Native Currency and ERC20**: Telcoin Network uses TEL as its native gas currency, originating from Ethereum's ERC20 TEL. A robust solution for interchain conversion is essential to facilitate seamless integration.
- **Axelar ITS Integration**: The Interchain Token Service (ITS) is integrated as system precompiles, enabling efficient interchain token transfers.

The contract-layer ITS protocol requires TN to designate an ERC20 contract which inherits InterchainTokenStandard and assign it an interchain token ID. This is the InterchainTEL contract which enables both the Ethereum ERC20 TEL contract and the Telcoin native gas currency with interchain access.

A general overview of ITS system design can be found [in this design md](src/its-design.md) and in Axelar's documentation.

### InterchainTEL Contract

- **Custom-Linked Token**: InterchainTEL is a custom-linked interchain token registered under Ethereum TEL's interchain ID. It inherits the `InterchainTokenStandard` and will be deployed to the ITS expected create3 address to ensure compliance with ITS requirements.
- **Token Manager**: Utilizes a `MINT_BURN` `TokenManagerProxy` to manage mint and burn operations for inbound and outbound TEL transfers.

## Interchain Bridging

- **Minting and Burning**: Native TEL is minted via the `mint()` function when TEL is locked on a remote chain, and outbound TEL is exported using the `burn()` function.
- **Double-Wrapping for Security**: Outbound TEL must be double-wrapped to iTEL, ensuring that only settled `iTEL` token balances are eligible for bridging. The wrapping can be done through wTEL or directly from native TEL.

## Native TEL at Genesis

- **Supply Allocation**: At network genesis, an amount equivalent to TEL's total supply (minus validator stakes) is allocated to the InterchainTEL module. The contract's private key is inaccessible, making the supply effectively "burned". The only way to mint native TEL on Telcoin-Network is by locking/burning TEL on a remote chain which passes a valid bridge message through ITS.

## Custom-Linked ITS Token IDs

- **Flexibility and Interoperability**: Custom-linked token IDs allow for seamless linking of pre-existing tokens across chains. This involves translating ERC20 metadata such as name, symbol, and decimals to facilitate interoperability across different blockchain environments.

InterchainTEL uses the custom-linked interchain token ID, which is originally derived on Ethereum before TN genesis. The linked token ID can then be used when deploying ITS TEL contracts to new chains.

## Telcoin <> Axelar ITS Integration via Precompiles

### Integration Steps

To comply with ITS, both InterchainTEL and its accompanying `MINT_BURN` TokenManagerProxy are deployed to the Interchain Token Service's expected `create3` addresses by using the same custom-linked interchain `linkedTokenDeploySalt` and `tokenId` derived by registering Ethereum TEL as a custom interchain token.

1. **Declare TEL as a Custom-Linked Token**: On Ethereum, use `InterchainTokenService::registerTokenMetadata()` to declare TEL as a custom-linked token.
2. **Pre-Register on Telcoin Network**: Before TN genesis, pre-sign the corresponding `MESSAGE_TYPE_REGISTER_TOKEN_METADATA` message on Telcoin Network using TN verifier keys. This message can then be fed to the Axelar network VotingVerifier CosmWasm contract.
   - This action instructs the Axelar Hub that InterchainTEL is ready for linking even before network genesis and stores token metadata in the hub for cross-chain decimal conversion.
3. **Link TEL Pre-Genesis**: Use `InterchainTokenFactory::linkToken()` to link TEL to TN on Ethereum before genesis.
   - Normally, this would involve delivering a `MESSAGE_TYPE_LINK_TOKEN` to the TN gateway, but this step is bypassed since the TEL token manager is pre-configured as a precompile.
4. **Launch Telcoin Network**: Deploy all required ITS contracts as genesis precompiles, configured according to Axelar's requirements.
   - Initiate a genesis system call to deliver a queued TEL bridge transaction payload, enabling the relayer to use TEL for gas and process TEL bridged from Ethereum.

![Interchain Token Service & InterchainTEL](https://i.imgur.com/pymULlU.png)
