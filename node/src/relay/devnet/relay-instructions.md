## Step by Step Relaying

### Setup

From the telcoin-network root directory, start a local testnet (change chain-id to 0x7e1 to match Viem's `telcoinTestnet` record), eg:

`./etc/local-testnet.sh --start --dev-funds 0xc1612C97537c2CC62a11FC4516367AB6F62d4B23`

Initiate tofnd and ampd processes so that the verifier key is ready for signing and starts watching the localhost testnet node rpc (port 8545):

`tofnd && ampd`

Once the local testnet is running set the GMP message's config in memory:

```bash
export SRC="telcoin"
export SRC_ADDR=0xc1612C97537c2CC62a11FC4516367AB6F62d4B23 # msg.sender of IAxelarGateway::CallContract
export SRC_GATEWAY=0xF128c84c3326727c3e155168daAa4C0156B87AD1 # TN devnet gateway
export DEST="eth-sepolia"
export DEST_ADDR=0xF128c84c3326727c3e155168daAa4C0156B87AD1 # Sepolia devnet gateway
export PAYLOAD=0x68656c6c6f20776f726c64 # "hello world"
```

### Initiation

Then, from the tn-contracts root directory, initiate a GMP message on the external source gateway, eg:

```bash
npm run initiate -- --target-chain $SRC --target-contract $SRC_GATEWAY --amount 0 --destination-chain $DEST --destination-contract $DEST_ADDR --payload $PAYLOAD
```

**ITS**
For ITS transfers, first use the link token and interchain transfer scripts:

```bash
forge script script/LinkToken.s.sol -vvvv
forge script script/InterchainTransfer.s.sol -vvvv
```

### Message-ID parameters

After the transaction(s) confirm, write the tx hash and log index to memory:

```bash
export HASH=0xe13d7c9621c777a638a677e1a702c88e249b8e6d9af83e0a6cc1f7fa91e70d98
export LOGINDEX=0
export ENV="devnet"
```

This values will be used when submitting a `verify_messages` transaction, upon which the tofnd & ampd processes will examine using the RPC configured in `~/.ampd/config.toml`.

### Verification

If deemed valid, the ampd verifier will submit a `batch` transaction which confirms the message validity.

```bash
npm run verify -- --env $ENV --source-chain $SRC --source-address $SRC_ADDR --destination-chain $DEST --destination-address $DEST_ADDR --tx-hash $HASH --log-index $LOGINDEX --payload $PAYLOAD
```

### Routing

Once the above actions have settled, progress the GMP message to the next step by routing it to the destination chain's prover contract:

```bash
npm run route -- --env $ENV --source-chain $SRC --source-address $SRC_ADDR --destination-chain $DEST --destination-address $DEST_ADDR --payload $PAYLOAD --tx-hash $HASH --log-index $LOGINDEX
```

### Proof Construction

Next, the destination chain's multisig prover must be instructed to construct a proof for the verified & routed GMP message. This proof is what the relayer will deliver to the destination chain.

```bash
npm run construct-proof -- --env $ENV --source-chain $SRC --tx-hash $HASH --log-index $LOGINDEX
```

Grab the `multisig_session_id` from the utility's output for use in the next step.

### Approval

Once the proof has been constructed and the destination chain's verifiers have voted on it, the proof can be fetched and settled to the destination chain in an approval tx to complete the GMP flow:

```bash
export SESSIONID=20181
npm run approve -- --env $ENV --target-chain $DEST --target-contract $DEST_ADDR --multisig-session-id $SESSIONID
```

### Execution

If the GMP message is an ITS message, it can be executed once approved:

```bash
export ITS=0x2269B93c8D8D4AfcE9786d2940F5Fcd4386Db7ff
npm run execute -- --target-chain $DEST --target-address $ITS --tx-hash $HASH --log-index $LOGINDEX --source-chain $SRC --source-address $SRC_ADDR --payload $PAYLOAD
```
