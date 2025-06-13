import {
  getKeystoreAccount,
  GMPMessage,
  keystoreAccount,
  processGmpCLIArgs,
  targetConfig,
  transactViaEncryptedKeystore,
} from "../utils.js";
import {
  Chain,
  createPublicClient,
  encodeFunctionData,
  http,
  parseAbi,
  PublicClient,
} from "viem";
import * as dotenv from "dotenv";
dotenv.config();

/**
 * @dev Can be used via CLI or within the TypeScript runtime when imported by another TypeScript file.
 * @dev Usage example for executing an approved cross chain message to the target destination chain
 * @notice InterchainTokenService should be the target contract and the gateway should be `destinationAddress`
 *
 * `npm run execute -- \
 * --target-chain $DEST --target-contract $ITS --tx-hash $HASH --log-index $LOGINDEX \
 * --source-chain $SRC --source-address $SRC_ADDR --payload $PAYLOAD
 */

export async function execute({
  sourceChain,
  sourceAddress,
  destinationAddress,
  txHash,
  logIndex,
  payload,
}: GMPMessage) {
  console.log("Executing ITS message on target chain");

  getKeystoreAccount();
  const targetChain = targetConfig.chain as Chain;
  const targetContract = targetConfig.contract as `0x${string}`;
  const client = createPublicClient({
    chain: targetChain,
    transport: http(targetConfig.rpcUrl),
  });
  const commandId = await getCommandId(client, {
    destinationAddress,
    txHash,
    logIndex,
  });

  const calldata = encodeFunctionData({
    abi: ["function execute(bytes32 commandId) external"],
    args: [commandId, sourceChain, sourceAddress, payload],
  });
  await transactViaEncryptedKeystore(
    targetChain,
    targetConfig.rpcUrl!,
    keystoreAccount.account!,
    targetContract!,
    0n,
    calldata,
    keystoreAccount.ksPath!,
    keystoreAccount.ksPw!
  );
}

export async function getCommandId(
  client: PublicClient,
  { sourceChain, destinationAddress, txHash, logIndex }: GMPMessage
): Promise<`0x${string}`> {
  const messageId = `${txHash}-${logIndex}`;
  console.log(
    `Retrieving command ID for message ID ${messageId} from ${destinationAddress}`
  );

  const messageToCommandId = parseAbi([
    "function messageToCommandId(string calldata sourceChain, string calldata messageId) external returns (bytes32)",
  ]);
  const commandId = await client.readContract({
    address: destinationAddress,
    abi: messageToCommandId,
    functionName: "messageToCommandId",
    args: [sourceChain, messageId],
    code: "0x",
  });

  return commandId as `0x${string}`;
}

async function main() {
  const args = process.argv.slice(2);
  await execute(processGmpCLIArgs(args));
}

// supports CLI invocation by checking if being run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
