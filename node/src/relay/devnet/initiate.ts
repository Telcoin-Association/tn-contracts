import {
  createWalletClient,
  http,
  WalletClient,
  Address,
  publicActions,
  encodeFunctionData,
  parseAbi,
} from "viem";
import * as dotenv from "dotenv";
import {
  GMPMessage,
  processTargetCLIArgs,
  targetConfig,
  validateEnvVar,
} from "../utils.js";
import { privateKeyToAccount } from "viem/accounts";

dotenv.config();
const privateKey: Address = validateEnvVar("PK") as `0x${string}`;

/**
 * @dev This function can be used via CLI or within the TypeScript runtime when imported by another TypeScript file.
 * CLI Usage example for initiating GMP message flow on a target AxelarAmplifierGateway:
 *
 * `npm run initiate -- \
 *    --target-chain <target_chain> --target-contract <target_contract>`
 *    --amount <amount> --destination-chain <destination_chain>
 *    --destination-contract <destination-address> --payload <payload>
 */

async function initiate({
  amount,
  destinationChain,
  destinationAddress,
  payload,
}: GMPMessage): Promise<void> {
  console.log("Initiating interchain GMP message");

  const args = process.argv.slice(2);
  processInitiateCLIArgs(args);

  console.log(
    `Sending GMP message from ${
      targetConfig.chain!.name
    } to ${destinationChain}`
  );

  const account = privateKeyToAccount(privateKey!);
  const walletClient = createWalletClient({
    account,
    chain: targetConfig.chain,
    transport: http(targetConfig.rpcUrl),
  });

  try {
    const callContract = parseAbi([
      "function callContract(string calldata destinationChain, string calldata destinationContractAddress,bytes calldata payload) external",
    ]);
    const calldata = encodeFunctionData({
      abi: callContract,
      functionName: "callContract",
      args: [destinationChain!, destinationAddress!, payload!],
    });
    const txHash = await walletClient.sendTransaction({
      account: account,
      chain: targetConfig.chain,
      to: targetConfig.contract,
      value: amount,
      data: calldata,
    });

    console.log("Transaction sent: ", txHash);

    const receipt = await walletClient
      .extend(publicActions)
      .waitForTransactionReceipt({ hash: txHash });
    console.log("Transaction confirmed: ", receipt.transactionHash);
  } catch (err) {
    console.error("Error sending transaction: ", err);
  }
}

function processInitiateCLIArgs(args: string[]) {
  processTargetCLIArgs(args);

  let amount: bigint = 0n;
  let destinationChain: `0x${string}` | undefined;
  let destinationAddress: `0x${string}` | undefined;
  let payload: `0x${string}` | undefined;

  args.forEach((arg, index) => {
    const valueIndex = index + 1;
    switch (arg) {
      case "--amount":
        amount = BigInt(args[valueIndex]);
        break;
      case "--destination-chain":
        destinationChain = args[valueIndex] as `0x${string}`;
        break;
      case "--destination-contract":
        destinationAddress = args[valueIndex] as `0x${string}`;
        break;
      case "--payload":
        payload = args[valueIndex] as `0x${string}`;
        break;
    }
  });

  if (!destinationChain || !destinationAddress || !payload) {
    throw new Error(
      "Must set --destination-chain, --destination-contract, and --payload"
    );
  }

  return { amount, destinationChain, destinationAddress, payload };
}

function main() {
  const args = process.argv.slice(2);
  initiate(processInitiateCLIArgs(args));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
