import { exec } from "child_process";
import {
  axelarConfig,
  getKeystoreAccount,
  GMPMessage,
  keystoreAccount,
  processTargetCLIArgs,
  Proof,
  setAxelarEnv,
  targetConfig,
  transactViaEncryptedKeystore,
} from "../utils.js";
import { promisify } from "util";
import yaml from "js-yaml";
import * as dotenv from "dotenv";
import { Chain } from "viem";
dotenv.config();

/**
 * @dev Can be used via CLI or within the TypeScript runtime when imported by another TypeScript file.
 * @dev Usage example for fetching and settling proofs from a destination chain's multisig prover
 *
 * `npm run approve -- \
 * --target-chain <target_chain> --target-contract <target_contract> \
 * --multisig-session-id <multisig_session_id> --env <env> \`
 */

const execAsync = promisify(exec);

export async function approve({
  destinationChainMultisigProver,
  multisigSessionId,
  amount,
}: GMPMessage) {
  getKeystoreAccount();

  const output = await getProofAsync({
    multisigSessionId,
    destinationChainMultisigProver,
  });
  const parsedOutput = yaml.load(output) as Proof;
  const gmpMessage = parsedOutput.data.status.completed
    .execute_data as `0x${string}`;

  console.log("Submitting gateway approval as EVM transaction with proof data");

  // deliver proof data as GMP message in an EVM transaction
  const targetChain = targetConfig.chain as Chain;
  const targetContract = targetConfig.contract as `0x${string}`;
  await transactViaEncryptedKeystore(
    targetChain,
    targetConfig.rpcUrl!,
    keystoreAccount.account!,
    targetContract,
    amount!,
    `0x${gmpMessage}`,
    keystoreAccount.ksPath!,
    keystoreAccount.ksPw!
  );
}

export async function getProofAsync({
  destinationChainMultisigProver,
  multisigSessionId,
}: GMPMessage): Promise<`0x${string}`> {
  console.log(
    `Retrieving proof for multisig session ID ${multisigSessionId} from prover ${destinationChainMultisigProver}`
  );

  let gmpMessage: string = "";
  try {
    // fetch the proof data from axelar network
    const { stdout } =
      await execAsync(`axelard q wasm contract-state smart ${destinationChainMultisigProver} \
          '{
              "proof":{
                  "multisig_session_id":"${multisigSessionId}"
              }
          }' \
          --node ${axelarConfig.rpcUrl}`);

    console.log(`Proof data retrieved: ${stdout}`);

    gmpMessage = stdout;
  } catch (error: any) {
    console.error(
      `Error fetching proof or submitting transaction: ${error.message}`
    );
  }

  return gmpMessage as `0x${string}`;
}

export async function getProof({
  destinationChainMultisigProver,
  multisigSessionId,
}: GMPMessage): Promise<void> {
  console.log(
    `Retrieving proof for multisig session ID ${multisigSessionId} from prover ${destinationChainMultisigProver}`
  );

  // Construct the axelard command
  const axelardCommand = `axelard q wasm contract-state smart ${destinationChainMultisigProver} \
      '{
          "proof":{
              "multisig_session_id":"${multisigSessionId}"
          }
      }' \
      --node ${axelarConfig.rpcUrl}`;

  exec(axelardCommand, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error executing command: ${error.message}`);
      return;
    }
    if (stderr) {
      console.error(`Error in command output: ${stderr}`);
      return;
    }
    console.log(`Command output: ${stdout}`);
  });
}

// returns values for `getProof()`; only used if invoked via command line
function processApproveCLIArgs(args: string[]): GMPMessage {
  processTargetCLIArgs(args);

  let multisigSessionId: string | undefined;

  args.forEach((arg, index) => {
    const valueIndex = index + 1;
    switch (arg) {
      case "--multisig-session-id":
        multisigSessionId = args[valueIndex];
        break;
      case "--env":
        setAxelarEnv(args[valueIndex], "prover");
        break;
    }
  });

  const destinationChainMultisigProver = axelarConfig.contract;
  if (!multisigSessionId || !destinationChainMultisigProver) {
    throw new Error("Must set --multisig-session-id and --env");
  }

  return {
    multisigSessionId,
    destinationChainMultisigProver,
  };
}

async function main() {
  const args = process.argv.slice(2);
  await approve(processApproveCLIArgs(args));
}

// supports CLI invocation by checking if being run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
