import { exec } from "child_process";
import {
  getKeystoreAccount,
  GMPMessage,
  keystoreAccount,
  processTargetCLIArgs,
  targetConfig,
  transactViaEncryptedKeystore,
} from "../utils.js";
import { promisify } from "util";

/**
 * @dev Can be used via CLI or within the TypeScript runtime when imported by another TypeScript file.
 * @dev Usage example for fetching and settling proofs from a destination chain's multisig prover
 *
 * `npm run get-proof -- \
 *    --multisig-session-id <multisig_session_id>`
 */

// when migrating beyond devnet these can be initialized via CLI flag
let rpc: string = "http://devnet-amplifier.axelar.dev:26657";

const execAsync = promisify(exec);

export async function approve({
  destinationChainMultisigProver,
  multisigSessionId,
  amount,
}: GMPMessage) {
  getKeystoreAccount();

  const gmpMessage = await getProofAsync({
    multisigSessionId,
    destinationChainMultisigProver,
  });
  // deliver proof data as GMP message in an EVM transaction
  await transactViaEncryptedKeystore(
    targetConfig.chain!,
    targetConfig.rpcUrl!,
    keystoreAccount.account!,
    targetConfig.contract!,
    amount!,
    gmpMessage,
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
              "get_proof":{
                  "multisig_session_id":"${multisigSessionId}"
              }
          }' \
          --node ${rpc}`);

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
          "get_proof":{
              "multisig_session_id":"${multisigSessionId}"
          }
      }' \
      --node ${rpc}`;

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
  let destinationChainMultisigProver: string | undefined;

  args.forEach((arg, index) => {
    const valueIndex = index + 1;
    switch (arg) {
      case "--multisig-session-id":
        multisigSessionId = args[valueIndex];
        break;
      case "--destination-chain-multisig-prover":
        destinationChainMultisigProver = args[valueIndex];
        break;
    }
  });

  if (!multisigSessionId || !destinationChainMultisigProver) {
    throw new Error(
      "Must set --multisig-session-id and --destination-chain-multisig-prover"
    );
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
if (require.main === module) {
  await main();
}
