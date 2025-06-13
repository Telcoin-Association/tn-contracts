import {
  axelarConfig,
  axelardTxExecute,
  GMPMessage,
  setAxelarEnv,
} from "../utils.js";
import * as dotenv from "dotenv";
dotenv.config();

/**
 * @dev Can be used via CLI or within the TypeScript runtime when imported by another TypeScript file.
 * @dev Usage example for constructing proofs on a destination chain's multisig prover:
 *
 * `npm run construct-proof -- \
 *    --env <env> --source-chain <source_chain> --tx-hash <tx_hash> --log-index <log_index>
 *    --destination-chain-multisig-prover <destination_chain_multisig_prover>`
 */

// when migrating beyond devnet these can be initialized via CLI flag
let rpc: string = "http://devnet-amplifier.axelar.dev:26657";
let axelarWallet: string = "axelard-test-wallet";
let axelarChainId: string = "devnet-amplifier";

export async function constructProof({
  txHash,
  logIndex,
  sourceChain,
  destinationChainMultisigProver,
}: GMPMessage): Promise<void> {
  console.log(
    `Instructing destination chain's multisig prover ${destinationChainMultisigProver} to construct GMP message proof`
  );

  const jsonPayload = JSON.stringify({
    construct_proof: [
      {
        source_chain: `${sourceChain}`,
        message_id: `${txHash}-${logIndex}`,
      },
    ],
  });

  await axelardTxExecute(
    destinationChainMultisigProver!,
    jsonPayload,
    rpc,
    axelarWallet,
    axelarChainId
  );
}

// returns values for `constructProof()`; only used if invoked via command line
function processConstructProofCLIArgs(args: string[]) {
  let sourceChain: string | undefined;
  let txHash: `0x${string}` | undefined;
  let logIndex: number | undefined;

  args.forEach((arg, index) => {
    const valueIndex = index + 1;
    switch (arg) {
      case "--source-chain":
        sourceChain = args[valueIndex];
        break;
      case "--tx-hash":
        txHash = args[valueIndex] as `0x${string}`;
        break;
      case "--log-index":
        logIndex = parseInt(args[valueIndex], 10);
        break;
      case "--env":
        setAxelarEnv(args[valueIndex], "prover");
        break;
    }
  });

  const destinationChainMultisigProver = axelarConfig.contract;
  if (
    !sourceChain ||
    !txHash ||
    logIndex === undefined ||
    !destinationChainMultisigProver
  ) {
    throw new Error("Must set --source-chain, --tx-hash, --log-index --env");
  }

  return {
    txHash,
    logIndex,
    sourceChain,
    destinationChainMultisigProver,
  };
}

function main() {
  const args = process.argv.slice(2);
  constructProof(processConstructProofCLIArgs(args));
}

// supports CLI invocation by checking if being run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
