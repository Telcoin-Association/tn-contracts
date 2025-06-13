import { execSync, spawn } from "child_process";
import { readFileSync } from "fs";
import {
  Address,
  createWalletClient,
  getAddress,
  http,
  keccak256,
  parseSignature,
  publicActions,
  serializeTransaction,
  TransactionRequest,
  TransactionSerializable,
} from "viem";
import { mainnet, sepolia, telcoinTestnet, Chain } from "viem/chains";
import * as https from "https";

/// Utils suited for single-chain components, supports Cosmos IBC
export interface TargetConfig {
  chain?: Chain;
  contract?: Address;
  rpcUrl?: string;
}

export const targetConfig: TargetConfig = {};

export interface AxelarConfig {
  chain?: string;
  contract?: string;
  rpcUrl?: string;
  walletName?: string;
}

export const axelarConfig: AxelarConfig = {};

export function processTargetCLIArgs(args: string[]) {
  args.forEach((arg, index) => {
    const valueIndex = index + 1;

    // Parse chain and set RPC URL
    if (arg === "--target-chain" && args[valueIndex]) {
      switch (args[valueIndex]) {
        case "eth-sepolia": // devnet
          targetConfig.chain = sepolia;
          setRpcUrl("SEPOLIA_RPC_URL");
          break;
        case "ethereum-sepolia": // testnet
          targetConfig.chain = sepolia;
          setRpcUrl("SEPOLIA_RPC_URL");
          break;
        case "ethereum":
          targetConfig.chain = mainnet;
          setRpcUrl("MAINNET_RPC_URL");
          break;
        case "telcoin": // devnet
          targetConfig.chain = telcoinTestnet;
          setRpcUrl("LOCAL_RPC_URL");
          break;
        case "telcoin-network":
          targetConfig.chain = telcoinTestnet;
          setRpcUrl("TN_RPC_URL");
          break;
      }
    }

    // Parse target contract
    if (arg === "--target-contract" && args[valueIndex]) {
      // if EVM address, validate and checksum it
      if (args[valueIndex].startsWith("0x")) {
        targetConfig.contract = getAddress(args[valueIndex]);
      } else {
        throw new Error(`Invalid target contract address: ${args[valueIndex]}`);
      }
    }
  });

  if (!targetConfig.chain || !targetConfig.contract) {
    throw new Error(`Must set --target-chain and --target-contract`);
  }
}

export function processGmpCLIArgs(
  args: string[],
  axelarTarget?: string
): GMPMessage {
  let sourceChain: string | undefined;
  let sourceAddress: `0x${string}` | undefined;
  let destinationChain: string | undefined;
  let destinationAddress: `0x${string}` | undefined;
  let payload: `0x${string}` | undefined;
  let txHash: `0x${string}` | undefined;
  let logIndex: number | undefined;

  args.forEach((arg, index) => {
    const valueIndex = index + 1;
    switch (arg) {
      case "--source-chain":
        sourceChain = args[valueIndex];
        break;
      case "--source-address":
        sourceAddress = args[valueIndex] as `0x${string}`;
        break;
      case "--destination-chain":
        destinationChain = args[valueIndex];
        break;
      case "--destination-address":
        destinationAddress = args[valueIndex] as `0x${string}`;
        break;
      case "--payload":
        payload = args[valueIndex] as `0x${string}`;
        break;
      case "--tx-hash":
        txHash = args[valueIndex] as `0x${string}`;
        break;
      case "--log-index":
        logIndex = parseInt(args[valueIndex], 10);
        break;
      case "--env":
        setAxelarEnv(args[valueIndex], axelarTarget!);
        break;
    }
  });

  if (
    !axelarConfig.rpcUrl ||
    !sourceChain ||
    !sourceAddress ||
    !destinationChain ||
    !destinationAddress ||
    !payload ||
    !txHash ||
    logIndex === undefined
  ) {
    throw new Error(
      "Must set --source-chain, --source-address, --destination-chain, --destination-address, --payload, --tx-hash, and --log-index"
    );
  }

  return {
    txHash,
    logIndex,
    sourceChain,
    sourceAddress,
    destinationChain,
    destinationAddress,
    payload,
  };
}

/// GMP utils

export interface Proof {
  data: {
    status: {
      completed: {
        execute_data: string;
      };
    };
  };
}

export interface GMPMessage {
  txHash?: `0x${string}`;
  logIndex?: number;
  sourceChain?: string;
  sourceAddress?: `0x${string}`;
  destinationChain?: string;
  destinationAddress?: `0x${string}`;
  amount?: bigint;
  payload?: `0x${string}`;
  destinationChainMultisigProver?: string;
  multisigSessionId?: string;
}

export interface GMPEnv {
  crtPath?: string;
  keyPath?: string;
  gmpApiUrl?: string;
}
export const gmpEnv: GMPEnv = {};

export function getGMPEnv() {
  const crtPath = process.env.CRT_PATH;
  const keyPath = process.env.KEY_PATH;
  const gmpApiUrl = process.env.GMP_API_URL;

  if (!crtPath || !keyPath || !gmpApiUrl) {
    throw new Error("Set all required ENV vars in .env");
  }

  gmpEnv.crtPath = crtPath;
  gmpEnv.keyPath = keyPath;
  gmpEnv.gmpApiUrl = gmpApiUrl;
}

export function createHttpsAgent(
  crtPath: string,
  keyPath: string
): https.Agent {
  const cert = readFileSync(crtPath);
  const key = readFileSync(keyPath);
  return new https.Agent({ cert, key });
}

export async function axelardTxExecute(
  targetWasmContract: string,
  jsonPayload: string,
  rpc: string,
  axelarWallet: string,
  axelarChainId: string
): Promise<void> {
  const axelardArgs = [
    "tx",
    "wasm",
    "execute",
    targetWasmContract,
    jsonPayload,
    "--from",
    axelarWallet,
    "--keyring-backend",
    "file",
    "--node",
    rpc,
    "--chain-id",
    axelarChainId,
    "--gas-prices",
    "0.00005uamplifier",
    "--gas",
    "auto",
    "--gas-adjustment",
    "1.5",
  ];
  console.log(`Running bash: \naxelard ${axelardArgs.join(" \\\n  ")}`);

  const axelardProcess = spawn("axelard", axelardArgs);

  if (process.env.PASSPHRASE) {
    axelardProcess.stdin.write(`${process.env.PASSPHRASE}\n`);
  } else {
    console.error("Must set PASSPHRASE in .env");
    axelardProcess.kill();
    return;
  }

  let stdoutData = "";

  axelardProcess.stdout.on("data", (chunk) => {
    stdoutData += chunk.toString();
  });

  axelardProcess.stdout.on("end", () => {
    // extract tx hash from the output
    const output = JSON.parse(stdoutData.toString());
    const { txhash, raw_log } = output;
    console.log(`Transaction hash: ${txhash}\n`);

    try {
      // if "multisig_session_id" is in the raw log, log it
      if (raw_log) {
        const rawLogObject = JSON.parse(raw_log);
        rawLogObject.forEach((logEntry: any) => {
          logEntry.events.forEach((event: any) => {
            event.attributes.forEach((attribute: any) => {
              if (attribute.key === "multisig_session_id") {
                console.log(`Multisig Session ID: ${attribute.value}`);
              }
            });
          });
        });
      }
    } catch (error) {
      console.error("Error parsing output, check explorer for details:", error);
    }
  });

  axelardProcess.stderr.on("data", (stdErr) => {
    console.error(`StdErr: ${stdErr}`);
  });

  axelardProcess.on("close", (code) => {
    console.log(`Process exited with code ${code}`);
  });
}

/// TX utils
export interface KeystoreAccount {
  account?: Address;
  ksPath?: string;
  ksPw?: string;
}
export const keystoreAccount: KeystoreAccount = {};

export function getKeystoreAccount() {
  const accountStr = process.env.RELAYER;
  const account = accountStr ? getAddress(accountStr) : undefined;
  const ksPath = process.env.KEYSTORE_PATH;
  const ksPw = process.env.KS_PW;

  if (!ksPath || !ksPw || !account) {
    throw new Error("Set all required ENV vars in .env");
  }

  keystoreAccount.account = account;
  keystoreAccount.ksPath = ksPath;
  keystoreAccount.ksPw = ksPw;
}

/// @dev Viem does not support signing via encrypted keystore so
/// a context switch dipping into Foundry is required
export async function signViaEncryptedKeystore(
  txRequest: TransactionRequest,
  chainId: number,
  ksPath: string,
  ksPw: string
) {
  // convert tx to serializable format
  const txSerializable: TransactionSerializable = {
    chainId: chainId,
    gas: txRequest.gas,
    maxFeePerGas: txRequest.maxFeePerGas,
    maxPriorityFeePerGas: txRequest.maxPriorityFeePerGas,
    nonce: txRequest.nonce,
    to: txRequest.to,
    data: txRequest.data,
  };
  const serializedTx = serializeTransaction(txSerializable);

  // pre-derive tx hash to be securely signed before submission
  const txHash = keccak256(serializedTx);
  const command = `cast wallet sign ${txHash} --keystore ${ksPath} --password ${ksPw} --no-hash`;
  try {
    const stdout = execSync(command, { encoding: "utf8" });
    console.log(`stdout: ${stdout}`);

    const signature = stdout.trim() as `0x${string}`;
    // attach signature and re-serialize tx
    const parsedSignature = parseSignature(signature);
    txSerializable.r = parsedSignature.r;
    txSerializable.s = parsedSignature.s;
    txSerializable.v = parsedSignature.v;

    return txSerializable;
  } catch (err) {
    console.error(`Error signing tx: ${err}`);
    throw err;
  }
}

export async function transactViaEncryptedKeystore(
  chain: Chain,
  rpcUrl: string,
  from: Address,
  to: Address,
  value: bigint,
  data: `0x${string}`,
  ksPath: string,
  ksPw: string
): Promise<void> {
  // fetch tx params (gas, nonce, etc)
  const walletClient = createWalletClient({
    account: from,
    transport: http(rpcUrl),
    chain: chain,
  }).extend(publicActions);
  try {
    const txRequest = await walletClient.prepareTransactionRequest({
      to: to,
      data: data,
      value: value,
    });
    // sign tx using encrypted keystore
    const txSerializable = await signViaEncryptedKeystore(
      txRequest,
      chain.id,
      ksPath!,
      ksPw!
    );

    // send raw signed tx
    const rawTx = serializeTransaction(txSerializable);
    const txHash = await walletClient.sendRawTransaction({
      serializedTransaction: rawTx,
    });

    const receipt = await walletClient.waitForTransactionReceipt({
      hash: txHash,
    });
    console.log("Transaction receipt: ", receipt);
  } catch (err) {
    console.error("Error sending transaction: ", err);
  }
}

export function setRpcUrl(envVarName: string) {
  const rpcUrl = process.env[envVarName];
  if (!rpcUrl) throw new Error("RPC URL not found");
  targetConfig.rpcUrl = rpcUrl;
}

export function validateEnvVar(envVarName: string): string {
  const envVar = process.env[envVarName];
  if (!envVar) throw new Error(`Failed to set env variable: ${envVarName}`);

  return envVar;
}

/// misc axelar env helpers
export function setAxelarEnv(env: string, targetIdentifier: string) {
  switch (env) {
    case "devnet":
      axelarConfig.chain = "devnet-amplifier";
      axelarConfig.rpcUrl = validateEnvVar("AXELAR_DEVNET_RPC_URL");
      axelarConfig.walletName = axelarDevnetWallet;
      setAxelarTarget(targetIdentifier);
      break;
    case "testnet":
      axelarConfig.chain = "axelar-testnet";
      axelarConfig.rpcUrl = validateEnvVar("AXELAR_TESTNET_RPC_URL");
      axelarConfig.walletName = axelarTestnetWallet;
      setAxelarTarget(targetIdentifier);
      break;
    case "mainnet":
      axelarConfig.chain = "axelar-network";
      axelarConfig.rpcUrl = validateEnvVar("AXELAR_NETWORK_RPC_URL");
      axelarConfig.walletName = axelarMainnetWallet;
      setAxelarTarget(targetIdentifier);
      break;
    default:
      throw new Error(`Unknown Axelar environment: ${env}`);
  }
}

export function setAxelarTarget(targetIdentifier: string) {
  switch (targetIdentifier) {
    case "gateway":
      axelarConfig.contract = axelarDevnetInternalGateway;
      break;
    case "prover":
      axelarConfig.contract = axelarDevnetMultisigProver;
      break;
  }

  if (!targetIdentifier) {
    throw new Error("Target axelar contract identifier is required");
  }
}

export const axelarDevnetWallet: string = "axelard-test-wallet";
export const axelarDevnetChainId: string = "devnet-amplifier";
export const axelarDevnetInternalGateway: string =
  "axelar1r2s8ye304vtyhfgajljdjj6pcpeya7jwdn9tgw8wful83uy2stnqk4x7ya";
export const axelarDevnetMultisigProver: string =
  "axelar15ra7d5uvnmc6ety6sqxsvsfz4t34ud6lc5gmt39res0c5thkqp2qdwj4af";
export const axelarTestnetWallet: string = "axelard-test-wallet";
export const axelarTestnetChainId: string = "axelar-testnet";
export const axelarTestnetInternalGateway: string = "";
export const axelarTestnetMultisigProver: string = "";
export const axelarMainnetWallet: string = "axelard-wallet";
export const axelarMainnetChainId: string = "axelar-network";
export const axelarMainnetInternalGateway: string = "";
export const axelarMainnetMultisigProver: string = "";
