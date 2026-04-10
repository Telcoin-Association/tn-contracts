#!/usr/bin/env bash
set -euo pipefail

# Testnet Infrastructure Deployment Script
# Deploys all testnet contracts in the correct order.
# Idempotent: automatically skips steps where contracts are already deployed on-chain.

# Required environment variables in .env:
#   ADMIN_PK    - Private key for the admin/deployer account
source .env

TN_RPC_URL="https://node1.telcoin.network"
DEPLOYMENTS_JSON="deployments/deployments.json"

# Validate dependencies
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed"
    exit 1
fi

if [[ -z "${TN_RPC_URL:-}" ]]; then
    echo "Error: TN_RPC_URL environment variable is not set"
    exit 1
fi

if [[ -z "${ADMIN_PK:-}" ]]; then
    echo "Error: ADMIN_PK environment variable is not set"
    exit 1
fi

# Check if a contract has code deployed on-chain
# Args: $1 = jq path to address in deployments.json (e.g., ".StablecoinImpl")
# Returns: 0 if code exists, 1 if no code
has_code() {
    local jq_path="$1"
    local addr
    addr=$(jq -r "$jq_path" "$DEPLOYMENTS_JSON")

    if [[ -z "$addr" || "$addr" == "null" || "$addr" == "0x0000000000000000000000000000000000000000" ]]; then
        return 1
    fi

    local code
    if ! code=$(cast code "$addr" --rpc-url "$TN_RPC_URL"); then
        echo "Error: failed to query on-chain code for $addr" >&2
        exit 1
    fi

    [[ "$code" != "0x" ]]
}

echo "============================================"
echo "Testnet Infrastructure Deployment"
echo "============================================"
echo ""

# Step 1: Deploy Stablecoin Tokens
if has_code ".StablecoinImpl"; then
    echo "[Step 1/6] Stablecoin Tokens already deployed, skipping..."
else
    echo "[Step 1/6] Deploying Stablecoin Tokens (23 eXYZ tokens)..."
    forge script script/testnet/deploy/TestnetDeployTokens.s.sol \
        --rpc-url "$TN_RPC_URL" \
        -vvvv \
        --private-key "$ADMIN_PK" \
        --broadcast
    echo "Stablecoin tokens deployed successfully"
fi
echo ""

# Step 2: Deploy StablecoinManager (Faucet)
if has_code ".StablecoinManager"; then
    echo "[Step 2/6] StablecoinManager already deployed, skipping..."
else
    echo "[Step 2/6] Deploying StablecoinManager..."
    forge script script/testnet/deploy/TestnetDeployStablecoinManager.s.sol \
        --rpc-url "$TN_RPC_URL" \
        -vvvv \
        --private-key "$ADMIN_PK" \
        --broadcast
    echo "StablecoinManager deployed successfully"
fi
echo ""

# Step 3: Deploy GitAttestationRegistry
if has_code ".GitAttestationRegistry"; then
    echo "[Step 3/6] GitAttestationRegistry already deployed, skipping..."
else
    echo "[Step 3/6] Deploying GitAttestationRegistry..."
    forge script script/testnet/deploy/TestnetDeployGitAttestationRegistry.s.sol \
        --rpc-url "$TN_RPC_URL" \
        -vvvv \
        --private-key "$ADMIN_PK" \
        --broadcast
    echo "GitAttestationRegistry deployed successfully"
fi
echo ""

# Step 4: Deploy Uniswap V2
if has_code ".uniswapV2.UniswapV2Factory"; then
    echo "[Step 4/6] Uniswap V2 already deployed, skipping..."
else
    echo "[Step 4/6] Deploying Uniswap V2 (Factory, Router, and 45 pools)..."
    forge script script/testnet/deploy/TestnetDeployUniswapV2.s.sol \
        --rpc-url "$TN_RPC_URL" \
        -vvvv \
        --private-key "$ADMIN_PK" \
        --broadcast
    echo "Uniswap V2 deployed successfully"
fi
echo ""

# Step 5: Grant Roles to Faucet Addresses (idempotent, always run)
echo "[Step 5/6] Granting roles to faucet addresses..."
forge script script/testnet/TestnetGrantRole.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast
echo "Roles granted successfully"
echo ""

# Step 6: Configure Faucet (idempotent, always run)
echo "[Step 6/6] Configuring faucet (enabling tokens)..."
forge script script/testnet/TestnetManageFaucet.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast
echo "Faucet configured successfully"
echo ""

echo "============================================"
echo "Testnet Infrastructure Deployment Complete"
echo "============================================"
echo ""
echo "Deployed contracts have been saved to deployments/deployments.json"
