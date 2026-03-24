#!/usr/bin/env bash
set -euo pipefail

# Testnet Infrastructure Deployment Script
# Deploys all testnet contracts in the correct order

# Required environment variables in .env:
#   ADMIN_PK    - Private key for the admin/deployer account
source .env

TN_RPC_URL="https://node4.telcoin.network"

if [[ -z "${TN_RPC_URL:-}" ]]; then
    echo "Error: TN_RPC_URL environment variable is not set"
    exit 1
fi

if [[ -z "${ADMIN_PK:-}" ]]; then
    echo "Error: ADMIN_PK environment variable is not set"
    exit 1
fi

echo "============================================"
echo "Testnet Infrastructure Deployment"
echo "============================================"
echo ""

# Step 0: Deploy Stablecoin Tokens
echo "[Step 1/6] Deploying Stablecoin Tokens (23 eXYZ tokens)..."
forge script script/testnet/deploy/TestnetDeployTokens.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast \
    --resume
echo "Stablecoin tokens deployed successfully"
echo ""

# Step 1: Deploy StablecoinManager (Faucet)
echo "[Step 2/6] Deploying StablecoinManager..."
forge script script/testnet/deploy/TestnetDeployStablecoinManager.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast \
    --resume
echo "StablecoinManager deployed successfully"
echo ""

# Step 2: Deploy GitAttestationRegistry
echo "[Step 3/6] Deploying GitAttestationRegistry..."
forge script script/testnet/deploy/TestnetDeployGitAttestationRegistry.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast \
    --resume
echo "GitAttestationRegistry deployed successfully"
echo ""

# Step 3: Deploy Uniswap V2
echo "[Step 4/6] Deploying Uniswap V2 (Factory, Router, and 45 pools)..."
forge script script/testnet/deploy/TestnetDeployUniswapV2.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast \
    --resume
echo "Uniswap V2 deployed successfully"
echo ""

# Step 4: Grant Roles to Faucet Addresses
echo "[Step 5/6] Granting roles to faucet addresses..."
forge script script/testnet/TestnetGrantRole.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast \
    --resume
echo "Roles granted successfully"
echo ""

# Step 5: Configure Faucet
echo "[Step 6/6] Configuring faucet (enabling tokens)..."
forge script script/testnet/TestnetManageFaucet.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast \
    --resume
echo "Faucet configured successfully"
echo ""

echo "============================================"
echo "Testnet Infrastructure Deployment Complete"
echo "============================================"
echo ""
echo "Deployed contracts have been saved to deployments/deployments.json"
