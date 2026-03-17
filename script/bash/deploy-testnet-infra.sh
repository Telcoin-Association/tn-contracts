#!/usr/bin/env bash
set -euo pipefail

# Testnet Infrastructure Deployment Script
# Deploys all testnet contracts in the correct order

# Required environment variables in .env:
#   ADMIN_PK    - Private key for the admin/deployer account
source .env

TN_RPC_URL="https://adiri.tel"

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

# Step 0: Deploy Arachnid Deterministic Deploy Factory
echo "[Step 0/6] Deploying Arachnid Deterministic Deploy Factory..."
ARACHNID_DEPLOYER="0x3fab184622dc19b6109349b94811493bf2a45362"
ARACHNID_FACTORY="0x4e59b44847b379578588920ca78fbf26c0b4956c"

# Check if factory already exists
FACTORY_CODE=$(cast code "$ARACHNID_FACTORY" --rpc-url "$TN_RPC_URL" 2>/dev/null || echo "0x")
if [[ "$FACTORY_CODE" != "0x" && "$FACTORY_CODE" != "" ]]; then
    echo "Arachnid factory already deployed at $ARACHNID_FACTORY, skipping..."
else
    echo "Funding Arachnid deployer account..."
    cast send "$ARACHNID_DEPLOYER" --value 0.01ether --rpc-url "$TN_RPC_URL" --private-key "$ADMIN_PK"

    echo "Publishing Arachnid factory deployment transaction..."
    cast publish --rpc-url "$TN_RPC_URL" 0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222

    # Verify deployment
    FACTORY_CODE=$(cast code "$ARACHNID_FACTORY" --rpc-url "$TN_RPC_URL")
    if [[ "$FACTORY_CODE" == "0x" || "$FACTORY_CODE" == "" ]]; then
        echo "Error: Arachnid factory deployment failed"
        exit 1
    fi
    echo "Arachnid factory deployed successfully"
fi
echo ""

# Step 1: Deploy Stablecoin Tokens
echo "[Step 1/6] Deploying Stablecoin Tokens (23 eXYZ tokens)..."
forge script script/testnet/deploy/TestnetDeployTokens.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast
echo "Stablecoin tokens deployed successfully"
echo ""

# Step 2: Deploy StablecoinManager (Faucet)
echo "[Step 2/6] Deploying StablecoinManager..."
forge script script/testnet/deploy/TestnetDeployStablecoinManager.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast
echo "StablecoinManager deployed successfully"
echo ""

# Step 3: Deploy GitAttestationRegistry
echo "[Step 3/6] Deploying GitAttestationRegistry..."
forge script script/testnet/deploy/TestnetDeployGitAttestationRegistry.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast
echo "GitAttestationRegistry deployed successfully"
echo ""

# Step 4: Deploy Uniswap V2
echo "[Step 4/6] Deploying Uniswap V2 (Factory, Router, and 45 pools)..."
forge script script/testnet/deploy/TestnetDeployUniswapV2.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast
echo "Uniswap V2 deployed successfully"
echo ""

# Step 5: Grant Roles to Faucet Addresses
echo "[Step 5/6] Granting roles to faucet addresses..."
forge script script/testnet/TestnetGrantRole.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast
echo "Roles granted successfully"
echo ""

# Step 6: Configure Faucet
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
