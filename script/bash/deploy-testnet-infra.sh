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
    echo "[Step 1/7] Stablecoin Tokens already deployed, skipping..."
else
    echo "[Step 1/7] Deploying Stablecoin Tokens (23 eXYZ tokens)..."
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
    echo "[Step 2/7] StablecoinManager already deployed, skipping..."
else
    echo "[Step 2/7] Deploying StablecoinManager..."
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
    echo "[Step 3/7] GitAttestationRegistry already deployed, skipping..."
else
    echo "[Step 3/7] Deploying GitAttestationRegistry..."
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
    echo "[Step 4/7] Uniswap V2 already deployed, skipping..."
else
    echo "[Step 4/7] Deploying Uniswap V2 (Factory, Router, and 45 pools)..."
    forge script script/testnet/deploy/TestnetDeployUniswapV2.s.sol \
        --rpc-url "$TN_RPC_URL" \
        -vvvv \
        --private-key "$ADMIN_PK" \
        --broadcast
    echo "Uniswap V2 deployed successfully"
fi
echo ""

# BEGIN uniswap-v3-v4 -----------------------------------------------------------
# These two steps are added by feature/uniswap-v3-v4. The block is bracketed
# with BEGIN / END markers so rebase or merge conflicts during the eventual
# merge with the in-flight faucet branch are obvious to resolve. Each step
# defers gracefully (no error, just a console log) when the underlying deploy
# inputs aren't yet present: each step checks every required bytecode file
# under external/uniswap/precompiles/v3/ or v4/ for a populated hex literal,
# and bypasses the deploy if any file is empty.
# See script/testnet/deploy/UNISWAP_V3_V4.md for the design + the bytecode
# refresh recipe.

# Step 5: Deploy Uniswap V3
# All V3 contracts ship as bytecode literals. Gate checks each file has a
# populated hex literal (rather than just file presence, since the README
# also lives in this directory).
if has_code ".uniswapV3.UniswapV3Factory"; then
    echo "[Step 5/7] Uniswap V3 already deployed, skipping..."
elif ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v3/UniswapV3Factory.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v3/NFTDescriptor.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v3/NonfungibleTokenPositionDescriptor.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v3/NonfungiblePositionManager.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v3/SwapRouter02.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v3/QuoterV2.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v3/TickLens.sol; then
    echo "[Step 5/7] Uniswap V3 bytecode unpopulated, deferring..."
    echo "          See script/bash/fetch-uniswap-v3-bytecode.sh to populate."
else
    echo "[Step 5/7] Deploying Uniswap V3 (Factory + periphery, no pools)..."
    forge script script/testnet/deploy/TestnetDeployUniswapV3.s.sol \
        --rpc-url "$TN_RPC_URL" \
        -vvvv \
        --private-key "$ADMIN_PK" \
        --broadcast
    echo "Uniswap V3 deployed successfully"
fi
echo ""

# Step 6: Deploy Uniswap V4
# All V4 contracts ship as bytecode literals (same shape as V2 / V3 / Permit2).
# The gate checks each bytecode file has a populated hex literal.
if has_code ".uniswapV4.PoolManager"; then
    echo "[Step 6/7] Uniswap V4 already deployed, skipping..."
elif ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v4/Permit2Bytecode.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v4/PoolManager.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v4/PositionManager.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v4/PositionDescriptor.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v4/V4Quoter.sol \
   || ! grep -qE 'hex"[0-9a-fA-F]+"' external/uniswap/precompiles/v4/StateView.sol; then
    echo "[Step 6/7] Uniswap V4 bytecode unpopulated, deferring..."
    echo "          See script/bash/fetch-uniswap-v4-bytecode.sh to populate."
else
    echo "[Step 6/7] Deploying Uniswap V4 (Permit2 + PoolManager + periphery)..."
    forge script script/testnet/deploy/TestnetDeployUniswapV4.s.sol \
        --rpc-url "$TN_RPC_URL" \
        -vvvv \
        --private-key "$ADMIN_PK" \
        --broadcast
    echo "Uniswap V4 deployed successfully"
fi
echo ""
# END uniswap-v3-v4 -------------------------------------------------------------

# Step 7: Grant Roles to Faucet Addresses (idempotent, always run)
echo "[Step 7/7] Granting roles to faucet addresses..."
forge script script/testnet/TestnetGrantRole.s.sol \
    --rpc-url "$TN_RPC_URL" \
    -vvvv \
    --private-key "$ADMIN_PK" \
    --broadcast
echo "Roles granted successfully"
echo ""

# NOTE: a previous "Step 6" ran TestnetManageFaucet.s.sol to enable / disable tokens on the
# faucet. Removed because:
#   1. The script calls the old 4-arg `UpdateXYZ` which the current StablecoinManager has
#      tombstoned (`UpdateXYZRequiresBaseDripAmount`).
#   2. Its default config disables every enabled token, which is the opposite of what you want
#      after a fresh deploy where init already enables all 23 stables + native.
# If batch enable/disable is needed in the future, port TestnetManageFaucet.s.sol to the 5-arg
# `UpdateXYZ` signature and re-introduce it as a separately-invoked maintenance script rather
# than a step in the deploy orchestration.

echo "============================================"
echo "Testnet Infrastructure Deployment Complete"
echo "============================================"
echo ""
echo "Deployed contracts have been saved to deployments/deployments.json"
