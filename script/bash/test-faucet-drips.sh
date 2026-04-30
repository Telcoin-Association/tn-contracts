#!/usr/bin/env bash
set -euo pipefail

# Faucet drip test suite for the freshly-deployed StablecoinManager.
# Exercises native drips, stablecoin drips, dripTo (third-party-funded),
# cooldown enforcement, amount-cap enforcement, and per-recipient overrides.
#
# Prereqs:
#   .env contains ADMIN_PK (maintainer key, deployer of the new manager)
#   jq + cast on PATH

source .env
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

RPC="https://node1.telcoin.network"
DEPLOYMENTS="deployments/deployments.json"

MGR=$(jq -r '.StablecoinManager' "$DEPLOYMENTS")
EUSD=$(jq -r '.eXYZs.eUSD' "$DEPLOYMENTS")
EAUD=$(jq -r '.eXYZs.eAUD' "$DEPLOYMENTS")
NATIVE=0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE
SENDER=$(cast wallet address --private-key "$ADMIN_PK")

# Throwaway recipients (one per scenario so per-recipient cooldowns don't collide)
R_NATIVE=0x000000000000000000000000000000000000bEE1
R_EUSD=0x000000000000000000000000000000000000bEE2
R_DRIPTO=0x000000000000000000000000000000000000bEE3
R_COOLDOWN=0x000000000000000000000000000000000000bEE4
R_CAP=0x000000000000000000000000000000000000bEE5
R_OVERRIDE=0x000000000000000000000000000000000000bEE6

banner() { echo; echo "=============================="; echo "$1"; echo "=============================="; }
expect_revert() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "FAIL: $label -- expected revert, got success"
        exit 1
    else
        echo "OK:   $label reverted as expected"
    fi
}

banner "Setup info"
echo "Manager:    $MGR"
echo "eUSD:       $EUSD"
echo "eAUD:       $EAUD"
echo "Sender:     $SENDER"
echo "Sender bal: $(cast from-wei "$(cast balance "$SENDER" --rpc-url "$RPC")") TEL"

banner "Test 1 - native drip to a fresh wallet"
# anyone can call drip(); recipient is msg.sender, which is the sender of the cast send
# Use dripTo so we can target $R_NATIVE without sending the tx from there
echo "before: recipient $R_NATIVE balance = $(cast from-wei "$(cast balance "$R_NATIVE" --rpc-url "$RPC")") TEL"
cast send "$MGR" "dripTo(address,address,uint256)" "$R_NATIVE" "$NATIVE" 1000000000000000000 \
    --rpc-url "$RPC" --private-key "$ADMIN_PK" >/dev/null
echo "after:  recipient $R_NATIVE balance = $(cast from-wei "$(cast balance "$R_NATIVE" --rpc-url "$RPC")") TEL"
echo "Expected: ~1.0 TEL gained (1e18 wei)"

banner "Test 2 - stablecoin drip (eUSD) to a fresh wallet"
echo "before: recipient $R_EUSD eUSD balance = $(cast call "$EUSD" "balanceOf(address)(uint256)" "$R_EUSD" --rpc-url "$RPC")"
cast send "$MGR" "dripTo(address,address,uint256)" "$R_EUSD" "$EUSD" 100000000 \
    --rpc-url "$RPC" --private-key "$ADMIN_PK" >/dev/null
echo "after:  recipient $R_EUSD eUSD balance = $(cast call "$EUSD" "balanceOf(address)(uint256)" "$R_EUSD" --rpc-url "$RPC")"
echo "Expected: 100000000 (= 100.0 eUSD at 6 decimals)"

banner "Test 3 - dripTo: third party funds a different recipient"
echo "before: recipient $R_DRIPTO eAUD balance = $(cast call "$EAUD" "balanceOf(address)(uint256)" "$R_DRIPTO" --rpc-url "$RPC")"
cast send "$MGR" "dripTo(address,address,uint256)" "$R_DRIPTO" "$EAUD" 100000000 \
    --rpc-url "$RPC" --private-key "$ADMIN_PK" >/dev/null
echo "after:  recipient $R_DRIPTO eAUD balance = $(cast call "$EAUD" "balanceOf(address)(uint256)" "$R_DRIPTO" --rpc-url "$RPC")"
echo "Sender's lastFulfilledDripTimestamp for eAUD (should be 0 - cooldown is on the recipient):"
cast call "$MGR" "getLastFulfilledDripTimestamp(address,address)(uint256)" "$SENDER" "$EAUD" --rpc-url "$RPC"
echo "Recipient's lastFulfilledDripTimestamp for eAUD (should be > 0):"
cast call "$MGR" "getLastFulfilledDripTimestamp(address,address)(uint256)" "$R_DRIPTO" "$EAUD" --rpc-url "$RPC"

banner "Test 4 - cooldown enforcement: drip then immediate retry should revert"
cast send "$MGR" "dripTo(address,address,uint256)" "$R_COOLDOWN" "$EUSD" 100000000 \
    --rpc-url "$RPC" --private-key "$ADMIN_PK" >/dev/null
echo "first drip succeeded; trying second drip in same window..."
expect_revert "second drip within cooldown" \
    cast send "$MGR" "dripTo(address,address,uint256)" "$R_COOLDOWN" "$EUSD" 100000000 \
        --rpc-url "$RPC" --private-key "$ADMIN_PK"
echo "Next-eligible timestamp for $R_COOLDOWN on eUSD (should be ~now + 1 day):"
cast call "$MGR" "getNextEligibleDripTimestamp(address,address)(uint256)" "$R_COOLDOWN" "$EUSD" --rpc-url "$RPC"

banner "Test 5 - amount cap: requesting > baseline should revert"
expect_revert "drip 200 eUSD when baseline is 100" \
    cast send "$MGR" "dripTo(address,address,uint256)" "$R_CAP" "$EUSD" 200000000 \
        --rpc-url "$RPC" --private-key "$ADMIN_PK"
echo "below-cap drip (50 eUSD) on the same wallet should still succeed:"
cast send "$MGR" "dripTo(address,address,uint256)" "$R_CAP" "$EUSD" 50000000 \
    --rpc-url "$RPC" --private-key "$ADMIN_PK" >/dev/null
echo "$R_CAP eUSD balance: $(cast call "$EUSD" "balanceOf(address)(uint256)" "$R_CAP" --rpc-url "$RPC")"
echo "Expected: 50000000 (50.0 eUSD)"

banner "Test 6 - per-recipient max override"
echo "set $R_OVERRIDE override to 500 eUSD..."
cast send "$MGR" "setMaxDripAmountOverride(address,address,uint256)" "$R_OVERRIDE" "$EUSD" 500000000 \
    --rpc-url "$RPC" --private-key "$ADMIN_PK" >/dev/null
echo "getMaxDripAmount($R_OVERRIDE, eUSD): $(cast call "$MGR" "getMaxDripAmount(address,address)(uint256)" "$R_OVERRIDE" "$EUSD" --rpc-url "$RPC")"
echo "drip 500 eUSD to $R_OVERRIDE (would have reverted without override)..."
cast send "$MGR" "dripTo(address,address,uint256)" "$R_OVERRIDE" "$EUSD" 500000000 \
    --rpc-url "$RPC" --private-key "$ADMIN_PK" >/dev/null
echo "$R_OVERRIDE eUSD balance: $(cast call "$EUSD" "balanceOf(address)(uint256)" "$R_OVERRIDE" --rpc-url "$RPC")"
echo "Expected: 500000000 (500.0 eUSD)"

banner "Done"
echo "If you got OK on all expect_reverts and the printed balances match, end-to-end is healthy."
echo "Note: cooldown is 1 day; rerunning this script same-day will revert most tests because"
echo "      the throwaway recipients are now in cooldown. Bump R_* labels to retry."
