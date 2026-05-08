#!/usr/bin/env bash
# Seed LP across V2/V3/V4 on Adiri Testnet using live FX rates.
#
# Pulls free FX rates (USD-base) from open.er-api.com, scales them to a
# 1e6 fixed-point integer the forge script can read as uint256, and stamps
# the result into ./cache/seed-testnet-lps-fx.json. Then runs
# SeedTestnetLPs.s.sol with
# --broadcast.
#
# Currency notes:
#   - eCFA -> XOF (West African CFA franc)
#   - eSDR -> XDR (IMF Special Drawing Rights)
#   - All other 20 stablecoins map directly to their ISO 4217 code.
#
# Required env (from .env):
#   ADMIN_PK     - admin/deployer private key
#   TN_RPC_URL   - Adiri RPC URL
set -euo pipefail
source .env

mkdir -p cache
FX_FILE="cache/seed-testnet-lps-fx.json"

echo "Fetching FX rates from open.er-api.com..."
curl -sSf "https://open.er-api.com/v6/latest/USD" \
    | jq '
        .rates as $r
        | { ts: .time_last_update_utc,
            rates: {
                eAUD: ($r.AUD * 1000000 | floor),
                eCAD: ($r.CAD * 1000000 | floor),
                eCFA: ($r.XOF * 1000000 | floor),
                eCHF: ($r.CHF * 1000000 | floor),
                eCZK: ($r.CZK * 1000000 | floor),
                eDKK: ($r.DKK * 1000000 | floor),
                eEUR: ($r.EUR * 1000000 | floor),
                eGBP: ($r.GBP * 1000000 | floor),
                eHKD: ($r.HKD * 1000000 | floor),
                eHUF: ($r.HUF * 1000000 | floor),
                eINR: ($r.INR * 1000000 | floor),
                eISK: ($r.ISK * 1000000 | floor),
                eJPY: ($r.JPY * 1000000 | floor),
                eKES: ($r.KES * 1000000 | floor),
                eMXN: ($r.MXN * 1000000 | floor),
                eNOK: ($r.NOK * 1000000 | floor),
                eNZD: ($r.NZD * 1000000 | floor),
                eSDR: ($r.XDR * 1000000 | floor),
                eSEK: ($r.SEK * 1000000 | floor),
                eSGD: ($r.SGD * 1000000 | floor),
                eTRY: ($r.TRY * 1000000 | floor),
                eZAR: ($r.ZAR * 1000000 | floor)
            }
        }' > "$FX_FILE"

echo "FX rates written to $FX_FILE:"
jq . "$FX_FILE"

echo
echo "Running SeedTestnetLPs forge script..."
forge script script/testnet/SeedTestnetLPs.s.sol \
    --rpc-url "$TN_RPC_URL" \
    --private-key "$ADMIN_PK" \
    --broadcast \
    --slow \
    -vv
