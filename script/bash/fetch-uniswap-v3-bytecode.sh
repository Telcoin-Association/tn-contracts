#!/usr/bin/env bash
set -euo pipefail

# Fetches canonical Uniswap V3 contract bytecode from the published npm artifacts
# and writes it as Solidity bytecode-literal files under
# `external/uniswap/precompiles/v3/`.
#
# Idempotent: re-running overwrites the .sol files with the same bytecode if
# the upstream npm versions don't change. Pinned versions are the canonical
# Uniswap mainnet releases:
#   - @uniswap/v3-core@1.0.0
#   - @uniswap/v3-periphery@1.4.4
#   - @uniswap/swap-router-contracts@1.3.0
#
# This script is the V3 counterpart to the V2 bytecode files at
# external/uniswap/precompiles/UniswapV2*Bytecode.sol, which were extracted
# from @uniswap/v2-core@1.0.1 by the same process (manual then, automated
# now).
#
# Usage: bash script/bash/fetch-uniswap-v3-bytecode.sh

V3_CORE_VERSION="1.0.0"
V3_PERIPHERY_VERSION="1.4.4"
SWAP_ROUTER_CONTRACTS_VERSION="1.3.0"

OUT_DIR="external/uniswap/precompiles/v3"
mkdir -p "$OUT_DIR"

# Validate node is available - we use it to parse the artifact JSON.
if ! command -v node >/dev/null 2>&1; then
    echo "Error: node is required but not installed" >&2
    exit 1
fi

# Validate curl is available.
if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required but not installed" >&2
    exit 1
fi

# fetch_artifact <unpkg-path> <output-name> <constant-name> <package-pin>
#
# Downloads the artifact JSON from unpkg, extracts the `bytecode` field,
# and writes a Solidity file at $OUT_DIR/$2 containing a single
# `bytes constant $3 = hex"...";` declaration plus a provenance comment
# block citing the package pin and the unpkg URL.
fetch_artifact() {
    local unpkg_path="$1"
    local output_name="$2"
    local constant_name="$3"
    local package_pin="$4"

    local url="https://unpkg.com/${unpkg_path}"
    local tmp_json
    tmp_json="$(mktemp)"

    echo "fetching ${unpkg_path} ..."
    curl -sf "$url" > "$tmp_json"

    # Use node to extract bytecode and emit the .sol file. node sees a
    # Windows-style absolute path on git-bash, so cp the json into the
    # project tree first.
    cp "$tmp_json" "$OUT_DIR/.fetch.tmp.json"
    rm "$tmp_json"

    node --input-type=module -e "
import fs from 'fs';
const a = JSON.parse(fs.readFileSync('$OUT_DIR/.fetch.tmp.json', 'utf8'));
const bytecode = a.bytecode;
if (typeof bytecode !== 'string' || !bytecode.startsWith('0x')) {
  console.error('Artifact has no bytecode field');
  process.exit(1);
}
let hex = bytecode.slice(2);

// Scrub library-link placeholders. Uniswap's npm artifacts include
// placeholders of the form __\$<keccak-truncated>\$__ at every linked-library
// reference site. These are 40-char tokens that aren't valid Solidity hex
// digits and would break a hex\"\" literal at compile time. The deploy
// script splices the real library address into the known offset before
// invoking the CREATE2 deployer, so replacing the placeholder with 40
// zero-hex chars is safe and preserves byte length / offsets.
const placeholderRe = /__\\\$[0-9a-fA-F]+\\\$__/g;
const placeholderCount = (hex.match(placeholderRe) || []).length;
hex = hex.replace(placeholderRe, '0'.repeat(40));

if (placeholderCount > 0) {
  console.log('  scrubbed', placeholderCount, 'library-link placeholder(s)');
}

const contractName = '$constant_name';
// Plain // comments below instead of natspec ///. Natspec uses @-prefixed tags
// (@notice, @dev, @title, etc.) and Solidity's parser treats any @-prefix as
// a custom tag - which breaks when our provenance text mentions Uniswap npm
// package pins like @uniswap/v3-periphery@1.4.4. Plain comments dodge that.
const sol = \`// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

// Bytecode of the canonical $output_name (without .sol extension).
//
// Taken from the official Uniswap npm artifact:
//   https://unpkg.com/${unpkg_path}
// Package pin: ${package_pin}
// Refresh recipe: script/bash/fetch-uniswap-v3-bytecode.sh
//
// Constructor arguments are NOT included in this bytecode and must be appended
// at deploy time. See TestnetDeployUniswapV3.s.sol for which constructor each
// contract takes.
//
// Linker placeholders (if any) have been replaced with 20 zero-bytes at the
// appropriate offsets. The deploy script splices in the real library address
// before invoking CREATE2.
contract ${output_name%.sol}Bytecode {
    bytes public constant ${constant_name} =
        hex\"\${hex}\";
}
\`;
fs.writeFileSync('$OUT_DIR/${output_name}', sol);
console.log('wrote $OUT_DIR/${output_name}', '(', hex.length / 2, 'bytes bytecode )');
"

    rm "$OUT_DIR/.fetch.tmp.json"
}

# v3-core: Factory.
fetch_artifact \
    "@uniswap/v3-core@${V3_CORE_VERSION}/artifacts/contracts/UniswapV3Factory.sol/UniswapV3Factory.json" \
    "UniswapV3Factory.sol" \
    "UNISWAPV3FACTORY_BYTECODE" \
    "@uniswap/v3-core@${V3_CORE_VERSION}"

# v3-periphery: NFTDescriptor library.
fetch_artifact \
    "@uniswap/v3-periphery@${V3_PERIPHERY_VERSION}/artifacts/contracts/libraries/NFTDescriptor.sol/NFTDescriptor.json" \
    "NFTDescriptor.sol" \
    "NFTDESCRIPTOR_BYTECODE" \
    "@uniswap/v3-periphery@${V3_PERIPHERY_VERSION}"

# v3-periphery: NonfungibleTokenPositionDescriptor.
# NOTE: This contract is library-linked to NFTDescriptor. The bytecode contains
# linker placeholders of the form __$<keccak256-truncated>$__ that must be
# replaced with the deployed NFTDescriptor address before this contract is
# deployed. The deploy script handles that splice.
fetch_artifact \
    "@uniswap/v3-periphery@${V3_PERIPHERY_VERSION}/artifacts/contracts/NonfungibleTokenPositionDescriptor.sol/NonfungibleTokenPositionDescriptor.json" \
    "NonfungibleTokenPositionDescriptor.sol" \
    "NONFUNGIBLE_TOKEN_POSITION_DESCRIPTOR_BYTECODE" \
    "@uniswap/v3-periphery@${V3_PERIPHERY_VERSION}"

# v3-periphery: NonfungiblePositionManager.
fetch_artifact \
    "@uniswap/v3-periphery@${V3_PERIPHERY_VERSION}/artifacts/contracts/NonfungiblePositionManager.sol/NonfungiblePositionManager.json" \
    "NonfungiblePositionManager.sol" \
    "NONFUNGIBLE_POSITION_MANAGER_BYTECODE" \
    "@uniswap/v3-periphery@${V3_PERIPHERY_VERSION}"

# v3-periphery: QuoterV2.
fetch_artifact \
    "@uniswap/v3-periphery@${V3_PERIPHERY_VERSION}/artifacts/contracts/lens/QuoterV2.sol/QuoterV2.json" \
    "QuoterV2.sol" \
    "QUOTER_V2_BYTECODE" \
    "@uniswap/v3-periphery@${V3_PERIPHERY_VERSION}"

# v3-periphery: TickLens.
fetch_artifact \
    "@uniswap/v3-periphery@${V3_PERIPHERY_VERSION}/artifacts/contracts/lens/TickLens.sol/TickLens.json" \
    "TickLens.sol" \
    "TICK_LENS_BYTECODE" \
    "@uniswap/v3-periphery@${V3_PERIPHERY_VERSION}"

# swap-router-contracts: SwapRouter02 (V2 + V3 unified router).
fetch_artifact \
    "@uniswap/swap-router-contracts@${SWAP_ROUTER_CONTRACTS_VERSION}/artifacts/contracts/SwapRouter02.sol/SwapRouter02.json" \
    "SwapRouter02.sol" \
    "SWAP_ROUTER_02_BYTECODE" \
    "@uniswap/swap-router-contracts@${SWAP_ROUTER_CONTRACTS_VERSION}"

echo ""
echo "All seven V3 bytecode files written to ${OUT_DIR}/"
echo "Run forge build to confirm they compile."
