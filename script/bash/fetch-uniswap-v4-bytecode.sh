#!/usr/bin/env bash
set -euo pipefail

# Builds Uniswap V4 (core + periphery) from the lib/v4-periphery submodule
# using its own foundry.toml (via_ir + 44_444_444 optimizer runs + cancun
# evm_version + bytecode_hash=none, plus per-file compilation_restrictions
# for PositionManager and PositionDescriptor). Extracts the resulting
# creation bytecode from foundry-out/ and writes Solidity bytecode-literal
# files under external/uniswap/precompiles/v4/.
#
# This is the V4 counterpart to fetch-uniswap-v3-bytecode.sh, but builds
# from source rather than fetching from npm because v4-periphery doesn't
# publish creation-bytecode artifacts on npm.
#
# Why bytecode literals: Uniswap V4 source needs via_ir = true at the solc
# level, which conflicts with tn-contracts' default 200-runs / no-via_ir
# compile profile. Enabling via_ir at the project level crashes solc on
# Windows; scoping it via Foundry's compilation_restrictions fails to
# reconcile cross-imports under our pinned Foundry version. Treating V4
# the way we treat V2 + V3 + Permit2 (CREATE2-deploy of pre-compiled
# bytecode literals via Arachnid) sidesteps the compile-config problem
# entirely and gives us deterministic deployments matching what Uniswap
# Labs would produce themselves.
#
# Pinned versions (see lib/v4-periphery/.gitmodules + lib/v4-core HEAD):
#   - Uniswap/v4-core    @ 59d3ecf53afa9264a16bba0e38f4c5d2231f80bc (npm 1.0.2 = v4.0.0+12)
#   - Uniswap/v4-periphery @ 9dafaaecc1e2e1e824eda9d941085f96517d827b (no release tags)
#
# Refresh recipe:
#   1. cd lib/v4-periphery && git pull (or check out a different commit)
#   2. cd lib/v4-periphery && forge install
#   3. From the repo root, bash script/bash/fetch-uniswap-v4-bytecode.sh
#   4. Review the diff in external/uniswap/precompiles/v4/ before commit.
#
# Usage: bash script/bash/fetch-uniswap-v4-bytecode.sh

OUT_DIR="external/uniswap/precompiles/v4"
PERIPHERY_DIR="lib/v4-periphery"
PERIPHERY_OUT="${PERIPHERY_DIR}/foundry-out"

mkdir -p "$OUT_DIR"

if ! command -v node >/dev/null 2>&1; then
    echo "Error: node is required but not installed" >&2
    exit 1
fi

if [[ ! -d "$PERIPHERY_DIR" ]]; then
    echo "Error: $PERIPHERY_DIR not found. Run forge install Uniswap/v4-periphery first." >&2
    exit 1
fi

# Build v4-periphery (which imports v4-core via its nested submodule). This
# uses v4-periphery's own foundry.toml settings, NOT tn-contracts' settings,
# so the bytecode matches what the canonical Uniswap recipe would produce.
echo "building v4-periphery (this may take 1-2 minutes; ignore Windows nightly warnings)..."
(cd "$PERIPHERY_DIR" && forge build --silent)

# write_artifact <relative-path-under-foundry-out> <output-name> <constant-name>
#
# Reads the artifact JSON, extracts bytecode.object, and writes a .sol file
# at $OUT_DIR/$2 containing a single `bytes constant $3 = hex"...";`.
write_artifact() {
    local artifact_path="$1"
    local output_name="$2"
    local constant_name="$3"
    local source_pkg="$4"

    local full_path="$PERIPHERY_OUT/$artifact_path"
    if [[ ! -f "$full_path" ]]; then
        echo "Error: artifact missing: $full_path" >&2
        exit 1
    fi

    # Use a project-local temp file so node sees a path it can read.
    cp "$full_path" "$OUT_DIR/.fetch.tmp.json"

    node --input-type=module -e "
import fs from 'fs';
const a = JSON.parse(fs.readFileSync('$OUT_DIR/.fetch.tmp.json', 'utf8'));
const bytecodeRaw = (a.bytecode && (a.bytecode.object || a.bytecode)) || '';
if (typeof bytecodeRaw !== 'string' || !bytecodeRaw.startsWith('0x')) {
  console.error('Artifact has no bytecode.object field');
  process.exit(1);
}
const hex = bytecodeRaw.slice(2);
const linkRe = /__\\\$[0-9a-fA-F]+\\\$__/g;
const placeholders = (hex.match(linkRe) || []).length;
if (placeholders > 0) {
  console.error('V4 artifact has', placeholders, 'library-link placeholders (unexpected for V4 - they should all be inline libraries)');
  process.exit(1);
}
const sol = \`// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

// Bytecode of the canonical $output_name (without .sol extension).
//
// Built from: ${source_pkg}
// Build recipe: lib/v4-periphery/foundry.toml (solc 0.8.26, via_ir = true,
//   optimizer_runs as set in compilation_restrictions for this contract,
//   evm_version = cancun, bytecode_hash = none).
// Refresh: bash script/bash/fetch-uniswap-v4-bytecode.sh
//
// Constructor arguments are NOT included in this bytecode; the V4 deploy
// script appends them at deploy time before the CREATE2 call.
//
// V4 contracts use inline libraries (via 'using ... for') rather than
// link-time library references, so there are no __\\\$...\\\$__
// placeholders to splice. Uniswap V4 was specifically designed to avoid
// the V3-style library-linking complexity.
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

# v4-core: PoolManager (singleton). Uses default profile (44M optimizer runs).
write_artifact \
    "PoolManager.sol/PoolManager.default.json" \
    "PoolManager.sol" \
    "POOL_MANAGER_BYTECODE" \
    "Uniswap/v4-core (lib/v4-core nested under lib/v4-periphery)"

# v4-periphery: PositionManager. Uses 'posm' profile (30k optimizer runs).
# This deviation from default is what lets PositionManager fit under the
# 24kb runtime size limit.
write_artifact \
    "PositionManager.sol/PositionManager.json" \
    "PositionManager.sol" \
    "POSITION_MANAGER_BYTECODE" \
    "Uniswap/v4-periphery"

# v4-periphery: PositionDescriptor. Uses 'descriptor' profile (1 optimizer run)
# because the bulk SVG-rendering logic blows past the 24kb limit at higher
# optimizer settings.
write_artifact \
    "PositionDescriptor.sol/PositionDescriptor.json" \
    "PositionDescriptor.sol" \
    "POSITION_DESCRIPTOR_BYTECODE" \
    "Uniswap/v4-periphery"

# v4-periphery: V4Quoter. Default profile.
write_artifact \
    "V4Quoter.sol/V4Quoter.json" \
    "V4Quoter.sol" \
    "V4_QUOTER_BYTECODE" \
    "Uniswap/v4-periphery"

# v4-periphery: StateView. Default profile.
write_artifact \
    "StateView.sol/StateView.json" \
    "StateView.sol" \
    "STATE_VIEW_BYTECODE" \
    "Uniswap/v4-periphery"

echo ""
echo "All five V4 bytecode files written to ${OUT_DIR}/"
echo "Run forge build to confirm they compile, then update TestnetDeployUniswapV4.s.sol if needed."
