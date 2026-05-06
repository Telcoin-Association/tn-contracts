/// SPDX-License-Identifier MIT or Apache-2.0
pragma solidity ^0.8.26;

/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
/// therefore upper-case struct member names must come **BEFORE** lower-case ones!
struct Deployments {
    address ArachnidDeterministicDeployFactory;
    address ConsensusRegistry;
    address GitAttestationRegistry;
    address Issuance;
    address Safe;
    address SafeImpl;
    address SafeProxyFactory;
    address StablecoinImpl;
    address StablecoinManager;
    address StablecoinManagerImpl;
    address StakeManager;
    address TANIssuanceHistory;
    address TANIssuancePlugin;
    address WTEL;
    address WorkerConfigs;
    address admin;
    EXYZs eXYZs;
    MagicAddresses magicAddresses;
    UniswapV2 uniswapV2;
    UniswapV3 uniswapV3;
    UniswapV4 uniswapV4;
}

/// @notice Documents the magic / sentinel addresses used by Telcoin testnet contracts.
/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
///         therefore upper-case struct member names must come **BEFORE** lower-case ones!
struct MagicAddresses {
    /// @notice Sentinel for the chain's native token (TEL). Uses the conventional EEEE
    ///         magic address (popularised by 1inch / Aave) so callers can pass it
    ///         intentionally rather than relying on the zero address.
    address NATIVE_TOKEN_POINTER;
    /// @notice TN-custom precompile that mints the chain's native token (TEL). Called
    ///         by `StablecoinManager._drip` when the requested token is `NATIVE_TOKEN_POINTER`.
    address TEL_MINT_PRECOMPILE;
}

/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
struct EXYZs {
    address eAUD;
    address eCAD;
    address eCFA;
    address eCHF;
    address eCZK;
    address eDKK;
    address eEUR;
    address eGBP;
    address eHKD;
    address eHUF;
    address eINR;
    address eISK;
    address eJPY;
    address eKES;
    address eMXN;
    address eNOK;
    address eNZD;
    address eSDR;
    address eSEK;
    address eSGD;
    address eTRY;
    address eUSD;
    address eZAR;
}

/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
struct UniswapV2 {
    address UniswapV2Factory;
    address UniswapV2Router02;
    address eEUR_eAUD_Pool;
    address eEUR_eCAD_Pool;
    address eEUR_eCFA_Pool;
    address eEUR_eCHF_Pool;
    address eEUR_eCZK_Pool;
    address eEUR_eDKK_Pool;
    address eEUR_eGBP_Pool;
    address eEUR_eHKD_Pool;
    address eEUR_eHUF_Pool;
    address eEUR_eINR_Pool;
    address eEUR_eISK_Pool;
    address eEUR_eJPY_Pool;
    address eEUR_eKES_Pool;
    address eEUR_eMXN_Pool;
    address eEUR_eNOK_Pool;
    address eEUR_eNZD_Pool;
    address eEUR_eSDR_Pool;
    address eEUR_eSEK_Pool;
    address eEUR_eSGD_Pool;
    address eEUR_eTRY_Pool;
    address eEUR_eZAR_Pool;
    address eUSD_eAUD_Pool;
    address eUSD_eCAD_Pool;
    address eUSD_eCFA_Pool;
    address eUSD_eCHF_Pool;
    address eUSD_eCZK_Pool;
    address eUSD_eDKK_Pool;
    address eUSD_eEUR_Pool;
    address eUSD_eGBP_Pool;
    address eUSD_eHKD_Pool;
    address eUSD_eHUF_Pool;
    address eUSD_eINR_Pool;
    address eUSD_eISK_Pool;
    address eUSD_eJPY_Pool;
    address eUSD_eKES_Pool;
    address eUSD_eMXN_Pool;
    address eUSD_eNOK_Pool;
    address eUSD_eNZD_Pool;
    address eUSD_eSDR_Pool;
    address eUSD_eSEK_Pool;
    address eUSD_eSGD_Pool;
    address eUSD_eTRY_Pool;
    address eUSD_eZAR_Pool;
    /// @notice wTEL pool entries. Listed after the eXxx_* fields because lex
    ///         order on lowercase 'w' (0x77) > 'e' (0x65). Deployed by
    ///         TestnetDeployUniswapV2 against the WTEL contract (not the
    ///         legacy TEL precompile address).
    address wTEL_eEUR_Pool;
    address wTEL_eUSD_Pool;
}

/// @notice Uniswap V3 deployment surface. Periphery contracts are pinned at
///         a specific Uniswap V3 release (see external/uniswap/precompiles/v3/README.md
///         for the source recipe and init-code hash).
/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
///         therefore upper-case struct member names must come **BEFORE** lower-case ones!
struct UniswapV3 {
    /// @notice NFTDescriptor library used by NonfungibleTokenPositionDescriptor.
    address NFTDescriptor;
    /// @notice ERC721 position-NFT contract for V3 concentrated-liquidity positions.
    address NonfungiblePositionManager;
    /// @notice Renders the SVG / metadata for position NFTs.
    address NonfungibleTokenPositionDescriptor;
    /// @notice Off-chain quote helper for V3 swaps.
    address QuoterV2;
    /// @notice Universal router for V2 + V3 swaps. Constructor-pinned to factoryV2,
    ///         factoryV3, NonfungiblePositionManager, and wTEL (the WTEL contract).
    address SwapRouter02;
    /// @notice Pagination helper for tick liquidity reads.
    address TickLens;
    /// @notice V3 pool factory. Pools are not pre-seeded; liquidity providers
    ///         initialize pools on first mint per fee tier through the swap UI.
    address UniswapV3Factory;
}

/// @notice Uniswap V4 deployment surface. V4 core + periphery compile from source
///         under lib/v4-core and lib/v4-periphery (Solidity 0.8.26).
/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
///         therefore upper-case struct member names must come **BEFORE** lower-case ones!
/// @notice UniversalRouter is intentionally not in this struct yet. As of the foundation
///         commit, no tagged universal-router release includes V4 routing; the V4-aware
///         build lives on a non-canonical branch. We deploy V4Quoter + StateView from
///         v4-periphery so the swap UI can compose V4 swaps via direct PoolManager-unlock
///         callbacks until Uniswap tags a V4-aware UniversalRouter we can pin against.
struct UniswapV4 {
    /// @notice Canonical Permit2 address. Identical on every chain that has Permit2
    ///         deployed via the canonical Arachnid + salt recipe (commit cc306b6 on
    ///         Uniswap/permit2; the tag name on that repo IS the canonical address).
    address Permit2;
    /// @notice V4 pool singleton. Holds all pool state for every PoolKey.
    address PoolManager;
    /// @notice ERC721 position-NFT contract for V4 positions. Lives in v4-periphery.
    address PositionManager;
    /// @notice Read-only pool state accessor (v4-periphery `src/lens/StateView.sol`).
    ///         Lets clients fetch slot0, liquidity, ticks, and positions without
    ///         entering the PoolManager unlock pattern.
    address StateView;
    /// @notice Off-chain quote helper (v4-periphery `src/lens/V4Quoter.sol`). Mirrors
    ///         V3's QuoterV2 role for the V4 price-impact / amount-out preview.
    address V4Quoter;
    /// @notice Mediator that lets EOAs call V4 swap. Implements PoolManager's
    ///         IUnlockCallback and exposes a V3-SwapRouter02-shaped
    ///         `exactInputSingle` so the swap UI can keep one ABI across
    ///         V2 / V3 / V4. Constructor-pinned to `PoolManager`.
    address V4SwapHelper;
}
