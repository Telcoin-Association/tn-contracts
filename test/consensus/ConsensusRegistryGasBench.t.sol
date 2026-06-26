// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { IStakeManager } from "src/interfaces/IStakeManager.sol";

/// @title per-status set query gas benchmark
/// @notice Measures the post-refactor status queries against the former O(n) `tokenByIndex` scan.
/// The eligible count is three set-length reads; `getValidators(status)` returns the set's addresses
/// directly; `getValidatorsInfo(status)` adds the `ValidatorInfo` copies. Compare these numbers against
/// the fork point (`enhancement/consensus-registry-eligible-count`), where `getValidators(Active)`
/// allocated `totalSupply()` entries and cold-SLOADed every validator's slots.
contract ConsensusRegistryGasBench is ConsensusRegistryTestUtils {
    /// @dev Build a genesis set of `n` Active validators with length-correct PoP fixtures (secrets
    /// offset to avoid colliding with the genesis validators 1-4 used elsewhere).
    function _buildGenesis(uint256 n)
        internal
        view
        returns (ValidatorInfo[] memory vals, bytes[] memory pubkeys, IStakeManager.ProofOfPossession[] memory pops)
    {
        vals = new ValidatorInfo[](n);
        pubkeys = new bytes[](n);
        pops = new IStakeManager.ProofOfPossession[](n);
        for (uint256 i; i < n; ++i) {
            uint256 secret = 1000 + i;
            address addr = _addressFromPrivateKey(secret);
            vals[i] = ValidatorInfo(addr, uint32(0), uint32(0), ValidatorStatus.Active, false, uint8(0), uint8(0));
            pubkeys[i] = _blsDummyPubkeyFromSecret(secret);
            pops[i] = IStakeManager.ProofOfPossession(_blsDummySigFromSecret(secret));
        }
    }

    function _deploy(uint256 n) internal returns (ConsensusRegistry reg) {
        (ValidatorInfo[] memory vals, bytes[] memory pubkeys, IStakeManager.ProofOfPossession[] memory pops) = _buildGenesis(n);
        StakeConfig memory cfg = StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_);
        reg = new ConsensusRegistry(cfg, vals, pubkeys, pops, crOwner);
    }

    function test_gas_perStatusSets() public {
        uint256[4] memory sizes = [uint256(8), 32, 64, 128];
        for (uint256 s; s < sizes.length; ++s) {
            uint256 n = sizes[s];
            ConsensusRegistry reg = _deploy(n);

            // committee-eligible count: cached counter, a single SLOAD (kept alongside the sets)
            uint256 g0 = gasleft();
            uint256 counted = reg.getEligibleValidatorCount();
            uint256 countGas = g0 - gasleft();

            // addresses-only query (the protocol's path): set read, no struct copies (was an O(n) scan
            // returning ValidatorInfo[])
            uint256 g1 = gasleft();
            uint256 addrsLen = reg.getValidators(ValidatorStatus.Active).length;
            uint256 addrsGas = g1 - gasleft();

            // full-struct query: set read + ValidatorInfo copies (apples-to-apples vs the old scan that
            // also returned ValidatorInfo[])
            uint256 g2 = gasleft();
            uint256 infoLen = reg.getValidatorsInfo(ValidatorStatus.Active).length;
            uint256 infoGas = g2 - gasleft();

            assertEq(counted, n);
            assertEq(addrsLen, n);
            assertEq(infoLen, n);
            emit log_named_uint("N validators", n);
            emit log_named_uint("  getEligibleValidatorCount gas (cached counter)", countGas);
            emit log_named_uint("  getValidators(Active) gas      (address[] set)", addrsGas);
            emit log_named_uint("  getValidatorsInfo(Active) gas  (ValidatorInfo[])", infoGas);
        }
    }
}
