// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { BlsG1 } from "src/consensus/BlsG1.sol";

/// @title eligibleValidatorCount gas benchmark
/// @notice Measures the O(1) `getEligibleValidatorCount()` counter against the O(n)
/// `getValidators(Active)` scan it replaced at the four hot count call sites
/// (`concludeEpoch`, `setNextCommitteeSize`, `beginExit`, `_consensusBurn`). The scan allocates
/// `totalSupply()` entries and cold-SLOADs each validator's slots; the counter is a single SLOAD,
/// so the gap grows linearly with the validator set.
contract ConsensusRegistryGasBench is ConsensusRegistryTestUtils {
    /// @dev Build a genesis set of `n` Active validators with real PoPs (secrets offset to avoid
    /// colliding with the genesis validators 1-4 used elsewhere).
    function _buildGenesis(uint256 n)
        internal
        view
        returns (ValidatorInfo[] memory vals, bytes[] memory pubkeys, BlsG1.ProofOfPossession[] memory pops)
    {
        vals = new ValidatorInfo[](n);
        pubkeys = new bytes[](n);
        pops = new BlsG1.ProofOfPossession[](n);
        for (uint256 i; i < n; ++i) {
            uint256 secret = 1000 + i;
            address addr = _addressFromPrivateKey(secret);
            vals[i] = ValidatorInfo(addr, uint32(0), uint32(0), ValidatorStatus.Active, false, uint8(0), uint8(0));
            pubkeys[i] = _blsDummyPubkeyFromSecret(secret);
            bytes memory uncompressed = BlsG1.decodeG2PointFromEIP2537(_blsEIP2537PubkeyFromSecret(secret));
            bytes memory message = proofOfPossessionMessage(uncompressed, addr);
            bytes memory sig = BlsG1.decodeG1PointFromEIP2537(_blsEIP2537SignatureFromSecret(secret, message));
            pops[i] = BlsG1.ProofOfPossession(uncompressed, sig);
        }
    }

    function _deploy(uint256 n) internal returns (ConsensusRegistry reg) {
        (ValidatorInfo[] memory vals, bytes[] memory pubkeys, BlsG1.ProofOfPossession[] memory pops) = _buildGenesis(n);
        StakeConfig memory cfg = StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_);
        reg = new ConsensusRegistry(cfg, vals, pubkeys, pops, crOwner);
    }

    function test_gas_eligibleCount_vs_scan() public {
        uint256[4] memory sizes = [uint256(8), 32, 64, 128];
        for (uint256 s; s < sizes.length; ++s) {
            uint256 n = sizes[s];
            ConsensusRegistry reg = _deploy(n);

            uint256 g0 = gasleft();
            uint256 counted = reg.getEligibleValidatorCount();
            uint256 counterGas = g0 - gasleft();

            uint256 g1 = gasleft();
            uint256 scanned = reg.getValidators(ValidatorStatus.Active).length;
            uint256 scanGas = g1 - gasleft();

            assertEq(counted, n);
            assertEq(scanned, n);
            emit log_named_uint("N validators", n);
            emit log_named_uint("  O(1) getEligibleValidatorCount gas", counterGas);
            emit log_named_uint("  O(n) getValidators(Active) gas    ", scanGas);
        }
    }
}
