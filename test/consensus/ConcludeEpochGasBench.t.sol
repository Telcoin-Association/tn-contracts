// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { RewardInfo, Slash, IStakeManager } from "src/interfaces/IStakeManager.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";

/// @dev Measures worst-case gas for the epoch-boundary system calls - applyIncentives, then
/// applySlashes, then concludeEpoch, sequenced as the protocol does within the closing block -
/// against the client's per-call gas budget. Boundary cost grows linearly at roughly 76k gas per
/// in-service validator all-in, dominated by reward entries, committee rotation, and queue
/// settlement at about 30k per settling stake decrease. Recorded history: under the pre-split
/// unified three-argument call and the client's earlier 30M budget, the measured worst case was
/// 7.66M at N=100 (9.48M before refunds became pull credits), a 1000-entry settlement wave
/// measured 34.26M, and the single-call settlement ceiling sat near 860 entries; a 700-entry
/// wave measured about 25.4M against that 30M budget.
contract ConcludeEpochGasBench is ConsensusRegistryTestUtils {
    /// @dev Mirrors `SYSTEM_CALL_GAS_LIMIT` in telcoin-network's `crates/tn-reth/src/evm/mod.rs`.
    /// Each boundary system call receives this budget individually; update in lockstep with the
    /// client constant.
    uint256 internal constant SYSTEM_CALL_GAS_BUDGET = 100_000_000;

    /// @dev Per-call gas figures for one full boundary sequence
    struct BoundaryGas {
        uint256 incentives;
        uint256 slashes;
        uint256 conclude;
    }

    function setUp() public {
        consensusRegistry = ConsensusRegistry(0x07E17e17E17e17E17e17E17E17E17e17e17E17e1);

        vm.startStateDiffRecording();
        StakeConfig memory stakeConfig_ = StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_);
        ConsensusRegistry tempRegistry =
            new ConsensusRegistry(stakeConfig_, initialValidators, initialBlsPubkeys, initialBLSPops, crOwner);
        Vm.AccountAccess[] memory records = vm.stopAndReturnStateDiff();
        bytes32[] memory slots = saveWrittenSlots(address(tempRegistry), records);
        copyContractState(address(tempRegistry), address(consensusRegistry), slots);

        registryGenesisBal = stakeAmount_ * initialValidators.length;
        vm.deal(address(consensusRegistry), registryGenesisBal);
        sysAddress = consensusRegistry.SYSTEM_ADDRESS();

        vm.deal(crOwner, epochIssuance_);
        vm.prank(crOwner);
        consensusRegistry.allocateIssuance{ value: epochIssuance_ }();
    }

    /// @dev Mints, stakes, and activates validators with secrets 5..total so `total` are in service
    function _scaleValidators(uint256 total) internal {
        for (uint256 secret = 5; secret <= total; ++secret) {
            address v = _addressFromPrivateKey(secret);
            vm.prank(crOwner);
            consensusRegistry.mint(v);
            vm.deal(v, stakeAmount_);
            vm.startPrank(v);
            consensusRegistry.stake{ value: stakeAmount_ }(
                _blsDummyPubkeyFromSecret(secret), IStakeManager.ProofOfPossession(_blsDummySigFromSecret(secret))
            );
            consensusRegistry.activate();
            vm.stopPrank();
        }
    }

    /// @dev Queues a stake decrease for validators 1..n so the wave settles two boundaries later
    function _queueDecreases(uint256 n) internal {
        vm.prank(crOwner);
        uint8 lowVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(600_000e18, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );
        for (uint256 secret = 1; secret <= n; ++secret) {
            address v = _addressFromPrivateKey(secret);
            vm.prank(v);
            consensusRegistry.requestStakeVersionChange(v, lowVersion);
        }
    }

    /// @dev Runs the protocol's closing-block sequence, measuring each system call separately
    function _measureSequence(
        address[] memory committee,
        RewardInfo[] memory rewardInfos,
        Slash[] memory slashes
    )
        internal
        returns (BoundaryGas memory gasUsed)
    {
        vm.startPrank(sysAddress);
        uint256 g = gasleft();
        consensusRegistry.applyIncentives(rewardInfos);
        gasUsed.incentives = g - gasleft();
        g = gasleft();
        consensusRegistry.applySlashes(slashes);
        gasUsed.slashes = g - gasleft();
        g = gasleft();
        consensusRegistry.concludeEpoch(committee);
        gasUsed.conclude = g - gasleft();
        vm.stopPrank();
    }

    /// @dev Asserts every call in the sequence fits the per-call budget and logs the figures
    function _assertAndLog(string memory label, BoundaryGas memory gasUsed) internal {
        emit log_named_uint(string.concat(label, " applyIncentives gas"), gasUsed.incentives);
        emit log_named_uint(string.concat(label, " applySlashes gas"), gasUsed.slashes);
        emit log_named_uint(string.concat(label, " concludeEpoch gas"), gasUsed.conclude);
        assertLt(gasUsed.incentives, SYSTEM_CALL_GAS_BUDGET);
        assertLt(gasUsed.slashes, SYSTEM_CALL_GAS_BUDGET);
        assertLt(gasUsed.conclude, SYSTEM_CALL_GAS_BUDGET);
    }

    function _measure(uint256 n, bool withQueue, uint256 numSlashes) internal returns (BoundaryGas memory) {
        _scaleValidators(n);
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(n));
        address[] memory committee = _createTokenIdCommittee(n);

        // activate the scaled set and reach steady state on the full-size committee
        vm.startPrank(sysAddress);
        _concludeEpoch(committee);
        vm.stopPrank();

        if (withQueue) {
            _queueDecreases(n);
        }

        // one aging boundary so every queued decrease settles at the measured sequence
        vm.startPrank(sysAddress);
        _concludeEpoch(committee);
        vm.stopPrank();

        RewardInfo[] memory rewardInfos = new RewardInfo[](n);
        for (uint256 i; i < n; ++i) {
            rewardInfos[i] = RewardInfo(_addressFromPrivateKey(i + 1), 10);
        }
        Slash[] memory slashes = new Slash[](numSlashes);
        for (uint256 i; i < numSlashes; ++i) {
            // partial, non-ejecting slashes
            slashes[i] = Slash(_addressFromPrivateKey(i + 1), 1000e18);
        }

        return _measureSequence(committee, rewardInfos, slashes);
    }

    function test_gas_boundary_rewardsOnly_100() public {
        BoundaryGas memory gasUsed = _measure(100, false, 0);
        _assertAndLog("N=100 committee + 100 rewards, no queue:", gasUsed);
    }

    function test_gas_boundary_worstCase_50() public {
        BoundaryGas memory gasUsed = _measure(50, true, 5);
        _assertAndLog("N=50 committee + 50 rewards + 5 slashes + 50 settling decreases:", gasUsed);
    }

    function test_gas_boundary_worstCase_100() public {
        BoundaryGas memory gasUsed = _measure(100, true, 10);
        _assertAndLog("N=100 committee + 100 rewards + 10 slashes + 100 settling decreases:", gasUsed);
    }

    function test_gas_boundary_worstCase_150() public {
        BoundaryGas memory gasUsed = _measure(150, true, 15);
        _assertAndLog("N=150 committee + 150 rewards + 15 slashes + 150 settling decreases:", gasUsed);
    }

    /// @dev The committee stays protocol-capped while the settlement wave scales with the full
    /// in-service set: every validator queues a decrease and all entries age out at one boundary
    function test_gas_boundary_settlementWave_1000() public {
        uint256 n = 1000;
        _scaleValidators(n);
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(100);
        address[] memory committee = _createTokenIdCommittee(100);

        vm.startPrank(sysAddress);
        _concludeEpoch(committee);
        vm.stopPrank();

        _queueDecreases(n);

        // one aging boundary so every queued decrease settles at the measured sequence
        vm.startPrank(sysAddress);
        _concludeEpoch(committee);
        vm.stopPrank();

        RewardInfo[] memory rewardInfos = new RewardInfo[](100);
        for (uint256 i; i < 100; ++i) {
            rewardInfos[i] = RewardInfo(_addressFromPrivateKey(i + 1), 10);
        }

        BoundaryGas memory gasUsed = _measureSequence(committee, rewardInfos, new Slash[](0));
        _assertAndLog("100 committee + 100 rewards + 1000 settling decreases:", gasUsed);
    }
}
