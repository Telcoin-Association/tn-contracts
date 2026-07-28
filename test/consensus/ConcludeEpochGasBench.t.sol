// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { RewardInfo, Slash, IStakeManager } from "src/interfaces/IStakeManager.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";

/// @dev Measures worst-case gas for the unified concludeEpoch system call against the client's
/// 30M per-call budget: N-validator committee rotation, N reward entries, partial slashes, and a
/// full settlement wave of N queued stake decreases with per-entry refund pushes
contract ConcludeEpochGasBench is ConsensusRegistryTestUtils {
    uint256 internal constant SYSTEM_CALL_GAS_BUDGET = 30_000_000;

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

    function _measure(uint256 n, bool withQueue, uint256 numSlashes) internal returns (uint256 gasUsed) {
        _scaleValidators(n);
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(uint16(n));
        address[] memory committee = _createTokenIdCommittee(n);

        // activate the scaled set and reach steady state on the full-size committee
        vm.startPrank(sysAddress);
        _concludeEpoch(committee);
        vm.stopPrank();

        if (withQueue) {
            // author a lower-stake version and queue a decrease for every in-service validator
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

        // one aging boundary so every queued decrease settles at the measured call
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

        vm.prank(sysAddress);
        uint256 g = gasleft();
        consensusRegistry.concludeEpoch(committee, rewardInfos, slashes);
        gasUsed = g - gasleft();
    }

    function test_gas_concludeEpoch_rewardsOnly_100() public {
        uint256 gasUsed = _measure(100, false, 0);
        emit log_named_uint("concludeEpoch gas: N=100 committee + 100 rewards, no queue", gasUsed);
        assertLt(gasUsed, SYSTEM_CALL_GAS_BUDGET);
    }

    function test_gas_concludeEpoch_worstCase_100() public {
        uint256 gasUsed = _measure(100, true, 10);
        emit log_named_uint("concludeEpoch gas: N=100 committee + 100 rewards + 10 slashes + 100 settling decreases", gasUsed);
        assertLt(gasUsed, SYSTEM_CALL_GAS_BUDGET);
    }

    function test_gas_concludeEpoch_worstCase_50() public {
        uint256 gasUsed = _measure(50, true, 5);
        emit log_named_uint("concludeEpoch gas: N=50 committee + 50 rewards + 5 slashes + 50 settling decreases", gasUsed);
        assertLt(gasUsed, SYSTEM_CALL_GAS_BUDGET);
    }

    function test_gas_concludeEpoch_worstCase_150() public {
        uint256 gasUsed = _measure(150, true, 15);
        emit log_named_uint("concludeEpoch gas: N=150 committee + 150 rewards + 15 slashes + 150 settling decreases", gasUsed);
        emit log_named_uint("budget", SYSTEM_CALL_GAS_BUDGET);
    }

    /// @dev The committee stays protocol-capped while the settlement wave scales with the full
    /// in-service set: every validator queues a decrease and all entries age out at one boundary
    function test_gas_concludeEpoch_settlementWave_1000() public {
        uint256 n = 1000;
        _scaleValidators(n);
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(100);
        address[] memory committee = _createTokenIdCommittee(100);

        vm.startPrank(sysAddress);
        _concludeEpoch(committee);
        vm.stopPrank();

        vm.prank(crOwner);
        uint8 lowVersion = consensusRegistry.upgradeStakeVersion(
            StakeConfig(600_000e18, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );
        for (uint256 secret = 1; secret <= n; ++secret) {
            address v = _addressFromPrivateKey(secret);
            vm.prank(v);
            consensusRegistry.requestStakeVersionChange(v, lowVersion);
        }

        // one aging boundary so every queued decrease settles at the measured call
        vm.startPrank(sysAddress);
        _concludeEpoch(committee);
        vm.stopPrank();

        RewardInfo[] memory rewardInfos = new RewardInfo[](100);
        for (uint256 i; i < 100; ++i) {
            rewardInfos[i] = RewardInfo(_addressFromPrivateKey(i + 1), 10);
        }

        vm.prank(sysAddress);
        uint256 g = gasleft();
        consensusRegistry.concludeEpoch(committee, rewardInfos, _noSlashes());
        uint256 gasUsed = g - gasleft();
        emit log_named_uint("concludeEpoch gas: 100 committee + 100 rewards + 1000 settling decreases", gasUsed);
        emit log_named_uint("budget", SYSTEM_CALL_GAS_BUDGET);
    }
}
