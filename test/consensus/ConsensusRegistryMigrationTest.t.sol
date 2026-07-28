// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { SystemCallable } from "src/consensus/SystemCallable.sol";
import { IStakeManager } from "src/interfaces/IStakeManager.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";

/// @notice Tests for `migrateValidatorSets`, the one-time back-fill used when upgrading an existing
/// deployment (one that predates the per-status `EnumerableSet`s) in place. The pre-upgrade state is
/// emulated by clearing the sets and the cached eligible count on a populated registry, after which
/// the migration must rebuild them exactly from `validators[].currentStatus` (the preserved source
/// of truth that survives the code swap because the layout is a clean append).
contract ConsensusRegistryMigrationTest is ConsensusRegistryTestUtils {
    function setUp() public {
        consensusRegistry = ConsensusRegistry(0x07E17e17E17e17E17e17E17E17E17e17e17E17e1);

        vm.startStateDiffRecording();
        StakeConfig memory stakeConfig_ =
            StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_);
        ConsensusRegistry tempRegistry =
            new ConsensusRegistry(stakeConfig_, initialValidators, initialBlsPubkeys, initialBLSPops, crOwner);
        Vm.AccountAccess[] memory records = vm.stopAndReturnStateDiff();
        bytes32[] memory slots = saveWrittenSlots(address(tempRegistry), records);
        copyContractState(address(tempRegistry), address(consensusRegistry), slots);

        // simulate protocol allocation of validators' initial stake
        registryGenesisBal = stakeAmount_ * initialValidators.length;
        vm.deal(address(consensusRegistry), registryGenesisBal);
        sysAddress = consensusRegistry.SYSTEM_ADDRESS();

        vm.deal(validator5, stakeAmount_);
    }

    function test_migrateValidatorSets_rebuildsClearedSets() public {
        // build a mix of statuses: 4 Active (genesis) + 1 Staked + 1 PendingActivation
        _mintAndStake(validator5, validator5Secret); // -> Staked
        address validator6 = _addressFromPrivateKey(6);
        _mintAndStake(validator6, 6); // -> Staked
        vm.prank(validator6);
        consensusRegistry.activate(); // -> PendingActivation

        _assertSetInvariant();
        // 4 Active + 1 PendingActivation are committee-eligible; the Staked validator is not
        assertEq(consensusRegistry.getEligibleValidatorCount(), 5);

        // emulate a deployment that predates the sets: validators + ConsensusNFTs are present, but the
        // per-status sets and the cached eligible count are empty
        _clearValidatorSets();
        assertEq(consensusRegistry.getValidators(ValidatorStatus.Active).length, 0, "active not cleared");
        assertEq(consensusRegistry.getValidators(ValidatorStatus.Staked).length, 0, "staked not cleared");
        assertEq(
            consensusRegistry.getValidators(ValidatorStatus.PendingActivation).length, 0, "pending not cleared"
        );
        assertEq(consensusRegistry.getEligibleValidatorCount(), 0, "count not cleared");

        // back-fill via the system call
        vm.expectEmit(true, true, true, true);
        emit ValidatorSetsMigrated(5);
        vm.prank(sysAddress);
        consensusRegistry.migrateValidatorSets();

        // the rebuilt sets must mirror `currentStatus` exactly again, and the eligible count restored
        _assertSetInvariant();
        assertEq(consensusRegistry.getEligibleValidatorCount(), 5, "count not restored");
        assertEq(consensusRegistry.getValidators(ValidatorStatus.Active).length, 4);
        assertEq(consensusRegistry.getValidators(ValidatorStatus.Staked).length, 1);
        assertEq(consensusRegistry.getValidators(ValidatorStatus.PendingActivation).length, 1);

        // idempotent: re-running leaves state unchanged
        vm.prank(sysAddress);
        consensusRegistry.migrateValidatorSets();
        _assertSetInvariant();
        assertEq(consensusRegistry.getEligibleValidatorCount(), 5, "count drifted on re-run");
    }

    function test_migrateValidatorSets_noopOnFreshGenesis() public {
        // a freshly seeded genesis already satisfies the invariant; migrate must leave it unchanged
        _assertSetInvariant();
        uint256 countBefore = consensusRegistry.getEligibleValidatorCount();

        vm.prank(sysAddress);
        consensusRegistry.migrateValidatorSets();

        _assertSetInvariant();
        assertEq(consensusRegistry.getEligibleValidatorCount(), countBefore);
        assertEq(consensusRegistry.getValidators(ValidatorStatus.Active).length, 4);
    }

    function test_migrateValidatorSets_reindexesBlsReverseLookup() public {
        // emulate a deployment whose BLS reverse index is keyed by keccak256(blsPubkey) rather than the
        // canonical `_blsKeyId` (x-coordinate) used by every current read path
        for (uint256 i; i < initialValidators.length; ++i) {
            bytes memory pubkey = initialBlsPubkeys[i];
            address v = initialValidators[i].validatorAddress;

            _storeBlsReverseIndex(_blsKeyIdLocal(pubkey), address(0));
            _storeBlsReverseIndex(keccak256(pubkey), v);

            assertFalse(consensusRegistry.isValidator(pubkey), "reverse index should miss pre-migration");
        }

        vm.prank(sysAddress);
        consensusRegistry.migrateValidatorSets();

        // every validator now resolves through the `_blsKeyId`-keyed slot, and the stale slot is cleared
        for (uint256 i; i < initialValidators.length; ++i) {
            assertTrue(consensusRegistry.isValidator(initialBlsPubkeys[i]), "reverse index reindexed");
        }
    }

    function test_migrateValidatorSets_revertsForNonSystemCaller() public {
        vm.expectRevert(abi.encodeWithSelector(SystemCallable.OnlySystemCall.selector, address(this)));
        consensusRegistry.migrateValidatorSets();
    }

    function _mintAndStake(address validatorAddr, uint256 secret) internal {
        vm.prank(crOwner);
        consensusRegistry.mint(validatorAddr);
        vm.deal(validatorAddr, stakeAmount_);
        vm.prank(validatorAddr);
        consensusRegistry.stake{ value: stakeAmount_ }(
            _blsDummyPubkeyFromSecret(secret), IStakeManager.ProofOfPossession(_blsDummySigFromSecret(secret))
        );
    }

    /// @dev Clears `validatorSets` (storage slot 42) and `eligibleValidatorCount` (slot 43) to emulate
    /// a pre-sets deployment. `validatorSets` is `mapping(uint8 => EnumerableSet.AddressSet)`, where
    /// `AddressSet` wraps `Set { bytes32[] _values; mapping(bytes32 => uint256) _positions }`; the
    /// `_positions` entries must be cleared too, else `add` would treat the member as already present
    /// and skip it. The post-clear `getValidators(...).length == 0` assertions in the test double as a
    /// guard that these slot numbers are correct.
    function _clearValidatorSets() internal {
        ValidatorStatus[5] memory statuses = [
            ValidatorStatus.Staked,
            ValidatorStatus.PendingActivation,
            ValidatorStatus.Active,
            ValidatorStatus.PendingExit,
            ValidatorStatus.Exited
        ];
        for (uint256 s; s < statuses.length; ++s) {
            address[] memory members = consensusRegistry.getValidators(statuses[s]);
            bytes32 base = keccak256(abi.encode(uint256(uint8(statuses[s])), uint256(42)));
            vm.store(address(consensusRegistry), base, bytes32(0)); // _values length = 0
            for (uint256 i; i < members.length; ++i) {
                bytes32 posSlot =
                    keccak256(abi.encode(bytes32(uint256(uint160(members[i]))), uint256(base) + 1));
                vm.store(address(consensusRegistry), posSlot, bytes32(0)); // _positions[member] = 0
            }
        }
        vm.store(address(consensusRegistry), bytes32(uint256(43)), bytes32(0)); // eligibleValidatorCount = 0
    }

    /// @dev Writes `blsPubkeyHashToValidator[key] = v` directly. The mapping lives at storage slot 16
    /// (see `forge inspect ConsensusRegistry storage-layout`).
    function _storeBlsReverseIndex(bytes32 key, address v) internal {
        bytes32 slot = keccak256(abi.encode(key, uint256(16)));
        vm.store(address(consensusRegistry), slot, bytes32(uint256(uint160(v))));
    }

    /// @dev Mirrors `ConsensusRegistry._blsKeyId`: keccak of the 96-byte compressed key with the three
    /// flag bits in the most-significant byte cleared.
    function _blsKeyIdLocal(bytes memory compressed) internal pure returns (bytes32) {
        bytes memory b = bytes.concat(compressed);
        b[0] = b[0] & bytes1(0x1f);
        return keccak256(b);
    }
}
