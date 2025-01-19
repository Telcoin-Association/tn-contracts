// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {LibString} from "solady/utils/LibString.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ConsensusRegistry} from "src/consensus/ConsensusRegistry.sol";
import {IConsensusRegistry} from "src/consensus/interfaces/IConsensusRegistry.sol";

/// @title ConsensusRegistry Genesis Storage Config Generator
/// @notice Generates a .txt file comprising the storage slots and their values written by `initialize()`
/// Used by Telcoin-Network protocol to instantiate the contract with required configuration at genesis

/// @dev Usage: `forge script script/GenerateConsensusRegistryStorage.s.sol -vvvv`
contract GenerateConsensusRegistryStorage is Script, Test {
    ConsensusRegistry consensusRegistryImpl;
    ConsensusRegistry recordedRegistry;

    /// @dev Config: set all variables known outside of genesis time here
    address public rwTEL = address(0x7e1);
    uint256 public stakeAmount = 1_000_000 ether;
    uint256 public minWithdrawAmount = 10_000 ether;
    IConsensusRegistry.ValidatorInfo[] initialValidators;
    address public owner = address(0x42);

    /// @dev Config: these will be overwritten into collision-resistant labels and replaced when known at genesis
    IConsensusRegistry.ValidatorInfo public validatorInfo1;
    IConsensusRegistry.ValidatorInfo public validatorInfo2;
    IConsensusRegistry.ValidatorInfo public validatorInfo3;
    IConsensusRegistry.ValidatorInfo public validatorInfo4;
    bytes32 constant VALIDATOR_1_BLS_A = keccak256("VALIDATOR_1_BLS_A");
    bytes32 constant VALIDATOR_1_BLS_B = keccak256("VALIDATOR_1_BLS_B");
    bytes32 constant VALIDATOR_1_BLS_C = keccak256("VALIDATOR_1_BLS_C");
    bytes validator1BlsPubkey;

    bytes32 constant VALIDATOR_2_BLS_A = keccak256("VALIDATOR_2_BLS_A");
    bytes32 constant VALIDATOR_2_BLS_B = keccak256("VALIDATOR_2_BLS_B");
    bytes32 constant VALIDATOR_2_BLS_C = keccak256("VALIDATOR_2_BLS_C");
    bytes validator2BlsPubkey;

    bytes32 constant VALIDATOR_3_BLS_A = keccak256("VALIDATOR_3_BLS_A");
    bytes32 constant VALIDATOR_3_BLS_B = keccak256("VALIDATOR_3_BLS_B");
    bytes32 constant VALIDATOR_3_BLS_C = keccak256("VALIDATOR_3_BLS_C");
    bytes validator3BlsPubkey;

    bytes32 constant VALIDATOR_4_BLS_A = keccak256("VALIDATOR_4_BLS_A");
    bytes32 constant VALIDATOR_4_BLS_B = keccak256("VALIDATOR_4_BLS_B");
    bytes32 constant VALIDATOR_4_BLS_C = keccak256("VALIDATOR_4_BLS_C");
    bytes validator4BlsPubkey;

    bytes32 VALIDATOR_1_ED25519 = keccak256("VALIDATOR_1_ED25519");
    bytes32 VALIDATOR_2_ED25519 = keccak256("VALIDATOR_2_ED25519");
    bytes32 VALIDATOR_3_ED25519 = keccak256("VALIDATOR_3_ED25519");
    bytes32 VALIDATOR_4_ED25519 = keccak256("VALIDATOR_4_ED25519");

    address public validator1 = address(0xbabe);
    address public validator2 = address(0xbeefbabe);
    address public validator3 = address(0xdeadbeefbabe);
    address public validator4 = address(0xc0ffeebabe);

    // misc utils
    bytes32[] writtenStorageSlots;
    bytes32 sharedBLSWord;

    function setUp() public {
        consensusRegistryImpl = new ConsensusRegistry();

        validator1BlsPubkey = abi.encodePacked(
            VALIDATOR_1_BLS_A,
            VALIDATOR_1_BLS_B,
            VALIDATOR_1_BLS_C
        );
        validator2BlsPubkey = abi.encodePacked(
            VALIDATOR_2_BLS_A,
            VALIDATOR_2_BLS_B,
            VALIDATOR_2_BLS_C
        );
        validator3BlsPubkey = abi.encodePacked(
            VALIDATOR_3_BLS_A,
            VALIDATOR_3_BLS_B,
            VALIDATOR_3_BLS_C
        );
        validator4BlsPubkey = abi.encodePacked(
            VALIDATOR_4_BLS_A,
            VALIDATOR_4_BLS_B,
            VALIDATOR_4_BLS_C
        );

        // populate `initialValidators` array with base struct from storage
        validatorInfo1 = IConsensusRegistry.ValidatorInfo(
            validator1BlsPubkey,
            VALIDATOR_1_ED25519,
            validator1,
            uint32(0),
            uint32(0),
            uint24(1),
            IConsensusRegistry.ValidatorStatus.Active
        );
        initialValidators.push(validatorInfo1);

        validatorInfo2 = IConsensusRegistry.ValidatorInfo(
            validator2BlsPubkey,
            VALIDATOR_2_ED25519,
            validator2,
            uint32(0),
            uint32(0),
            uint24(2),
            IConsensusRegistry.ValidatorStatus.Active
        );
        initialValidators.push(validatorInfo2);

        validatorInfo3 = IConsensusRegistry.ValidatorInfo(
            validator3BlsPubkey,
            VALIDATOR_3_ED25519,
            validator3,
            uint32(0),
            uint32(0),
            uint24(3),
            IConsensusRegistry.ValidatorStatus.Active
        );
        initialValidators.push(validatorInfo3);

        validatorInfo4 = IConsensusRegistry.ValidatorInfo(
            validator4BlsPubkey,
            VALIDATOR_4_ED25519,
            validator4,
            uint32(0),
            uint32(0),
            uint24(4),
            IConsensusRegistry.ValidatorStatus.Active
        );
        initialValidators.push(validatorInfo4);
    }

    function run() public {
        vm.startBroadcast();

        vm.startStateDiffRecording();
        recordedRegistry = ConsensusRegistry(
            payable(
                address(new ERC1967Proxy(address(consensusRegistryImpl), ""))
            )
        );
        recordedRegistry.initialize(
            address(rwTEL),
            stakeAmount,
            minWithdrawAmount,
            initialValidators,
            owner
        );
        Vm.AccountAccess[] memory records = vm.stopAndReturnStateDiff();

        // loop through all records to identify written storage slots so their final (current) value can later be read
        // this is necessary because `AccountAccess.storageAccesses` contains duplicates (due to re-writes on a slot)
        for (uint256 i; i < records.length; ++i) {
            // grab all slots with recorded state changes associated with `consensusRegistry`
            uint256 storageAccessesLen = records[i].storageAccesses.length;
            for (uint256 j; j < storageAccessesLen; ++j) {
                VmSafe.StorageAccess memory currentStorageAccess = records[i]
                    .storageAccesses[j];
                // sanity check the slot is relevant to registry
                assertEq(
                    currentStorageAccess.account,
                    address(recordedRegistry)
                );

                if (currentStorageAccess.isWrite) {
                    // check `writtenStorageSlots` to skip duplicates, since some slots are updated multiple times
                    bool isDuplicate;
                    for (uint256 k; k < writtenStorageSlots.length; ++k) {
                        if (
                            writtenStorageSlots[k] == currentStorageAccess.slot
                        ) {
                            isDuplicate = true;
                            break;
                        }
                    }

                    // store non-duplicate storage slots to read from later
                    if (!isDuplicate) {
                        writtenStorageSlots.push(currentStorageAccess.slot);
                    }
                }
            }
        }

        string memory root = vm.projectRoot();
        string memory dest = string.concat(
            root,
            "/deployments/consensus-registry-storage.yaml"
        );
        vm.writeLine(dest, "---"); // indicate yaml format

        // read all unique storage slots touched by `initialize()` and fetch their final value
        for (uint256 i; i < writtenStorageSlots.length; ++i) {
            // load slot value
            bytes32 currentSlot = writtenStorageSlots[i];
            bytes32 slotValue = vm.load(address(recordedRegistry), currentSlot);

            // check if value is a validator ecdsaPubkey and assign collision-resistant label for replacement
            if (uint256(slotValue) == uint256(uint160(validator1))) {
                slotValue = keccak256("VALIDATOR_1_ECDSA");
            } else if (uint256(slotValue) == uint256(uint160(validator2))) {
                slotValue = keccak256("VALIDATOR_2_ECDSA");
            } else if (uint256(slotValue) == uint256(uint160(validator3))) {
                slotValue = keccak256("VALIDATOR_3_ECDSA");
            } else if (uint256(slotValue) == uint256(uint160(validator4))) {
                slotValue = keccak256("VALIDATOR_4_ECDSA");
            }

            // write slot and value to file
            string memory slot = LibString.toHexString(
                uint256(currentSlot),
                32
            );
            string memory value = LibString.toHexString(uint256(slotValue), 32);
            string memory entry = string.concat(slot, ": ", value);

            vm.writeLine(dest, entry);
        }

        vm.stopBroadcast();
    }
}

/* below are slots that will be dynamic depending on genesis config (number of validators, committee size & content)
these are kept here as they may be relevant to keep track of depending on whether client runs this script at genesis

`epochInfo[0:2].committee.length == 4` (only 0-2 are set)
0xAF33537D204B7C8488A91AD2A40F2C043712BAD394401B7DD7BD4CB801F23101 : `epochInfo[0].committee.length == 4`
0xAF33537D204B7C8488A91AD2A40F2C043712BAD394401B7DD7BD4CB801F23103 : `epochInfo[1].committee.length == 4`
0xAF33537D204B7C8488A91AD2A40F2C043712BAD394401B7DD7BD4CB801F23105 : `epochInfo[2].committee.length == 4`
0xAF33537D204B7C8488A91AD2A40F2C043712BAD394401B7DD7BD4CB801F23107 : `epochInfo[3].committee.length == 0`

`futureEpochInfo[0:2].committee.length` (only 0-2 are set)
0xAF33537D204B7C8488A91AD2A40F2C043712BAD394401B7DD7BD4CB801F23109 : `futureEpochInfo[0].committee.length == 4`
0xAF33537D204B7C8488A91AD2A40F2C043712BAD394401B7DD7BD4CB801F2310a : `futureEpochInfo[1].committee.length == 4`
0xAF33537D204B7C8488A91AD2A40F2C043712BAD394401B7DD7BD4CB801F2310b : `futureEpochInfo[2].committee.length == 4`
0xAF33537D204B7C8488A91AD2A40F2C043712BAD394401B7DD7BD4CB801F2310c : `futureEpochInfo[3].committee.length == 0`

`validator[1:4].packedSlot` ->
`validators[1:4].packed(currentStatus.validatorIndex.exitEpoch.activationEpoch.ecdsaPubkey)`
0x8127B3D06D1BC4FC33994FE62C6BB5AC3963BB2D1BCB96F34A40E1BDC5624A2C : 0x20000010000000000000000000000000000000000000000000000000000BABE
0x8127B3D06D1BC4FC33994FE62C6BB5AC3963BB2D1BCB96F34A40E1BDC5624A2F : 0x2000002000000000000000000000000000000000000000000000000BEEFBABE
0x8127B3D06D1BC4FC33994FE62C6BB5AC3963BB2D1BCB96F34A40E1BDC5624A32 : 0x200000300000000000000000000000000000000000000000000DEADBEEFBABE
0x8127B3D06D1BC4FC33994FE62C6BB5AC3963BB2D1BCB96F34A40E1BDC5624A35 : 0x20000040000000000000000000000000000000000000000000000C0FFEEBABE

`validators.length` (includes undefined placeholder `validatorIndex == 0`)
0xAF33537D204B7C8488A91AD2A40F2C043712BAD394401B7DD7BD4CB801F2310D : `validators.length == 5`

`numGenesisValidators`
0xaf33537d204b7c8488a91ad2a40f2c043712bad394401b7dd7bd4cb801f2310E : `numGenesisValidators == 4`

stakeInfo.validatorIndex -> `keccak256(abi.encodePacked(validator, stakeInfo.slot))`
`keccak256(abi.encodePacked(validator1, stakeInfo.slot))`          : `validatorIndex(1)`
`keccak256(abi.encodePacked(validator2, stakeInfo.slot))`          : `validatorIndex(2)`
`keccak256(abi.encodePacked(validator3, stakeInfo.slot))`          : `validatorIndex(3)`
`keccak256(abi.encodePacked(validator4, stakeInfo.slot))`          : `validatorIndex(4)`
*/
