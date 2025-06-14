// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import {LibString} from "solady/utils/LibString.sol";

/// @title Genesis Precompiler
/// @author Telcoin Association
/// @notice Used to generate genesis precompile configuration by simulating deployment
/// to set nonce, balance, generate bytecode, and record storage slot/values

/** @notice Precompile Yaml entries are formatted thusly:
`targetAddress`: 
    `genesisAccount`:
      `nonce`: `nonce`
      `balance`: `balance`
      `code`: `runtimeCode`
      `storage:`: 
        `slotA: valueA`
        `slotB: valueB`
 */

/// @dev Precompile configuration, written to yaml and consumed by protocol at genesis
/// @notice Reth member `private_key` for testing purposes is not used
struct GenesisAccount {
    uint64 nonce;
    uint256 balance;
    bytes code;
    StorageEntry[] storageConfig;
}

/// @dev Storage key/value pair, used as Solidity equivalent to BTreeMap
struct StorageEntry {
    bytes32 slot;
    bytes32 value;
}

abstract contract GenesisPrecompiler is Test {
    mapping (address => GenesisAccount) public genesisAccounts;
    mapping (address => bytes32[]) writtenStorageSlots;

    /// @dev Populates `writtenStorageSlots` for `simulatedDeployment` with slots in `records`
    /// @param simulatedDeployment The deployed contract with storage written by simulation
    /// @param records The AccountAccesses recorded by foundry diff 
    function saveWrittenSlots(address simulatedDeployment, Vm.AccountAccess[] memory records) public virtual returns (bytes32[] memory) {
        bytes32[] storage slots = writtenStorageSlots[simulatedDeployment];
        require(slots.length == 0, "Must clear storage array before populating");

        // loop through all records to identify written storage slots so their final (current) value can later be read
        for (uint256 i; i < records.length; ++i) {
            // grab all slots with recorded state changes
            uint256 storageAccessesLen = records[i].storageAccesses.length;
            for (uint256 j; j < storageAccessesLen; ++j) {
                VmSafe.StorageAccess memory currentStorageAccess = records[i]
                    .storageAccesses[j];
                // skip records not relevant to requested contract
                if (currentStorageAccess.account != simulatedDeployment) continue;

                if (currentStorageAccess.isWrite) {
                    // check `slots` to skip duplicates, since some slots are updated multiple times
                    bool isDuplicate;
                    for (uint256 k; k < slots.length; ++k) {
                        if (
                            slots[k] == currentStorageAccess.slot
                        ) {
                            isDuplicate = true;
                            break;
                        }
                    }

                    // store non-duplicate storage slots to read from later
                    if (!isDuplicate) {
                        slots.push(currentStorageAccess.slot);
                    }
                }
            }
        }

        return slots;
    }

    /// @dev Appends a genesis account entry to given YAML file 
    /// @dev Uses current `writtenStorageSlots` values; simulation results must be populated correctly
    /// @param simulatedDeployment The simulated contract deployment whose config to copy onto `genesisTarget`
    /// @param genesisTarget The target precompile address to write to at genesis
    function yamlAppendGenesisAccount(string memory dest, address simulatedDeployment, address genesisTarget, uint64 nonce, uint256 balance) public virtual returns (bool hasStorage) {
        require(simulatedDeployment != address(0) && genesisTarget != address(0), "Invalid deployment or target address");
        GenesisAccount storage account = genesisAccounts[simulatedDeployment];
        require(account.code.length == 0, "Precompile already processed");
        account.nonce = nonce;
        account.balance = balance;
        account.code = simulatedDeployment.code;
        require(account.code.length != 0, "Contract is not deployed");

        // Convert genesisTarget to hex string (20 bytes, i.e. address) and write
        string memory targetKey = LibString.toHexString(uint256(uint160(genesisTarget)), 20);
        vm.writeLine(dest, string.concat('"', targetKey, '":'));

        // Write the genesisAccount entry with nonce, balance, and code
        vm.writeLine(dest, string.concat("  nonce: ", LibString.toString(nonce)));
        vm.writeLine(dest, string.concat("  balance: ", LibString.toString(balance)));
        vm.writeLine(dest, string.concat("  code: ", LibString.toHexString(account.code)));

        // Write the storage entries if relevant
        bytes32[] storage slots = writtenStorageSlots[simulatedDeployment];
        if (slots.length == 0) return false;

        vm.writeLine(dest, "  storage:");
        for (uint256 i; i < slots.length; ++i) {
            bytes32 slot = slots[i];
            bytes32 slotValue = vm.load(simulatedDeployment, slot);

            account.storageConfig.push(StorageEntry(slot, slotValue));

            // write to yaml
            string memory slotStr = LibString.toHexString(uint256(slot), 32);
            string memory valueStr = LibString.toHexString(uint256(slotValue), 32);
            vm.writeLine(dest, string.concat('    "', slotStr, '": "', valueStr, '"'));
        }

        return true;
    }

    /// @dev Copies runtime bytecode and the given storage slots from one address to another
    /// @notice Useful for testing genesis simulations or forking
    function copyContractState(address from, address to, bytes32[] memory slotsToCopy) public {
        vm.etch(to, from.code);

        for (uint256 i; i < slotsToCopy.length; ++i) {
            bytes32 slotToCopy = slotsToCopy[i];
            bytes32 valueToCopy = vm.load(from, slotToCopy);
            vm.store(to, slotToCopy, valueToCopy);
        }
    }
}