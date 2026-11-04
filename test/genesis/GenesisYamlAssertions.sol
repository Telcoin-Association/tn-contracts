// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { LibString } from "solady/utils/LibString.sol";

/// @title Genesis Yaml Assertions
/// @notice Shared checks that the committed genesis yaml carries an account exactly as the
/// generator writes it. Comparisons run on whole entry bodies, so a failure never prints the
/// bytecode it compared
abstract contract GenesisYamlAssertions is Test {
    string internal constant GENESIS_YAML = "/deployments/genesis/precompile-config.yaml";
    string internal constant CANONICAL_BYTECODE_DIR = "/deployments/genesis/canonical-bytecode/";

    function _genesisYaml() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), GENESIS_YAML));
    }

    /// @dev Asserts `account` appears exactly once as a yaml key, followed by exactly `nonce`,
    /// `balance: 0`, the vendored `<name>.hex` bytes (`name` may name a subdirectory, as in
    /// `erc4337/EntryPointV07`) and no `storage:` block. Returns the key line's offset
    function _assertYamlAccount(
        string memory yaml,
        address account,
        string memory name,
        uint256 nonce
    )
        internal
        view
        returns (uint256 keyAt)
    {
        return _assertYamlAccount(yaml, account, name, nonce, new bytes32[](0), new bytes32[](0));
    }

    /// @dev As above, with a `storage:` block that holds exactly `slots[i]: values[i]`, in order
    function _assertYamlAccount(
        string memory yaml,
        address account,
        string memory name,
        uint256 nonce,
        bytes32[] memory slots,
        bytes32[] memory values
    )
        internal
        view
        returns (uint256 keyAt)
    {
        assertEq(slots.length, values.length, "slots and values differ in length");
        keyAt = _assertSingleKey(yaml, string.concat('"', LibString.toHexString(account), '":'), name);

        string memory code = vm.readFile(string.concat(vm.projectRoot(), CANONICAL_BYTECODE_DIR, name, ".hex"));
        string memory body = string.concat("\n  nonce: ", vm.toString(nonce), "\n  balance: 0\n  code: ", code);
        if (slots.length != 0) body = string.concat(body, "\n  storage:");
        for (uint256 i; i < slots.length; ++i) {
            body = string.concat(
                body,
                '\n    "',
                LibString.toHexString(uint256(slots[i]), 32),
                '": "',
                LibString.toHexString(uint256(values[i]), 32),
                '"'
            );
        }
        // the entry ends where the next account's quoted key begins
        body = string.concat(body, '\n"');

        uint256 eol = LibString.indexOf(yaml, "\n", keyAt);
        assertTrue(
            keccak256(bytes(LibString.slice(yaml, eol, eol + bytes(body).length))) == keccak256(bytes(body)),
            string.concat(name, ": yaml entry differs from the expected nonce, balance, code or storage")
        );
    }

    /// @dev Asserts the deployer EOA entry that marks `deployer`'s nonce-0 creation of `created`
    /// as spent: nonce 1, zero balance, no code
    function _assertYamlSpentDeployer(string memory yaml, address deployer, address created) internal pure {
        string memory key =
            string.concat('"', vm.toString(deployer), '": # use nonce 0 for creating ', vm.toString(created));
        uint256 keyAt = _assertSingleKey(yaml, key, "deployer EOA");
        string memory body = "\n  nonce: 1\n  balance: 0\n\"";
        uint256 eol = keyAt + bytes(key).length;
        assertEq(LibString.slice(yaml, eol, eol + bytes(body).length), body, "deployer EOA: yaml entry");
    }

    /// @dev Returns the yaml line that begins at `at`, without its newline
    function _yamlLineAt(string memory yaml, uint256 at) internal pure returns (string memory) {
        return LibString.slice(yaml, at, LibString.indexOf(yaml, "\n", at));
    }

    function _assertSingleKey(
        string memory yaml,
        string memory key,
        string memory name
    )
        private
        pure
        returns (uint256 keyAt)
    {
        keyAt = LibString.indexOf(yaml, key);
        assertTrue(keyAt != LibString.NOT_FOUND, string.concat(name, ": missing from yaml"));
        assertEq(
            LibString.indexOf(yaml, key, keyAt + 1), LibString.NOT_FOUND, string.concat(name, ": duplicated in yaml")
        );
        // a key starts a line
        assertTrue(keyAt == 0 || bytes(yaml)[keyAt - 1] == "\n", string.concat(name, ": key is not at a line start"));
    }
}
