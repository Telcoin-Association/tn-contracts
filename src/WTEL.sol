// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import {WETH} from "solady/tokens/WETH.sol";

contract WTEL is WETH {
    /// @dev Returns the name of the wTEL token.
    function name() public view virtual override returns (string memory) {
        return "Wrapped Telcoin";
    }

    /// @dev Returns the symbol of the token.
    function symbol() public view virtual override returns (string memory) {
        return "wTEL";
    }
}
