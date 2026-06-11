// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { WTEL } from "../../src/WTEL.sol";

/// @title Genesis WTEL Test
/// @notice Replays the genesis precompile simulation and verifies WTEL lands at its
/// vanity address with working wrapped-native behavior against the etched state
contract GenesisWTELTest is Test {
    address constant WTEL_VANITY = 0x00000000000000000000000000000000000037E1;

    WTEL wTEL;

    function setUp() public {
        // replay the genesis simulation; copies WTEL code onto the vanity address
        GenerateGenesisPrecompileConfig genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        wTEL = WTEL(payable(address(genesis.instantiateWTEL())));

        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/deployments/deployments-mainnet.json"));
        Deployments memory deployments = abi.decode(vm.parseJson(json), (Deployments));
        assertEq(deployments.WTEL, WTEL_VANITY);
        wTEL = WTEL(payable(deployments.WTEL));
    }

    function test_wtelDeployedAtVanityAddress() public view {
        assertTrue(WTEL_VANITY.code.length > 0);
        assertEq(wTEL.name(), "Wrapped Tel");
        assertEq(wTEL.symbol(), "WTEL");
        assertEq(wTEL.decimals(), 18);
    }

    /// @notice Exercises deposit, transfer, and withdraw against the genesis-etched code
    function test_wtelWrapUnwrapAtGenesisAddress() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        vm.deal(alice, 10 ether);

        vm.startPrank(alice);
        wTEL.deposit{ value: 3 ether }();
        assertEq(wTEL.balanceOf(alice), 3 ether);
        assertEq(wTEL.totalSupply(), 3 ether);

        assertTrue(wTEL.transfer(bob, 1 ether));
        assertEq(wTEL.balanceOf(bob), 1 ether);

        wTEL.withdraw(2 ether);
        assertEq(wTEL.balanceOf(alice), 0);
        assertEq(alice.balance, 9 ether);
        vm.stopPrank();

        // bare native send routes through receive() as a deposit
        vm.deal(bob, 1 ether);
        vm.prank(bob);
        (bool ok,) = payable(address(wTEL)).call{ value: 1 ether }("");
        assertTrue(ok);
        assertEq(wTEL.balanceOf(bob), 2 ether);
    }
}
