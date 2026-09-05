// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Test } from "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ERC1967Utils } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { Stablecoin } from "../../src/testnet/Stablecoin.sol";
import { ShieldVault } from "../../src/shield/ShieldVault.sol";

/// @title ShieldVault etch-versus-deploy tests
///
/// @notice Pins what etching the artifact's `deployedBytecode` (the node's e2e harness does this
///         instead of deploying) costs, so nobody reads the etched implementation as equivalent to
///         a deployed one: the constructor never runs, so the etched implementation is not locked
///         and anyone can initialize it; and UUPS's `__self` immutable, filled by the constructor
///         at deployment, is zero in the artifact, so an owner upgrade through a proxy over an
///         etched implementation reverts with `UUPSUnauthorizedCallContext` where the same upgrade
///         over a deployed implementation succeeds.
/// @dev `vm.getDeployedCode` returns the compiler's `deployedBytecode` with its immutable
///      references zero-filled, byte for byte what `artifacts/ShieldVault.json` carries and the
///      harness etches.
contract ShieldVaultEtchTest is Test {
    Stablecoin token;
    address governance = address(0x7A0);

    /// @dev Where the artifact is etched; any codeless address would do.
    address etched = address(0x5e1f);

    function setUp() public {
        token = new Stablecoin();
        token.initialize("Telcoin eUSD", "eUSD", 6);
        vm.etch(etched, vm.getDeployedCode("ShieldVault.sol:ShieldVault"));
    }

    function _proxyOver(address impl) internal returns (ShieldVault vault) {
        bytes memory initCall = abi.encodeCall(ShieldVault.initialize, (address(token), governance));
        vault = ShieldVault(address(new ERC1967Proxy(impl, initCall)));
        assertEq(address(vault.token()), address(token), "proxy initialized");
        assertEq(vault.owner(), governance, "proxy owned by governance");
    }

    /// @dev Through a proxy the etched implementation serves shield-side state like a deployed one,
    ///      but the owner cannot upgrade it: `__self` is zero, so UUPS refuses the call context.
    function test_EtchedImplementationCannotBeUpgradedThroughItsProxy() public {
        ShieldVault vault = _proxyOver(etched);
        ShieldVault next = new ShieldVault();

        vm.prank(governance);
        vm.expectRevert(UUPSUpgradeable.UUPSUnauthorizedCallContext.selector);
        vault.upgradeToAndCall(address(next), "");

        assertEq(
            vm.load(address(vault), ERC1967Utils.IMPLEMENTATION_SLOT),
            bytes32(uint256(uint160(etched))),
            "the refused upgrade must leave the implementation slot on the etched code"
        );
    }

    /// @dev The same upgrade, over an implementation whose constructor ran, succeeds.
    function test_DeployedImplementationUpgradesThroughItsProxy() public {
        ShieldVault deployed = new ShieldVault();
        ShieldVault vault = _proxyOver(address(deployed));
        ShieldVault next = new ShieldVault();

        vm.prank(governance);
        vault.upgradeToAndCall(address(next), "");

        assertEq(
            vm.load(address(vault), ERC1967Utils.IMPLEMENTATION_SLOT),
            bytes32(uint256(uint160(address(next)))),
            "the owner upgrade must rotate the implementation slot"
        );
        assertEq(address(vault.token()), address(token), "storage preserved across the upgrade");
    }

    /// @dev The constructor's `_disableInitializers` never ran on the etched code, so anyone can
    ///      claim the etched implementation's owner slot; a deployed one refuses.
    function test_EtchedImplementationIsInitializableByAnyone() public {
        address stranger = address(0xBAD);

        vm.prank(stranger);
        ShieldVault(etched).initialize(address(token), stranger);

        assertEq(ShieldVault(etched).owner(), stranger, "the etched implementation is unlocked");
    }
}
