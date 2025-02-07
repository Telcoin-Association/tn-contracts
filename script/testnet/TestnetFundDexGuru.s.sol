// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { Stablecoin } from "telcoin-contracts/contracts/stablecoin/Stablecoin.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { WTEL } from "../../src/WTEL.sol";

/// @dev Usage: `forge script script/TestnetFundDexGuru.s.sol -vvvv --rpc-url $TN_RPC_URL --private-key $ADMIN_PK`
contract TestnetFundDexGuru is Script {
    // config: send $wTEL and stables to the following address
    address dexGuru = 0x3da87b1c3743BD2dA60DF2ef1BC6F26Ef9Da6086;
    uint256 telAmount;
    uint256 wTelAmount;
    uint256 stablecoinAmount;

    WTEL wTEL;
    Stablecoin[] stables; // 11 canonical Telcoin stablecoins

    // json source
    Deployments deployments;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        telAmount = 1e18;
        wTelAmount = 10_000e18; // wTel.decimals() == 18
        stablecoinAmount = 10_000e6; // stablecoin.decimals() == 6

        wTEL = WTEL(payable(deployments.wTEL));
        // populate array for iteration
        stables.push(Stablecoin(deployments.eAUD));
        stables.push(Stablecoin(deployments.eCAD));
        stables.push(Stablecoin(deployments.eCHF));
        stables.push(Stablecoin(deployments.eEUR));
        stables.push(Stablecoin(deployments.eGBP));
        stables.push(Stablecoin(deployments.eHKD));
        stables.push(Stablecoin(deployments.eJPY));
        stables.push(Stablecoin(deployments.eMXN));
        stables.push(Stablecoin(deployments.eNOK));
        stables.push(Stablecoin(deployments.eSDR));
        stables.push(Stablecoin(deployments.eSGD));
    }

    function run() public {
        vm.startBroadcast(); // must be called by minter role

        // send $TEL for gas
        (bool r,) = dexGuru.call{ value: telAmount }("");
        require(r);

        // wrap $TEL and send $wTEL
        wTEL.deposit{ value: wTelAmount }();
        wTEL.transfer(dexGuru, wTelAmount);

        // mint and transfer stables
        for (uint256 i; i < stables.length; ++i) {
            stables[i].mint(stablecoinAmount);
            stables[i].transfer(dexGuru, stablecoinAmount);
        }

        vm.stopBroadcast();
    }
}
