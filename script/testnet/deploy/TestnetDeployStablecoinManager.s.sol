// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { StablecoinHandler } from "telcoin-contracts/contracts/stablecoin/StablecoinHandler.sol";
import { Stablecoin } from "telcoin-contracts/contracts/stablecoin/Stablecoin.sol";
import { StablecoinManager } from "../../../src/faucet/StablecoinManager.sol";
import { WTEL } from "../../../src/WTEL.sol";
import { Deployments } from "../../../deployments/Deployments.sol";

/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployStablecoinManager.s.sol \
/// --rpc-url $TN_RPC_URL -vvvv --private-key $ADMIN_PK`
contract TestnetDeployStablecoinManager is Script {
    StablecoinManager stablecoinManagerImpl;
    StablecoinManager stablecoinManager;

    bytes32 stablecoinManagerSalt; // used for both impl and proxy
    // true: enable $TEL and all `stables` | false: enable $TEL only
    bool enableAllXYZs = true;
    address[] stables;
    uint256 maxLimit;
    uint256 minLimit;

    address faucet0 = 0xE626Ce81714CB7777b1Bf8aD2323963fb3398ad5;
    address faucet1 = 0xB3FabBd1d2EdDE4D9Ced3CE352859CE1bebf7907;
    address faucet2 = 0xA3478861957661b2D8974D9309646A71271D98b9;
    address faucet3 = 0xE69151677E5aeC0B4fC0a94BFcAf20F6f0f975eB;
    address[] faucets; // will contain above
    uint256 dripAmount;
    uint256 nativeDripAmount;
    uint256 lowBalanceThreshold;

    Deployments deployments;
    address admin; // admin, support, minter, burner role

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        admin = deployments.admin;

        stablecoinManagerSalt = bytes32(bytes("StablecoinManager"));
        maxLimit = type(uint256).max;
        minLimit = 1000;
        dripAmount = 100e6; // 100 units of the stablecoin (decimals == 6)
        nativeDripAmount = 1e18; // 1 $TEL
        lowBalanceThreshold = 10_000;

        // populate stables array
        stables.push(deployments.eXYZs.eAUD);
        stables.push(deployments.eXYZs.eCAD);
        stables.push(deployments.eXYZs.eCFA);
        stables.push(deployments.eXYZs.eCHF);
        stables.push(deployments.eXYZs.eCZK);
        stables.push(deployments.eXYZs.eDKK);
        stables.push(deployments.eXYZs.eEUR);
        stables.push(deployments.eXYZs.eGBP);
        stables.push(deployments.eXYZs.eHKD);
        stables.push(deployments.eXYZs.eHUF);
        stables.push(deployments.eXYZs.eINR);
        stables.push(deployments.eXYZs.eISK);
        stables.push(deployments.eXYZs.eJPY);
        stables.push(deployments.eXYZs.eKES);
        stables.push(deployments.eXYZs.eMXN);
        stables.push(deployments.eXYZs.eNOK);
        stables.push(deployments.eXYZs.eNZD);
        stables.push(deployments.eXYZs.eSDR);
        stables.push(deployments.eXYZs.eSEK);
        stables.push(deployments.eXYZs.eSGD);
        stables.push(deployments.eXYZs.eTRY);
        stables.push(deployments.eXYZs.eUSD);
        stables.push(deployments.eXYZs.eZAR);

        faucets.push(faucet0);
        faucets.push(faucet1);
        faucets.push(faucet2);
        faucets.push(faucet3);
    }

    function run() public {
        // uncomment for debugging
        // stablecoinManager = StablecoinManager(payable(deployments.StablecoinManager));
        // stablecoinManagerImpl = StablecoinManager(payable(deployments.StablecoinManagerImpl));

        vm.startBroadcast();

        // deploy the deterministic faucet proxy pointing to latest faucet version
        stablecoinManagerImpl = new StablecoinManager{ salt: stablecoinManagerSalt }();
        StablecoinManager.StablecoinManagerInitParams memory initParams = StablecoinManager.StablecoinManagerInitParams(
            admin, admin, new address[](0), maxLimit, minLimit, new address[](0), dripAmount, nativeDripAmount
        );
        bytes memory initCall = abi.encodeWithSelector(StablecoinManager.initialize.selector, initParams);
        stablecoinManager = StablecoinManager(
            payable(address(new ERC1967Proxy{ salt: stablecoinManagerSalt }(address(stablecoinManagerImpl), initCall)))
        );

        // set configs (TEL is enabled by default)
        stablecoinManager.setNativeDripAmount(nativeDripAmount);
        stablecoinManager.setDripAmount(dripAmount);
        stablecoinManager.setLowBalanceThreshold(lowBalanceThreshold);

        // grant minter role to StablecoinManager on all tokens and disables XYZs if `!enableAllXYZs`
        bytes32 minterRole = keccak256("MINTER_ROLE");
        for (uint256 i; i < stables.length; ++i) {
            Stablecoin(stables[i]).grantRole(minterRole, address(stablecoinManager));

            if (!enableAllXYZs && stablecoinManager.isEnabledXYZ(stables[i])) {
                stablecoinManager.UpdateXYZ(stables[i], false, maxLimit, minLimit);
            } else if (enableAllXYZs && !stablecoinManager.isEnabledXYZ(stables[i])) {
                stablecoinManager.UpdateXYZ(stables[i], true, maxLimit, minLimit);
            }
        }

        bytes32 faucetRole = keccak256("FAUCET_ROLE");
        for (uint256 i; i < faucets.length; ++i) {
            stablecoinManager.grantRole(faucetRole, faucets[i]);
        }

        vm.stopBroadcast();

        // asserts
        assert(stablecoinManager.isEnabledXYZ(address(0x0)));
        assert(stablecoinManager.getEnabledXYZs().length == 23);
        assert(stablecoinManager.getEnabledXYZsWithMetadata().length == 23);
        assert(minterRole == Stablecoin(stables[0]).MINTER_ROLE());
        for (uint256 i; i < stables.length; ++i) {
            assert(Stablecoin(stables[i]).hasRole(minterRole, address(stablecoinManager)));
            assert(stablecoinManager.isEnabledXYZ(stables[i]) == enableAllXYZs);
        }
        for (uint256 i; i < faucets.length; ++i) {
            assert(stablecoinManager.hasRole(stablecoinManager.FAUCET_ROLE(), faucets[i]));
        }
        assert(stablecoinManager.getDripAmount() == dripAmount);
        assert(stablecoinManager.getNativeDripAmount() == nativeDripAmount);

        // logs
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(stablecoinManager))), 20), dest, ".StablecoinManager"
        );
    }
}
