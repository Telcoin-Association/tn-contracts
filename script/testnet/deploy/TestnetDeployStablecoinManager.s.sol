// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { StablecoinHandler } from "../../../src/testnet/StablecoinHandler.sol";
import { Stablecoin } from "../../../src/testnet/Stablecoin.sol";
import { StablecoinManager } from "../../../src/testnet/StablecoinManager.sol";
import { Deployments } from "../../../deployments/Deployments.sol";

/// @dev Usage: `forge script script/testnet/deploy/TestnetDeployStablecoinManager.s.sol \
/// --rpc-url $TN_RPC_URL -vvvv --private-key $ADMIN_PK || --`
contract TestnetDeployStablecoinManager is Script {
    StablecoinManager stablecoinManagerImpl;
    StablecoinManager stablecoinManager;

    bytes32 stablecoinManagerSalt; // used for both impl and proxy
        // true: enable $TEL and all `stables` | false: enable $TEL only
    bool enableAllXYZs = true;
    address[] stables;
    uint256 maxLimit;
    uint256 minLimit;

    uint256 dripAmount;
    uint256 nativeDripAmount;
    uint256 baseDripCooldown;
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
        baseDripCooldown = 1 days;

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

    }

    function run() public {
        // uncomment for debugging
        // stablecoinManager = StablecoinManager(payable(deployments.StablecoinManager));
        // stablecoinManagerImpl = StablecoinManager(payable(deployments.StablecoinManagerImpl));

        vm.startBroadcast();

        // deploy the deterministic faucet proxy pointing to latest faucet version. When
        // `enableAllXYZs` is true the init loop seeds each token in `tokens_` with the baseline
        // drip amount; we pass an empty array here and rely on the post-init loop below otherwise.
        address[] memory initTokens = enableAllXYZs ? stables : new address[](0);

        stablecoinManagerImpl = new StablecoinManager{ salt: stablecoinManagerSalt }();
        StablecoinManager.StablecoinManagerInitParams memory initParams = StablecoinManager.StablecoinManagerInitParams(
            admin,
            admin,
            initTokens,
            maxLimit,
            minLimit,
            dripAmount,
            nativeDripAmount,
            baseDripCooldown
        );
        bytes memory initCall = abi.encodeWithSelector(StablecoinManager.initialize.selector, initParams);
        stablecoinManager = StablecoinManager(
            payable(address(new ERC1967Proxy{ salt: stablecoinManagerSalt }(address(stablecoinManagerImpl), initCall)))
        );

        // grant minter role to StablecoinManager on every stable
        bytes32 minterRole = keccak256("MINTER_ROLE");
        for (uint256 i; i < stables.length; ++i) {
            Stablecoin(stables[i]).grantRole(minterRole, address(stablecoinManager));
        }

        vm.stopBroadcast();

        // asserts
        assert(stablecoinManager.isEnabledXYZ(stablecoinManager.NATIVE_TOKEN_POINTER()));
        assert(stablecoinManager.getEnabledXYZs().length == 23);
        assert(stablecoinManager.getEnabledXYZsWithMetadata().length == 23);
        // 23 stablecoins + NATIVE_TOKEN_POINTER
        assert(stablecoinManager.getDrippableTokensWithDripAmount().length == 24);
        assert(minterRole == Stablecoin(stables[0]).MINTER_ROLE());
        for (uint256 i; i < stables.length; ++i) {
            assert(Stablecoin(stables[i]).hasRole(minterRole, address(stablecoinManager)));
            assert(stablecoinManager.isEnabledXYZ(stables[i]) == enableAllXYZs);
            assert(stablecoinManager.getBaselineMaxDripAmount(stables[i]) == dripAmount);
        }
        assert(stablecoinManager.getBaselineMaxDripAmount(stablecoinManager.NATIVE_TOKEN_POINTER()) == nativeDripAmount);
        assert(stablecoinManager.getBaselineDripCooldown() == baseDripCooldown);

        // logs
        string memory root = vm.projectRoot();
        string memory dest = string.concat(root, "/deployments/deployments.json");
        vm.writeJson(
            LibString.toHexString(uint256(uint160(address(stablecoinManager))), 20), dest, ".StablecoinManager"
        );
    }
}
