// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { console2 } from "forge-std/console2.sol";
import { MainnetDeployBase } from "../MainnetDeployBase.sol";

/// @title Deploy the canonical Safe v1.3.0 suite on Telcoin Network mainnet
///
/// @notice Deploys the nine contracts of the safe-deployments v1.3.0 `canonical` registry at
///         their cross-chain addresses by replaying their original Ethereum deployments through
///         the Arachnid proxy with salt 0. With the suite in place, a v1.3.0 counterfactual Safe
///         created on another chain can be created on TN at the same address from the same
///         parameters. The v1.4.1 suite is genesis-assigned and untouched by this script.
///
/// @notice The v1.3.0 proxy factory does not check that the singleton has code. A factory live
///         before its singletons would let anyone create a counterfactual Safe against an empty
///         singleton (`setup` silently does nothing) and later call `setup` with their own
///         owners. The factory is therefore deployed only once GnosisSafe, GnosisSafeL2 and the
///         fallback handler are already live on chain when the script starts. A fresh chain
///         takes two runs: the first deploys everything except the factory, the second deploys
///         the factory. This holds however forge batches the transactions.
///
/// @dev Vendored initcode and its provenance: deployments/canonical-initcode/README.md
///
/// @dev Usage: `forge script script/mainnet/deploy/MainnetDeploySafeV130.s.sol -vvvv \
///      --rpc-url $TN_MAINNET_RPC_URL --private-key $DEPLOYER_PK --broadcast`
contract MainnetDeploySafeV130 is MainnetDeployBase {
    struct Component {
        string name;
        address canonical;
        bytes32 initcodeHash;
        bytes32 runtimeHash;
    }

    /// @dev Every v1.3.0 canonical contract was deployed through the Arachnid proxy with salt 0
    bytes32 internal constant SALT = bytes32(0);

    function run() public {
        _loadMainnet();
        Component[9] memory components = _components();

        // index 8 is the factory; components 0-2 must be live before it may be deployed
        bool factoryPrerequisitesLive = components[0].canonical.code.length != 0
            && components[1].canonical.code.length != 0 && components[2].canonical.code.length != 0;

        vm.startBroadcast();
        for (uint256 i; i < components.length; ++i) {
            Component memory c = components[i];
            if (i == components.length - 1 && c.canonical.code.length == 0 && !factoryPrerequisitesLive) {
                console2.log("GnosisSafeProxyFactory deferred: re-run once the singletons are confirmed on chain");
                continue;
            }

            bytes memory initcode = _readInitcode(string.concat("safe-v1.3.0/", c.name, ".hex"), c.initcodeHash);
            address deployed = _deployDeterministic(SALT, initcode, c.name);
            require(deployed == c.canonical, string.concat("MainnetDeploySafeV130: non-canonical address for ", c.name));
            _requireCodehash(deployed, c.runtimeHash, c.name);
        }
        vm.stopBroadcast();

        for (uint256 i; i < components.length; ++i) {
            if (components[i].canonical.code.length == 0) continue;
            _record(string.concat(".safeV130.", components[i].name), components[i].canonical);
        }
    }

    /// @dev Deployment order: both singletons, the fallback handler and the delegatecall
    ///      libraries first, the proxy factory last. Runtime hashes are those of the Ethereum
    ///      mainnet deployments; none of these contracts embeds a chain id, and each sits at
    ///      the same address everywhere, so the deployed bytes are identical on every chain.
    function _components() internal pure returns (Component[9] memory c) {
        c[0] = Component(
            "GnosisSafe",
            0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552,
            0x30632ce72e4de7408243bfe08d3359ce0f494543f08c113cc4d4232282bf6c6c,
            0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e
        );
        c[1] = Component(
            "GnosisSafeL2",
            0x3E5c63644E683549055b9Be8653de26E0B4CD36E,
            0x49f30800a6ac5996a48b80c47ff20f19f8728812498a2a7fe75a14864fab6438,
            0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f
        );
        c[2] = Component(
            "CompatibilityFallbackHandler",
            0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4,
            0x272190de126b4577e187d9f00b9ca5daeae76d771965d734876891a51f9c43d8,
            0x03e69f7ce809e81687c69b19a7d7cca45b6d551ffdec73d9bb87178476de1abf
        );
        c[3] = Component(
            "MultiSend",
            0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761,
            0x319ec670832dc89915c70968563439764e1f45db07ce205115fef547c4d7a7ba,
            0x0208282bd262360d0320862c5ac70f375f5ed3b9d89a83a615b4d398415bdc83
        );
        c[4] = Component(
            "MultiSendCallOnly",
            0x40A2aCCbd92BCA938b02010E17A5b8929b49130D,
            0x35e699c3e43ec3e03a101730ab916c5e540893eaaf806451e929d138c3ff53b7,
            0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad
        );
        c[5] = Component(
            "SignMessageLib",
            0xA65387F16B013cf2Af4605Ad8aA5ec25a2cbA3a2,
            0xf351650cab7419d02a85bc577276cc69272ea9ba117a56f599039531d1689962,
            0x3ac65dea3cc9dd0d7b7b800f834e3d73415b4e944bb94555c3e4a08fb137e918
        );
        c[6] = Component(
            "CreateCall",
            0x7cbB62EaA69F79e6873cD1ecB2392971036cFAa4,
            0x81b71c6ca3958124fc3f1368afb83eff85b35d12725f55c65360842a19119e35,
            0x8155d988823a4f6f1bcbc76a64af8e510c4ce68819290d43cf24956bd24dee82
        );
        c[7] = Component(
            "SimulateTxAccessor",
            0x59AD6735bCd8152B84860Cb256dD9e96b85F69Da,
            0xe5993412e711df6cc93d867252a993881b9e5ba1f9458be7b69e27499b52e232,
            0xb3fb9763869f2c09a2ac5a425d2dd6060bf7ef46b3899049d71a711e71e00f04
        );
        c[8] = Component(
            "GnosisSafeProxyFactory",
            0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2,
            0x13d77c68fe7529013a9a57a295a785084b80e3d6ae9358c7f334752e0c8615f4,
            0x337d7f54be11b6ed55fef7b667ea5488db53db8320a05d1146aa4bd169a39a9b
        );
    }
}
