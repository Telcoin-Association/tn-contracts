// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
import { WTEL } from "../src/WTEL.sol";
import { Deployments } from "../deployments/Deployments.sol";
import { GenesisPrecompiler } from "../deployments/genesis/GenesisPrecompiler.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";

/// @title Genesis Precompile Config Generator
/// @notice Generates a yaml file comprising the storage slots and their values
/// Used by Telcoin-Network protocol to instantiate the contracts with required configuration at genesis

/// @dev Usage: `forge script script/GenerateGenesisPrecompileConfig.s.sol -vvvv`
contract GenerateGenesisPrecompileConfig is GenesisPrecompiler, Script {
    Deployments deployments;
    string root;
    string dest;
    string fileName = "/deployments/genesis/precompile-config.yaml";

    uint64 sharedNonce = 0;
    uint256 sharedBalance = 0;

    uint256 public constant telTotalSupply = 100_000_000_000e18;
    /// @dev TEL genesis allocation to the governance safe for gas
    uint256 public constant governanceInitialBalance = 10e18;
    // will be further decremented at genesis by protocol, based on initial validators stake
    uint256 telSupplyBalance = telTotalSupply - governanceInitialBalance;

    // Safe infrastructure
    WTEL wTEL;
    Safe safeImpl;
    SafeProxyFactory safeProxyFactory;
    Safe governanceSafe;
    address[] safeOwners;
    uint256 safeThreshold;

    function setUp() public {
        root = vm.projectRoot();
        dest = string.concat(root, fileName);
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        wTEL = WTEL(payable(deployments.wTEL));
        safeImpl = Safe(payable(deployments.SafeImpl));
        safeProxyFactory = SafeProxyFactory(deployments.SafeProxyFactory);
        governanceSafe = Safe(payable(deployments.Safe));

        _setGovernanceSafeConfig();
    }

    function run() public {
        vm.startBroadcast();

        // initialize clean yaml file
        if (vm.exists(dest)) vm.removeFile(dest);
        vm.writeLine(dest, "---"); // indicate yaml format

        // wTEL
        address simulatedWTEL = address(payable(instantiateWTEL()));
        assertFalse(yamlAppendGenesisAccount(dest, simulatedWTEL, address(wTEL), sharedNonce, sharedBalance));

        // safe impl (has storage)
        address simulatedSafeImpl = address(instantiateSafeImpl());
        assertTrue(yamlAppendGenesisAccount(dest, simulatedSafeImpl, address(safeImpl), sharedNonce, sharedBalance));

        // safe proxy factory (no storage)
        address simulatedSafeFactory = address(instantiateSafeProxyFactory());
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedSafeFactory, address(safeProxyFactory), sharedNonce, sharedBalance
            )
        );

        // governance safe (has storage)
        address simulatedSafe = address(instantiateGovernanceSafe());
        assertTrue(
            yamlAppendGenesisAccount(dest, simulatedSafe, address(governanceSafe), sharedNonce, governanceInitialBalance)
        );

        // TEL supply allocation to 0xde1e7e
        vm.writeLine(dest, '"0x0000000000000000000000000000000000de1e7e":');
        vm.writeLine(dest, "  nonce: 0");
        vm.writeLine(dest, string.concat("  balance: ", vm.toString(telSupplyBalance)));

        // EIP-2935 and EIP-4788 system contracts
        instantiateEIP2935AndEIP4788();

        vm.stopBroadcast();
    }

    function _setGovernanceSafeConfig() internal {
        safeOwners.push(0x2358CF87e62618663E781CE52EE7a7F777aC4e65);
        safeOwners.push(0x84B0fc1Bb26212a1BfFb48F03B010FDA4aDCe3c9);
        safeOwners.push(0x707856C0089Fd59d9e686A47784d5DAd7c0784c4);
        safeOwners.push(0xfeCeE4Ab07127fFf4EE4a3BA61dF5fD7B906F84C);
        safeOwners.push(0xf5b3944629F9303fa94670B2a6611eE1b11Cd538);
        safeOwners.push(0xd7e88D492Dc992127384215b8555C9305C218299);
        safeThreshold = 3;
    }

    function instantiateWTEL() public returns (WTEL simulatedDeployment) {
        simulatedDeployment = new WTEL();
        copyContractState(address(simulatedDeployment), address(wTEL), new bytes32[](0));
    }

    function instantiateSafeImpl() public returns (Safe simulatedDeployment) {
        vm.startStateDiffRecording();
        simulatedDeployment = new Safe();
        Vm.AccountAccess[] memory safeImplRecords = vm.stopAndReturnStateDiff();

        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), safeImplRecords);
        copyContractState(address(simulatedDeployment), address(safeImpl), slots);
    }

    function instantiateSafeProxyFactory() public returns (SafeProxyFactory simulatedDeployment) {
        simulatedDeployment = new SafeProxyFactory();
        copyContractState(address(simulatedDeployment), address(safeProxyFactory), new bytes32[](0));
    }

    function instantiateGovernanceSafe() public returns (Safe simulatedDeployment) {
        vm.startStateDiffRecording();

        address to; bytes memory data; address fallbackHandler;
        address paymentToken; uint256 payment; address paymentReceiver;
        bytes memory setupData = abi.encodeWithSelector(
            Safe.setup.selector,
            safeOwners, safeThreshold,
            to, data, fallbackHandler, paymentToken, payment, paymentReceiver);
        simulatedDeployment = Safe(payable(address(safeProxyFactory.createProxyWithNonce(address(safeImpl), setupData, 0x0))));

        Vm.AccountAccess[] memory safeRecords = vm.stopAndReturnStateDiff();
        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), safeRecords);
        copyContractState(address(simulatedDeployment), address(governanceSafe), slots);
    }

    /// @dev Writes EIP-2935 and EIP-4788 system contracts configuration directly to the yaml
    function instantiateEIP2935AndEIP4788() internal {
        // EIP-2935: Historic Block Hashes
        vm.writeLine(dest, '"0x0000F90827F1C53a10cb7A02335B175320002935": # historic block hashes');
        vm.writeLine(dest, "  nonce: 0");
        vm.writeLine(dest, "  balance: 0");
        vm.writeLine(
            dest,
            "  code: 0x3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500"
        );

        // EIP-4788: Beacon Block Roots
        vm.writeLine(dest, '"0x000f3df6d732807ef1319fb7b8bb8522d0beac02": # consensus block roots');
        vm.writeLine(dest, "  nonce: 0");
        vm.writeLine(dest, "  balance: 0");
        vm.writeLine(
            dest,
            "  code: 0x3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500"
        );

        // Factory/Creator Nonces
        vm.writeLine(
            dest,
            '"0x0B799C86a49DEeb90402691F1041aa3AF2d3C875": # use nonce 0 for creating 0x000f3df6d732807ef1319fb7b8bb8522d0beac02'
        );
        vm.writeLine(dest, "  nonce: 1");
        vm.writeLine(dest, "  balance: 0");

        vm.writeLine(
            dest,
            '"0x3462413Af4609098e1E27A490f554f260213D685": # use nonce 0 for creating 0x0000F90827F1C53a10cb7A02335B175320002935'
        );
        vm.writeLine(dest, "  nonce: 1");
        vm.writeLine(dest, "  balance: 0");
    }
}
