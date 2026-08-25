// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {Deployments} from "../deployments/Deployments.sol";
import {GenesisPrecompiler} from "../deployments/genesis/GenesisPrecompiler.sol";
import {Safe} from "safe-contracts/contracts/Safe.sol";
import {SafeProxyFactory} from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {CompatibilityFallbackHandler} from "safe-contracts/contracts/handler/CompatibilityFallbackHandler.sol";
import {WTEL} from "../src/WTEL.sol";

/// @title Genesis Precompile Config Generator
/// @notice Generates a yaml file comprising the storage slots and their values
/// Used by Telcoin-Network protocol to instantiate the contracts with required configuration at genesis

/// @dev The Safe suite is NOT compiled from `lib/safe-contracts`: canonical Safe v1.4.1
/// was built with solc 0.7.6, and recompiling the same source with this repo's toolchain
/// yields byte-different contracts. `SafeProxyFactory` derives proxy addresses via CREATE2
/// over its embedded proxy creation code, so non-canonical factory bytes break cross-chain
/// counterfactual Safe addresses on TN. Instead, byte-exact runtime bytecode captured from
/// the live Ethereum mainnet deployments is vendored under
/// `deployments/genesis/canonical-bytecode/` (provenance + hashes in its README) and etched
/// at the canonical addresses, mirroring how Multicall3 and the Arachnid factory are
/// already handled below.

/// @dev Usage: `forge script script/GenerateGenesisPrecompileConfig.s.sol -vvvv`
contract GenerateGenesisPrecompileConfig is GenesisPrecompiler, Script {
    Deployments deployments;
    string root;
    string dest;
    string fileName = "/deployments/genesis/precompile-config.yaml";
    string bytecodeDir = "/deployments/genesis/canonical-bytecode/";

    // ---------------------------------------------------------------------
    // Canonical Safe v1.4.1 suite — addresses identical on all EVM chains
    // ---------------------------------------------------------------------

    address constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address constant SAFE_L2_SINGLETON = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;
    address constant SAFE_PROXY_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;
    address constant SAFE_FALLBACK_HANDLER = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;
    address constant SAFE_TO_L2_SETUP = 0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54;
    address constant SAFE_MULTI_SEND = 0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526;
    address constant SAFE_MULTI_SEND_CALL_ONLY = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address constant SAFE_SIGN_MESSAGE_LIB = 0xd53cd0aB83D845Ac265BE939c57F53AD838012c9;
    address constant SAFE_CREATE_CALL = 0x9b35Af71d77eaf8d7e40252370304687390A1A52;
    address constant SAFE_SIMULATE_TX_ACCESSOR = 0x3d4BA2E0884aa488718476ca2FB8Efc291A46199;
    address constant SAFE_SINGLETON_FACTORY = 0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7;

    /// @dev keccak256 of the vendored runtime bytecode; asserted before etching
    bytes32 constant SAFE_CODEHASH = 0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4;
    bytes32 constant SAFE_L2_CODEHASH = 0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff;
    bytes32 constant SAFE_PROXY_FACTORY_CODEHASH =
        0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317;
    bytes32 constant SAFE_FALLBACK_HANDLER_CODEHASH =
        0x7c6007a5d711cea8dfd5d91f5940ec29c7f200fe511eb1fc1397b367af3c42f9;
    bytes32 constant SAFE_TO_L2_SETUP_CODEHASH =
        0x2f25df28caf984366ee584e13241707e85dcd5a6ea0c14267928dafc1fd6274b;
    bytes32 constant SAFE_MULTI_SEND_CODEHASH =
        0x0e4f7fc66550a322d1e7688e181b75e217e662a4f3f4d6a29b22bc61217c4b77;
    bytes32 constant SAFE_MULTI_SEND_CALL_ONLY_CODEHASH =
        0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939;
    bytes32 constant SAFE_SIGN_MESSAGE_LIB_CODEHASH =
        0x525c754a46b79e05543a59bb61e8de3c9eee0d955a59352409cbe67ea1077528;
    bytes32 constant SAFE_CREATE_CALL_CODEHASH =
        0x2b3060c55fcb8275653e99ad511a71f67ba76934ed66a7d74d6e68b52afff889;
    bytes32 constant SAFE_SIMULATE_TX_ACCESSOR_CODEHASH =
        0x91f82615581fc73b190b83d72e883608b25e392f72322035df1b13d51766cf8d;
    bytes32 constant SAFE_SINGLETON_FACTORY_CODEHASH =
        0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989;

    /// @dev Safe/SafeL2 `threshold` storage slot; constructors set it to 1 so the
    /// singleton itself can never be `setup()`-hijacked — replicated here since
    /// etched code never runs a constructor
    bytes32 constant SAFE_THRESHOLD_SLOT = bytes32(uint256(4));

    /// @dev EIP-161 initial nonce for a contract account. Every predeploy below exists as a real
    /// deployment on Ethereum/Sepolia/Base carrying nonce >= 1, and genesis mirrors that so TN
    /// behaves identically. This is not cosmetic for all of them: `CreateCall.performCreate`
    /// invoked directly does a CREATE from `CreateCall`'s own account, and a Safe that
    /// delegatecalls it — the governance Safe included — does a CREATE from the Safe's account.
    /// Both derive the new address from `keccak256(rlp([account, nonce]))`, so leaving these at 0
    /// would shift every such deployment one nonce off the address the identical call produces on
    /// any other chain. CREATE2 deployers (`SafeProxyFactory`, `SafeSingletonFactory`) do not read
    /// the nonce, but carry the same value for consistency.
    uint64 constant PREDEPLOY_NONCE = 1;

    uint256 sharedBalance = 0;

    uint256 public constant telTotalSupply = 100_000_000_000e18;
    /// @dev TEL genesis allocation to the governance safe for gas
    uint256 public constant governanceInitialBalance = 10e18;
    // will be further decremented at genesis by protocol, based on initial validators stake
    uint256 telSupplyBalance = telTotalSupply - governanceInitialBalance;

    // Safe infrastructure
    Safe safeImpl;
    SafeProxyFactory safeProxyFactory;
    CompatibilityFallbackHandler compatibilityFallbackHandler;
    Safe governanceSafe;
    address[] safeOwners;
    uint256 safeThreshold;

    // Wrapped TEL, genesis-assigned at the 0x...37e1 vanity address
    WTEL wTEL;

    function setUp() public {
        root = vm.projectRoot();
        dest = string.concat(root, fileName);
        // genesis-assigned addresses are identical on every network, and the mainnet
        // file holds exactly those, making it the genesis source of truth
        string memory path = string.concat(root, "/deployments/deployments-mainnet.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        safeImpl = Safe(payable(deployments.SafeImpl));
        safeProxyFactory = SafeProxyFactory(deployments.SafeProxyFactory);
        compatibilityFallbackHandler = CompatibilityFallbackHandler(deployments.CompatibilityFallbackHandler);
        governanceSafe = Safe(payable(deployments.Safe));
        wTEL = WTEL(payable(deployments.WTEL));

        // guard against deployments-mainnet.json drifting from the canonical addresses
        assertEq(address(safeImpl), SAFE_SINGLETON);
        assertEq(address(safeProxyFactory), SAFE_PROXY_FACTORY);
        assertEq(address(compatibilityFallbackHandler), SAFE_FALLBACK_HANDLER);

        _setGovernanceSafeConfig();
    }

    function run() public {
        vm.startBroadcast();

        // initialize clean yaml file
        if (vm.exists(dest)) vm.removeFile(dest);
        vm.writeLine(dest, "---"); // indicate yaml format

        // safe impl (has storage)
        address simulatedSafeImpl = address(instantiateSafeImpl());
        assertTrue(
            yamlAppendGenesisAccount(
                dest, simulatedSafeImpl, address(safeImpl), PREDEPLOY_NONCE, sharedBalance, "safe impl"
            )
        );

        // safe proxy factory (no storage)
        address simulatedSafeFactory = address(instantiateSafeProxyFactory());
        assertFalse(
            yamlAppendGenesisAccount(
                dest,
                simulatedSafeFactory,
                address(safeProxyFactory),
                PREDEPLOY_NONCE,
                sharedBalance,
                "safe proxy factory"
            )
        );

        // compatibility fallback handler (no storage), pinned to the canonical Safe v1.4.1
        // address so Safe tooling that defaults the fallback handler resolves it on TN
        address simulatedFallbackHandler = address(instantiateCompatibilityFallbackHandler());
        assertFalse(
            yamlAppendGenesisAccount(
                dest,
                simulatedFallbackHandler,
                address(compatibilityFallbackHandler),
                PREDEPLOY_NONCE,
                sharedBalance,
                "compatibility fallback handler"
            )
        );

        // safe l2 impl (has storage) — event-emitting singleton flavor; SafeToL2Setup
        // switches counterfactual Safes to it during setup on non-mainnet chains
        address simulatedSafeL2 = instantiateSafeL2();
        assertTrue(
            yamlAppendGenesisAccount(
                dest, simulatedSafeL2, SAFE_L2_SINGLETON, PREDEPLOY_NONCE, sharedBalance, "safe l2 impl"
            )
        );

        // safe to l2 setup (no storage) — required by counterfactual (multichain)
        // Safe creations: Safe v1.4.1 `setupModules` reverts GS002 unless the
        // initializer's delegatecall target has code
        address simulatedToL2Setup = instantiateSafeToL2Setup();
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedToL2Setup, SAFE_TO_L2_SETUP, PREDEPLOY_NONCE, sharedBalance, "safe to l2 setup"
            )
        );

        // multisend + multisend call only (no storage) — Safe batched transactions
        address simulatedMultiSend = instantiateMultiSend();
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedMultiSend, SAFE_MULTI_SEND, PREDEPLOY_NONCE, sharedBalance, "multisend"
            )
        );
        address simulatedMultiSendCallOnly = instantiateMultiSendCallOnly();
        assertFalse(
            yamlAppendGenesisAccount(
                dest,
                simulatedMultiSendCallOnly,
                SAFE_MULTI_SEND_CALL_ONLY,
                PREDEPLOY_NONCE,
                sharedBalance,
                "multisend call only"
            )
        );

        // sign message lib + create call (no storage) — remaining canonical Safe libs
        address simulatedSignMessageLib = instantiateSignMessageLib();
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedSignMessageLib, SAFE_SIGN_MESSAGE_LIB, PREDEPLOY_NONCE, sharedBalance, "sign message lib"
            )
        );
        address simulatedCreateCall = instantiateCreateCall();
        assertFalse(
            yamlAppendGenesisAccount(
                dest, simulatedCreateCall, SAFE_CREATE_CALL, PREDEPLOY_NONCE, sharedBalance, "create call"
            )
        );

        // simulate tx accessor (no storage) — used by Safe SDK/UI transaction simulation
        // via CompatibilityFallbackHandler.simulate
        address simulatedSimulateTxAccessor = instantiateSimulateTxAccessor();
        assertFalse(
            yamlAppendGenesisAccount(
                dest,
                simulatedSimulateTxAccessor,
                SAFE_SIMULATE_TX_ACCESSOR,
                PREDEPLOY_NONCE,
                sharedBalance,
                "simulate tx accessor"
            )
        );

        // safe singleton factory (no storage) — Safe's deterministic CREATE2 factory;
        // lets future canonical Safe contracts be deployed permissionlessly at
        // byte-exact parity addresses without another genesis change. It only ever
        // CREATE2s, so its nonce is never read for address derivation
        address simulatedSingletonFactory = instantiateSafeSingletonFactory();
        assertFalse(
            yamlAppendGenesisAccount(
                dest,
                simulatedSingletonFactory,
                SAFE_SINGLETON_FACTORY,
                PREDEPLOY_NONCE,
                sharedBalance,
                "safe singleton factory (create2)"
            )
        );

        // singleton factory's deployer EOA: mark its nonce-0 presigned deployment tx as
        // spent, mirroring the multicall/arachnid entries below. Unlike those two this is
        // not a Nick's-method keyless address — Safe holds the key and signs one
        // deployment tx per chain (safe-global/safe-singleton-factory) — so the burn
        // guards against a chain-id-matching replay rather than an unowned presigned tx
        vm.writeLine(
            dest,
            '"0xE1CB04A0fA36DdD16a06ea828007E35e1a3cBC37": # use nonce 0 for creating 0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7'
        );
        vm.writeLine(dest, "  nonce: 1");
        vm.writeLine(dest, "  balance: 0");

        // governance safe (has storage)
        address simulatedSafe = address(instantiateGovernanceSafe());
        assertTrue(
            yamlAppendGenesisAccount(
                dest,
                simulatedSafe,
                address(governanceSafe),
                PREDEPLOY_NONCE,
                governanceInitialBalance,
                "governance safe"
            )
        );

        // wrapped TEL (no constructor, no storage; name/symbol/decimals are constants)
        address simulatedWTEL = address(instantiateWTEL());
        assertFalse(
            yamlAppendGenesisAccount(dest, simulatedWTEL, address(wTEL), PREDEPLOY_NONCE, sharedBalance, "wrapped TEL")
        );

        // EIP-2935 and EIP-4788 system contracts
        instantiateEIP2935AndEIP4788();

        // Multicall3 deterministic deployment
        instantiateMulticall3();

        // Arachnid deterministic deployment proxy (CREATE2)
        instantiateArachnidFactory();

        // TEL precompile (native Rust handler at 0x7e1, needs code for EXTCODESIZE check)
        instantiateTelPrecompile();

        vm.stopBroadcast();
    }

    function _setGovernanceSafeConfig() internal {
        safeOwners.push(0x2358CF87e62618663E781CE52EE7a7F777aC4e65); // l
        safeOwners.push(0x389C4bd707FAb237578A9603F55A02554CAa034b); // s
        safeOwners.push(0xDE5346d15Dc5e0D7b3bE7feFF5d96f548c321e88); // g
        safeOwners.push(0xf5b3944629F9303fa94670B2a6611eE1b11Cd538); // p
        safeOwners.push(0xDCe4Ef7679E8A81EEE8c71917b21EbbCef45B5BA); // c
        safeOwners.push(0xa21B09Ff93A6ffc466F9d2D979fb2268fDaff248); // no
        safeOwners.push(0x5b9e70501a845FA8105B2f8228a0d243A98d97Fc); // ni
        safeThreshold = 3;
    }

    /// @dev Reads the vendored canonical runtime bytecode, asserts its hash, and etches
    /// it at `target`. Self-referential immutables (SafeToL2Setup, MultiSend,
    /// SignMessageLib bake `address(this)` into their runtime bytes) stay valid because
    /// the bytes were captured from — and are placed at — the same canonical address.
    function _etchCanonical(string memory name, address target, bytes32 expectedCodehash) internal {
        bytes memory runtimeCode = vm.parseBytes(vm.readFile(string.concat(root, bytecodeDir, name, ".hex")));
        assertEq(keccak256(runtimeCode), expectedCodehash, string.concat(name, ": vendored bytecode hash mismatch"));
        vm.etch(target, runtimeCode);
    }

    /// @dev Etches a canonical Safe singleton and replicates its constructor's only
    /// storage effect (`threshold = 1`), registering the slot for yaml emission
    function _etchCanonicalSingleton(string memory name, address target, bytes32 expectedCodehash) internal {
        _etchCanonical(name, target, expectedCodehash);
        vm.store(target, SAFE_THRESHOLD_SLOT, bytes32(uint256(1)));
        writtenStorageSlots[target].push(SAFE_THRESHOLD_SLOT);
    }

    function instantiateSafeImpl() public returns (Safe) {
        _etchCanonicalSingleton("Safe", SAFE_SINGLETON, SAFE_CODEHASH);
        return Safe(payable(SAFE_SINGLETON));
    }

    function instantiateSafeL2() public returns (address) {
        _etchCanonicalSingleton("SafeL2", SAFE_L2_SINGLETON, SAFE_L2_CODEHASH);
        return SAFE_L2_SINGLETON;
    }

    function instantiateSafeProxyFactory() public returns (SafeProxyFactory) {
        _etchCanonical("SafeProxyFactory", SAFE_PROXY_FACTORY, SAFE_PROXY_FACTORY_CODEHASH);
        return SafeProxyFactory(SAFE_PROXY_FACTORY);
    }

    function instantiateCompatibilityFallbackHandler() public returns (CompatibilityFallbackHandler) {
        _etchCanonical("CompatibilityFallbackHandler", SAFE_FALLBACK_HANDLER, SAFE_FALLBACK_HANDLER_CODEHASH);
        return CompatibilityFallbackHandler(SAFE_FALLBACK_HANDLER);
    }

    function instantiateSafeToL2Setup() public returns (address) {
        _etchCanonical("SafeToL2Setup", SAFE_TO_L2_SETUP, SAFE_TO_L2_SETUP_CODEHASH);
        return SAFE_TO_L2_SETUP;
    }

    function instantiateMultiSend() public returns (address) {
        _etchCanonical("MultiSend", SAFE_MULTI_SEND, SAFE_MULTI_SEND_CODEHASH);
        return SAFE_MULTI_SEND;
    }

    function instantiateMultiSendCallOnly() public returns (address) {
        _etchCanonical("MultiSendCallOnly", SAFE_MULTI_SEND_CALL_ONLY, SAFE_MULTI_SEND_CALL_ONLY_CODEHASH);
        return SAFE_MULTI_SEND_CALL_ONLY;
    }

    function instantiateSignMessageLib() public returns (address) {
        _etchCanonical("SignMessageLib", SAFE_SIGN_MESSAGE_LIB, SAFE_SIGN_MESSAGE_LIB_CODEHASH);
        return SAFE_SIGN_MESSAGE_LIB;
    }

    function instantiateCreateCall() public returns (address) {
        _etchCanonical("CreateCall", SAFE_CREATE_CALL, SAFE_CREATE_CALL_CODEHASH);
        return SAFE_CREATE_CALL;
    }

    function instantiateSimulateTxAccessor() public returns (address) {
        _etchCanonical("SimulateTxAccessor", SAFE_SIMULATE_TX_ACCESSOR, SAFE_SIMULATE_TX_ACCESSOR_CODEHASH);
        return SAFE_SIMULATE_TX_ACCESSOR;
    }

    function instantiateSafeSingletonFactory() public returns (address) {
        _etchCanonical("SafeSingletonFactory", SAFE_SINGLETON_FACTORY, SAFE_SINGLETON_FACTORY_CODEHASH);
        return SAFE_SINGLETON_FACTORY;
    }

    function instantiateWTEL() public returns (WTEL simulatedDeployment) {
        simulatedDeployment = new WTEL();
        copyContractState(address(simulatedDeployment), address(wTEL), new bytes32[](0));
    }

    function instantiateGovernanceSafe() public returns (Safe simulatedDeployment) {
        vm.startStateDiffRecording();

        address to;
        bytes memory data;
        address fallbackHandler = address(compatibilityFallbackHandler);
        address paymentToken;
        uint256 payment;
        address paymentReceiver;
        bytes memory setupData = abi.encodeWithSelector(
            Safe.setup.selector,
            safeOwners,
            safeThreshold,
            to,
            data,
            fallbackHandler,
            paymentToken,
            payment,
            paymentReceiver
        );
        simulatedDeployment =
            Safe(payable(address(safeProxyFactory.createProxyWithNonce(address(safeImpl), setupData, 0x0))));

        Vm.AccountAccess[] memory safeRecords = vm.stopAndReturnStateDiff();
        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), safeRecords);
        copyContractState(address(simulatedDeployment), address(governanceSafe), slots);
    }

    /// @dev Writes Multicall3 deterministic deployment configuration directly to the yaml
    function instantiateMulticall3() internal {
        // Multicall3: well-known deterministic deployment
        vm.writeLine(dest, '"0xcA11bde05977b3631167028862bE2a173976CA11": # multicall');
        vm.writeLine(dest, "  nonce: 0");
        vm.writeLine(dest, "  balance: 0");
        vm.writeLine(
            dest,
            "  code: 0x6080604052600436106100f35760003560e01c80634d2301cc1161008a578063a8b0574e11610059578063a8b0574e1461025a578063bce38bd714610275578063c3077fa914610288578063ee82ac5e1461029b57600080fd5b80634d2301cc146101ec57806372425d9d1461022157806382ad56cb1461023457806386d516e81461024757600080fd5b80633408e470116100c65780633408e47014610191578063399542e9146101a45780633e64a696146101c657806342cbb15c146101d957600080fd5b80630f28c97d146100f8578063174dea711461011a578063252dba421461013a57806327e86d6e1461015b575b600080fd5b34801561010457600080fd5b50425b6040519081526020015b60405180910390f35b61012d610128366004610a85565b6102ba565b6040516101119190610bbe565b61014d610148366004610a85565b6104ef565b604051610111929190610bd8565b34801561016757600080fd5b50437fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0140610107565b34801561019d57600080fd5b5046610107565b6101b76101b2366004610c60565b610690565b60405161011193929190610cba565b3480156101d257600080fd5b5048610107565b3480156101e557600080fd5b5043610107565b3480156101f857600080fd5b50610107610207366004610ce2565b73ffffffffffffffffffffffffffffffffffffffff163190565b34801561022d57600080fd5b5044610107565b61012d610242366004610a85565b6106ab565b34801561025357600080fd5b5045610107565b34801561026657600080fd5b50604051418152602001610111565b61012d610283366004610c60565b61085a565b6101b7610296366004610a85565b610a1a565b3480156102a757600080fd5b506101076102b6366004610d18565b4090565b60606000828067ffffffffffffffff8111156102d8576102d8610d31565b60405190808252806020026020018201604052801561031e57816020015b6040805180820190915260008152606060208201528152602001906001900390816102f65790505b5092503660005b8281101561047757600085828151811061034157610341610d60565b6020026020010151905087878381811061035d5761035d610d60565b905060200281019061036f9190610d8f565b6040810135958601959093506103886020850185610ce2565b73ffffffffffffffffffffffffffffffffffffffff16816103ac6060870187610dcd565b6040516103ba929190610e32565b60006040518083038185875af1925050503d80600081146103f7576040519150601f19603f3d011682016040523d82523d6000602084013e6103fc565b606091505b50602080850191909152901515808452908501351761046d577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260846000fd5b5050600101610325565b508234146104e6576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601a60248201527f4d756c746963616c6c333a2076616c7565206d69736d6174636800000000000060448201526064015b60405180910390fd5b50505092915050565b436060828067ffffffffffffffff81111561050c5761050c610d31565b60405190808252806020026020018201604052801561053f57816020015b606081526020019060019003908161052a5790505b5091503660005b8281101561068657600087878381811061056257610562610d60565b90506020028101906105749190610e42565b92506105836020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166105a66020850185610dcd565b6040516105b4929190610e32565b6000604051808303816000865af19150503d80600081146105f1576040519150601f19603f3d011682016040523d82523d6000602084013e6105f6565b606091505b5086848151811061060957610609610d60565b602090810291909101015290508061067d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b50600101610546565b5050509250929050565b43804060606106a086868661085a565b905093509350939050565b6060818067ffffffffffffffff8111156106c7576106c7610d31565b60405190808252806020026020018201604052801561070d57816020015b6040805180820190915260008152606060208201528152602001906001900390816106e55790505b5091503660005b828110156104e657600084828151811061073057610730610d60565b6020026020010151905086868381811061074c5761074c610d60565b905060200281019061075e9190610e76565b925061076d6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166107906040850185610dcd565b60405161079e929190610e32565b6000604051808303816000865af19150503d80600081146107db576040519150601f19603f3d011682016040523d82523d6000602084013e6107e0565b606091505b506020808401919091529015158083529084013517610851577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260646000fd5b50600101610714565b6060818067ffffffffffffffff81111561087657610876610d31565b6040519080825280602002602001820160405280156108bc57816020015b6040805180820190915260008152606060208201528152602001906001900390816108945790505b5091503660005b82811015610a105760008482815181106108df576108df610d60565b602002602001015190508686838181106108fb576108fb610d60565b905060200281019061090d9190610e42565b925061091c6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff1661093f6020850185610dcd565b60405161094d929190610e32565b6000604051808303816000865af19150503d806000811461098a576040519150601f19603f3d011682016040523d82523d6000602084013e61098f565b606091505b506020830152151581528715610a07578051610a07576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b506001016108c3565b5050509392505050565b6000806060610a2b60018686610690565b919790965090945092505050565b60008083601f840112610a4b57600080fd5b50813567ffffffffffffffff811115610a6357600080fd5b6020830191508360208260051b8501011115610a7e57600080fd5b9250929050565b60008060208385031215610a9857600080fd5b823567ffffffffffffffff811115610aaf57600080fd5b610abb85828601610a39565b90969095509350505050565b6000815180845260005b81811015610aed57602081850181015186830182015201610ad1565b81811115610aff576000602083870101525b50601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169290920160200192915050565b600082825180855260208086019550808260051b84010181860160005b84811015610bb1578583037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe001895281518051151584528401516040858501819052610b9d81860183610ac7565b9a86019a9450505090830190600101610b4f565b5090979650505050505050565b602081526000610bd16020830184610b32565b9392505050565b600060408201848352602060408185015281855180845260608601915060608160051b870101935082870160005b82811015610c52577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0888703018452610c40868351610ac7565b95509284019290840190600101610c06565b509398975050505050505050565b600080600060408486031215610c7557600080fd5b83358015158114610c8557600080fd5b9250602084013567ffffffffffffffff811115610ca157600080fd5b610cad86828701610a39565b9497909650939450505050565b838152826020820152606060408201526000610cd96060830184610b32565b95945050505050565b600060208284031215610cf457600080fd5b813573ffffffffffffffffffffffffffffffffffffffff81168114610bd157600080fd5b600060208284031215610d2a57600080fd5b5035919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81833603018112610dc357600080fd5b9190910192915050565b60008083357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe1843603018112610e0257600080fd5b83018035915067ffffffffffffffff821115610e1d57600080fd5b602001915036819003821315610a7e57600080fd5b8183823760009101908152919050565b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc1833603018112610dc357600080fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa1833603018112610dc357600080fdfea2646970667358221220bb2b5c71a328032f97c676ae39a1ec2148d3e5d6f73d95e9b17910152d61f16264736f6c634300080c0033"
        );

        // Multicall3 Creator Nonce
        vm.writeLine(
            dest,
            '"0x05f32B3cC3888453ff71B01135B34FF8e41263F2": # use nonce 0 for creating 0xcA11bde05977b3631167028862bE2a173976CA11'
        );
        vm.writeLine(dest, "  nonce: 1");
        vm.writeLine(dest, "  balance: 0");
    }

    /// @dev Writes Arachnid deterministic deployment proxy (CREATE2 factory) configuration to yaml
    function instantiateArachnidFactory() internal {
        // CREATE2 Factory
        vm.writeLine(
            dest, '"0x4e59b44847b379578588920cA78FbF26c0B4956C": # arachnid deterministic deployment proxy (CREATE2)'
        );
        vm.writeLine(dest, "  nonce: 0");
        vm.writeLine(dest, "  balance: 0");
        vm.writeLine(
            dest,
            "  code: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3"
        );

        // Keyless deployer nonce
        vm.writeLine(
            dest,
            '"0x3fAB184622Dc19b6109349B94811493BF2a45362": # use nonce 0 for creating 0x4e59b44847b379578588920cA78FbF26c0B4956C'
        );
        vm.writeLine(dest, "  nonce: 1");
        vm.writeLine(dest, "  balance: 0");
    }

    /// @dev Writes TEL precompile genesis account so EXTCODESIZE returns non-zero
    function instantiateTelPrecompile() internal {
        vm.writeLine(dest, '"0x00000000000000000000000000000000000007e1": # TEL precompile');
        vm.writeLine(dest, "  nonce: 0");
        vm.writeLine(dest, "  balance: 0");
        vm.writeLine(dest, '  code: "0xfe"'); // use "" otherwise yaml deserializes a number
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
