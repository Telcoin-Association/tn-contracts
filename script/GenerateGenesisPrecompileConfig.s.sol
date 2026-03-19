// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { Script } from "forge-std/Script.sol";
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

        // safe impl (has storage)
        address simulatedSafeImpl = address(instantiateSafeImpl());
        assertTrue(yamlAppendGenesisAccount(dest, simulatedSafeImpl, address(safeImpl), sharedNonce, sharedBalance, "safe impl"));

        // safe proxy factory (no storage)
        address simulatedSafeFactory = address(instantiateSafeProxyFactory());
        assertFalse(
            yamlAppendGenesisAccount(dest, simulatedSafeFactory, address(safeProxyFactory), sharedNonce, sharedBalance, "safe proxy factory")
        );

        // governance safe (has storage)
        address simulatedSafe = address(instantiateGovernanceSafe());
        assertTrue(
            yamlAppendGenesisAccount(
                dest, simulatedSafe, address(governanceSafe), sharedNonce, governanceInitialBalance, "governance safe"
            )
        );

        // EIP-2935 and EIP-4788 system contracts
        instantiateEIP2935AndEIP4788();

        // Multicall3 deterministic deployment
        instantiateMulticall3();

        vm.stopBroadcast();
    }

    function _setGovernanceSafeConfig() internal {
        safeOwners.push(0x2358CF87e62618663E781CE52EE7a7F777aC4e65);
        safeOwners.push(0x84B0fc1Bb26212a1BfFb48F03B010FDA4aDCe3c9);
        safeOwners.push(0x707856C0089Fd59d9e686A47784d5DAd7c0784c4);
        safeOwners.push(0xfeCeE4Ab07127fFf4EE4a3BA61dF5fD7B906F84C);
        safeOwners.push(0xf5b3944629F9303fa94670B2a6611eE1b11Cd538);
        safeOwners.push(0xDCe4Ef7679E8A81EEE8c71917b21EbbCef45B5BA);
        safeThreshold = 3;
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

        address to;
        bytes memory data;
        address fallbackHandler;
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
