// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { GenerateGenesisPrecompileConfig } from "../../script/GenerateGenesisPrecompileConfig.s.sol";
import { GenesisPrecompiler } from "../../deployments/genesis/GenesisPrecompiler.sol";
import { GenesisYamlAssertions } from "./GenesisYamlAssertions.sol";
import { BlsG1PrecompileMockDeployed } from "../consensus/BlsG1PrecompileMock.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { Issuance } from "src/consensus/Issuance.sol";
import { IConsensusRegistry } from "src/interfaces/IConsensusRegistry.sol";
import { IStakeManager, RewardInfo } from "src/interfaces/IStakeManager.sol";

/// @dev The Safe v1.5.0 ABI the tests use (`lib/safe-contracts` is v1.4.1); `operation` is
/// `Enum.Operation` (0 call, 1 delegatecall)
interface IValidatorSafe {
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    )
        external
        payable
        returns (bool success);
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce
    )
        external
        view
        returns (bytes32);
    function approveHash(bytes32 hashToApprove) external;
    function domainSeparator() external view returns (bytes32);
    function nonce() external view returns (uint256);
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function getModulesPaginated(
        address start,
        uint256 pageSize
    )
        external
        view
        returns (address[] memory array, address next);
    function VERSION() external view returns (string memory);
}

/// @dev `SafeProxy` answers `masterCopy()` itself, without delegating
interface ISafeProxy {
    function masterCopy() external view returns (address);
}

/// @title Genesis Validator Safes Test
/// @notice Replays the genesis simulation and verifies the ten validator Safes: one per genesis
/// validator, at the assigned addresses, each a SafeL2 v1.5.0 proxy whose owners and threshold are
/// the governance Safe's. The real owner keys are not available, so every transaction on a validator
/// Safe here is authorized with approved-hash signatures: each signing owner calls `approveHash` from
/// its own address (`vm.prank`), and a non-owner relayer submits the transaction. No owner, threshold
/// or storage slot is overridden. ECDSA signing is shown on fixture Safes built the same way but owned
/// by test keys. It also verifies the ten reserve Safes, built like the validator Safes and funded so
/// that each can stake one of the next ten validators to join
contract GenesisValidatorSafesTest is GenesisYamlAssertions, GenesisPrecompiler, BlsG1PrecompileMockDeployed {
    string constant VALIDATOR_SAFES_YAML = "/deployments/genesis/validator-safes.yaml";

    // canonical addresses, spelled out rather than read from the generator so an edit to its
    // constants cannot make an assertion self-satisfying
    address constant GOVERNANCE_SAFE = 0x00000000000000000000000000000000000007A0;
    address constant SAFE_V150_L2_SINGLETON = 0xEdd160fEBBD92E350D4D398fb636302fccd67C7e;
    address constant SAFE_V150_FALLBACK_HANDLER = 0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4;
    address constant SAFE_V150_PROXY_FACTORY = 0x14F2982D601c9458F93bd70B218933A6f8165e7b;
    address constant CONSENSUS_REGISTRY = 0x07E17e17E17e17E17e17E17E17E17e17e17E17e1;
    address constant RESERVE_SAFE_BASE = 0x000000000000000000000000000007A00005EED0;
    /// @dev The 1,000,000 TEL stake plus 1 TEL for gas
    uint256 constant RESERVE_SAFE_BALANCE = 1_000_001e18;

    /// @dev keccak256 of `safe-v1.5.0/SafeProxy.hex`, the runtime of every v1.5.0 factory proxy
    bytes32 constant SAFE_V150_PROXY_CODEHASH = 0x4e381985ca68b3e5d27b4425fa581c19cf33146d3f887a3cfca96f55528ea46f;

    /// @dev Safe storage layout, unchanged from v1.4.1 to v1.5.0: singleton 0, modules 1,
    /// owners 2, ownerCount 3, threshold 4, nonce 5
    uint256 constant MODULES_SLOT = 1;
    uint256 constant OWNERS_SLOT = 2;
    uint256 constant OWNER_COUNT_SLOT = 3;
    uint256 constant THRESHOLD_SLOT = 4;
    bytes32 constant FALLBACK_HANDLER_STORAGE_SLOT = keccak256("fallback_manager.handler.address");
    bytes32 constant GUARD_STORAGE_SLOT = keccak256("guard_manager.guard.address");
    /// @dev v1.5.0 adds a module guard
    bytes32 constant MODULE_GUARD_STORAGE_SLOT = keccak256("module_manager.module_guard.address");
    address constant SENTINEL = address(0x1);
    /// @dev The Safe's EIP-712 domain, unchanged from v1.4.1 to v1.5.0: no name or version, only the
    /// chain id and the Safe's own address
    bytes32 constant DOMAIN_SEPARATOR_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    uint256 constant MAINNET_CHAIN_ID = 731;

    uint8 constant CALL = 0;

    // registry fixture, the values `ConsensusRegistryTestUtils` uses
    uint256 constant STAKE_AMOUNT = 1_000_000e18;
    uint256 constant MIN_WITHDRAW_AMOUNT = 1000e18;
    uint256 constant EPOCH_ISSUANCE = 25_806e18;
    uint32 constant EPOCH_DURATION = 24 hours;

    address relayer = makeAddr("relayer");
    address registryOwner = makeAddr("registry owner");
    /// @dev The factory proxies the generator simulated before copying each to its assigned address
    address[] simulatedSafes;

    function setUp() public {
        // replay the genesis simulation: the v1.4.1 suite and the governance Safe, then the v1.5.0
        // suite, the validator Safes and the reserve Safes, copying code and storage onto the genesis
        // addresses
        GenerateGenesisPrecompileConfig genesis = new GenerateGenesisPrecompileConfig();
        genesis.setUp();
        genesis.instantiateSafeL2();
        genesis.instantiateSafeProxyFactory();
        genesis.instantiateCompatibilityFallbackHandler();
        genesis.instantiateGovernanceSafe();
        genesis.instantiateSafeV150Suite();
        simulatedSafes = genesis.instantiateValidatorSafes();
        genesis.instantiateReserveSafes();
    }

    /// @notice Validator N's Safe is `0x…07310005eedN`, in validator order
    function _validatorSafes() internal pure returns (address[10] memory) {
        return [
            0x000000000000000000000000000007310005eED0,
            0x000000000000000000000000000007310005EEd1,
            0x000000000000000000000000000007310005eEd2,
            0x000000000000000000000000000007310005EED3,
            0x000000000000000000000000000007310005Eed4,
            0x000000000000000000000000000007310005Eed5,
            0x000000000000000000000000000007310005EEd6,
            0x000000000000000000000000000007310005EEd7,
            0x000000000000000000000000000007310005eeD8,
            0x000000000000000000000000000007310005EEd9
        ];
    }

    /// @notice Reserve Safe N is `0x…07a00005eedN`
    function _reserveSafes() internal pure returns (address[10] memory) {
        return [
            0x000000000000000000000000000007A00005EED0,
            0x000000000000000000000000000007a00005EeD1,
            0x000000000000000000000000000007A00005Eed2,
            0x000000000000000000000000000007a00005EED3,
            0x000000000000000000000000000007a00005EEd4,
            0x000000000000000000000000000007a00005eed5,
            0x000000000000000000000000000007A00005Eed6,
            0x000000000000000000000000000007A00005Eed7,
            0x000000000000000000000000000007a00005Eed8,
            0x000000000000000000000000000007A00005EeD9
        ];
    }

    function test_validatorSafesAreTenDistinctProxies() public view {
        address[10] memory safes = _validatorSafes();
        for (uint256 i; i < safes.length; ++i) {
            for (uint256 j = i + 1; j < safes.length; ++j) {
                assertTrue(safes[i] != safes[j], "validator safes must be distinct");
            }
            assertEq(keccak256(safes[i].code), SAFE_V150_PROXY_CODEHASH, "validator safe is not a v1.5.0 proxy");
        }
        // nothing past the tenth
        assertEq(address(uint160(safes[9]) + 1).code.length, 0);
    }

    function test_validatorSafesUseSafeL2V150() public view {
        address[10] memory safes = _validatorSafes();
        for (uint256 i; i < safes.length; ++i) {
            IValidatorSafe safe = IValidatorSafe(safes[i]);
            assertEq(_loadAddress(address(safe), bytes32(0)), SAFE_V150_L2_SINGLETON);
            assertEq(ISafeProxy(address(safe)).masterCopy(), SAFE_V150_L2_SINGLETON);
            assertEq(safe.VERSION(), "1.5.0");
            assertEq(_loadAddress(address(safe), FALLBACK_HANDLER_STORAGE_SLOT), SAFE_V150_FALLBACK_HANDLER);
        }
    }

    /// @notice Owners sign Safe transactions as EIP-712 typed data over the Safe's domain. On chain
    /// 731 each validator Safe's domain is that of its assigned address, not of the factory proxy the
    /// generator simulated and copied from, and no two validator Safes share a domain
    function test_validatorSafeDomainsBindChainAndAssignedAddress() public {
        vm.chainId(MAINNET_CHAIN_ID);
        address[10] memory safes = _validatorSafes();
        assertEq(simulatedSafes.length, safes.length);
        bytes32[10] memory domains;
        for (uint256 i; i < safes.length; ++i) {
            domains[i] = IValidatorSafe(safes[i]).domainSeparator();
            assertEq(domains[i], keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, MAINNET_CHAIN_ID, safes[i])));
            assertTrue(
                domains[i] != keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, MAINNET_CHAIN_ID, simulatedSafes[i])),
                "domain is the simulated proxy's"
            );
            for (uint256 j; j < i; ++j) {
                assertTrue(domains[i] != domains[j], "validator safes share a domain");
            }
        }
    }

    /// @notice The owners and threshold come from the governance Safe's genesis state, not a
    /// second list, so a correction to the governance configuration carries over by construction
    function test_validatorSafesShareGovernanceOwnersAndThreshold() public view {
        address[] memory governanceOwners = IValidatorSafe(GOVERNANCE_SAFE).getOwners();
        uint256 governanceThreshold = IValidatorSafe(GOVERNANCE_SAFE).getThreshold();
        // a real multisig, so the equality below is not vacuous
        assertGt(governanceOwners.length, 1);
        assertGt(governanceThreshold, 1);

        address[10] memory safes = _validatorSafes();
        for (uint256 i; i < safes.length; ++i) {
            assertEq(IValidatorSafe(safes[i]).getOwners(), governanceOwners);
            assertEq(IValidatorSafe(safes[i]).getThreshold(), governanceThreshold);
            assertEq(IValidatorSafe(safes[i]).nonce(), 0);
        }
    }

    function test_validatorSafesHaveNoModulesGuardOrBalance() public view {
        address[10] memory safes = _validatorSafes();
        for (uint256 i; i < safes.length; ++i) {
            (address[] memory modules, address next) = IValidatorSafe(safes[i]).getModulesPaginated(SENTINEL, 10);
            assertEq(modules.length, 0);
            assertEq(next, SENTINEL);
            assertEq(vm.load(safes[i], GUARD_STORAGE_SLOT), bytes32(0));
            assertEq(vm.load(safes[i], MODULE_GUARD_STORAGE_SLOT), bytes32(0));
            assertEq(safes[i].balance, 0);
        }
    }

    /// @notice Every slot the governance Safe carries holds the same value in each validator Safe,
    /// except the singleton (v1.5.0 SafeL2) and the fallback handler (v1.5.0)
    function test_validatorSafeStorageMirrorsGovernanceSafe() public view {
        (bytes32[] memory slots,) = _expectedStorage();
        address[10] memory safes = _validatorSafes();
        for (uint256 i; i < safes.length; ++i) {
            for (uint256 j; j < slots.length; ++j) {
                if (slots[j] == bytes32(0) || slots[j] == FALLBACK_HANDLER_STORAGE_SLOT) continue;
                assertEq(vm.load(safes[i], slots[j]), vm.load(GOVERNANCE_SAFE, slots[j]));
            }
        }
    }

    /// @notice The committed yaml carries the ten validator Safes, in order and nowhere else, each
    /// exactly as genesis must: nonce 1, no balance, the v1.5.0 proxy runtime, and the storage
    /// `setup` writes for the governance owners and threshold. The entries are matched as one block
    /// so the yaml is scanned a fixed number of times rather than once per account
    function test_yamlCarriesValidatorSafes() public view {
        _assertYamlSafeBlock(
            _genesisYaml(),
            _yamlSafeEntries(_validatorSafes(), "validator safe ", "0"),
            '"0x000000000000000000000000000007310005eed',
            "validator safes"
        );
    }

    /// @notice The committed yaml carries the ten reserve Safes right after the validator Safes and
    /// before wrapped TEL, in order and nowhere else, each identical to a validator Safe's entry but
    /// for its address, its comment and its balance of 1,000,001 TEL
    function test_yamlCarriesReserveSafes() public view {
        string memory yaml = _genesisYaml();
        (, uint256 validatorsEnd) = _assertYamlSafeBlock(
            yaml,
            _yamlSafeEntries(_validatorSafes(), "validator safe ", "0"),
            '"0x000000000000000000000000000007310005eed',
            "validator safes"
        );
        (uint256 blockAt, uint256 blockEnd) = _assertYamlSafeBlock(
            yaml,
            _yamlSafeEntries(_reserveSafes(), "reserve safe ", "1000001000000000000000000"),
            '"0x000000000000000000000000000007a00005eed',
            "reserve safes"
        );
        assertEq(blockAt, validatorsEnd, "reserve safes: not right after the validator safes");
        string memory next = '"0x00000000000000000000000000000000000037e1": # wrapped TEL\n';
        assertEq(LibString.slice(yaml, blockEnd, blockEnd + bytes(next).length), next, "reserve safes: next entry");
    }

    /// @notice Reserve Safe N is at `RESERVE_SAFE_BASE + N` with the v1.5.0 proxy runtime, nothing is
    /// past the tenth, and none is a validator Safe. The yaml test above shows no other genesis
    /// account shares their addresses
    function test_reserveSafesAreTenProxiesAtAssignedAddresses() public view {
        address[10] memory reserves = _reserveSafes();
        address[10] memory validators = _validatorSafes();
        for (uint256 i; i < reserves.length; ++i) {
            assertEq(reserves[i], address(uint160(RESERVE_SAFE_BASE) + uint160(i)));
            assertEq(keccak256(reserves[i].code), SAFE_V150_PROXY_CODEHASH, "reserve safe is not a v1.5.0 proxy");
            assertEq(reserves[i].codehash, validators[0].codehash);
            for (uint256 j; j < validators.length; ++j) {
                assertTrue(reserves[i] != validators[j], "reserve safe is a validator safe");
            }
        }
        assertEq(address(uint160(reserves[9]) + 1).code.length, 0);
    }

    /// @notice Each reserve Safe is configured like a validator Safe: the governance owners and
    /// threshold (three of seven), the v1.5.0 SafeL2 singleton and fallback handler, no modules, no
    /// guard, nonce 0. It holds exactly 1,000,001 TEL
    function test_reserveSafesMatchValidatorSafesAndHoldTheirBalance() public view {
        address[] memory governanceOwners = IValidatorSafe(GOVERNANCE_SAFE).getOwners();
        assertEq(governanceOwners.length, 7);
        assertEq(IValidatorSafe(GOVERNANCE_SAFE).getThreshold(), 3);

        address[10] memory reserves = _reserveSafes();
        for (uint256 i; i < reserves.length; ++i) {
            IValidatorSafe safe = IValidatorSafe(reserves[i]);
            assertEq(safe.getOwners(), governanceOwners);
            assertEq(safe.getThreshold(), 3);
            assertEq(safe.nonce(), 0);
            assertEq(_loadAddress(address(safe), bytes32(0)), SAFE_V150_L2_SINGLETON);
            assertEq(ISafeProxy(address(safe)).masterCopy(), SAFE_V150_L2_SINGLETON);
            assertEq(safe.VERSION(), "1.5.0");
            assertEq(_loadAddress(address(safe), FALLBACK_HANDLER_STORAGE_SLOT), SAFE_V150_FALLBACK_HANDLER);
            (address[] memory modules, address next) = safe.getModulesPaginated(SENTINEL, 10);
            assertEq(modules.length, 0);
            assertEq(next, SENTINEL);
            assertEq(vm.load(address(safe), GUARD_STORAGE_SLOT), bytes32(0));
            assertEq(vm.load(address(safe), MODULE_GUARD_STORAGE_SLOT), bytes32(0));
            assertEq(address(safe).balance, RESERVE_SAFE_BALANCE);
        }
    }

    /// @notice Once the registry owner mints the ConsensusNFT for it, reserve Safe 0 stakes itself as a
    /// new validator from its own balance, through a Safe transaction three of the seven owners
    /// approve. The relayer pays the gas and the transaction sets no gas refund (`gasPrice` 0), so the
    /// Safe spends exactly the stake and keeps 1 TEL
    function test_reserveSafeStakesNewValidatorFromItsBalance() public {
        ConsensusRegistry registry = _genesisRegistry(_validatorSafes());
        IValidatorSafe safe = IValidatorSafe(_reserveSafes()[0]);
        address[] memory owners = IValidatorSafe(GOVERNANCE_SAFE).getOwners();
        address[] memory signers = new address[](3);
        for (uint256 i; i < signers.length; ++i) {
            signers[i] = owners[i];
        }

        vm.prank(registryOwner);
        registry.mint(address(safe));

        uint256 registryBefore = address(registry).balance;
        // key fixture 10: the ten genesis validators hold 0 to 9
        bytes memory stakeCall = abi.encodeCall(
            ConsensusRegistry.stake, (_blsPubkey(10), IStakeManager.ProofOfPossession(_blsSignature(10)))
        );
        assertTrue(_execAsOwners(safe, signers, address(registry), STAKE_AMOUNT, stakeCall));

        assertEq(
            uint8(registry.getValidator(address(safe)).currentStatus), uint8(IConsensusRegistry.ValidatorStatus.Staked)
        );
        assertEq(address(registry).balance, registryBefore + STAKE_AMOUNT);
        assertEq(address(safe).balance, 1e18);
    }

    /// @notice `validator-safes.yaml` is the ordered list of the ten addresses, checksummed
    function test_validatorSafeListYaml() public view {
        string memory list = vm.readFile(string.concat(vm.projectRoot(), VALIDATOR_SAFES_YAML));
        string memory expected = string.concat(
            "# Generated by script/GenerateGenesisPrecompileConfig.s.sol; do not edit by hand.\n",
            "# The genesis validator Safes in validator order: entry N is validator N's Safe.\n"
        );
        address[10] memory safes = _validatorSafes();
        for (uint256 i; i < safes.length; ++i) {
            expected = string.concat(expected, '- "', vm.toString(safes[i]), '"\n');
        }
        assertEq(list, expected);
    }

    /// @notice A threshold of owners executes a transaction and one owner fewer cannot, on every
    /// validator Safe: three and two with the genesis governance threshold of three
    function test_thresholdOwnersExecuteOneFewerCannot() public {
        address[] memory owners = IValidatorSafe(GOVERNANCE_SAFE).getOwners();
        uint256 threshold = IValidatorSafe(GOVERNANCE_SAFE).getThreshold();
        assertGe(owners.length, 2 * threshold - 1);
        // a quorum of the last `threshold` owners, in reverse list order so the signatures must be
        // sorted, against the first `threshold - 1` owners alone and then with the next owner named
        // as a signer that never approved
        address[] memory quorum = new address[](threshold);
        for (uint256 i; i < threshold; ++i) {
            quorum[i] = owners[owners.length - 1 - i];
        }
        address[] memory belowQuorum = new address[](threshold - 1);
        address[] memory withUnapproved = new address[](threshold);
        for (uint256 i; i < threshold; ++i) {
            if (i < threshold - 1) belowQuorum[i] = owners[i];
            withUnapproved[i] = owners[i];
        }

        address payable recipient = payable(makeAddr("recipient"));
        address[10] memory safes = _validatorSafes();
        for (uint256 i; i < safes.length; ++i) {
            IValidatorSafe safe = IValidatorSafe(safes[i]);
            vm.deal(address(safe), 1 ether);

            // one approval short of the threshold is too few signatures
            _approve(safe, belowQuorum, _txHash(safe, recipient, 1 ether, ""));
            (bool ok, bytes memory revertData) =
                _submit(safe, recipient, 1 ether, "", _approvedHashSignatures(belowQuorum));
            assertFalse(ok);
            assertEq(revertData, abi.encodeWithSignature("Error(string)", "GS020"));

            // nor does naming one more owner count without its approval
            (ok, revertData) = _submit(safe, recipient, 1 ether, "", _approvedHashSignatures(withUnapproved));
            assertFalse(ok);
            assertEq(revertData, abi.encodeWithSignature("Error(string)", "GS025"));

            // a threshold of approvals executes
            uint256 recipientBefore = recipient.balance;
            assertTrue(_execAsOwners(safe, quorum, recipient, 1 ether, ""));
            assertEq(recipient.balance, recipientBefore + 1 ether);
            assertEq(address(safe).balance, 0);
            assertEq(safe.nonce(), 1);
        }
    }

    /// @notice The real owners sign with their keys, which this suite does not have. Two fixture
    /// Safes built the way the generator builds the validator Safes, owned by three test keys with
    /// threshold two, show that two ECDSA signatures over `getTransactionHash` execute a transaction,
    /// and that the same signatures do not execute on a Safe at another address with the same owners,
    /// threshold and nonce
    function test_ecdsaSignaturesExecuteAndDoNotReplayAcrossSafes() public {
        vm.chainId(MAINNET_CHAIN_ID);
        address[] memory owners = new address[](3);
        uint256[] memory keys = new uint256[](3);
        for (uint256 i; i < owners.length; ++i) {
            (owners[i], keys[i]) = makeAddrAndKey(string.concat("fixture owner ", vm.toString(i)));
        }
        IValidatorSafe safe = _fixtureSafe(owners, 2, 0, makeAddr("fixture safe"));
        IValidatorSafe sibling = _fixtureSafe(owners, 2, 1, makeAddr("sibling fixture safe"));
        assertEq(sibling.getOwners(), safe.getOwners());
        address payable recipient = payable(makeAddr("recipient"));
        vm.deal(address(safe), 1 ether);
        vm.deal(address(sibling), 1 ether);

        // owners 0 and 1 sign, concatenated in ascending owner order as the Safe requires
        bytes32 txHash = _txHash(safe, recipient, 1 ether, "");
        bytes memory signatures = owners[0] < owners[1]
            ? bytes.concat(_ecdsaSignature(keys[0], txHash), _ecdsaSignature(keys[1], txHash))
            : bytes.concat(_ecdsaSignature(keys[1], txHash), _ecdsaSignature(keys[0], txHash));

        (bool ok, bytes memory returnData) = _submit(safe, recipient, 1 ether, "", signatures);
        assertTrue(ok && abi.decode(returnData, (bool)), "ecdsa-signed transaction did not execute");
        assertEq(recipient.balance, 1 ether);
        assertEq(safe.nonce(), 1);

        // the sibling's domain differs only in its address, so the signatures recover non-owners
        (ok, returnData) = _submit(sibling, recipient, 1 ether, "", signatures);
        assertFalse(ok);
        assertEq(returnData, abi.encodeWithSignature("Error(string)", "GS026"));
        assertEq(address(sibling).balance, 1 ether);
        assertEq(sibling.nonce(), 0);
    }

    /// @notice The registry pays a validator's stake (and refunds) through
    /// `Issuance.distributeStakeReward` capped at `REFUND_GAS_LIMIT = 100_000` gas
    /// (`ConsensusRegistry._settleStakePayout`, `_settleValue`), and Issuance pays with a plain value
    /// call, `recipient.call{ value: totalAmount }("")`. A validator Safe accepts such a transfer
    function test_validatorSafesAcceptValueWithin100kGas() public {
        address[10] memory safes = _validatorSafes();
        for (uint256 i; i < safes.length; ++i) {
            vm.deal(address(this), 1 ether);
            (bool ok,) = safes[i].call{ value: 1 ether, gas: 100_000 }("");
            assertTrue(ok, "validator safe rejected a 100k-gas value transfer");
            assertEq(safes[i].balance, 1 ether);
        }
    }

    /// @notice A genesis validator whose address is its Safe runs its own lifecycle on the real
    /// ConsensusRegistry through Safe transactions: it claims rewards, begins its exit and, once
    /// exited, unstakes. The unstake payout reaches the Safe through the 100k-gas-capped Issuance
    /// push rather than falling back to a `claimRefund` credit
    function test_validatorSafeRunsItsRegistryLifecycle() public {
        address[10] memory safes = _validatorSafes();
        ConsensusRegistry registry = _genesisRegistry(safes);
        IValidatorSafe safe = IValidatorSafe(safes[0]);
        address[] memory owners = IValidatorSafe(GOVERNANCE_SAFE).getOwners();
        address[] memory signers = new address[](IValidatorSafe(GOVERNANCE_SAFE).getThreshold());
        for (uint256 i; i < signers.length; ++i) {
            signers[i] = owners[i];
        }

        // the closing block of epoch 0 rewards only this validator
        address[] memory committee = new address[](safes.length);
        for (uint256 i; i < safes.length; ++i) {
            committee[i] = safes[i];
        }
        RewardInfo[] memory rewardInfos = new RewardInfo[](1);
        rewardInfos[0] = RewardInfo(address(safe), 1);
        vm.startPrank(registry.SYSTEM_ADDRESS());
        registry.applyIncentives(rewardInfos);
        registry.concludeEpoch(committee);
        vm.stopPrank();

        // claim rewards
        uint256 rewards = registry.getRewards(address(safe));
        assertGe(rewards, MIN_WITHDRAW_AMOUNT);
        assertTrue(
            _execAsOwners(
                safe,
                signers,
                address(registry),
                0,
                abi.encodeCall(ConsensusRegistry.claimStakeRewards, (address(safe)))
            )
        );
        assertEq(address(safe).balance, rewards);
        assertEq(registry.getRewards(address(safe)), 0);

        // begin exit
        assertTrue(_execAsOwners(safe, signers, address(registry), 0, abi.encodeCall(ConsensusRegistry.beginExit, ())));
        assertEq(
            uint8(registry.getValidator(address(safe)).currentStatus),
            uint8(IConsensusRegistry.ValidatorStatus.PendingExit)
        );

        // the protocol exits it by leaving it out of every upcoming committee
        vm.prank(registryOwner);
        registry.setNextCommitteeSize(uint16(safes.length - 1));
        address[] memory withoutSafe = new address[](safes.length - 1);
        for (uint256 i = 1; i < safes.length; ++i) {
            withoutSafe[i - 1] = safes[i];
        }
        vm.startPrank(registry.SYSTEM_ADDRESS());
        for (
            uint256 epochs;
            registry.getValidator(address(safe)).currentStatus != IConsensusRegistry.ValidatorStatus.Exited;
            ++epochs
        ) {
            assertLt(epochs, 4, "validator safe never exited");
            registry.concludeEpoch(withoutSafe);
        }
        // unstaking opens one epoch after the exit
        registry.concludeEpoch(withoutSafe);
        vm.stopPrank();

        // unstake
        uint256 registryBefore = address(registry).balance;
        assertTrue(
            _execAsOwners(
                safe, signers, address(registry), 0, abi.encodeCall(ConsensusRegistry.unstake, (address(safe), false))
            )
        );
        assertEq(address(safe).balance, rewards + STAKE_AMOUNT);
        assertEq(address(registry).balance, registryBefore - STAKE_AMOUNT);
        assertEq(registry.claimableRefunds(address(safe)), 0);
        assertEq(registry.claimableRewards(address(safe)), 0);
        assertTrue(registry.isRetired(address(safe)));
    }

    /// @dev Builds a ConsensusRegistry whose genesis validators are the ten validator Safes, at its
    /// protocol address and holding their stake, as the node's genesis does, with Issuance funded
    /// for one epoch
    function _genesisRegistry(address[10] memory safes) internal returns (ConsensusRegistry registry) {
        IConsensusRegistry.ValidatorInfo[] memory validators = new IConsensusRegistry.ValidatorInfo[](safes.length);
        bytes[] memory blsPubkeys = new bytes[](safes.length);
        IStakeManager.ProofOfPossession[] memory pops = new IStakeManager.ProofOfPossession[](safes.length);
        for (uint256 i; i < safes.length; ++i) {
            validators[i] = IConsensusRegistry.ValidatorInfo(
                safes[i], 0, 0, IConsensusRegistry.ValidatorStatus.Active, false, 0, 0
            );
            blsPubkeys[i] = _blsPubkey(i);
            pops[i] = IStakeManager.ProofOfPossession(_blsSignature(i));
        }

        vm.startStateDiffRecording();
        ConsensusRegistry simulated = new ConsensusRegistry(
            IStakeManager.StakeConfig(STAKE_AMOUNT, MIN_WITHDRAW_AMOUNT, EPOCH_ISSUANCE, EPOCH_DURATION),
            validators,
            blsPubkeys,
            pops,
            registryOwner
        );
        Vm.AccountAccess[] memory records = vm.stopAndReturnStateDiff();
        copyContractState(address(simulated), CONSENSUS_REGISTRY, saveWrittenSlots(address(simulated), records));
        registry = ConsensusRegistry(CONSENSUS_REGISTRY);
        vm.deal(address(registry), STAKE_AMOUNT * safes.length);

        vm.etch(registry.issuance(), type(Issuance).runtimeCode);
        vm.deal(registryOwner, EPOCH_ISSUANCE);
        vm.prank(registryOwner);
        registry.allocateIssuance{ value: EPOCH_ISSUANCE }();
    }

    /// @dev Has each of `signers` approve `txHash`, then has the relayer execute the transaction
    function _execAsOwners(
        IValidatorSafe safe,
        address[] memory signers,
        address to,
        uint256 value,
        bytes memory data
    )
        internal
        returns (bool)
    {
        _approve(safe, signers, _txHash(safe, to, value, data));
        (bool ok, bytes memory returnData) = _submit(safe, to, value, data, _approvedHashSignatures(signers));
        assertTrue(ok, "safe transaction reverted");
        return abi.decode(returnData, (bool));
    }

    /// @dev Has the relayer submit a zero-gas-price Safe transaction with `signatures`
    function _submit(
        IValidatorSafe safe,
        address to,
        uint256 value,
        bytes memory data,
        bytes memory signatures
    )
        internal
        returns (bool ok, bytes memory returnData)
    {
        bytes memory execCall = abi.encodeCall(
            IValidatorSafe.execTransaction,
            (to, value, data, CALL, 0, 0, 0, address(0), payable(address(0)), signatures)
        );
        vm.prank(relayer);
        (ok, returnData) = address(safe).call(execCall);
    }

    function _approve(IValidatorSafe safe, address[] memory signers, bytes32 txHash) internal {
        for (uint256 i; i < signers.length; ++i) {
            vm.prank(signers[i]);
            safe.approveHash(txHash);
        }
    }

    function _txHash(IValidatorSafe safe, address to, uint256 value, bytes memory data)
        internal
        view
        returns (bytes32)
    {
        return safe.getTransactionHash(to, value, data, CALL, 0, 0, 0, address(0), address(0), safe.nonce());
    }

    /// @dev A Safe built the way the generator builds a validator Safe (`createProxyWithNonce` on the
    /// v1.5.0 factory over the SafeL2 singleton with the v1.5.0 fallback handler, then its code and
    /// written storage copied to `target`), but owned by `owners` with `threshold`
    function _fixtureSafe(
        address[] memory owners,
        uint256 threshold,
        uint256 saltNonce,
        address target
    )
        internal
        returns (IValidatorSafe)
    {
        bytes memory setupData = abi.encodeCall(
            Safe.setup,
            (owners, threshold, address(0), bytes(""), SAFE_V150_FALLBACK_HANDLER, address(0), 0, payable(address(0)))
        );
        vm.startStateDiffRecording();
        address simulated = address(
            SafeProxyFactory(SAFE_V150_PROXY_FACTORY).createProxyWithNonce(SAFE_V150_L2_SINGLETON, setupData, saltNonce)
        );
        copyContractState(simulated, target, saveWrittenSlots(simulated, vm.stopAndReturnStateDiff()));
        return IValidatorSafe(target);
    }

    /// @dev A 65-byte ECDSA signature over `hash`, packed `r`, `s`, `v` as `checkNSignatures` reads it
    function _ecdsaSignature(uint256 key, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Approved-hash signatures (`v = 1`, `r` = the owner), sorted by owner as the Safe requires
    function _approvedHashSignatures(address[] memory signers) internal pure returns (bytes memory signatures) {
        address[] memory sorted = new address[](signers.length);
        for (uint256 i; i < signers.length; ++i) {
            sorted[i] = signers[i];
            for (uint256 j = i; j > 0 && sorted[j - 1] > sorted[j]; --j) {
                (sorted[j - 1], sorted[j]) = (sorted[j], sorted[j - 1]);
            }
        }
        for (uint256 i; i < sorted.length; ++i) {
            signatures = abi.encodePacked(signatures, bytes32(uint256(uint160(sorted[i]))), bytes32(0), uint8(1));
        }
    }

    /// @dev The storage `setup` writes for the governance owners and threshold, in write order: the
    /// singleton, the owner linked list from the sentinel, the owner count, the threshold, the
    /// fallback handler and the empty module list
    function _expectedStorage() internal view returns (bytes32[] memory slots, bytes32[] memory values) {
        address[] memory owners = IValidatorSafe(GOVERNANCE_SAFE).getOwners();
        uint256 threshold = IValidatorSafe(GOVERNANCE_SAFE).getThreshold();
        uint256 count = owners.length + 6;
        slots = new bytes32[](count);
        values = new bytes32[](count);

        slots[0] = bytes32(0);
        values[0] = _word(SAFE_V150_L2_SINGLETON);
        address previous = SENTINEL;
        for (uint256 i; i <= owners.length; ++i) {
            address current = i == owners.length ? SENTINEL : owners[i];
            slots[1 + i] = keccak256(abi.encode(previous, OWNERS_SLOT));
            values[1 + i] = _word(current);
            previous = current;
        }
        uint256 k = owners.length + 2;
        (slots[k], values[k]) = (bytes32(OWNER_COUNT_SLOT), bytes32(owners.length));
        (slots[k + 1], values[k + 1]) = (bytes32(THRESHOLD_SLOT), bytes32(threshold));
        (slots[k + 2], values[k + 2]) = (FALLBACK_HANDLER_STORAGE_SLOT, _word(SAFE_V150_FALLBACK_HANDLER));
        (slots[k + 3], values[k + 3]) = (keccak256(abi.encode(SENTINEL, MODULES_SLOT)), _word(SENTINEL));
    }

    /// @dev The yaml entries the generator writes for `safes`, in order, each keyed by the address and
    /// commented `<label><index>`: nonce 1, `balance`, the v1.5.0 proxy runtime and the storage `setup`
    /// writes for the governance owners and threshold
    function _yamlSafeEntries(
        address[10] memory safes,
        string memory label,
        string memory balance
    )
        internal
        view
        returns (string memory entries)
    {
        string memory body = string.concat(
            "  nonce: 1\n  balance: ",
            balance,
            "\n  code: ",
            vm.readFile(string.concat(vm.projectRoot(), CANONICAL_BYTECODE_DIR, "safe-v1.5.0/SafeProxy.hex")),
            "\n  storage:\n"
        );
        (bytes32[] memory slots, bytes32[] memory values) = _expectedStorage();
        for (uint256 j; j < slots.length; ++j) {
            body = string.concat(
                body,
                '    "',
                LibString.toHexString(uint256(slots[j]), 32),
                '": "',
                LibString.toHexString(uint256(values[j]), 32),
                '"\n'
            );
        }
        for (uint256 i; i < safes.length; ++i) {
            entries = string.concat(
                entries, '"', LibString.toHexString(safes[i]), '": # ', label, vm.toString(i), "\n", body
            );
        }
    }

    /// @dev Asserts `entries` appear in `yaml` as one block starting a line and followed by another
    /// key, and that `keyPrefix`, the shared prefix of their keys, appears nowhere outside it
    function _assertYamlSafeBlock(
        string memory yaml,
        string memory entries,
        string memory keyPrefix,
        string memory name
    )
        internal
        pure
        returns (uint256 blockAt, uint256 blockEnd)
    {
        blockAt = LibString.indexOf(yaml, entries);
        assertTrue(blockAt != LibString.NOT_FOUND, string.concat(name, ": entries missing or different"));
        assertTrue(blockAt == 0 || bytes(yaml)[blockAt - 1] == "\n", string.concat(name, ": not at a line start"));
        blockEnd = blockAt + bytes(entries).length;
        assertEq(bytes(yaml)[blockEnd], bytes1('"'), string.concat(name, ": last entry continues"));
        assertEq(LibString.indexOf(yaml, keyPrefix), blockAt, string.concat(name, ": key before the block"));
        assertEq(LibString.indexOf(yaml, keyPrefix, blockEnd), LibString.NOT_FOUND, string.concat(name, ": key after"));
    }

    function _word(address account) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(account)));
    }

    function _loadAddress(address account, bytes32 slot) internal view returns (address) {
        return address(uint160(uint256(vm.load(account, slot))));
    }

    /// @dev A distinct 96-byte compressed BLS pubkey fixture with the compression flag set and the
    /// infinity flag clear, as the registry requires of a stored key; the mock precompile checks
    /// lengths only
    function _blsPubkey(uint256 i) internal pure returns (bytes memory pubkey) {
        pubkey = abi.encodePacked(
            keccak256(abi.encode("bls-pubkey", i)),
            keccak256(abi.encode("bls-pubkey-2", i)),
            keccak256(abi.encode("bls-pubkey-3", i))
        );
        pubkey[0] = bytes1((uint8(pubkey[0]) | 0x80) & 0xbf);
    }

    /// @dev A 48-byte BLS signature fixture
    function _blsSignature(uint256 i) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode("bls-sig", i)), bytes16(keccak256(abi.encode("bls-sig-2", i))));
    }
}
