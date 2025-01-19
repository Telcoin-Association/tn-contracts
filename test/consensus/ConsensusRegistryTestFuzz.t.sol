// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ConsensusRegistry} from "src/consensus/ConsensusRegistry.sol";
import {IConsensusRegistry} from "src/consensus/interfaces/IConsensusRegistry.sol";
import {SystemCallable} from "src/consensus/SystemCallable.sol";
import {StakeManager} from "src/consensus/StakeManager.sol";
import {StakeInfo, IStakeManager} from "src/consensus/interfaces/IStakeManager.sol";
import {RWTEL} from "src/RWTEL.sol";
import {KeyTestUtils} from "./KeyTestUtils.sol";

/// @dev Fuzz test module separated into new file with extra setup to avoid `OutOfGas`
contract ConsensusRegistryTestFuzz is KeyTestUtils, Test {
    ConsensusRegistry public consensusRegistryImpl;
    ConsensusRegistry public consensusRegistry;
    RWTEL public rwTEL;

    address public owner = address(0xc0ffee);
    address public validator0 = address(0xbabe);
    address public validator1 = address(0xbababee);
    address public validator2 = address(0xbabababeee);
    address public validator3 = address(0xbababababeeee);
    address public validator4 = address(0xbabababababeeeee);

    IConsensusRegistry.ValidatorInfo validatorInfo0;
    IConsensusRegistry.ValidatorInfo validatorInfo1;
    IConsensusRegistry.ValidatorInfo validatorInfo2;
    IConsensusRegistry.ValidatorInfo validatorInfo3;

    IConsensusRegistry.ValidatorInfo[] initialValidators; // contains validatorInfo0-3

    address public sysAddress;

    bytes public blsPubkey =
        hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    bytes public blsSig =
        hex"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    bytes32 public ed25519Pubkey =
        bytes32(
            hex"1234567890123456789012345678901234567890123456789012345678901234"
        );

    uint256 public telMaxSupply = 100_000_000_000 ether;
    uint256 public stakeAmount = 1_000_000 ether;
    uint256 public minWithdrawAmount = 10_000 ether;
    // `OZ::ERC721Upgradeable::mint()` supports up to ~14_300 fuzzed mint iterations
    uint256 public MAX_MINTABLE = 14_000;

    function setUp() public {
        // set RWTEL address (its bytecode is written after deploying ConsensusRegistry)
        rwTEL = RWTEL(address(0x7e1));

        // provide an initial validator as the network will launch with at least one validator
        bytes memory validator0BLSKey = _createRandomBlsPubkey(0);
        bytes32 validator0ED25519Key = keccak256(abi.encode(0));
        validatorInfo0 = IConsensusRegistry.ValidatorInfo(
            validator0BLSKey,
            validator0ED25519Key,
            validator0,
            uint32(0),
            uint32(0),
            uint24(1),
            IConsensusRegistry.ValidatorStatus.Active
        );
        validatorInfo1 = IConsensusRegistry.ValidatorInfo(
            _createRandomBlsPubkey(1),
            keccak256(abi.encode(1)),
            validator1,
            uint32(0),
            uint32(0),
            uint24(2),
            IConsensusRegistry.ValidatorStatus.Active
        );
        validatorInfo2 = IConsensusRegistry.ValidatorInfo(
            _createRandomBlsPubkey(2),
            keccak256(abi.encode(2)),
            validator2,
            uint32(0),
            uint32(0),
            uint24(3),
            IConsensusRegistry.ValidatorStatus.Active
        );
        validatorInfo3 = IConsensusRegistry.ValidatorInfo(
            _createRandomBlsPubkey(3),
            keccak256(abi.encode(3)),
            validator3,
            uint32(0),
            uint32(0),
            uint24(4),
            IConsensusRegistry.ValidatorStatus.Active
        );
        initialValidators.push(validatorInfo0);
        initialValidators.push(validatorInfo1);
        initialValidators.push(validatorInfo2);
        initialValidators.push(validatorInfo3);

        consensusRegistryImpl = new ConsensusRegistry();
        consensusRegistry = ConsensusRegistry(
            payable(
                address(new ERC1967Proxy(address(consensusRegistryImpl), ""))
            )
        );
        consensusRegistry.initialize(
            address(rwTEL),
            stakeAmount,
            minWithdrawAmount,
            initialValidators,
            owner
        );

        sysAddress = consensusRegistry.SYSTEM_ADDRESS();

        vm.deal(validator4, 100_000_000 ether);

        // deploy an RWTEL module and then use its bytecode to etch on a fixed address (use create2 in prod)
        RWTEL tmp = new RWTEL(
            address(consensusRegistry),
            address(0xbeef),
            "test",
            "TEST",
            0,
            address(0x0),
            address(0x0),
            0
        );
        vm.etch(address(rwTEL), address(tmp).code);
        // deal RWTEL max TEL supply to test reward distribution
        vm.deal(address(rwTEL), telMaxSupply);

        // to prevent exceeding block gas limit, `mint(newValidator)` is performed in setup
        for (uint256 i; i < MAX_MINTABLE; ++i) {
            address newValidator = address(
                uint160(uint256(keccak256(abi.encode(i))))
            );
            uint256 tokenId = i + 5; // account for initial validators

            // deal `stakeAmount` funds and prank governance NFT mint to `newValidator`
            vm.deal(newValidator, stakeAmount);
            vm.prank(owner);
            consensusRegistry.mint(newValidator, tokenId);
        }
    }

    function testFuzz_concludeEpoch(
        uint24 numValidators,
        uint240 fuzzedRewards
    ) public {
        numValidators = uint24(bound(uint256(numValidators), 4, 4000)); // fuzz up to 4k validators
        fuzzedRewards = uint240(
            bound(uint256(fuzzedRewards), minWithdrawAmount, telMaxSupply)
        );

        // // exit existing validator0 which was activated in constructor to clean up calculations
        // vm.prank(validator0);
        // consensusRegistry.exit();
        // Finalize epoch once to reach `PendingExit` for `validator0`
        vm.prank(sysAddress);
        // provide `committeeSize == 3` since there are now only 3 active validators
        consensusRegistry.concludeEpoch(new address[](4));

        // activate validators via `stake()` and construct `newCommittee` array as pseudorandom subset (1/3)
        uint256 numActiveValidators = uint256(numValidators) + 4;
        uint256 committeeSize = (uint256(numActiveValidators) * 10_000) /
            3 /
            10_000 +
            1; // address precision loss
        address[] memory newCommittee = new address[](committeeSize);
        uint256 committeeCounter;
        for (uint256 i; i < numValidators; ++i) {
            // recreate `newValidator` address minted a ConsensusNFT in `setUp()` loop
            address newValidator = address(
                uint160(uint256(keccak256(abi.encode(i))))
            );

            // create random new validator keys
            bytes memory newBLSPubkey = _createRandomBlsPubkey(i);
            bytes memory newBLSSig = _createRandomBlsSig(i);
            bytes32 newED25519Pubkey = _createRandomED25519Pubkey(i);

            vm.prank(newValidator);
            consensusRegistry.stake{value: stakeAmount}(
                newBLSPubkey,
                newBLSSig,
                newED25519Pubkey
            );

            // push first third of new validators to new committee
            if (committeeCounter < newCommittee.length) {
                newCommittee[committeeCounter] = newValidator;
                committeeCounter++;
            }
        }

        // Finalize epoch twice to reach activationEpoch for validators entered in the `stake()` loop
        vm.startPrank(sysAddress);
        // provide `committeeSize == 3` since there are now only 3 active validators
        consensusRegistry.concludeEpoch(new address[](4));
        consensusRegistry.concludeEpoch(newCommittee);

        uint256 numRecipients = newCommittee.length; // all committee members receive rewards
        uint240 rewardPerValidator = uint240(fuzzedRewards / numRecipients);
        // construct `committeeRewards` array to compensate voting committee equally (total `fuzzedRewards` divided
        // across committee)
        StakeInfo[] memory committeeRewards = new StakeInfo[](numRecipients);
        for (uint256 i; i < newCommittee.length; ++i) {
            uint24 recipientIndex = consensusRegistry.getValidatorIndex(
                newCommittee[i]
            );
            committeeRewards[i] = StakeInfo(recipientIndex, rewardPerValidator);
        }

        // Expect the event
        vm.expectEmit(true, true, true, true);
        emit IConsensusRegistry.NewEpoch(
            IConsensusRegistry.EpochInfo(newCommittee, uint64(block.number + 1))
        );
        // increment rewards by finalizing an epoch with a `StakeInfo` for constructed committee (new committee not
        // relevant)
        consensusRegistry.concludeEpoch(newCommittee);
        consensusRegistry.incrementRewards(committeeRewards);
        vm.stopPrank();

        // Check rewards were incremented for each committee member
        for (uint256 i; i < newCommittee.length; ++i) {
            uint24 index = consensusRegistry.getValidatorIndex(newCommittee[i]);
            address committeeMember = consensusRegistry
                .getValidatorByIndex(index)
                .ecdsaPubkey;
            uint256 updatedRewards = consensusRegistry.getRewards(
                committeeMember
            );
            assertEq(updatedRewards, rewardPerValidator);
        }
    }

    // Test for successful claim of staking rewards
    function testFuzz_claimStakeRewards(uint240 fuzzedRewards) public {
        fuzzedRewards = uint240(
            bound(uint256(fuzzedRewards), minWithdrawAmount, telMaxSupply)
        );

        vm.prank(owner);
        uint256 tokenId = MAX_MINTABLE + 5;
        consensusRegistry.mint(validator4, tokenId);

        // First stake
        vm.prank(validator4);
        consensusRegistry.stake{value: stakeAmount}(
            blsPubkey,
            blsSig,
            ed25519Pubkey
        );

        // Capture initial rewards info
        uint256 initialRewards = consensusRegistry.getRewards(validator4);

        // Finalize epoch twice to reach validator4 activationEpoch
        uint256 numActiveValidators = consensusRegistry
            .getValidators(IConsensusRegistry.ValidatorStatus.Active)
            .length;
        vm.startPrank(sysAddress);
        consensusRegistry.concludeEpoch(new address[](4));
        consensusRegistry.concludeEpoch(new address[](numActiveValidators + 1));

        // Simulate earning rewards by finalizing an epoch with a `StakeInfo` for validator4
        uint24 validator4Index = 5;
        StakeInfo[] memory validator4Rewards = new StakeInfo[](1);
        validator4Rewards[0] = StakeInfo(validator4Index, fuzzedRewards);
        consensusRegistry.concludeEpoch(new address[](4));
        consensusRegistry.incrementRewards(validator4Rewards);
        vm.stopPrank();

        // Check rewards were incremented
        uint256 updatedRewards = consensusRegistry.getRewards(validator4);
        assertEq(updatedRewards, initialRewards + fuzzedRewards);

        // Capture initial validator balance
        uint256 initialBalance = validator4.balance;

        // Check event emission and claim rewards
        vm.expectEmit(true, true, true, true);
        emit IConsensusRegistry.RewardsClaimed(validator4, fuzzedRewards);
        vm.prank(validator4);
        consensusRegistry.claimStakeRewards();

        // Check balance after claiming
        uint256 updatedBalance = validator4.balance;
        assertEq(updatedBalance, initialBalance + fuzzedRewards);
    }
}
