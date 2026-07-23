// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { StakeManager } from "src/consensus/StakeManager.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { RewardInfo, Slash, IStakeManager } from "src/interfaces/IStakeManager.sol";
import { Issuance } from "src/consensus/Issuance.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";

/// @dev A delegator that can refuse or gas-grief incoming refunds, for exercising the
/// settlement push's bounded-gas fallback path
contract QueueRecipientMock {
    ConsensusRegistry public immutable registry;
    bool public reject;
    bool public burnGas;

    constructor(ConsensusRegistry registry_) {
        registry = registry_;
    }

    function setReject(bool reject_) external {
        reject = reject_;
    }

    function setBurnGas(bool burnGas_) external {
        burnGas = burnGas_;
    }

    function delegate(
        bytes memory blsPubkey,
        IStakeManager.ProofOfPossession memory pop,
        address validatorAddress,
        bytes memory validatorSig
    )
        external
        payable
    {
        registry.delegateStake{ value: msg.value }(blsPubkey, pop, validatorAddress, validatorSig);
    }

    function claim() external {
        registry.claimRefund();
    }

    receive() external payable {
        if (reject) revert("reject");
        if (burnGas) {
            uint256 x;
            while (true) {
                x = uint256(keccak256(abi.encode(x)));
            }
        }
    }
}

/// @dev Exercises the stake version-change queue: request/cancel/claim flows, boundary
/// settlement ordering against slashes, escrow accounting, funder semantics, lifecycle
/// interactions, hostile refund recipients, and native-balance conservation
contract ConsensusRegistryVersionQueueTest is ConsensusRegistryTestUtils {
    function setUp() public {
        consensusRegistry = ConsensusRegistry(0x07E17e17E17e17E17e17E17E17E17e17e17E17e1);

        vm.startStateDiffRecording();
        StakeConfig memory stakeConfig_ = StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_);
        ConsensusRegistry tempRegistry =
            new ConsensusRegistry(stakeConfig_, initialValidators, initialBlsPubkeys, initialBLSPops, crOwner);
        Vm.AccountAccess[] memory records = vm.stopAndReturnStateDiff();
        bytes32[] memory slots = saveWrittenSlots(address(tempRegistry), records);
        copyContractState(address(tempRegistry), address(consensusRegistry), slots);

        // simulate protocol allocation of validators' initial stake
        registryGenesisBal = stakeAmount_ * initialValidators.length;
        vm.deal(address(consensusRegistry), registryGenesisBal);
        // set protocol system address
        sysAddress = consensusRegistry.SYSTEM_ADDRESS();

        vm.deal(validator5, stakeAmount_);

        // deal issuance contract epoch issuance to test reward distribution
        vm.deal(crOwner, epochIssuance_);
        vm.prank(crOwner);
        consensusRegistry.allocateIssuance{ value: epochIssuance_ }();
    }

    /// @dev Authors a new global stake version with the given amount and returns its index
    function _authorVersion(uint256 newStakeAmount) internal returns (uint8) {
        vm.prank(crOwner);
        return consensusRegistry.upgradeStakeVersion(
            StakeConfig(newStakeAmount, minWithdrawAmount_, epochIssuance_, epochDuration_)
        );
    }

    /// @dev Mints validator5 and returns its EIP-712 delegation signature for `delegatorAddr`
    function _mintValidator5AndSignDelegation(address delegatorAddr) internal returns (bytes memory sig) {
        vm.prank(crOwner);
        consensusRegistry.mint(validator5);
        bytes32 digest = consensusRegistry.delegationDigest(validator5BlsPubkey, validator5, delegatorAddr);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator5Secret, digest);
        sig = abi.encodePacked(r, s, v);
    }

    /*
     *   cancel
     */

    function test_cancel_decrease() public {
        uint8 lowVersion = _authorVersion(600_000e18);

        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange(validator1, lowVersion);
        assertEq(consensusRegistry.getPendingVersionChanges().length, 1);

        vm.expectEmit(true, true, true, true);
        emit StakeVersionChangeCanceled(validator1);
        vm.prank(validator1);
        consensusRegistry.cancelStakeVersionChange(validator1);

        assertEq(consensusRegistry.getPendingVersionChanges().length, 0);
        (uint8 target,,,) = consensusRegistry.versionChangeRequests(validator1);
        assertEq(target, 0);

        // boundaries are a no-op for the cancelled entry
        vm.startPrank(sysAddress);
        _concludeEpoch(_sortedGenesisCommittee());
        _concludeEpoch(_sortedGenesisCommittee());
        vm.stopPrank();
        assertEq(consensusRegistry.getValidator(validator1).stakeVersion, 0);

        // nothing left to cancel
        vm.prank(validator1);
        vm.expectRevert(IStakeManager.NoPendingVersionChange.selector);
        consensusRegistry.cancelStakeVersionChange(validator1);
    }

    function test_cancel_increase_returnsEscrowToFunder() public {
        uint8 highVersion = _authorVersion(2_000_000e18);
        uint256 deficit = 1_000_000e18;

        vm.deal(validator1, deficit);
        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange{ value: deficit }(validator1, highVersion);
        assertEq(validator1.balance, 0);
        assertEq(address(consensusRegistry).balance, registryGenesisBal + deficit);

        vm.prank(validator1);
        consensusRegistry.cancelStakeVersionChange(validator1);

        // escrow returned in full; the stake ledger never saw it
        assertEq(validator1.balance, deficit);
        assertEq(address(consensusRegistry).balance, registryGenesisBal);
        (uint256 bal,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(bal, stakeAmount_);
    }

    function testRevert_cancel_unauthorized() public {
        uint8 lowVersion = _authorVersion(600_000e18);
        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange(validator1, lowVersion);

        vm.prank(address(0xdead));
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.NotRecipient.selector, validator1));
        consensusRegistry.cancelStakeVersionChange(validator1);
    }

    function test_requeueAfterCancel() public {
        uint8 lowVersion = _authorVersion(600_000e18);

        vm.startPrank(validator1);
        consensusRegistry.requestStakeVersionChange(validator1, lowVersion);
        consensusRegistry.cancelStakeVersionChange(validator1);
        consensusRegistry.requestStakeVersionChange(validator1, lowVersion);
        vm.stopPrank();

        assertEq(consensusRegistry.getPendingVersionChanges().length, 1);
        (uint8 target,,,) = consensusRegistry.versionChangeRequests(validator1);
        assertEq(target, lowVersion);
    }

    /*
     *   overwrite semantics
     */

    function test_overwrite_returnsPriorEscrow() public {
        uint8 v1 = _authorVersion(1_500_000e18);
        uint8 v2 = _authorVersion(2_000_000e18);

        uint256 deficit1 = 500_000e18;
        uint256 deficit2 = 1_000_000e18;
        vm.deal(validator1, deficit1 + deficit2);

        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange{ value: deficit1 }(validator1, v1);

        // re-requesting overwrites the entry and returns the prior escrow to its funder
        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange{ value: deficit2 }(validator1, v2);
        assertEq(validator1.balance, deficit1);

        (uint8 target,,, uint256 escrow) = consensusRegistry.versionChangeRequests(validator1);
        assertEq(target, v2);
        assertEq(escrow, deficit2);
        assertEq(consensusRegistry.getPendingVersionChanges().length, 1);

        // the surviving request settles at the boundary
        vm.prank(sysAddress);
        _concludeEpoch(_sortedGenesisCommittee());
        assertEq(consensusRegistry.getValidator(validator1).stakeVersion, v2);
        (uint256 bal,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(bal, 2_000_000e18);
    }

    function test_overwrite_increaseThenDecrease() public {
        uint8 highVersion = _authorVersion(2_000_000e18);
        uint8 lowVersion = _authorVersion(600_000e18);

        uint256 deficit = 1_000_000e18;
        vm.deal(validator1, deficit);

        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange{ value: deficit }(validator1, highVersion);

        // switching to a decrease returns the escrow; the new entry holds none
        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange(validator1, lowVersion);
        assertEq(validator1.balance, deficit);
        (uint8 target,,, uint256 escrow) = consensusRegistry.versionChangeRequests(validator1);
        assertEq(target, lowVersion);
        assertEq(escrow, 0);
    }

    /*
     *   funder semantics on delegated stake
     */

    function test_delegated_decreaseRefundsRecipient() public {
        address delegator = _addressFromPrivateKey(42);
        bytes memory sig = _mintValidator5AndSignDelegation(delegator);

        vm.deal(delegator, stakeAmount_);
        vm.prank(delegator);
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig), validator5, sig
        );

        // enter service so the request routes through the queue
        vm.prank(validator5);
        consensusRegistry.activate();

        uint8 lowVersion = _authorVersion(600_000e18);
        vm.prank(validator5);
        consensusRegistry.requestStakeVersionChange(validator5, lowVersion);

        // age past the decrease delay and settle; the refund goes to the delegator (the recipient)
        vm.startPrank(sysAddress);
        _concludeEpoch(_sortedGenesisCommittee());
        _concludeEpoch(_sortedGenesisCommittee());
        vm.stopPrank();

        assertEq(consensusRegistry.getValidator(validator5).stakeVersion, lowVersion);
        assertEq(delegator.balance, stakeAmount_ - 600_000e18);
        assertEq(validator5.balance, stakeAmount_); // untouched setUp funds
    }

    function test_delegated_cancelReturnsEscrowToFunderNotRecipient() public {
        address delegator = _addressFromPrivateKey(42);
        bytes memory sig = _mintValidator5AndSignDelegation(delegator);

        vm.deal(delegator, stakeAmount_);
        vm.prank(delegator);
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig), validator5, sig
        );
        vm.prank(validator5);
        consensusRegistry.activate();

        // the validator funds the increase escrow itself
        uint8 highVersion = _authorVersion(2_000_000e18);
        uint256 deficit = 1_000_000e18;
        uint256 validator5BalBefore = validator5.balance;
        vm.prank(validator5);
        consensusRegistry.requestStakeVersionChange{ value: deficit }(validator5, highVersion);

        // the delegator cancels; the escrow returns to the funder (the validator), not the caller
        uint256 delegatorBalBefore = delegator.balance;
        vm.prank(delegator);
        consensusRegistry.cancelStakeVersionChange(validator5);

        assertEq(validator5.balance, validator5BalBefore);
        assertEq(delegator.balance, delegatorBalBefore);
    }

    /*
     *   lifecycle interactions
     */

    function test_burnWhileQueued_creditsEscrowToFunder() public {
        uint8 highVersion = _authorVersion(2_000_000e18);
        uint256 deficit = 1_000_000e18;
        vm.deal(validator1, deficit);
        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange{ value: deficit }(validator1, highVersion);

        uint256 issuanceBalBefore = issuance.balance;

        // a governance burn drops the entry and credits the escrow back; it is not confiscable
        vm.expectEmit(true, true, true, true);
        emit RefundQueued(validator1, deficit);
        vm.prank(crOwner);
        consensusRegistry.burn(validator1);

        assertTrue(consensusRegistry.isRetired(validator1));
        assertEq(consensusRegistry.getPendingVersionChanges().length, 0);
        assertEq(consensusRegistry.claimableRefunds(validator1), deficit);
        // the stake itself is confiscated onto Issuance per burn rules
        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_);

        // the credit is lifecycle-detached and claimable after retirement
        vm.expectEmit(true, true, true, true);
        emit RefundClaimed(validator1, deficit);
        vm.prank(validator1);
        consensusRegistry.claimRefund();
        assertEq(validator1.balance, deficit);
        assertEq(consensusRegistry.claimableRefunds(validator1), 0);
    }

    function test_exitWhileQueued_settlesThenUnstakes() public {
        uint8 lowVersion = _authorVersion(600_000e18);

        // queue the decrease, then begin exiting
        vm.startPrank(validator1);
        consensusRegistry.requestStakeVersionChange(validator1, lowVersion);
        consensusRegistry.beginExit();
        vm.stopPrank();

        uint256 balBefore = validator1.balance;

        // validator1 serves in the genesis committees for the first epochs, so conclude past them;
        // the queued decrease ages one boundary and settles at the second while still in service
        vm.startPrank(sysAddress);
        address[] memory waitCommittee = _createTokenIdCommittee(4);
        waitCommittee[3] = validator1;
        _concludeEpoch(waitCommittee);
        address[] memory tokenIdCommittee = _createTokenIdCommittee(4);
        _concludeEpoch(tokenIdCommittee);
        _concludeEpoch(tokenIdCommittee);
        vm.stopPrank();

        // settled during the exit tail: version flipped, surplus refunded
        assertEq(consensusRegistry.getValidator(validator1).stakeVersion, lowVersion);
        assertEq(validator1.balance, balBefore + 400_000e18);

        // resolve the exit and reach unstake eligibility
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(3);
        vm.startPrank(sysAddress);
        address[] memory afterExitCommittee = _createTokenIdCommittee(3);
        _concludeEpoch(afterExitCommittee);
        _concludeEpoch(afterExitCommittee);
        vm.stopPrank();

        // unstake settles at the version actually in force
        vm.prank(validator1);
        consensusRegistry.unstake(validator1);
        assertEq(validator1.balance, balBefore + 400_000e18 + 600_000e18);
        assertTrue(consensusRegistry.isRetired(validator1));
    }

    /*
     *   hostile refund recipients
     */

    function test_revertingRecipient_creditsInsteadOfBlocking() public {
        QueueRecipientMock mock = new QueueRecipientMock(consensusRegistry);
        bytes memory sig = _mintValidator5AndSignDelegation(address(mock));

        vm.deal(address(this), stakeAmount_);
        mock.delegate{ value: stakeAmount_ }(
            validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig), validator5, sig
        );
        vm.prank(validator5);
        consensusRegistry.activate();

        uint8 lowVersion = _authorVersion(600_000e18);
        vm.prank(validator5);
        consensusRegistry.requestStakeVersionChange(validator5, lowVersion);

        // the recipient rejects the settlement push; the boundary must complete regardless
        mock.setReject(true);
        uint32 epochBefore = consensusRegistry.getCurrentEpoch();
        vm.startPrank(sysAddress);
        _concludeEpoch(_sortedGenesisCommittee());
        _concludeEpoch(_sortedGenesisCommittee());
        vm.stopPrank();
        assertEq(consensusRegistry.getCurrentEpoch(), epochBefore + 2);

        // the flip landed and the refund fell back to a pull credit
        uint256 refund = 400_000e18;
        assertEq(consensusRegistry.getValidator(validator5).stakeVersion, lowVersion);
        assertEq(consensusRegistry.claimableRefunds(address(mock)), refund);

        // the pull fails while the recipient still rejects, preserving the credit
        vm.expectRevert(abi.encodeWithSelector(Issuance.RewardDistributionFailure.selector, address(mock)));
        mock.claim();
        assertEq(consensusRegistry.claimableRefunds(address(mock)), refund);

        // once the recipient accepts, the credit clears
        mock.setReject(false);
        mock.claim();
        assertEq(address(mock).balance, refund);
        assertEq(consensusRegistry.claimableRefunds(address(mock)), 0);
    }

    function test_gasGriefingRecipient_boundaryBounded() public {
        QueueRecipientMock mock = new QueueRecipientMock(consensusRegistry);
        bytes memory sig = _mintValidator5AndSignDelegation(address(mock));

        vm.deal(address(this), stakeAmount_);
        mock.delegate{ value: stakeAmount_ }(
            validator5BlsPubkey, IStakeManager.ProofOfPossession(validator5BlsSig), validator5, sig
        );
        vm.prank(validator5);
        consensusRegistry.activate();

        uint8 lowVersion = _authorVersion(600_000e18);
        vm.prank(validator5);
        consensusRegistry.requestStakeVersionChange(validator5, lowVersion);

        // an unbounded-gas recipient cannot stall the boundary: the push is gas-capped and
        // falls back to a credit
        mock.setBurnGas(true);
        uint32 epochBefore = consensusRegistry.getCurrentEpoch();
        vm.startPrank(sysAddress);
        _concludeEpoch(_sortedGenesisCommittee());
        _concludeEpoch(_sortedGenesisCommittee());
        vm.stopPrank();

        assertEq(consensusRegistry.getCurrentEpoch(), epochBefore + 2);
        assertEq(consensusRegistry.getValidator(validator5).stakeVersion, lowVersion);
        assertEq(consensusRegistry.claimableRefunds(address(mock)), 400_000e18);
    }

    /*
     *   reward-accounting hardening
     */

    function test_escrowNeverClaimableAsRewards() public {
        uint8 highVersion = _authorVersion(2_000_000e18);
        uint256 deficit = 1_000_000e18;
        vm.deal(validator1, deficit);
        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange{ value: deficit }(validator1, highVersion);

        // while queued, the escrow is invisible to reward accounting
        assertEq(consensusRegistry.getRewards(validator1), 0);
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(IStakeManager.InsufficientRewards.selector, 0));
        consensusRegistry.claimStakeRewards(validator1);

        // after the flip, the escrow is stake against the raised reward floor - still no rewards
        vm.prank(sysAddress);
        _concludeEpoch(_sortedGenesisCommittee());
        assertEq(consensusRegistry.getRewards(validator1), 0);
        (uint256 bal, uint256 stakeAmt,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(bal, 2_000_000e18);
        assertEq(stakeAmt, 2_000_000e18);
    }

    /*
     *   multi-validator boundary
     */

    function test_multiValidatorBoundary_mixedDirections() public {
        uint8 highVersion = _authorVersion(2_000_000e18);
        uint8 lowVersion = _authorVersion(600_000e18);
        uint8 sameVersion = _authorVersion(stakeAmount_);

        // validator1 increases, validator2 decreases, validator3 changes to an equal amount,
        // validator4 queues then cancels
        uint256 deficit = 1_000_000e18;
        vm.deal(validator1, deficit);
        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange{ value: deficit }(validator1, highVersion);
        vm.prank(validator2);
        consensusRegistry.requestStakeVersionChange(validator2, lowVersion);
        vm.prank(validator3);
        consensusRegistry.requestStakeVersionChange(validator3, sameVersion);
        vm.prank(validator4);
        consensusRegistry.requestStakeVersionChange(validator4, lowVersion);
        vm.prank(validator4);
        consensusRegistry.cancelStakeVersionChange(validator4);

        assertEq(consensusRegistry.getPendingVersionChanges().length, 3);

        // first boundary: the increase and the equal-amount change settle; the decrease ages
        vm.prank(sysAddress);
        _concludeEpoch(_sortedGenesisCommittee());
        assertEq(consensusRegistry.getValidator(validator1).stakeVersion, highVersion);
        assertEq(consensusRegistry.getValidator(validator3).stakeVersion, sameVersion);
        assertEq(consensusRegistry.getValidator(validator2).stakeVersion, 0);
        assertEq(consensusRegistry.getPendingVersionChanges().length, 1);

        // second boundary: the decrease settles
        uint256 validator2BalBefore = validator2.balance;
        vm.prank(sysAddress);
        _concludeEpoch(_sortedGenesisCommittee());
        assertEq(consensusRegistry.getValidator(validator2).stakeVersion, lowVersion);
        assertEq(validator2.balance, validator2BalBefore + 400_000e18);
        assertEq(consensusRegistry.getPendingVersionChanges().length, 0);

        // validator4 never changed
        assertEq(consensusRegistry.getValidator(validator4).stakeVersion, 0);
    }

    /*
     *   native-balance conservation
     */

    function test_conservation_registryBalanceMatchesLedgers() public {
        uint256 start = address(consensusRegistry).balance;
        uint8 highVersion = _authorVersion(2_000_000e18);
        uint8 lowVersion = _authorVersion(600_000e18);

        // validator1 escrows a 1M increase; validator2 queues a decrease
        uint256 deficit = 1_000_000e18;
        vm.deal(validator1, deficit);
        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange{ value: deficit }(validator1, highVersion);
        vm.prank(validator2);
        consensusRegistry.requestStakeVersionChange(validator2, lowVersion);

        // boundary 1: the increase settles
        vm.prank(sysAddress);
        _concludeEpoch(_sortedGenesisCommittee());

        // boundary 2 carries a 200k slash on validator2, landing before its decrease settles:
        // refund 200k to the recipient, 200k of slashed surplus consolidates on Issuance
        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator2, 200_000e18);
        vm.prank(sysAddress);
        _concludeEpochWithSlashes(_sortedGenesisCommittee(), slashes);

        // registry native balance exactly backs the stake ledger: no queue entries, no credits
        uint256 expected = start + deficit - 200_000e18 - 200_000e18;
        assertEq(address(consensusRegistry).balance, expected);

        uint256 ledgerSum;
        address[4] memory genesis = [validator1, validator2, validator3, validator4];
        for (uint256 i; i < 4; ++i) {
            (uint256 bal,,) = consensusRegistry.getBalanceBreakdown(genesis[i]);
            ledgerSum += bal;
        }
        assertEq(ledgerSum, expected);
        assertEq(consensusRegistry.getPendingVersionChanges().length, 0);
    }

    /*
     *   claimRefund and pause gating
     */

    function testRevert_claimRefund_noCredit() public {
        vm.prank(validator1);
        vm.expectRevert(IStakeManager.NoClaimableRefund.selector);
        consensusRegistry.claimRefund();
    }

    function testRevert_userPaths_paused() public {
        uint8 lowVersion = _authorVersion(600_000e18);
        vm.prank(validator1);
        consensusRegistry.requestStakeVersionChange(validator1, lowVersion);

        vm.prank(crOwner);
        consensusRegistry.pause();

        vm.prank(validator2);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        consensusRegistry.requestStakeVersionChange(validator2, lowVersion);

        vm.prank(validator1);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        consensusRegistry.cancelStakeVersionChange(validator1);

        vm.prank(validator1);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        consensusRegistry.claimRefund();

        // the boundary is never pausable: queued work still settles
        vm.startPrank(sysAddress);
        _concludeEpoch(_sortedGenesisCommittee());
        _concludeEpoch(_sortedGenesisCommittee());
        vm.stopPrank();
        assertEq(consensusRegistry.getValidator(validator1).stakeVersion, lowVersion);
    }
}
