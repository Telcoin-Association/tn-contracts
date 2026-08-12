// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import "forge-std/Test.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { RewardInfo, Slash, IStakeManager } from "src/interfaces/IStakeManager.sol";
import { IConsensusRegistry } from "src/interfaces/IConsensusRegistry.sol";
import { ConsensusRegistryTestUtils } from "./ConsensusRegistryTestUtils.sol";

/// @dev A wallet program with no ERC-1271 handler whose fallback reverts. Stands in both for a
/// 7702 delegate that cannot answer signature queries and for an account that rejects native TEL.
contract RevertingWallet {
    fallback() external payable {
        revert("RevertingWallet");
    }
}

/// @dev A 7702 delegate that approves every digest presented to it, modelling the permissive end
/// of the smart-account spectrum
contract PermissiveWallet {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }

    receive() external payable { }
}

/// @dev A genuine contract account that answers ERC-1271 against a fixed secp256k1 signer
contract ERC1271Wallet {
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (signature.length != 65) return 0xffffffff;
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);

        return ecrecover(hash, v, r, s) == signer ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    receive() external payable { }
}

/// Coverage for account abstraction reaching addresses the registry treats as validators.
///
/// Two properties are pinned here. First, `delegateStake` asks the right authority for the
/// validator's approval: an EOA answers with its secp256k1 key whether or not it has attached an
/// EIP-7702 delegation, and only a genuine contract account answers through ERC-1271. Second, the
/// governance-ejection paths - `burn` and the slash-to-zero branch of `applySlashes`, the latter
/// running inside an epoch-boundary system call - push no value to a validator-controlled address
/// and so cannot be blocked by account code a validator attaches after being whitelisted.
contract ConsensusRegistryEIP7702Test is ConsensusRegistryTestUtils {
    RevertingWallet internal revertingWallet;
    PermissiveWallet internal permissiveWallet;

    /// @dev A validator key distinct from the genesis set and from `validator5`
    uint256 internal constant DELEGATED_VALIDATOR_PK = 77;
    uint256 internal constant STRANGER_PK = 1337;

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
        sysAddress = consensusRegistry.SYSTEM_ADDRESS();

        vm.deal(crOwner, epochIssuance_);
        vm.prank(crOwner);
        consensusRegistry.allocateIssuance{ value: epochIssuance_ }();

        revertingWallet = new RevertingWallet();
        permissiveWallet = new PermissiveWallet();
    }

    /*
     *   helpers
     */

    /// @dev Mints a ConsensusNFT to `validatorAddress` and returns a funded delegator
    function _prepareDelegation(address validatorAddress) internal returns (address delegator) {
        vm.prank(crOwner);
        consensusRegistry.mint(validatorAddress);

        delegator = _addressFromPrivateKey(42);
        vm.deal(delegator, stakeAmount_);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /*
     *   delegateStake: an EOA is held to its key, delegated or not
     */

    /// A 7702-delegated validator whose wallet program has no ERC-1271 handler is still onboardable:
    /// the registry recovers against the validator's own key rather than querying the delegate.
    function test_delegateStake_delegatedEOA_acceptsKeySignature() public {
        address validatorAddress = vm.addr(DELEGATED_VALIDATOR_PK);
        address delegator = _prepareDelegation(validatorAddress);
        bytes memory blsPubkey = _blsDummyPubkeyFromSecret(DELEGATED_VALIDATOR_PK);
        bytes memory blsSig = _blsDummySigFromSecret(DELEGATED_VALIDATOR_PK);

        uint256 deadline = block.timestamp + 1 days;
        bytes memory validatorSig = _sign(
            DELEGATED_VALIDATOR_PK, consensusRegistry.delegationDigest(blsPubkey, validatorAddress, delegator, deadline)
        );

        // the validator upgrades to a smart account that answers no signature queries at all
        vm.signAndAttachDelegation(address(revertingWallet), DELEGATED_VALIDATOR_PK);
        assertEq(validatorAddress.code.length, 23, "expected a 7702 delegation designator");

        vm.prank(delegator);
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            blsPubkey, IStakeManager.ProofOfPossession(blsSig), validatorAddress, validatorSig, deadline
        );

        assertTrue(consensusRegistry.isDelegated(validatorAddress));
        assertEq(uint8(consensusRegistry.getValidator(validatorAddress).currentStatus), uint8(ValidatorStatus.Staked));
    }

    /// The EIP-2098 compact signature encoding is accepted on the delegated-EOA path too.
    function test_delegateStake_delegatedEOA_acceptsCompactSignature() public {
        address validatorAddress = vm.addr(DELEGATED_VALIDATOR_PK);
        address delegator = _prepareDelegation(validatorAddress);
        bytes memory blsPubkey = _blsDummyPubkeyFromSecret(DELEGATED_VALIDATOR_PK);
        bytes memory blsSig = _blsDummySigFromSecret(DELEGATED_VALIDATOR_PK);

        uint256 deadline = block.timestamp + 1 days;
        bytes32 digest = consensusRegistry.delegationDigest(blsPubkey, validatorAddress, delegator, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DELEGATED_VALIDATOR_PK, digest);
        bytes32 vs = bytes32((uint256(v - 27) << 255) | uint256(s));
        bytes memory validatorSig = abi.encodePacked(r, vs);
        assertEq(validatorSig.length, 64);

        vm.signAndAttachDelegation(address(revertingWallet), DELEGATED_VALIDATOR_PK);

        vm.prank(delegator);
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            blsPubkey, IStakeManager.ProofOfPossession(blsSig), validatorAddress, validatorSig, deadline
        );

        assertTrue(consensusRegistry.isDelegated(validatorAddress));
    }

    /// A delegate that rubber-stamps every digest cannot stand in for the validator's key: the
    /// digest is public, so an approval-by-delegate would let anyone bind themselves as delegator
    /// and become the recipient of every subsequent claim and unstake.
    function testRevert_delegateStake_permissiveDelegateCannotAuthorize() public {
        address validatorAddress = vm.addr(DELEGATED_VALIDATOR_PK);
        _prepareDelegation(validatorAddress);
        bytes memory blsPubkey = _blsDummyPubkeyFromSecret(DELEGATED_VALIDATOR_PK);
        bytes memory blsSig = _blsDummySigFromSecret(DELEGATED_VALIDATOR_PK);

        address stranger = _addressFromPrivateKey(STRANGER_PK);
        vm.deal(stranger, stakeAmount_);
        uint256 deadline = block.timestamp + 1 days;

        vm.signAndAttachDelegation(address(permissiveWallet), DELEGATED_VALIDATOR_PK);
        assertEq(validatorAddress.code.length, 23);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IConsensusRegistry.NotValidator.selector, validatorAddress));
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            blsPubkey, IStakeManager.ProofOfPossession(blsSig), validatorAddress, hex"deadbeef", deadline
        );

        assertFalse(consensusRegistry.isDelegated(validatorAddress));
    }

    /// A well-formed signature from the wrong key is rejected even when the delegate would approve it.
    function testRevert_delegateStake_delegatedEOA_wrongKeySignature() public {
        address validatorAddress = vm.addr(DELEGATED_VALIDATOR_PK);
        _prepareDelegation(validatorAddress);
        bytes memory blsPubkey = _blsDummyPubkeyFromSecret(DELEGATED_VALIDATOR_PK);
        bytes memory blsSig = _blsDummySigFromSecret(DELEGATED_VALIDATOR_PK);

        address stranger = _addressFromPrivateKey(STRANGER_PK);
        vm.deal(stranger, stakeAmount_);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory strangerSig =
            _sign(STRANGER_PK, consensusRegistry.delegationDigest(blsPubkey, validatorAddress, stranger, deadline));

        vm.signAndAttachDelegation(address(permissiveWallet), DELEGATED_VALIDATOR_PK);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IConsensusRegistry.NotValidator.selector, validatorAddress));
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            blsPubkey, IStakeManager.ProofOfPossession(blsSig), validatorAddress, strangerSig, deadline
        );
    }

    /// Designator detection matches the `0xef0100` prefix, not merely the 23-byte length: a real
    /// contract that happens to be 23 bytes long is still a contract and still answers via ERC-1271.
    function testRevert_delegateStake_twentyThreeByteContractIsNotADesignator() public {
        address validatorAddress = vm.addr(DELEGATED_VALIDATOR_PK);
        address delegator = _prepareDelegation(validatorAddress);
        bytes memory blsPubkey = _blsDummyPubkeyFromSecret(DELEGATED_VALIDATOR_PK);
        bytes memory blsSig = _blsDummySigFromSecret(DELEGATED_VALIDATOR_PK);

        uint256 deadline = block.timestamp + 1 days;
        bytes memory validatorSig = _sign(
            DELEGATED_VALIDATOR_PK, consensusRegistry.delegationDigest(blsPubkey, validatorAddress, delegator, deadline)
        );

        // 23 bytes of real (if useless) contract code: returns empty data, so the ERC-1271 probe
        // it is correctly routed to reads back no magic value
        bytes memory notADesignator = hex"60006000f3000000000000000000000000000000000000";
        assertEq(notADesignator.length, 23);
        vm.etch(validatorAddress, notADesignator);

        vm.prank(delegator);
        vm.expectRevert(abi.encodeWithSelector(IConsensusRegistry.NotValidator.selector, validatorAddress));
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            blsPubkey, IStakeManager.ProofOfPossession(blsSig), validatorAddress, validatorSig, deadline
        );
    }

    /// A 65-byte signature carrying a `v` outside {27, 28} must be rejected outright rather than
    /// recovering to some unrelated address.
    function testRevert_delegateStake_delegatedEOA_bogusRecoveryId() public {
        address validatorAddress = vm.addr(DELEGATED_VALIDATOR_PK);
        address delegator = _prepareDelegation(validatorAddress);
        bytes memory blsPubkey = _blsDummyPubkeyFromSecret(DELEGATED_VALIDATOR_PK);
        bytes memory blsSig = _blsDummySigFromSecret(DELEGATED_VALIDATOR_PK);

        uint256 deadline = block.timestamp + 1 days;
        bytes32 digest = consensusRegistry.delegationDigest(blsPubkey, validatorAddress, delegator, deadline);
        (, bytes32 r, bytes32 s) = vm.sign(DELEGATED_VALIDATOR_PK, digest);

        vm.signAndAttachDelegation(address(revertingWallet), DELEGATED_VALIDATOR_PK);

        vm.prank(delegator);
        vm.expectRevert(abi.encodeWithSelector(IConsensusRegistry.NotValidator.selector, validatorAddress));
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            blsPubkey,
            IStakeManager.ProofOfPossession(blsSig),
            validatorAddress,
            abi.encodePacked(r, s, uint8(99)),
            deadline
        );
    }

    /// An empty signature recovers to the zero address, which must not satisfy the check.
    function testRevert_delegateStake_delegatedEOA_emptySignature() public {
        address validatorAddress = vm.addr(DELEGATED_VALIDATOR_PK);
        address delegator = _prepareDelegation(validatorAddress);
        bytes memory blsPubkey = _blsDummyPubkeyFromSecret(DELEGATED_VALIDATOR_PK);
        bytes memory blsSig = _blsDummySigFromSecret(DELEGATED_VALIDATOR_PK);
        uint256 deadline = block.timestamp + 1 days;

        vm.signAndAttachDelegation(address(revertingWallet), DELEGATED_VALIDATOR_PK);

        vm.prank(delegator);
        vm.expectRevert(abi.encodeWithSelector(IConsensusRegistry.NotValidator.selector, validatorAddress));
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            blsPubkey, IStakeManager.ProofOfPossession(blsSig), validatorAddress, "", deadline
        );
    }

    /// The delegated and undelegated routes must accept exactly the same signature set, or the
    /// designator branch would be its own authorization surface. Probed at the known divergence
    /// candidate: neither route screens high-s, so `(r, n-s, v^1)` must be accepted by both or
    /// neither. It is inert here regardless - the digest binds the delegator and a nonce, and a
    /// successful call leaves `Undefined` status behind - but the two routes must not disagree.
    function test_delegateStake_delegatedAndPlainRoutesAcceptSameSignatures() public {
        address validatorAddress = vm.addr(DELEGATED_VALIDATOR_PK);
        address delegator = _prepareDelegation(validatorAddress);
        vm.deal(delegator, stakeAmount_ * 2);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory malleated = _malleatedSignature(DELEGATED_VALIDATOR_PK, delegator, deadline);

        uint256 snapshot = vm.snapshotState();
        bool acceptedPlain = _tryDelegateStake(DELEGATED_VALIDATOR_PK, delegator, malleated, deadline);
        vm.revertToState(snapshot);

        vm.signAndAttachDelegation(address(revertingWallet), DELEGATED_VALIDATOR_PK);
        assertEq(validatorAddress.code.length, 23);
        bool acceptedDelegated = _tryDelegateStake(DELEGATED_VALIDATOR_PK, delegator, malleated, deadline);

        assertTrue(acceptedPlain);
        assertEq(acceptedPlain, acceptedDelegated, "designator branch diverged from the plain EOA branch");
    }

    /// @dev The high-s counterpart of a valid signature: recovers the same signer, different bytes
    function _malleatedSignature(uint256 pk, address delegator, uint256 deadline) internal view returns (bytes memory) {
        uint256 secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 digest =
            consensusRegistry.delegationDigest(_blsDummyPubkeyFromSecret(pk), vm.addr(pk), delegator, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

        return abi.encodePacked(r, bytes32(secp256k1n - uint256(s)), uint8(v == 27 ? 28 : 27));
    }

    /// @dev Attempts a delegation and reports acceptance without reverting the test
    function _tryDelegateStake(
        uint256 pk,
        address delegator,
        bytes memory signature,
        uint256 deadline
    )
        internal
        returns (bool accepted)
    {
        vm.prank(delegator);
        (accepted,) = address(consensusRegistry).call{ value: stakeAmount_ }(
            abi.encodeCall(
                IStakeManager.delegateStake,
                (
                    _blsDummyPubkeyFromSecret(pk),
                    IStakeManager.ProofOfPossession(_blsDummySigFromSecret(pk)),
                    vm.addr(pk),
                    signature,
                    deadline
                )
            )
        );
    }

    /*
     *   delegateStake: genuine contract accounts still authorize through ERC-1271
     */

    function test_delegateStake_contractValidator_usesERC1271() public {
        uint256 walletSignerPk = 88;
        ERC1271Wallet wallet = new ERC1271Wallet(vm.addr(walletSignerPk));
        address validatorAddress = address(wallet);
        address delegator = _prepareDelegation(validatorAddress);
        bytes memory blsPubkey = _blsDummyPubkeyFromSecret(walletSignerPk);
        bytes memory blsSig = _blsDummySigFromSecret(walletSignerPk);

        uint256 deadline = block.timestamp + 1 days;
        bytes memory validatorSig =
            _sign(walletSignerPk, consensusRegistry.delegationDigest(blsPubkey, validatorAddress, delegator, deadline));

        vm.prank(delegator);
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            blsPubkey, IStakeManager.ProofOfPossession(blsSig), validatorAddress, validatorSig, deadline
        );

        assertTrue(consensusRegistry.isDelegated(validatorAddress));
        assertEq(uint8(consensusRegistry.getValidator(validatorAddress).currentStatus), uint8(ValidatorStatus.Staked));
    }

    function testRevert_delegateStake_contractValidator_rejectsBadSignature() public {
        uint256 walletSignerPk = 88;
        ERC1271Wallet wallet = new ERC1271Wallet(vm.addr(walletSignerPk));
        address validatorAddress = address(wallet);
        address delegator = _prepareDelegation(validatorAddress);
        bytes memory blsPubkey = _blsDummyPubkeyFromSecret(walletSignerPk);
        bytes memory blsSig = _blsDummySigFromSecret(walletSignerPk);

        uint256 deadline = block.timestamp + 1 days;
        bytes memory strangerSig =
            _sign(STRANGER_PK, consensusRegistry.delegationDigest(blsPubkey, validatorAddress, delegator, deadline));

        vm.prank(delegator);
        vm.expectRevert(abi.encodeWithSelector(IConsensusRegistry.NotValidator.selector, validatorAddress));
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            blsPubkey, IStakeManager.ProofOfPossession(blsSig), validatorAddress, strangerSig, deadline
        );
    }

    /*
     *   governance ejection survives hostile validator account code
     */

    /// Governance whitelists an address it has screened; the holder can attach a reverting
    /// delegation afterwards. `burn` must remain callable regardless.
    function test_burn_notBlockedByRevertingValidatorCode() public {
        uint256 issuanceBalBefore = issuance.balance;

        vm.signAndAttachDelegation(address(revertingWallet), 1);
        assertEq(validator1.code.length, 23);
        (bool reachable,) = validator1.call{ value: 0 }("");
        assertFalse(reachable, "validator account must reject plain calls for this test to mean anything");

        vm.prank(crOwner);
        consensusRegistry.burn(validator1);

        assertTrue(consensusRegistry.isRetired(validator1));
        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_, "stake confiscated to Issuance");
        (uint256 outstanding,,) = consensusRegistry.getBalanceBreakdown(validator1);
        assertEq(outstanding, 0);
        _assertSetInvariant();
    }

    /// The same property inside the epoch-boundary system call, where a revert would stall the
    /// closing block rather than merely inconvenience governance.
    function test_applySlashes_slashToZero_notBlockedByRevertingValidatorCode() public {
        uint256 issuanceBalBefore = issuance.balance;

        vm.signAndAttachDelegation(address(revertingWallet), 1);

        Slash[] memory slashes = new Slash[](1);
        slashes[0] = Slash(validator1, stakeAmount_);
        vm.prank(sysAddress);
        consensusRegistry.applySlashes(slashes);

        assertTrue(consensusRegistry.isRetired(validator1));
        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_);
        _assertSetInvariant();

        // the boundary still closes over the surviving committee
        vm.prank(crOwner);
        consensusRegistry.setNextCommitteeSize(3);
        address[] memory survivors = new address[](3);
        survivors[0] = validator2;
        survivors[1] = validator3;
        survivors[2] = validator4;
        _sortAddresses(survivors);
        vm.prank(sysAddress);
        _concludeEpoch(survivors);
    }

    /// A delegated validator's payout recipient is its delegator, so a hostile delegator must not
    /// be able to block the burn either.
    function test_burn_notBlockedByRevertingDelegator() public {
        address validatorAddress = vm.addr(DELEGATED_VALIDATOR_PK);
        vm.prank(crOwner);
        consensusRegistry.mint(validatorAddress);

        address delegator = address(revertingWallet);
        vm.deal(delegator, stakeAmount_);
        bytes memory blsPubkey = _blsDummyPubkeyFromSecret(DELEGATED_VALIDATOR_PK);
        bytes memory blsSig = _blsDummySigFromSecret(DELEGATED_VALIDATOR_PK);

        uint256 deadline = block.timestamp + 1 days;
        bytes memory validatorSig = _sign(
            DELEGATED_VALIDATOR_PK, consensusRegistry.delegationDigest(blsPubkey, validatorAddress, delegator, deadline)
        );

        vm.prank(delegator);
        consensusRegistry.delegateStake{ value: stakeAmount_ }(
            blsPubkey, IStakeManager.ProofOfPossession(blsSig), validatorAddress, validatorSig, deadline
        );
        assertTrue(consensusRegistry.isDelegated(validatorAddress));

        uint256 issuanceBalBefore = issuance.balance;
        vm.prank(crOwner);
        consensusRegistry.burn(validatorAddress);

        assertTrue(consensusRegistry.isRetired(validatorAddress));
        assertEq(issuance.balance, issuanceBalBefore + stakeAmount_);
        assertEq(delegator.balance, 0, "delegated stake is confiscated, not returned");
        _assertSetInvariant();
    }

    /// Escrow held for a queued stake-version change is the one balance a burn owes back. It is
    /// credited for pull-based claiming rather than pushed, so hostile funder code cannot block
    /// the burn.
    function test_burn_creditsEscrowRefundWhenValidatorCodeReverts() public {
        // in service (PendingActivation) so the request queues rather than settling immediately
        vm.deal(validator5, stakeAmount_);
        _addFifthValidator();

        uint256 raisedStake = stakeAmount_ * 2;
        uint8 newVersion = _fuzz_upgradeGlobalStakeVersion(raisedStake);
        uint256 deficit = raisedStake - stakeAmount_;

        vm.deal(validator5, deficit);
        vm.prank(validator5);
        consensusRegistry.requestStakeVersionChange{ value: deficit }(validator5, newVersion);
        assertEq(consensusRegistry.getPendingVersionChanges().length, 1);

        // only now does the validator attach account code that rejects every incoming call
        vm.signAndAttachDelegation(address(revertingWallet), validator5Secret);

        vm.prank(crOwner);
        consensusRegistry.burn(validator5);

        assertTrue(consensusRegistry.isRetired(validator5));
        assertEq(consensusRegistry.getPendingVersionChanges().length, 0);
        assertEq(consensusRegistry.claimableRefunds(validator5), deficit, "escrow credited, not pushed");
        _assertSetInvariant();
    }
}
