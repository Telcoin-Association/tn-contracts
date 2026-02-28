// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { OFT } from "@layerzerolabs/oft-evm/contracts/OFT.sol";
import { SendParam, OFTReceipt, IOFT } from "@layerzerolabs/oft-evm/contracts/interfaces/IOFT.sol";
import { MessagingReceipt, MessagingFee } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { TestHelperOz5 } from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import { WTEL } from "../../src/WTEL.sol";
import { InterchainTELAdapter } from "../../src/InterchainTELAdapter.sol";
import { IInterchainTELAdapter } from "../../src/interfaces/IInterchainTELAdapter.sol";

/// @dev Mock remote OFT for cross-chain testing (mint/burn model, 18 decimals, sharedDecimals=2)
contract MockRemoteOFT is OFT {
    constructor(
        string memory _name,
        string memory _symbol,
        address _lzEndpoint,
        address _delegate
    ) OFT(_name, _symbol, _lzEndpoint, _delegate) Ownable(_delegate) {}

    function sharedDecimals() public pure override returns (uint8) {
        return 2;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Contract that rejects native TEL transfers (for testing _credit failure)
contract RejectingReceiver {
    receive() external payable {
        revert("rejected");
    }
}

contract InterchainTELAdapterTest is TestHelperOz5 {
    using OptionsBuilder for bytes;

    InterchainTELAdapter adapter;
    MockRemoteOFT remoteOFT;
    WTEL wtel;

    uint32 constant TN_EID = 1;
    uint32 constant REMOTE_EID = 2;

    address admin = address(this);
    address user = address(0xabc);
    address recipient = address(0xdef);

    uint256 constant INITIAL_POOL = 100 ether;
    uint256 constant DECIMALS_CONVERTER = 1e16;

    function setUp() public override {
        super.setUp();

        // Set executor value cap high enough for native TEL delivery
        setExecutorValueCap(100 ether);

        // Create mock LZ endpoints for 2 chains
        setUpEndpoints(2, LibraryType.UltraLightNode);

        // Deploy WTEL
        wtel = new WTEL();

        // Deploy InterchainTELAdapter on TN (eid=1)
        adapter = new InterchainTELAdapter(
            address(wtel),
            address(endpoints[TN_EID]),
            admin
        );

        // Deploy MockRemoteOFT on remote chain (eid=2)
        remoteOFT = new MockRemoteOFT(
            "Remote TEL",
            "rTEL",
            address(endpoints[REMOTE_EID]),
            admin
        );

        // Wire peers
        address[] memory oapps = new address[](2);
        oapps[0] = address(adapter);
        oapps[1] = address(remoteOFT);
        wireOApps(oapps);

        // Fund adapter with native TEL for inbound credit operations
        vm.deal(address(adapter), INITIAL_POOL);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function _defaultOptions() internal pure returns (bytes memory) {
        return OptionsBuilder.newOptions().addExecutorLzReceiveOption(200_000, 0);
    }

    function _buildSendParam(
        uint32 dstEid,
        address to,
        uint256 amountLD,
        uint256 minAmountLD
    ) internal pure returns (SendParam memory) {
        return SendParam({
            dstEid: dstEid,
            to: addressToBytes32(to),
            amountLD: amountLD,
            minAmountLD: minAmountLD,
            extraOptions: _defaultOptions(),
            composeMsg: "",
            oftCmd: ""
        });
    }

    /// @dev Removes sub-sharedDecimals dust from an amount
    function _removeDust(uint256 amount) internal pure returns (uint256) {
        return (amount / DECIMALS_CONVERTER) * DECIMALS_CONVERTER;
    }

    /// @dev External wrapper for verifyPackets so it can be called via try/catch
    function externalVerifyPackets(uint32 eid, bytes32 addr) external {
        verifyPackets(eid, addr);
    }

    /// @dev Attempts packet delivery, returns false if it reverts (e.g. credit failure)
    function _tryVerifyPackets(uint32 eid, bytes32 addr) internal returns (bool success) {
        try this.externalVerifyPackets(eid, addr) {
            return true;
        } catch {
            return false;
        }
    }

    /*//////////////////////////////////////////////////////////////
                            SETUP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setUp() public view {
        assertEq(adapter.token(), address(wtel));
        assertEq(adapter.owner(), admin);
        assertEq(adapter.sharedDecimals(), 2);
        assertTrue(adapter.approvalRequired());
        assertEq(address(adapter).balance, INITIAL_POOL);
    }

    /*//////////////////////////////////////////////////////////////
                        BRIDGE OUT: send() WITH WTEL
    //////////////////////////////////////////////////////////////*/

    function test_send_withWTEL() public {
        uint256 amount = 1 ether;

        // Build send params and quote fee first
        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        // Give user native TEL for WTEL wrapping + LZ fee
        vm.deal(user, amount + fee.nativeFee);
        vm.startPrank(user);
        wtel.deposit{ value: amount }();
        wtel.approve(address(adapter), amount);

        // Execute send — msg.value is just the LZ fee
        adapter.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();

        // Verify WTEL taken from user
        assertEq(wtel.balanceOf(user), 0);

        // Verify native TEL now in adapter (from WTEL unwrap) plus initial pool
        assertEq(address(adapter).balance, INITIAL_POOL + amount);

        // Deliver packet to remote and verify recipient received tokens
        verifyPackets(REMOTE_EID, addressToBytes32(address(remoteOFT)));
        assertEq(remoteOFT.balanceOf(recipient), amount);
    }

    function testFuzz_send_withWTEL(uint96 amount) public {
        // Bound: must be >= 1e16 (1 unit in 2-decimal precision) and reasonable
        vm.assume(amount >= DECIMALS_CONVERTER && amount <= 1e27);
        uint256 amountSent = _removeDust(amount);

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amountSent);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        // Deal enough for wrapping + fee
        vm.deal(user, uint256(amount) + fee.nativeFee);
        vm.startPrank(user);
        wtel.deposit{ value: amount }();
        wtel.approve(address(adapter), amount);

        adapter.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();

        // Only dust-free amount is sent, remainder stays as WTEL with user
        assertEq(wtel.balanceOf(user), amount - amountSent);
        assertEq(address(adapter).balance, INITIAL_POOL + amountSent);

        // Deliver and verify
        verifyPackets(REMOTE_EID, addressToBytes32(address(remoteOFT)));
        assertEq(remoteOFT.balanceOf(recipient), amountSent);
    }

    function test_send_withWTEL_emitsOFTSent() public {
        uint256 amount = 1 ether;

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        vm.deal(user, amount + fee.nativeFee);
        vm.startPrank(user);
        wtel.deposit{ value: amount }();
        wtel.approve(address(adapter), amount);

        // Check that OFTSent event is emitted with correct amounts
        vm.expectEmit(false, true, true, true);
        emit IOFT.OFTSent(bytes32(0), REMOTE_EID, user, amount, amount);
        adapter.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                      BRIDGE OUT: sendNative()
    //////////////////////////////////////////////////////////////*/

    function test_sendNative() public {
        uint256 amount = 1 ether;

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        // User sends native TEL (bridge amount + LZ fee)
        vm.deal(user, amount + fee.nativeFee);
        vm.prank(user);
        adapter.sendNative{ value: amount + fee.nativeFee }(sendParam, fee, user);

        // Verify native TEL stayed in adapter
        assertEq(address(adapter).balance, INITIAL_POOL + amount);

        // Deliver and verify remote receipt
        verifyPackets(REMOTE_EID, addressToBytes32(address(remoteOFT)));
        assertEq(remoteOFT.balanceOf(recipient), amount);
    }

    function testFuzz_sendNative(uint96 amount) public {
        vm.assume(amount >= DECIMALS_CONVERTER && amount <= 1e27);
        uint256 amountSent = _removeDust(amount);

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amountSent);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        vm.deal(user, uint256(amount) + fee.nativeFee);
        vm.prank(user);
        adapter.sendNative{ value: uint256(amount) + fee.nativeFee }(sendParam, fee, user);

        // All of amount (including dust) stays in adapter
        assertEq(address(adapter).balance, INITIAL_POOL + amount);

        verifyPackets(REMOTE_EID, addressToBytes32(address(remoteOFT)));
        assertEq(remoteOFT.balanceOf(recipient), amountSent);
    }

    function test_sendNative_emitsOFTSent() public {
        uint256 amount = 1 ether;

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        vm.deal(user, amount + fee.nativeFee);
        vm.prank(user);

        vm.expectEmit(false, true, true, true);
        emit IOFT.OFTSent(bytes32(0), REMOTE_EID, user, amount, amount);
        adapter.sendNative{ value: amount + fee.nativeFee }(sendParam, fee, user);
    }

    function testRevert_sendNative_insufficientMsgValue() public {
        uint256 amount = 1 ether;

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        // Send less than required (only fee, no bridge amount)
        vm.deal(user, fee.nativeFee);
        vm.prank(user);
        vm.expectRevert(IInterchainTELAdapter.InsufficientMsgValue.selector);
        adapter.sendNative{ value: fee.nativeFee }(sendParam, fee, user);
    }

    function testRevert_sendNative_zeroMsgValue() public {
        uint256 amount = 1 ether;

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        vm.prank(user);
        vm.expectRevert(IInterchainTELAdapter.InsufficientMsgValue.selector);
        adapter.sendNative{ value: 0 }(sendParam, fee, user);
    }

    /*//////////////////////////////////////////////////////////////
                      BRIDGE IN: _credit via lzReceive
    //////////////////////////////////////////////////////////////*/

    function test_credit_deliversNativeTEL() public {
        uint256 amount = 1 ether;
        uint256 recipientBalBefore = recipient.balance;

        // Mint tokens on remote and send to TN
        remoteOFT.mint(user, amount);

        vm.startPrank(user);
        SendParam memory sendParam = _buildSendParam(TN_EID, recipient, amount, amount);
        MessagingFee memory fee = remoteOFT.quoteSend(sendParam, false);
        vm.deal(user, fee.nativeFee);
        remoteOFT.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();

        // Remote tokens burned
        assertEq(remoteOFT.balanceOf(user), 0);

        // Deliver packet to TN adapter — triggers _credit which sends native TEL
        verifyPackets(TN_EID, addressToBytes32(address(adapter)));

        // Recipient received native TEL
        assertEq(recipient.balance, recipientBalBefore + amount);
        // Adapter pool decreased
        assertEq(address(adapter).balance, INITIAL_POOL - amount);
    }

    function testFuzz_credit_deliversNativeTEL(uint96 amount) public {
        vm.assume(amount >= DECIMALS_CONVERTER && amount <= INITIAL_POOL);
        uint256 amountSent = _removeDust(amount);

        uint256 recipientBalBefore = recipient.balance;

        remoteOFT.mint(user, amount);

        vm.startPrank(user);
        SendParam memory sendParam = _buildSendParam(TN_EID, recipient, amount, amountSent);
        MessagingFee memory fee = remoteOFT.quoteSend(sendParam, false);
        vm.deal(user, fee.nativeFee);
        remoteOFT.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();

        verifyPackets(TN_EID, addressToBytes32(address(adapter)));

        // Only dust-free amount delivered
        assertEq(recipient.balance, recipientBalBefore + amountSent);
        assertEq(address(adapter).balance, INITIAL_POOL - amountSent);
    }

    function test_credit_rejectsToAddressZero() public {
        // Send to address(0) — _credit should redirect to address(0xdead)
        uint256 amount = 1 ether;
        remoteOFT.mint(user, amount);

        vm.startPrank(user);
        SendParam memory sendParam = _buildSendParam(TN_EID, address(0), amount, amount);
        MessagingFee memory fee = remoteOFT.quoteSend(sendParam, false);
        vm.deal(user, fee.nativeFee);
        remoteOFT.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();

        uint256 deadBalBefore = address(0xdead).balance;
        verifyPackets(TN_EID, addressToBytes32(address(adapter)));

        // Native TEL delivered to 0xdead instead of address(0)
        assertEq(address(0xdead).balance, deadBalBefore + amount);
        assertEq(address(adapter).balance, INITIAL_POOL - amount);
    }

    function test_credit_revertsOnFailedDelivery() public {
        // Deploy a contract that rejects native TEL
        RejectingReceiver rejector = new RejectingReceiver();
        uint256 amount = 1 ether;

        remoteOFT.mint(user, amount);

        vm.startPrank(user);
        SendParam memory sendParam = _buildSendParam(TN_EID, address(rejector), amount, amount);
        MessagingFee memory fee = remoteOFT.quoteSend(sendParam, false);
        vm.deal(user, fee.nativeFee);
        remoteOFT.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();

        // Delivery reverts because rejector refuses native TEL.
        // This causes the LZ message to enter failed state (retryable).
        bool delivered = _tryVerifyPackets(TN_EID, addressToBytes32(address(adapter)));
        assertFalse(delivered, "Expected delivery to fail");

        // Credit was NOT applied
        assertEq(address(rejector).balance, 0);
        assertEq(address(adapter).balance, INITIAL_POOL);
    }

    /*//////////////////////////////////////////////////////////////
                        ROUND-TRIP: OUT AND BACK
    //////////////////////////////////////////////////////////////*/

    function test_roundTrip_sendThenReceive() public {
        uint256 amount = 5 ether;

        // Step 1: Bridge out via sendNative (TN → remote)
        SendParam memory outParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);
        MessagingFee memory outFee = adapter.quoteSend(outParam, false);

        vm.deal(user, amount + outFee.nativeFee);
        vm.prank(user);
        adapter.sendNative{ value: amount + outFee.nativeFee }(outParam, outFee, user);

        verifyPackets(REMOTE_EID, addressToBytes32(address(remoteOFT)));
        assertEq(remoteOFT.balanceOf(recipient), amount);
        uint256 adapterBalAfterOut = address(adapter).balance;
        assertEq(adapterBalAfterOut, INITIAL_POOL + amount);

        // Step 2: Bridge back (remote → TN)
        vm.startPrank(recipient);
        SendParam memory inParam = _buildSendParam(TN_EID, user, amount, amount);
        MessagingFee memory inFee = remoteOFT.quoteSend(inParam, false);
        vm.deal(recipient, inFee.nativeFee);
        remoteOFT.send{ value: inFee.nativeFee }(inParam, inFee, recipient);
        vm.stopPrank();

        verifyPackets(TN_EID, addressToBytes32(address(adapter)));

        // User received native TEL back
        assertEq(user.balance, amount);
        // Remote tokens burned
        assertEq(remoteOFT.balanceOf(recipient), 0);
        // Adapter pool back to initial
        assertEq(address(adapter).balance, INITIAL_POOL);
    }

    /*//////////////////////////////////////////////////////////////
                    SEQUENTIAL OPERATIONS & ACCOUNTING
    //////////////////////////////////////////////////////////////*/

    function test_multipleSends_creditPoolAccumulates() public {
        uint256 amount1 = 2 ether;
        uint256 amount2 = 3 ether;

        // First send via WTEL
        SendParam memory sendParam1 = _buildSendParam(REMOTE_EID, recipient, amount1, amount1);
        MessagingFee memory fee1 = adapter.quoteSend(sendParam1, false);

        vm.deal(user, amount1 + fee1.nativeFee);
        vm.startPrank(user);
        wtel.deposit{ value: amount1 }();
        wtel.approve(address(adapter), amount1);
        adapter.send{ value: fee1.nativeFee }(sendParam1, fee1, user);
        vm.stopPrank();

        assertEq(address(adapter).balance, INITIAL_POOL + amount1);

        // Second send via sendNative
        SendParam memory sendParam2 = _buildSendParam(REMOTE_EID, recipient, amount2, amount2);
        MessagingFee memory fee2 = adapter.quoteSend(sendParam2, false);

        vm.deal(user, amount2 + fee2.nativeFee);
        vm.prank(user);
        adapter.sendNative{ value: amount2 + fee2.nativeFee }(sendParam2, fee2, user);

        // Both amounts accumulated in adapter
        assertEq(address(adapter).balance, INITIAL_POOL + amount1 + amount2);
    }

    function test_multipleCredits_poolDrains() public {
        uint256 amount1 = 10 ether;
        uint256 amount2 = 20 ether;

        // First inbound
        remoteOFT.mint(user, amount1);
        vm.startPrank(user);
        SendParam memory p1 = _buildSendParam(TN_EID, recipient, amount1, amount1);
        MessagingFee memory f1 = remoteOFT.quoteSend(p1, false);
        vm.deal(user, f1.nativeFee);
        remoteOFT.send{ value: f1.nativeFee }(p1, f1, user);
        vm.stopPrank();

        verifyPackets(TN_EID, addressToBytes32(address(adapter)));
        assertEq(address(adapter).balance, INITIAL_POOL - amount1);

        // Second inbound
        remoteOFT.mint(user, amount2);
        vm.startPrank(user);
        SendParam memory p2 = _buildSendParam(TN_EID, recipient, amount2, amount2);
        MessagingFee memory f2 = remoteOFT.quoteSend(p2, false);
        vm.deal(user, f2.nativeFee);
        remoteOFT.send{ value: f2.nativeFee }(p2, f2, user);
        vm.stopPrank();

        verifyPackets(TN_EID, addressToBytes32(address(adapter)));
        assertEq(address(adapter).balance, INITIAL_POOL - amount1 - amount2);
    }

    /*//////////////////////////////////////////////////////////////
                          DUST HANDLING
    //////////////////////////////////////////////////////////////*/

    function test_sendNative_dustStaysInAdapter() public {
        // Amount with dust: 1 ether + 5000 wei (5000 < 1e16)
        uint256 amount = 1 ether + 5000;
        uint256 amountSent = _removeDust(amount);
        assertEq(amountSent, 1 ether); // dust removed

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amountSent);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        vm.deal(user, amount + fee.nativeFee);
        vm.prank(user);
        adapter.sendNative{ value: amount + fee.nativeFee }(sendParam, fee, user);

        // Full amount (including dust) stays in adapter
        assertEq(address(adapter).balance, INITIAL_POOL + amount);

        verifyPackets(REMOTE_EID, addressToBytes32(address(remoteOFT)));
        // Only dust-free amount received on remote
        assertEq(remoteOFT.balanceOf(recipient), amountSent);
    }

    function test_send_dustRemainsAsWTEL() public {
        // Amount with dust
        uint256 amount = 2 ether + 1e15; // 1e15 < 1e16, so 1e15 is dust
        uint256 amountSent = _removeDust(amount);
        uint256 dust = amount - amountSent;
        assertTrue(dust > 0 && dust < DECIMALS_CONVERTER);

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amountSent);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        vm.deal(user, amount + fee.nativeFee);
        vm.startPrank(user);
        wtel.deposit{ value: amount }();
        wtel.approve(address(adapter), amount);
        adapter.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();

        // Dust remains as WTEL with user
        assertEq(wtel.balanceOf(user), dust);
        // Only dust-free amount unwrapped in adapter
        assertEq(address(adapter).balance, INITIAL_POOL + amountSent);
    }

    function testRevert_send_amountBelowDust() public {
        // Amount below minimum precision (< 1e16)
        uint256 amount = 1e15;

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);

        // quoteSend also reverts because amount rounds to 0 in shared decimals
        vm.expectRevert();
        adapter.quoteSend(sendParam, false);
    }

    /*//////////////////////////////////////////////////////////////
                          PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function test_pause_blocksSend() public {
        adapter.pause();
        assertTrue(adapter.paused());

        uint256 amount = 1 ether;

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        vm.deal(user, amount + fee.nativeFee);
        vm.startPrank(user);
        wtel.deposit{ value: amount }();
        wtel.approve(address(adapter), amount);

        vm.expectRevert(abi.encodeWithSelector(Pausable.EnforcedPause.selector));
        adapter.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();
    }

    function test_pause_blocksSendNative() public {
        adapter.pause();

        uint256 amount = 1 ether;
        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        vm.deal(user, amount + fee.nativeFee);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Pausable.EnforcedPause.selector));
        adapter.sendNative{ value: amount + fee.nativeFee }(sendParam, fee, user);
    }

    function test_pause_blocksInboundCredit() public {
        // Send from remote while adapter is NOT paused to get message in flight
        uint256 amount = 1 ether;
        remoteOFT.mint(user, amount);

        vm.startPrank(user);
        SendParam memory sendParam = _buildSendParam(TN_EID, recipient, amount, amount);
        MessagingFee memory fee = remoteOFT.quoteSend(sendParam, false);
        vm.deal(user, fee.nativeFee);
        remoteOFT.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();

        // Pause before delivery
        adapter.pause();

        // The LZ mock processes the packet but _credit reverts (whenNotPaused).
        // The message enters failed state (retryable after unpause).
        uint256 recipientBalBefore = recipient.balance;
        bool delivered = _tryVerifyPackets(TN_EID, addressToBytes32(address(adapter)));
        assertFalse(delivered, "Expected delivery to fail when paused");

        // Credit was NOT applied: pool and recipient unchanged
        assertEq(address(adapter).balance, INITIAL_POOL);
        assertEq(recipient.balance, recipientBalBefore);
    }

    function test_unpause() public {
        adapter.pause();
        assertTrue(adapter.paused());

        adapter.unpause();
        assertFalse(adapter.paused());

        // Verify send works after unpause
        uint256 amount = 1 ether;

        SendParam memory sendParam = _buildSendParam(REMOTE_EID, recipient, amount, amount);
        MessagingFee memory fee = adapter.quoteSend(sendParam, false);

        vm.deal(user, amount + fee.nativeFee);
        vm.startPrank(user);
        wtel.deposit{ value: amount }();
        wtel.approve(address(adapter), amount);
        adapter.send{ value: fee.nativeFee }(sendParam, fee, user);
        vm.stopPrank();
    }

    function testRevert_pause_onlyOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        adapter.pause();
    }

    function testRevert_unpause_onlyOwner() public {
        adapter.pause();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        adapter.unpause();
    }

    function testRevert_pause_whenAlreadyPaused() public {
        adapter.pause();

        vm.expectRevert(abi.encodeWithSelector(Pausable.EnforcedPause.selector));
        adapter.pause();
    }

    function testRevert_unpause_whenNotPaused() public {
        vm.expectRevert(abi.encodeWithSelector(Pausable.ExpectedPause.selector));
        adapter.unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_sharedDecimals() public view {
        assertEq(adapter.sharedDecimals(), 2);
        // decimalConversionRate = 10^(18-2) = 1e16
        assertEq(adapter.decimalConversionRate(), DECIMALS_CONVERTER);
    }

    function test_token() public view {
        assertEq(adapter.token(), address(wtel));
    }

    function test_receive_acceptsNativeTEL() public {
        uint256 balBefore = address(adapter).balance;
        uint256 funding = 10 ether;

        (bool success,) = address(adapter).call{ value: funding }("");
        assertTrue(success);
        assertEq(address(adapter).balance, balBefore + funding);
    }

    function testFuzz_receive_acceptsAnyAmount(uint96 amount) public {
        vm.assume(amount > 0);
        uint256 balBefore = address(adapter).balance;

        vm.deal(address(this), amount);
        (bool success,) = address(adapter).call{ value: amount }("");
        assertTrue(success);
        assertEq(address(adapter).balance, balBefore + amount);
    }
}
