// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import { Test, console2, Vm } from "forge-std/Test.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IDeploy } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/interfaces/IDeploy.sol";
import { AxelarAmplifierGateway } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol";
import { AxelarAmplifierGatewayProxy } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGatewayProxy.sol";
import { BaseAmplifierGateway } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/BaseAmplifierGateway.sol";
import { Message, CommandType } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/types/AmplifierGatewayTypes.sol";
import {
    WeightedSigner,
    WeightedSigners,
    Proof
} from "@axelar-network/axelar-gmp-sdk-solidity/contracts/types/WeightedMultisigTypes.sol";
import { Create3Deployer } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/deploy/Create3Deployer.sol";
import { AddressBytes } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/libs/AddressBytes.sol";
import { InterchainTokenService } from "@axelar-network/interchain-token-service/contracts/InterchainTokenService.sol";
import { InterchainProxy } from "@axelar-network/interchain-token-service/contracts/proxies/InterchainProxy.sol";
import { TokenManagerProxy } from "@axelar-network/interchain-token-service/contracts/proxies/TokenManagerProxy.sol";
import { InterchainTokenDeployer } from
    "@axelar-network/interchain-token-service/contracts/utils/InterchainTokenDeployer.sol";
import { InterchainTokenFactory } from "@axelar-network/interchain-token-service/contracts/InterchainTokenFactory.sol";
import { InterchainToken } from
    "@axelar-network/interchain-token-service/contracts/interchain-token/InterchainToken.sol";
import { TokenManagerDeployer } from "@axelar-network/interchain-token-service/contracts/utils/TokenManagerDeployer.sol";
import { TokenManager } from "@axelar-network/interchain-token-service/contracts/token-manager/TokenManager.sol";
import { ITokenManagerType } from "@axelar-network/interchain-token-service/contracts/interfaces/ITokenManagerType.sol";
import { IInterchainTokenService } from
    "@axelar-network/interchain-token-service/contracts/interfaces/IInterchainTokenService.sol";
import { TokenHandler } from "@axelar-network/interchain-token-service/contracts/TokenHandler.sol";
import { GatewayCaller } from "@axelar-network/interchain-token-service/contracts/utils/GatewayCaller.sol";
import { AxelarGasService } from "@axelar-network/axelar-cgp-solidity/contracts/gas-service/AxelarGasService.sol";
import { RecoverableWrapper } from "../../src/recoverable-wrapper/RecoverableWrapper.sol";
import { AxelarGasServiceProxy } from "../../external/axelar-cgp-solidity/AxelarGasServiceProxy.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { LibString } from "solady/utils/LibString.sol";
import { WTEL } from "../../src/WTEL.sol";
import { InterchainTEL } from "../../src/InterchainTEL.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { Create3Utils, Salts, ImplSalts } from "../../deployments/utils/Create3Utils.sol";
import { ITS } from "../../deployments/Deployments.sol";
import { HarnessCreate3FixedAddressForITS, ITSTestHelper } from "./ITSTestHelper.sol";

contract InterchainTELForkTest is Test, ITSTestHelper {
    Deployments deployments;
    address admin;

    string SEPOLIA_RPC_URL = vm.envString("SEPOLIA_RPC_URL");
    string TN_RPC_URL = vm.envString("TN_RPC_URL");
    uint256 sepoliaFork;
    uint256 tnFork;

    address user;
    address recipient;
    string originChain; // original EVM source chain pre-wrap
    address originAddress; // original EVM source chain ITS address
    string sourceChain; // ITS hub wraps messages and becomes sourceChain
    string sourceAddressString; // ITS hub wraps messages with hub identifier as source address
    string destinationChain;
    address destinationAddress;
    string destinationAddressString;
    string name;
    string symbol;
    uint8 decimals;
    uint256 interchainAmount;
    uint256 nativeAmount;
    bytes payload;
    bytes wrappedPayload; // ITS hub wraps payloads
    string messageId;
    Message[] messages;

    Vm.Wallet mockVerifier = vm.createWallet("mock-verifier"); // simulates Axelar verifier proofs

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        admin = deployments.admin;
        user = address(0x5d5d4d04B70BFe49ad7Aac8C4454536070dAf180);
        recipient = address(0x5d5d4d04B70BFe49ad7Aac8C4454536070dAf180); // bridge to self
        name = "Telcoin";
        symbol = "TEL";
        decimals = 2;
        interchainAmount = 100; // 1 interchain ERC20 TEL
        nativeAmount = 1e18; // 1 nativeTEL

        sepoliaFork = vm.createSelectFork(SEPOLIA_RPC_URL);
        // send tokenManager sepolia TEL so it can unlock them
        vm.prank(user);
        IERC20(deployments.sepoliaTEL).transfer(address(deployments.its.InterchainTELTokenManager), interchainAmount);

        tnFork = vm.createFork(TN_RPC_URL);
    }

    function test_tn_itelInterchainTransfer_InterchainTEL() public {
        vm.selectFork(tnFork);
        setUp_tnFork_devnetConfig_genesis(
            deployments.its,
            deployments.admin,
            deployments.sepoliaTEL,
            deployments.wTEL,
            deployments.its.InterchainTEL,
            deployments.its.InterchainTELTokenManager
        );

        // give funds to user
        vm.deal(user, nativeAmount + gasValue);
        // user double wraps native TEL
        vm.prank(user);
        iTEL.doubleWrap{ value: nativeAmount }();

        destinationChain = DEVNET_SEPOLIA_CHAIN_NAME;
        uint256 unsettledBal = IERC20(address(iTEL)).balanceOf(user);
        uint256 srcBalBeforeTEL = user.balance;
        uint256 itelBalBefore = address(iTEL).balance;
        assertEq(unsettledBal, 0);
        assertEq(srcBalBeforeTEL, gasValue);
        assertEq(itelBalBefore, telTotalSupply);

        // attempt outbound transfer without elapsing recoverable window
        vm.startPrank(user);
        vm.expectRevert();
        iTEL.interchainTransfer{ value: gasValue }(destinationChain, AddressBytes.toBytes(recipient), nativeAmount, "");

        // outbound interchain bridge transfers *MUST* await recoverable window to settle InterchainTEL balance
        uint256 recoverableEndBlock = block.timestamp + iTEL.recoverableWindow() + 1;
        vm.warp(recoverableEndBlock);
        uint256 settledBalBefore = IERC20(address(iTEL)).balanceOf(user);
        assertEq(settledBalBefore, nativeAmount);
        assertEq(IERC20(address(iTEL)).totalSupply(), nativeAmount);
        iTEL.interchainTransfer{ value: gasValue }(destinationChain, AddressBytes.toBytes(recipient), nativeAmount, "");

        vm.stopPrank();

        uint256 expectedUserBalTEL = settledBalBefore - nativeAmount;
        uint256 expectedInterchainTELBal = itelBalBefore + nativeAmount;
        assertEq(IERC20(address(iTEL)).balanceOf(user), expectedUserBalTEL);
        assertEq(IERC20(address(iTEL)).totalSupply(), 0);
        assertEq(address(iTEL).balance, expectedInterchainTELBal);
    }

    function test_tn_itelInterchainTransferFrom_InterchainTEL() public {
        vm.selectFork(tnFork);
        setUp_tnFork_devnetConfig_genesis(
            deployments.its,
            deployments.admin,
            deployments.sepoliaTEL,
            deployments.wTEL,
            deployments.its.InterchainTEL,
            deployments.its.InterchainTELTokenManager
        );

        // give funds to user
        vm.deal(user, nativeAmount + gasValue);
        // user double wraps native TEL and pre-approves contract to spend iTEL
        vm.startPrank(user);
        iTEL.doubleWrap{ value: nativeAmount }();
        iTEL.approve(address(this), nativeAmount);
        vm.stopPrank();

        destinationChain = DEVNET_SEPOLIA_CHAIN_NAME;
        uint256 unsettledBal = IERC20(address(iTEL)).balanceOf(user);
        uint256 srcBalBeforeTEL = user.balance;
        uint256 itelBalBefore = address(iTEL).balance;
        assertEq(unsettledBal, 0);
        assertEq(srcBalBeforeTEL, gasValue);
        assertEq(itelBalBefore, telTotalSupply);

        // attempt outbound transfer without elapsing recoverable window
        vm.expectRevert();
        iTEL.interchainTransferFrom{ value: gasValue }(
            user, destinationChain, AddressBytes.toBytes(recipient), nativeAmount, ""
        );

        // outbound interchain bridge transfers *MUST* await recoverable window to settle InterchainTEL balance
        uint256 recoverableEndBlock = block.timestamp + iTEL.recoverableWindow() + 1;
        vm.warp(recoverableEndBlock);
        uint256 settledBalBefore = IERC20(address(iTEL)).balanceOf(user);
        assertEq(settledBalBefore, nativeAmount);
        assertEq(IERC20(address(iTEL)).totalSupply(), nativeAmount);
        iTEL.interchainTransferFrom{ value: gasValue }(
            user, destinationChain, AddressBytes.toBytes(recipient), nativeAmount, ""
        );

        assertEq(IERC20(address(iTEL)).totalSupply(), 0);
        assertEq(IERC20(address(iTEL)).balanceOf(user), settledBalBefore - nativeAmount);
        assertEq(address(iTEL).balance, itelBalBefore + nativeAmount);
    }

    /// @notice Test TN genesis precompiles iTEL and iTELTokenManager match Ethereum ITS's origin addresses
    /// by simulating `linkToken()` to Telcoin Network (obviated by Telcoin-Network genesis)
    /// @notice Ensures precompiles for InterchainTEL + its TokenManager match those expected by ITS
    function test_e2eDevnet_linkToken_InterchainTEL() public {
        vm.selectFork(sepoliaFork);
        setUp_sepoliaFork_devnetConfig(
            deployments.admin,
            deployments.sepoliaTEL,
            deployments.its.InterchainTokenService,
            deployments.its.InterchainTokenFactory
        );

        // Register origin TEL metadata and deploy origin TEL token manager on origin as linker
        destinationChain = DEVNET_TN_CHAIN_NAME;
        vm.startPrank(linker);
        (bytes32 returnedInterchainTokenSalt, bytes32 returnedInterchainTokenId, TokenManager returnedTELTokenManager) =
        eth_registerCustomTokenAndLinkToken(
            originTEL,
            linker,
            destinationChain,
            deployments.its.InterchainTEL,
            originTMType,
            AddressBytes.toAddress(tmOperator),
            gasValue,
            sepoliaITF
        );
        vm.stopPrank();

        // sanity asserts for post origin registration
        assertEq(address(returnedTELTokenManager), deployments.its.InterchainTELTokenManager);
        bytes32 expectedTELTokenId = sepoliaITF.linkedTokenId(linker, salts.registerCustomTokenSalt);
        assertEq(expectedTELTokenId, sepoliaITS.interchainTokenId(address(0x0), returnedInterchainTokenSalt));

        // sends remote deploy message to ITS hub for iTEL and its TokenManager on TN
        payload = abi.encode(
            MESSAGE_TYPE_LINK_TOKEN,
            returnedInterchainTokenId,
            itelTMType,
            AddressBytes.toBytes(originTEL),
            AddressBytes.toBytes(deployments.its.InterchainTEL),
            tmOperator
        );

        /// @notice All following actions are handled at or before TN genesis & included here only for testing
        /// @notice iTEL metadata (decimals) registration uses a customized message to voting-verifier

        vm.selectFork(tnFork);
        setUp_tnFork_devnetConfig_genesis(
            deployments.its,
            deployments.admin,
            deployments.sepoliaTEL,
            deployments.wTEL,
            deployments.its.InterchainTEL,
            deployments.its.InterchainTELTokenManager
        );

        // assert returned ITS values match genesis expectations
        _devnetAsserts_iTEL_iTELTokenManager(
            expectedTELTokenId, returnedInterchainTokenSalt, returnedInterchainTokenId, address(returnedTELTokenManager)
        );
        /// @notice Incoming messages routed via ITS hub are in wrapped `RECEIVE_FROM_HUB` format
        /// for interchain transfers, Message's `destinationAddress = its` and payload's `recipient = user`
        originChain = DEVNET_SEPOLIA_CHAIN_NAME;
        wrappedPayload = abi.encode(MESSAGE_TYPE_RECEIVE_FROM_HUB, originChain, payload);
        sourceChain = ITS_HUB_CHAIN_NAME;
        sourceAddressString = ITS_HUB_ROUTING_IDENTIFIER;
        destinationAddress = address(its);
        messageId = "42";
        Message memory message =
            _craftITSMessage(messageId, sourceChain, sourceAddressString, destinationAddress, wrappedPayload);
        messages.push(message);

        // use gatewayOperator to overwrite devnet config verifier for tests
        vm.startPrank(admin);
        (WeightedSigners memory weightedSigners, bytes32 signersHash) =
            _overwriteWeightedSigners(gateway, mockVerifier.addr);
        vm.stopPrank();

        // Axelar gateway signer proofs are ECDSA signatures of bridge message `eth_sign` hash
        bytes32 approveMessagesHash =
            gateway.messageHashToSign(signersHash, keccak256(abi.encode(CommandType.ApproveMessages, messages)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mockVerifier.privateKey, approveMessagesHash);
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = abi.encodePacked(r, s, v);
        Proof memory proof = Proof(weightedSigners, signatures);

        bytes32 commandId = gateway.messageToCommandId(sourceChain, messageId);
        vm.expectEmit(true, true, true, true);
        emit MessageApproved(
            commandId, sourceChain, messageId, sourceAddressString, destinationAddress, keccak256(wrappedPayload)
        );
        gateway.approveMessages(messages, proof);

        // assert correct iTEL + token manager addresses
        bytes memory alreadyDeployed = abi.encodePacked(IDeploy.AlreadyDeployed.selector);
        bytes memory tokenManagerCollision =
            abi.encodeWithSelector(IInterchainTokenService.TokenManagerDeploymentFailed.selector, alreadyDeployed);
        vm.expectRevert(tokenManagerCollision);
        its.execute(commandId, sourceChain, sourceAddressString, wrappedPayload);

        // wipe genesis token manager to ensure link message would otherwise settle according to ITS protocol
        vm.etch(deployments.its.InterchainTELTokenManager, "");
        bytes memory deployTMParams = abi.encode(tmOperator, deployments.its.InterchainTEL);
        vm.expectEmit();
        emit IInterchainTokenService.TokenManagerDeployed(
            expectedTELTokenId, deployments.its.InterchainTELTokenManager, itelTMType, deployTMParams
        );
        its.execute(commandId, sourceChain, sourceAddressString, wrappedPayload);
    }

    function test_e2eDevnet_bridgeSimulation_toTN() public {
        vm.selectFork(sepoliaFork);
        setUp_sepoliaFork_devnetConfig(
            deployments.admin,
            deployments.sepoliaTEL,
            deployments.its.InterchainTokenService,
            deployments.its.InterchainTokenFactory
        );

        // Register origin TEL metadata and deploy origin TEL token manager on origin as linker
        destinationChain = DEVNET_TN_CHAIN_NAME;
        vm.startPrank(linker);
        (bytes32 returnedInterchainTokenSalt, bytes32 returnedInterchainTokenId, TokenManager returnedTELTokenManager) =
        eth_registerCustomTokenAndLinkToken(
            originTEL,
            linker,
            destinationChain,
            deployments.its.InterchainTEL,
            originTMType,
            AddressBytes.toAddress(tmOperator),
            gasValue,
            sepoliaITF
        );
        vm.stopPrank();

        // sanity asserts for post origin registration
        assertEq(sepoliaITS.interchainTokenAddress(returnedInterchainTokenId), deployments.its.InterchainTEL);
        assertEq(address(returnedTELTokenManager), deployments.its.InterchainTELTokenManager);
        bytes32 expectedTELTokenId = sepoliaITF.linkedTokenId(linker, salts.registerCustomTokenSalt);
        assertEq(expectedTELTokenId, sepoliaITS.interchainTokenId(address(0x0), returnedInterchainTokenSalt));

        // give gas funds to user
        vm.deal(user, gasValue);
        originAddress = address(sepoliaITS);
        payload = abi.encode(
            MESSAGE_TYPE_INTERCHAIN_TRANSFER,
            returnedInterchainTokenId,
            AddressBytes.toBytes(user),
            AddressBytes.toBytes(recipient),
            interchainAmount,
            ""
        );
        wrappedPayload = abi.encode(MESSAGE_TYPE_SEND_TO_HUB, destinationChain, payload);

        vm.startPrank(user);
        // user must have tokens and approve ITS to spend its TEL
        IERC20(originTEL).approve(address(sepoliaITS), interchainAmount);

        uint256 srcBalBefore = IERC20(originTEL).balanceOf(user);
        uint256 destBalBefore = IERC20(originTEL).balanceOf(address(returnedTELTokenManager));

        // ITS wraps `ContractCall` events with Axelar Hub info
        vm.expectEmit(true, true, true, true);
        emit ContractCall(
            originAddress, ITS_HUB_CHAIN_NAME, ITS_HUB_ROUTER_ADDR, keccak256(wrappedPayload), wrappedPayload
        );

        sepoliaITS.interchainTransfer{ value: gasValue }(
            returnedInterchainTokenId, destinationChain, AddressBytes.toBytes(recipient), interchainAmount, "", gasValue
        );
        vm.stopPrank();

        assertEq(IERC20(originTEL).balanceOf(user), srcBalBefore - interchainAmount);
        assertEq(IERC20(originTEL).balanceOf(address(returnedTELTokenManager)), destBalBefore + interchainAmount);

        /**
         * @dev Relayer Action: Monitor Source Gateway for GMP Message Event Emission
         * subscriber picks up event + forwards to GMP API where it is processed by TN verifier
         */
        vm.selectFork(tnFork);
        setUp_tnFork_devnetConfig_genesis(
            deployments.its,
            deployments.admin,
            deployments.sepoliaTEL,
            deployments.wTEL,
            deployments.its.InterchainTEL,
            deployments.its.InterchainTELTokenManager
        );

        /**
         * @dev Verifier Action: Vote on GMP Message Event Validity via Ampd
         * GMP message reaches Axelar Network Voting Verifier contract, where a "verifier" (ampd client ECDSA key)
         * signs and submits signatures ie "votes" or "proofs" via RPC. Verifiers are also known as `WeightedSigners`
         * @notice Devnet config uses `admin` as a single signer with weight and threshold == 1
         */

        /// @notice The Axelar Hub converts decimals before sending the message payload to destination prover
        uint256 decimalConvertedAmt = toEighteenDecimals(interchainAmount);
        payload = abi.encode(
            MESSAGE_TYPE_INTERCHAIN_TRANSFER,
            returnedInterchainTokenId,
            AddressBytes.toBytes(user),
            AddressBytes.toBytes(recipient),
            decimalConvertedAmt,
            ""
        );
        /// @notice Incoming messages routed via ITS hub are in wrapped `RECEIVE_FROM_HUB` format
        /// for interchain transfers, Message's `destinationAddress = its` and payload's `recipient = user`
        originChain = DEVNET_SEPOLIA_CHAIN_NAME;
        wrappedPayload = abi.encode(MESSAGE_TYPE_RECEIVE_FROM_HUB, originChain, payload);
        sourceChain = ITS_HUB_CHAIN_NAME;
        sourceAddressString = ITS_HUB_ROUTING_IDENTIFIER;
        destinationAddress = address(its);
        messageId = "42";
        Message memory message =
            _craftITSMessage(messageId, sourceChain, sourceAddressString, destinationAddress, wrappedPayload);
        messages.push(message);

        // use gatewayOperator to overwrite devnet config verifier for tests
        vm.startPrank(admin);
        (WeightedSigners memory weightedSigners, bytes32 signersHash) =
            _overwriteWeightedSigners(gateway, mockVerifier.addr);
        vm.stopPrank();

        // Axelar gateway signer proofs are ECDSA signatures of bridge message `eth_sign` hash
        bytes32 approveMessagesHash =
            gateway.messageHashToSign(signersHash, keccak256(abi.encode(CommandType.ApproveMessages, messages)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mockVerifier.privateKey, approveMessagesHash);
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = abi.encodePacked(r, s, v);
        Proof memory proof = Proof(weightedSigners, signatures);

        /**
         * @dev Relayer Action: Approve ITS Message on Destination Gateway
         * Includer polls GMP API for the message processed by Axelar Network verifiers, writes to TN gateway in TX
         * Once settled, GMP message has been successfully sent across chains (bridged) and awaits execution
         */
        bytes32 commandId = gateway.messageToCommandId(sourceChain, messageId);
        vm.expectEmit(true, true, true, true);
        emit MessageApproved(
            commandId, sourceChain, messageId, sourceAddressString, destinationAddress, keccak256(wrappedPayload)
        );
        gateway.approveMessages(messages, proof);

        assertTrue(
            gateway.isMessageApproved(
                sourceChain, messageId, sourceAddressString, destinationAddress, keccak256(wrappedPayload)
            )
        );

        /**
         * @dev Relayer Action: Execute ITS Message (`ContractCall`) on InterchainTEL Module
         * Includer executes GMP messages that have been written to the TN gateway in previous step
         * execution calls InterchainTEL's TokenManager which in turn calls InterchainTEL module's `mint()` function,
         * translating interchain TEL decimals to mint native TEL to the recipient
         */
        uint256 userBalBefore = user.balance;
        uint256 itelBalBefore = address(iTEL).balance;
        assertEq(itelBalBefore, telTotalSupply);

        vm.expectEmit(true, true, true, true);
        emit MessageExecuted(commandId);
        its.execute(commandId, sourceChain, sourceAddressString, wrappedPayload);

        assertTrue(gateway.isMessageExecuted(sourceChain, messageId));

        // sepolia TEL ERC20 has been bridged and delivered to user as native TEL
        assertEq(user.balance, userBalBefore + decimalConvertedAmt);
        assertEq(address(iTEL).balance, itelBalBefore - decimalConvertedAmt);
    }

    function test_e2eDevnet_bridgeSimulation_fromTN() public {
        vm.selectFork(tnFork);
        setUp_tnFork_devnetConfig_genesis(
            deployments.its,
            deployments.admin,
            deployments.sepoliaTEL,
            deployments.wTEL,
            deployments.its.InterchainTEL,
            deployments.its.InterchainTELTokenManager
        );

        uint256 startingNativeBal = nativeAmount + gasValue;
        vm.deal(user, startingNativeBal);
        // user double wraps native TEL
        vm.prank(user);
        iTEL.doubleWrap{ value: nativeAmount }();

        uint256 unsettledBal = IERC20(address(iTEL)).balanceOf(user);
        uint256 srcBalBeforeTEL = user.balance;
        uint256 itelBalBefore = address(iTEL).balance;
        assertEq(unsettledBal, 0);
        assertEq(srcBalBeforeTEL, startingNativeBal - nativeAmount);
        assertEq(itelBalBefore, telTotalSupply);

        // outbound interchain bridge transfers *MUST* await recoverable window to settle InterchainTEL balance
        uint256 recoverableEndBlock = block.timestamp + iTEL.recoverableWindow() + 1;
        vm.warp(recoverableEndBlock);
        uint256 settledBalBefore = IERC20(address(iTEL)).balanceOf(user);
        assertEq(settledBalBefore, nativeAmount);
        assertEq(IERC20(address(iTEL)).totalSupply(), nativeAmount);

        destinationChain = DEVNET_SEPOLIA_CHAIN_NAME;
        originAddress = address(its);
        payload = abi.encode(
            MESSAGE_TYPE_INTERCHAIN_TRANSFER,
            iTEL.interchainTokenId(),
            AddressBytes.toBytes(user),
            AddressBytes.toBytes(recipient),
            nativeAmount, // Axelar Hub will convert to 2 decimals before reaching Sepolia
            ""
        );
        wrappedPayload = abi.encode(MESSAGE_TYPE_SEND_TO_HUB, destinationChain, payload);

        // ITS wraps `ContractCall` events with Axelar Hub info
        vm.expectEmit(true, true, true, true);
        emit ContractCall(
            originAddress, ITS_HUB_CHAIN_NAME, ITS_HUB_ROUTING_IDENTIFIER, keccak256(wrappedPayload), wrappedPayload
        );

        vm.prank(user);
        iTEL.interchainTransfer{ value: gasValue }(destinationChain, AddressBytes.toBytes(recipient), nativeAmount, "");

        uint256 expectedUserBalTEL = settledBalBefore - nativeAmount;
        uint256 expectedInterchainTELBal = itelBalBefore + nativeAmount;
        assertEq(IERC20(address(iTEL)).balanceOf(user), expectedUserBalTEL);
        assertEq(IERC20(address(iTEL)).totalSupply(), 0);
        assertEq(address(iTEL).balance, expectedInterchainTELBal);

        /**
         * @dev Relayer Action: Monitor Source Gateway for GMP Message Event Emission
         * subscriber picks up event + forwards to GMP API where it is processed by TN verifier
         */
        vm.selectFork(sepoliaFork);
        setUp_sepoliaFork_devnetConfig(
            deployments.admin,
            deployments.sepoliaTEL,
            deployments.its.InterchainTokenService,
            deployments.its.InterchainTokenFactory
        );

        // Register origin TEL metadata and deploy origin TEL token manager on origin as linker
        destinationChain = DEVNET_TN_CHAIN_NAME; // linking done out of order after TN actions
        vm.startPrank(linker);
        (, bytes32 itelInterchainTokenId,) = eth_registerCustomTokenAndLinkToken(
            originTEL,
            linker,
            destinationChain,
            deployments.its.InterchainTEL,
            originTMType,
            AddressBytes.toAddress(tmOperator),
            gasValue,
            sepoliaITF
        );
        vm.stopPrank();

        payload = abi.encode(
            MESSAGE_TYPE_INTERCHAIN_TRANSFER,
            itelInterchainTokenId,
            AddressBytes.toBytes(user),
            AddressBytes.toBytes(recipient),
            interchainAmount, // Axelar Hub will convert to 2 decimals before reaching Sepolia
            ""
        );
        originChain = DEVNET_TN_CHAIN_NAME;
        wrappedPayload = abi.encode(MESSAGE_TYPE_RECEIVE_FROM_HUB, originChain, payload);

        // for interchain transfers, Message's `destinationAddress = its` and payload's `recipient = user`
        sourceChain = ITS_HUB_CHAIN_NAME;
        sourceAddressString = ITS_HUB_ROUTING_IDENTIFIER;
        destinationAddress = address(sepoliaITS);
        messageId = "42";
        Message memory message =
            _craftITSMessage(messageId, sourceChain, sourceAddressString, destinationAddress, wrappedPayload);
        messages.push(message);

        // use gatewayOperator to overwrite devnet config verifier for tests
        vm.prank(sepoliaGateway.operator());
        (WeightedSigners memory newSigners, bytes32 signersHash) =
            _overwriteWeightedSigners(sepoliaGateway, mockVerifier.addr);

        // spoof verifier signature of approval params
        bytes32 approveMessagesHash =
            sepoliaGateway.messageHashToSign(signersHash, keccak256(abi.encode(CommandType.ApproveMessages, messages)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mockVerifier.privateKey, approveMessagesHash);
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = abi.encodePacked(r, s, v);
        Proof memory proof = Proof(newSigners, signatures);

        bytes32 commandId = gateway.messageToCommandId(sourceChain, messageId);
        vm.expectEmit(true, true, true, true);
        emit MessageApproved(
            commandId, sourceChain, messageId, sourceAddressString, destinationAddress, keccak256(wrappedPayload)
        );
        gateway.approveMessages(messages, proof);

        vm.startPrank(sepoliaITS.owner());
        sepoliaITS.setTrustedAddress(sourceChain, ITS_HUB_ROUTING_IDENTIFIER);

        uint256 userBalBefore = IERC20(originTEL).balanceOf(user);

        vm.expectEmit(true, true, true, true);
        emit IInterchainTokenService.InterchainTransferReceived(
            commandId,
            customLinkedTokenId,
            originChain,
            AddressBytes.toBytes(user),
            recipient,
            interchainAmount,
            bytes32(0x0)
        );
        sepoliaITS.execute(commandId, sourceChain, sourceAddressString, wrappedPayload);

        assertTrue(sepoliaGateway.isCommandExecuted(commandId));
        // native TN TEL has been bridged and delivered to user as interchain ERC20 TEL
        assertEq(IERC20(originTEL).balanceOf(user), userBalBefore + interchainAmount);
    }
}
