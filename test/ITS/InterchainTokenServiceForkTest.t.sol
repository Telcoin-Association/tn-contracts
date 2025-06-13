// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

import { Test, console2, Vm } from "forge-std/Test.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
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
import { AxelarGasServiceProxy } from "../../external/axelar-cgp-solidity/AxelarGasServiceProxy.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { LibString } from "solady/utils/LibString.sol";
import { WTEL } from "../../src/WTEL.sol";
import { InterchainTEL } from "../../src/InterchainTEL.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { Create3Utils, Salts, ImplSalts } from "../../deployments/utils/Create3Utils.sol";
import { ITSConfig } from "../../deployments/utils/ITSConfig.sol";
import { HarnessCreate3FixedAddressForITS, ITSTestHelper } from "./ITSTestHelper.sol";

contract InterchainTokenServiceForkTest is Test, ITSTestHelper {
    Deployments deployments;
    address admin; // note: possesses all permissions on devnet only

    string SEPOLIA_RPC_URL = vm.envString("SEPOLIA_RPC_URL");
    string TN_RPC_URL = vm.envString("TN_RPC_URL");
    uint256 sepoliaFork;
    uint256 tnFork;

    Vm.Wallet mockVerifier = vm.createWallet("mock-verifier");
    address user;
    address recipient;
    string originChain; // original EVM source chain pre-wrap
    address originAddress; // original EVM source chain ITS address
    string sourceChain; // ITS hub wraps messages and becomes sourceChain
    string sourceAddressString; // ITS hub wraps messages with hub identifier as source address
    string destinationChain;
    address destinationAddress;
    string axelarHubAddress;
    string name;
    string symbol;
    uint8 decimals;
    uint256 amount;
    bytes payload;
    bytes wrappedPayload;
    string messageId;
    Message[] messages;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/deployments/deployments.json");
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        deployments = abi.decode(data, (Deployments));

        admin = deployments.admin;
        user = address(0x5d5d4d04B70BFe49ad7Aac8C4454536070dAf180);
        recipient = user;
        name = "Telcoin";
        symbol = "TEL";
        decimals = 2;
        amount = 100; // 1 ERC20 tel

        sepoliaFork = vm.createSelectFork(SEPOLIA_RPC_URL);
        // send tokenManager sepolia TEL so it can unlock them
        vm.prank(user);
        IERC20(deployments.sepoliaTEL).transfer(address(deployments.its.InterchainTELTokenManager), amount);

        tnFork = vm.createFork(TN_RPC_URL);
    }

    /// @dev Test the flow for registering a token with ITS hub + deploying its manager
    /// @notice In prod, these calls must be performed on Ethereum prior to TN genesis
    function test_sepoliaFork_registerCustomTokenAndLinkToken() public {
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

        vm.expectRevert();
        returnedTELTokenManager.proposeOperatorship(admin);
        vm.expectRevert();
        returnedTELTokenManager.transferOperatorship(admin);
        vm.expectRevert();
        returnedTELTokenManager.acceptOperatorship(admin);
        vm.expectRevert();
        returnedTELTokenManager.addFlowLimiter(admin);
        vm.expectRevert();
        returnedTELTokenManager.removeFlowLimiter(admin);
        uint256 dummyAmt = 1;
        vm.expectRevert();
        returnedTELTokenManager.setFlowLimit(dummyAmt);
        vm.expectRevert();
        returnedTELTokenManager.addFlowIn(dummyAmt);
        vm.expectRevert();
        returnedTELTokenManager.addFlowOut(dummyAmt);
        vm.expectRevert();
        returnedTELTokenManager.mintToken(address(originTEL), address(admin), dummyAmt);
        vm.expectRevert();
        returnedTELTokenManager.burnToken(address(originTEL), address(admin), dummyAmt);

        // `BaseProxy::setup()` doesn't revert but does nothing if invoked outside of `TokenManagerProxy` constructor
        returnedTELTokenManager.setup(abi.encode(address(0), address(0x42)));
        assertFalse(returnedTELTokenManager.isOperator(address(0x42)));

        // check expected create3 address for originTEL TokenManager using harness & restore
        bytes memory restoreCodeITS = address(sepoliaITS).code;
        vm.etch(address(sepoliaITS), type(HarnessCreate3FixedAddressForITS).runtimeCode);
        HarnessCreate3FixedAddressForITS itsCreate3 = HarnessCreate3FixedAddressForITS(address(sepoliaITS));
        // note to deploy TokenManagers ITS uses a different create3 salt schema that 'wraps' the token's origin
        // deploy salt
        bytes32 tmDeploySaltIsTELInterchainTokenId =
            keccak256(abi.encode(keccak256("its-interchain-token-id"), address(0x0), returnedInterchainTokenSalt));
        assertEq(itsCreate3.create3Address(tmDeploySaltIsTELInterchainTokenId), address(returnedTELTokenManager));
        vm.etch(address(sepoliaITS), restoreCodeITS);

        // ITS asserts post registration && deployed returnedTELTokenManager
        address returnedTELTokenManagerExpected = sepoliaITS.tokenManagerAddress(returnedInterchainTokenId);
        assertEq(address(returnedTELTokenManager), returnedTELTokenManagerExpected);
        assertTrue(returnedTELTokenManagerExpected.code.length > 0);
        assertEq(address(sepoliaITS.deployedTokenManager(returnedInterchainTokenId)), address(returnedTELTokenManager));
        assertEq(sepoliaITS.registeredTokenAddress(returnedInterchainTokenId), originTEL);

        // originTEL TokenManager asserts
        assertEq(returnedTELTokenManager.contractId(), keccak256("token-manager"));
        assertEq(returnedTELTokenManager.interchainTokenId(), tmDeploySaltIsTELInterchainTokenId);
        assertEq(returnedTELTokenManager.implementationType(), uint256(ITokenManagerType.TokenManagerType.LOCK_UNLOCK));
        assertEq(returnedTELTokenManager.tokenAddress(), address(originTEL));
        assertEq(returnedTELTokenManager.isOperator(owner_), true);
        assertEq(returnedTELTokenManager.isOperator(address(sepoliaITS)), true);
        assertEq(returnedTELTokenManager.isFlowLimiter(address(sepoliaITS)), true);
        assertEq(returnedTELTokenManager.flowLimit(), 0); // set by ITS
        assertEq(returnedTELTokenManager.flowInAmount(), 0); // set by ITS
        assertEq(returnedTELTokenManager.flowOutAmount(), 0); // set by ITS
        bytes memory ethTMSetupParams = abi.encode(bytes(""), originTEL);
        assertEq(returnedTELTokenManager.getTokenAddressFromParams(ethTMSetupParams), originTEL);
        (uint256 implementationType, address tokenAddress) =
            TokenManagerProxy(payable(address(returnedTELTokenManager))).getImplementationTypeAndTokenAddress();
        assertEq(implementationType, uint256(ITokenManagerType.TokenManagerType.LOCK_UNLOCK));
        assertEq(tokenAddress, originTEL);
    }

    /// @dev TN-inbound ITS bridge tests

    function test_sepoliaFork_itsInterchainTransfer_TEL() public {
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
        (, bytes32 returnedInterchainTokenId, TokenManager returnedTELTokenManager) =
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

        // note that TN must have been added as a trusted chain to the Ethereum ITS contract
        destinationChain = DEVNET_TN_CHAIN_NAME;
        vm.prank(sepoliaITS.owner());
        sepoliaITS.setTrustedAddress(destinationChain, ITS_HUB_ROUTING_IDENTIFIER);

        // give gas funds to user and pre-approve ITS to spend its TEL
        vm.deal(user, gasValue);
        vm.prank(user);
        IERC20(originTEL).approve(address(sepoliaITS), amount);

        bytes memory destAddressBytes = AddressBytes.toBytes(user);
        uint256 srcBalBefore = IERC20(originTEL).balanceOf(user);
        uint256 destBalBefore = IERC20(originTEL).balanceOf(address(returnedTELTokenManager));
        vm.prank(user);
        sepoliaITS.interchainTransfer{ value: gasValue }(
            returnedInterchainTokenId, destinationChain, destAddressBytes, amount, "", gasValue
        );

        assertEq(IERC20(originTEL).balanceOf(user), srcBalBefore - amount);
        assertEq(IERC20(originTEL).balanceOf(address(returnedTELTokenManager)), destBalBefore + amount);
    }

    function test_sepoliaFork_itsTransmitInterchainTransfer_TEL() public {
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
        (, bytes32 returnedInterchainTokenId, TokenManager returnedTELTokenManager) =
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

        // note that TN must have been added as a trusted chain to the Ethereum ITS contract
        destinationChain = DEVNET_TN_CHAIN_NAME;
        vm.prank(sepoliaITS.owner());
        sepoliaITS.setTrustedAddress(destinationChain, ITS_HUB_ROUTING_IDENTIFIER);

        // give gas funds to user and pre-approve ITS to spend its TEL
        vm.deal(user, gasValue);
        vm.prank(user);
        IERC20(originTEL).approve(address(sepoliaITS), amount);

        bytes memory destAddressBytes = AddressBytes.toBytes(user);
        uint256 srcBalBefore = IERC20(originTEL).balanceOf(user);
        uint256 destBalBefore = IERC20(originTEL).balanceOf(address(returnedTELTokenManager));

        // note: direct calls to `ITS::transmitInterchainTransfer()` can only be called by the token
        // thus it is disabled on Ethereum since ethTEL doesn't have this function
        vm.prank(user);
        vm.expectRevert();
        sepoliaITS.transmitInterchainTransfer{ value: gasValue }(
            returnedInterchainTokenId, user, destinationChain, destAddressBytes, amount, ""
        );

        assertEq(IERC20(originTEL).balanceOf(user), srcBalBefore);
        assertEq(IERC20(originTEL).balanceOf(address(returnedTELTokenManager)), destBalBefore);
    }

    function test_sepoliaFork_execute() public {
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

        /// @notice Incoming messages routed via ITS hub are in wrapped `RECEIVE_FROM_HUB` format
        payload = abi.encode(
            MESSAGE_TYPE_INTERCHAIN_TRANSFER,
            customLinkedTokenId, // set in setup fn
            AddressBytes.toBytes(user),
            AddressBytes.toBytes(recipient),
            amount,
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

        bytes32 commandId = sepoliaGateway.messageToCommandId(sourceChain, messageId);
        vm.expectEmit(true, true, true, true);
        emit MessageApproved(
            commandId, sourceChain, messageId, sourceAddressString, destinationAddress, keccak256(wrappedPayload)
        );
        sepoliaGateway.approveMessages(messages, proof);

        vm.prank(sepoliaITS.owner());
        sepoliaITS.setTrustedAddress(sourceChain, ITS_HUB_ROUTING_IDENTIFIER);

        uint256 userBalBefore = IERC20(originTEL).balanceOf(user);

        vm.expectEmit(true, true, true, true);
        emit IInterchainTokenService.InterchainTransferReceived(
            commandId, customLinkedTokenId, originChain, AddressBytes.toBytes(user), recipient, amount, bytes32(0x0)
        );
        sepoliaITS.execute(commandId, sourceChain, sourceAddressString, wrappedPayload);

        assertTrue(sepoliaGateway.isCommandExecuted(commandId));
        assertEq(IERC20(originTEL).balanceOf(user), userBalBefore + amount);
    }

    function test_tnFork_approveMessages() public {
        vm.selectFork(tnFork);
        setUp_tnFork_devnetConfig_genesis(
            deployments.its,
            deployments.admin,
            deployments.sepoliaTEL,
            deployments.wTEL,
            deployments.its.InterchainTEL,
            deployments.its.InterchainTELTokenManager
        );

        /// @notice Incoming messages routed via ITS hub are in wrapped `RECEIVE_FROM_HUB` format
        payload = abi.encode(
            MESSAGE_TYPE_INTERCHAIN_TRANSFER,
            iTEL.interchainTokenId(),
            AddressBytes.toBytes(user),
            AddressBytes.toBytes(recipient),
            amount,
            ""
        );
        originChain = DEVNET_SEPOLIA_CHAIN_NAME;
        wrappedPayload = abi.encode(MESSAGE_TYPE_RECEIVE_FROM_HUB, originChain, payload);

        // for interchain transfers, Message's `destinationAddress = its` and payload's `recipient = user`
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
        bytes32 approveMessagesHash =
            gateway.messageHashToSign(signersHash, keccak256(abi.encode(CommandType.ApproveMessages, messages)));
        vm.stopPrank();

        // Axelar gateway signer proofs are ECDSA signatures of bridge message `eth_sign` hash
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

        assertTrue(
            gateway.isMessageApproved(
                sourceChain, messageId, sourceAddressString, destinationAddress, keccak256(wrappedPayload)
            )
        );
    }

    function test_tnFork_execute() public {
        vm.selectFork(tnFork);
        setUp_tnFork_devnetConfig_genesis(
            deployments.its,
            deployments.admin,
            deployments.sepoliaTEL,
            deployments.wTEL,
            deployments.its.InterchainTEL,
            deployments.its.InterchainTELTokenManager
        );

        /// @notice Axelar Hub performs decimal conversion of interchain TEL to native TEL
        uint256 decimalConvertedAmt = toEighteenDecimals(amount);
        payload = abi.encode(
            MESSAGE_TYPE_INTERCHAIN_TRANSFER,
            iTEL.interchainTokenId(),
            AddressBytes.toBytes(user),
            AddressBytes.toBytes(recipient),
            decimalConvertedAmt,
            ""
        );
        /// @notice Incoming messages routed via ITS hub are in wrapped `RECEIVE_FROM_HUB` format
        originChain = DEVNET_SEPOLIA_CHAIN_NAME;
        wrappedPayload = abi.encode(MESSAGE_TYPE_RECEIVE_FROM_HUB, originChain, payload);

        // for interchain transfers, Message's `destinationAddress = its` and payload's `recipient = user`
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
        bytes32 approveMessagesHash =
            gateway.messageHashToSign(signersHash, keccak256(abi.encode(CommandType.ApproveMessages, messages)));
        vm.stopPrank();

        // Axelar gateway signer proofs are ECDSA signatures of bridge message `eth_sign` hash
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

        uint256 userBalBefore = user.balance;

        vm.expectEmit(true, true, true, true);
        emit MessageExecuted(commandId);
        its.execute(commandId, sourceChain, sourceAddressString, wrappedPayload);

        assertTrue(gateway.isMessageExecuted(sourceChain, messageId));
        assertEq(user.balance, userBalBefore + decimalConvertedAmt);
    }

    /// @dev TN-outbound ITS bridge tests

    function test_tnFork_itsInterchainTransfer_InterchainTEL() public {
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
        amount = 1e18; // 1 nativeTEL
        vm.deal(user, amount + gasValue);
        // user double wraps native TEL
        vm.prank(user);
        iTEL.doubleWrap{ value: amount }();

        destinationChain = DEVNET_SEPOLIA_CHAIN_NAME;
        bytes memory destAddressBytes = AddressBytes.toBytes(user);
        uint256 unsettledBal = IERC20(address(iTEL)).balanceOf(user);
        uint256 srcBalBeforeTEL = user.balance;
        uint256 itelBalBefore = address(iTEL).balance;
        assertEq(unsettledBal, 0);
        assertEq(srcBalBeforeTEL, gasValue);
        assertEq(itelBalBefore, telTotalSupply);

        // attempt outbound transfer without elapsing recoverable window
        vm.startPrank(user);
        vm.expectRevert();
        iTEL.interchainTransfer{ value: gasValue }(destinationChain, destAddressBytes, amount, "");

        // outbound interchain bridge transfers *MUST* await recoverable window to settle InterchainTEL balance
        uint256 recoverableEndBlock = block.timestamp + iTEL.recoverableWindow() + 1;
        vm.warp(recoverableEndBlock);
        uint256 settledBalBefore = IERC20(address(iTEL)).balanceOf(user);
        assertEq(settledBalBefore, amount);
        assertEq(IERC20(address(iTEL)).totalSupply(), amount);
        its.interchainTransfer{ value: gasValue }(
            customLinkedTokenId, destinationChain, destAddressBytes, amount, "", gasValue
        );

        uint256 expectedUserBalTEL = settledBalBefore - amount;
        uint256 expectedInterchainTELBal = itelBalBefore + amount;
        assertEq(IERC20(address(iTEL)).balanceOf(user), expectedUserBalTEL);
        assertEq(IERC20(address(iTEL)).totalSupply(), 0);
        assertEq(address(iTEL).balance, expectedInterchainTELBal);
    }
}
