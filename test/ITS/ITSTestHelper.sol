/// SPDX-License-Identifier MIT or Apache-2.0
pragma solidity ^0.8.26;

import { Test, console2 } from "forge-std/Test.sol";
import { Create3Deployer } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/deploy/Create3Deployer.sol";
import { Create3AddressFixed } from "@axelar-network/interchain-token-service/contracts/utils/Create3AddressFixed.sol";
import { AxelarAmplifierGateway } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol";
import { AxelarAmplifierGatewayProxy } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGatewayProxy.sol";
import { Message, CommandType } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/types/AmplifierGatewayTypes.sol";
import {
    WeightedSigner,
    WeightedSigners,
    Proof
} from "@axelar-network/axelar-gmp-sdk-solidity/contracts/types/WeightedMultisigTypes.sol";
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
import { ITokenManager } from "@axelar-network/interchain-token-service/contracts/interfaces/ITokenManager.sol";
import { ITokenManagerType } from "@axelar-network/interchain-token-service/contracts/interfaces/ITokenManagerType.sol";
import { TokenHandler } from "@axelar-network/interchain-token-service/contracts/TokenHandler.sol";
import { GatewayCaller } from "@axelar-network/interchain-token-service/contracts/utils/GatewayCaller.sol";
import { AxelarGasService } from "@axelar-network/axelar-cgp-solidity/contracts/gas-service/AxelarGasService.sol";
import { AxelarGasServiceProxy } from "../../external/axelar-cgp-solidity/AxelarGasServiceProxy.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
import { WTEL } from "../../src/WTEL.sol";
import { InterchainTEL } from "../../src/InterchainTEL.sol";
import { IInterchainTEL } from "../../src/interfaces/IInterchainTEL.sol";
import { Salts, ImplSalts } from "../../deployments/utils/Create3Utils.sol";
import { ITSUtils } from "../../deployments/utils/ITSUtils.sol";
import { ITS } from "../../deployments/Deployments.sol";
import { ITSGenesis } from "../../deployments/genesis/ITSGenesis.sol";

abstract contract ITSTestHelper is Test, ITSGenesis {
    uint256 internal constant DECIMALS_CONVERTER = 1e16;

    function setUp_sepoliaFork_devnetConfig(
        address linker_,
        address sepoliaTel,
        address sepoliaIts,
        address sepoliaItf
    )
        internal
    {
        linker = linker_;
        vm.deal(linker, 1 ether);
        tmOperator = AddressBytes.toBytes(linker);
        gasValue = 0.001 ether;
        sepoliaTEL = IERC20(sepoliaTel);
        sepoliaITS = InterchainTokenService(sepoliaIts);
        sepoliaITF = InterchainTokenFactory(sepoliaItf);
        sepoliaGateway = AxelarAmplifierGateway(DEVNET_SEPOLIA_GATEWAY);
        // etch InterchainTEL impl bytecode for fetching origin linkedTokenId
        originTEL = address(sepoliaTEL);
        originChainName_ = DEVNET_SEPOLIA_CHAIN_NAME;
        owner_ = address(linker);
        create3 = new Create3Deployer{ salt: salts.Create3DeployerSalt }();
        customLinkedTokenId = ITSUtils.instantiateInterchainTEL(sepoliaIts).interchainTokenId();

        // note that TN must be added as a trusted chain to the Ethereum ITS contract
        vm.prank(sepoliaITS.owner());
        sepoliaITS.setTrustedAddress(DEVNET_TN_CHAIN_NAME, ITS_HUB_ROUTING_IDENTIFIER);
    }

    /// @notice Test utility for deploying ITS architecture, including InterchainTEL and its TokenManager, via create3
    /// @dev Used for tests only since live deployment is obviated by genesis precompiles
    function setUp_tnFork_devnetConfig_create3(address admin, address originTEL) internal {
        linker = admin;
        vm.deal(linker, 1 ether);

        create3 = new Create3Deployer{ salt: salts.Create3DeployerSalt }();
        (address precalculatedITS, address precalculatedWTEL, address precalculatedInterchainTEL) =
            _precalculateCreate3ConstructorArgs(create3, admin);

        _setUpDevnetConfig(admin, originTEL, precalculatedWTEL, precalculatedInterchainTEL);

        vm.startPrank(admin);

        // InterchainTEL impl's bytecode is used to fetch devnet tokenID
        wTEL = ITSUtils.instantiateWTEL();
        iTEL = ITSUtils.instantiateInterchainTEL(precalculatedITS);
        customLinkedTokenId = iTEL.interchainTokenId();
        // mock-seed iTEL with TEL total supply as genesis precompile
        vm.deal(address(iTEL), telTotalSupply);

        gatewayImpl = ITSUtils.instantiateAxelarAmplifierGatewayImpl();
        gateway = ITSUtils.instantiateAxelarAmplifierGateway(address(gatewayImpl));
        tokenManagerDeployer = ITSUtils.instantiateTokenManagerDeployer();
        interchainTokenImpl = ITSUtils.instantiateInterchainTokenImpl(create3.deployedAddress("", admin, salts.itsSalt));
        itDeployer = ITSUtils.instantiateInterchainTokenDeployer(address(interchainTokenImpl));
        tokenManagerImpl = ITSUtils.instantiateTokenManagerImpl(create3.deployedAddress("", admin, salts.itsSalt));
        tokenHandler = ITSUtils.instantiateTokenHandler();
        gasServiceImpl = ITSUtils.instantiateAxelarGasServiceImpl();
        gasService = ITSUtils.instantiateAxelarGasService(address(gasServiceImpl));
        gatewayCaller = ITSUtils.instantiateGatewayCaller(address(gateway), address(gasService));
        itsImpl = ITSUtils.instantiateITSImpl(
            address(tokenManagerDeployer),
            address(itDeployer),
            address(gateway),
            address(gasService),
            create3.deployedAddress("", admin, salts.itfSalt),
            address(tokenManagerImpl),
            address(tokenHandler),
            address(gatewayCaller)
        );
        its = ITSUtils.instantiateITS(address(itsImpl));
        itFactoryImpl = ITSUtils.instantiateITFImpl(address(its));
        itFactory = ITSUtils.instantiateITF(address(itFactoryImpl));

        iTELTokenManager = ITSUtils.instantiateInterchainTELTokenManager(address(its), customLinkedTokenId);

        customLinkedTokenSalt = iTEL.linkedTokenDeploySalt();
        originTELTokenManager = TokenManager(iTEL.tokenManagerAddress());
        assertEq(customLinkedTokenId, iTEL.interchainTokenId());

        vm.stopPrank();

        assertEq(address(its), create3.deployedAddress("", admin, salts.itsSalt));
        assertEq(address(itFactory), create3.deployedAddress("", admin, salts.itfSalt));
    }

    /// @notice Simulates genesis instantiation of ITS, InterchainTEL, and its TokenManager. Targets `deployments.json`
    /// @dev For devnet, a developer admin address serves all permissioned roles
    function setUp_tnFork_devnetConfig_genesis(
        ITS memory genesisITSTargets,
        address admin,
        address originTEL,
        address wtel,
        address itel,
        address itelTokenManager
    )
        internal
    {
        linker = admin;
        vm.deal(linker, 1 ether);

        // first set target genesis addresses in state (not yet deployed) for use with recording
        address payable governancePlaceholder = payable(admin); // governance safe not used in devnet
        _setGenesisTargets(
            genesisITSTargets,
            payable(wtel),
            payable(itel),
            itelTokenManager,
            governancePlaceholder,
            governancePlaceholder,
            governancePlaceholder
        );

        // instantiate deployer for state diff recording and set up config vars for devnet
        create3 = new Create3Deployer{ salt: salts.Create3DeployerSalt }();
        _setUpDevnetConfig(admin, originTEL, wtel, itel);

        instantiateAxelarAmplifierGatewayImpl();
        instantiateAxelarAmplifierGateway(address(gatewayImpl));
        instantiateTokenManagerDeployer();
        instantiateInterchainTokenImpl(address(its));
        instantiateInterchainTokenDeployer(address(interchainTokenImpl));
        instantiateTokenManagerImpl(address(its));
        instantiateTokenHandler();
        instantiateAxelarGasServiceImpl();
        instantiateAxelarGasService(address(gasServiceImpl));
        instantiateGatewayCaller(address(gateway), address(gasService));
        instantiateITSImpl(
            address(tokenManagerDeployer),
            address(itDeployer),
            address(gateway),
            address(gasService),
            address(itFactory),
            address(tokenManagerImpl),
            address(tokenHandler),
            address(gatewayCaller)
        );
        instantiateITS(address(itsImpl));
        instantiateITFImpl(address(its));
        instantiateITF(address(itFactoryImpl));

        instantiateWTEL();
        instantiateInterchainTEL(address(its));
        // mock-seed iTEL with TEL total supply as genesis precompile
        vm.deal(address(iTEL), telTotalSupply);

        customLinkedTokenSalt = iTEL.linkedTokenDeploySalt();
        originTELTokenManager = TokenManager(iTEL.tokenManagerAddress());
        customLinkedTokenId = iTEL.interchainTokenId();
        instantiateInterchainTELTokenManager(address(its), customLinkedTokenId);
    }

    /// @dev Assert correctness of origin ITS return values against TN contracts
    function _devnetAsserts_iTEL_iTELTokenManager(
        bytes32 expectedTELTokenId,
        bytes32 returnedTELSalt,
        bytes32 returnedTELTokenId,
        address returnedTELTokenManager
    )
        internal
        view
    {
        // config asserts
        assertEq(expectedTELTokenId, customLinkedTokenId);
        assertEq(returnedTELSalt, customLinkedTokenSalt);
        assertEq(returnedTELTokenId, customLinkedTokenId);
        assertEq(returnedTELTokenManager, address(originTELTokenManager));

        // itel asserts, sanity first
        assertEq(customLinkedTokenSalt, iTEL.linkedTokenDeploySalt());
        assertEq(customLinkedTokenId, iTEL.interchainTokenId());
        assertEq(address(originTELTokenManager), iTEL.tokenManagerAddress());
        assertEq(returnedTELSalt, iTEL.linkedTokenDeploySalt());
        assertEq(returnedTELTokenId, iTEL.tokenManagerCreate3Salt());
        assertEq(returnedTELTokenManager, iTEL.tokenManagerAddress());

        // its asserts
        assertEq(address(iTEL), its.interchainTokenAddress(returnedTELTokenId));
        assertEq(customLinkedTokenId, its.interchainTokenId(address(0x0), returnedTELSalt));
        // ITF::linkedTokenIds are chain-specific so TN itFactory should return differently
        assertFalse(customLinkedTokenId == itFactory.linkedTokenId(linker, salts.registerCustomTokenSalt));
    }

    /// @dev Overwrites TN devnet config with given `newSigner` as sole verifier for tests
    /// @notice Mocks `rotateSigners()` state changes with `vm.store()`
    function _overwriteWeightedSigners(
        AxelarAmplifierGateway targetGateway,
        address newSigner
    )
        internal
        returns (WeightedSigners memory, bytes32)
    {
        // some fork tests tests don't initialize with config setup fn, so push with default vals
        if (signerArray.length == 0) {
            ampdVerifierSigners.push();
            signerArray.push();
        }
        ampdVerifierSigners[0] = newSigner;
        signerArray[0] = WeightedSigner(newSigner, weight);
        WeightedSigners memory newSigners = WeightedSigners(signerArray, threshold, nonce);
        bytes32 newSignersHash = keccak256(abi.encode(newSigners));

        // rewind to a known epoch
        bytes32 epochSlot = 0x457f3fc26bf430b020fe76358b1bfaba57e1657ace718da6437cda9934eabfe8;
        bytes32 epochForTests = 0x0000000000000000000000000000000000000000000000000000000000000001;
        vm.store(address(targetGateway), epochSlot, epochForTests);

        // derive signersHashByEpoch mapping storage slot
        bytes32 signersHashByEpochBaseSlot = bytes32(uint256(epochSlot) + 2);
        bytes32 signersHashByEpochTestSlot = _getMappingSlot(epochForTests, signersHashByEpochBaseSlot);
        vm.store(address(targetGateway), signersHashByEpochTestSlot, newSignersHash);

        // derive epochBySignersHash mapping storage slot
        bytes32 epochBySignersHashBaseSlot = bytes32(uint256(epochSlot) + 3);
        bytes32 epochBySignersHashTestSlot = _getMappingSlot(newSignersHash, epochBySignersHashBaseSlot);
        vm.store(address(targetGateway), epochBySignersHashTestSlot, epochForTests);

        // assert correct slots were written to
        assertEq(targetGateway.epoch(), uint256(epochForTests));
        assertEq(targetGateway.signersHashByEpoch(uint256(epochForTests)), newSignersHash);
        assertEq(targetGateway.epochBySignersHash(newSignersHash), uint256(epochForTests));

        return (newSigners, newSignersHash);
    }

    /// @dev Overwrites a legacy gateway chain's verifiers with `newSigner` as sole verifier for tests
    /// @notice Required bc legacy gateway version incompatible with _overwriteWeightedSigners
    function _legacy_overwriteWeightedSigners(
        address targetGateway,
        address newSigner
    )
        internal
        returns (bytes32, address[] memory, uint256[] memory)
    {
        address[] memory newOperators = new address[](1);
        newOperators[0] = newSigner;
        uint256[] memory weights = new uint256[](1);
        weights[0] = weight;
        bytes memory params = abi.encode(newOperators, weights, threshold);
        bytes32 newOperatorsHash = keccak256(params);

        // mock `transferOperatorship()` state changes
        (, bytes memory ret) = targetGateway.call(abi.encodeWithSignature("authModule()"));
        address authModule = abi.decode(ret, (address));
        bytes32 currentEpochSlot = bytes32(0x0);
        // rewind to a known epoch
        bytes32 epochForTests = 0x00000000000000000000000000000000000000000000000000000000000000ae;
        vm.store(authModule, currentEpochSlot, epochForTests);

        // derive hashForEpoch mapping storage slot
        bytes32 hashForEpochBaseSlot = bytes32(abi.encode(1));
        bytes32 hashForEpochTestSlot = _getMappingSlot(epochForTests, hashForEpochBaseSlot);
        vm.store(authModule, hashForEpochTestSlot, newOperatorsHash);

        // derive epochForHash mapping storage slot
        bytes32 epochForHashBaseSlot = bytes32(abi.encode(2)); // `epochForHash` is in AuthModule storage slot 2
        bytes32 epochForHashTestSlot = _getMappingSlot(newOperatorsHash, epochForHashBaseSlot);
        vm.store(authModule, epochForHashTestSlot, epochForTests);

        // assert correct slot was written to
        (, bytes memory r) = authModule.call(abi.encodeWithSignature("epochForHash(bytes32)", newOperatorsHash));
        assert(abi.decode(r, (bytes32)) == epochForTests);

        return (newOperatorsHash, newOperators, weights);
    }

    /// @dev Returns a origin chain gateway's `approveContractCall()` parameters for signing
    /// @notice Required bc origin gateways use a legacy version incompatible with `approveMessages()`
    function _getLegacyGatewayApprovalParams(
        bytes32 commandId,
        string memory sourceChain,
        string memory sourceAddressString,
        address destinationAddress,
        bytes memory wrappedPayload
    )
        internal
        pure
        returns (bytes memory, bytes32)
    {
        bytes32[] memory commandIds = new bytes32[](1);
        commandIds[0] = commandId;
        string[] memory commands = new string[](1);
        commands[0] = "approveContractCall";
        bytes[] memory approveParams = new bytes[](1);
        approveParams[0] =
            abi.encode(sourceChain, sourceAddressString, destinationAddress, keccak256(wrappedPayload), bytes32(0x0), 0);

        bytes memory executeData = abi.encode(SEPOLIA_CHAINID, commandIds, commands, approveParams);
        bytes32 executeHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(executeData)));

        return (executeData, executeHash);
    }

    function _getMappingSlot(bytes32 key, bytes32 baseSlot) internal pure returns (bytes32 valueSlot) {
        return keccak256(bytes.concat(key, baseSlot));
    }

    function toEighteenDecimals(uint256 interchainAmount) public pure returns (uint256) {
        uint256 nativeAmount = interchainAmount * 1e16;
        return nativeAmount;
    }

    function toTwoDecimals(uint256 nativeAmount) public pure returns (uint256, uint256) {
        if (nativeAmount < DECIMALS_CONVERTER) revert IInterchainTEL.InvalidAmount(nativeAmount);
        uint256 interchainAmount = nativeAmount / DECIMALS_CONVERTER;
        uint256 remainder = nativeAmount % DECIMALS_CONVERTER;

        return (interchainAmount, remainder);
    }

    /// @notice Redeclared event from `IAxelarGMPGateway` for asserts
    event ContractCall(
        address indexed sender,
        string destinationChain,
        string destinationContractAddress,
        bytes32 indexed payloadHash,
        bytes payload
    );

    /// @notice Redeclared event from `BaseAmplifierGateway` for asserts
    event MessageApproved(
        bytes32 indexed commandId,
        string sourceChain,
        string messageId,
        string sourceAddress,
        address indexed contractAddress,
        bytes32 indexed payloadHash
    );

    /// @notice Redeclared event from `BaseAmplifierGateway` for asserts
    event MessageExecuted(bytes32 indexed commandId);
}

contract HarnessCreate3FixedAddressForITS is Create3AddressFixed {
    function create3Address(bytes32 deploySalt) public view returns (address) {
        return _create3Address(deploySalt);
    }
}

/// @dev Read by ITS for metadata registration and used for tests
contract MockTEL is ERC20 {
    function decimals() public view virtual override returns (uint8) {
        return 2;
    }

    function name() public view virtual override returns (string memory) {
        return "Mock Telcoin";
    }

    function symbol() public view virtual override returns (string memory) {
        return "mockTEL";
    }

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}
