/// SPDX-License-Identifier MIT or Apache-2.0
pragma solidity ^0.8.26;

import { Create3Deployer } from "@axelar-network/axelar-gmp-sdk-solidity/contracts/deploy/Create3Deployer.sol";
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
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
import { WTEL } from "../../src/WTEL.sol";
import { InterchainTEL } from "../../src/InterchainTEL.sol";
import { Create3Utils, Salts, ImplSalts } from "./Create3Utils.sol";

abstract contract ITSUtils is Create3Utils {
    // origin chain config for constructors, asserts (sepolia for devnet/testnet, ethereum for mainnet)
    address linker;
    bytes32 customLinkedTokenSalt;
    bytes32 customLinkedTokenId;
    TokenManager originTELTokenManager;
    ITokenManagerType.TokenManagerType originTMType = ITokenManagerType.TokenManagerType.LOCK_UNLOCK; 

    // ITS core contracts
    Create3Deployer create3; // not included in genesis
    AxelarAmplifierGateway gatewayImpl;
    AxelarAmplifierGateway gateway;
    TokenManagerDeployer tokenManagerDeployer;
    InterchainToken interchainTokenImpl;
    InterchainTokenDeployer itDeployer;
    AxelarGasService gasServiceImpl;
    AxelarGasService gasService;
    GatewayCaller gatewayCaller;
    InterchainTokenService itsImpl;
    InterchainTokenService its; // InterchainProxy
    InterchainTokenFactory itFactoryImpl;
    InterchainTokenFactory itFactory; // InterchainProxy
    TokenHandler tokenHandler;
    TokenManager tokenManagerImpl;
    TokenManager iTELTokenManager;

    // Telcoin Network contracts
    WTEL wTEL;
    InterchainTEL iTEL;
    Safe safeImpl;
    SafeProxyFactory safeProxyFactory;
    Safe governanceSafe;

    // AxelarAmplifierGateway config
    string axelarId;
    string routerAddress;
    uint256 telChainId;
    bytes32 domainSeparator;
    uint256 previousSignersRetention;
    uint256 minimumRotationDelay;
    uint128 weight;
    uint128 threshold;
    bytes32 nonce;
    address[] ampdVerifierSigners;
    WeightedSigner[] signerArray;
    address gatewayOperator;
    bytes gatewaySetupParams;
    address gatewayOwner;

    // AxelarGasService config
    address gasCollector;
    uint256 gasValue;
    address gsOwner;
    bytes gsSetupParams;

    // InterchainTokenService config
    address itsOwner;
    address itsOperator;
    string chainName_;
    string[] trustedChainNames;
    string[] trustedAddresses;
    bytes itsSetupParams;

    // InterchainTokenFactory config
    address itfOwner;

    // iTEL config
    address originTEL;
    string originChainName_;
    string symbol_;
    string name_;
    uint256 recoverableWindow_;
    address owner_;
    address baseERC20_; // wTEL
    uint16 maxToClean;

    // iTELTokenManager config
    ITokenManagerType.TokenManagerType itelTMType = ITokenManagerType.TokenManagerType.MINT_BURN;
    address tokenAddress;
    bytes tmOperator;
    bytes params;

    // governance safe config
    address[] safeOwners;
    uint256 safeThreshold;

    // stored for assertion
    bytes abiEncodedWeightedSigners;

    /// @notice Instantiation functions
    /// @notice All ITSUtils default implementations use CREATE3 a la ITS
    /// @dev Overrides such as the genesis impls in GenerateITSGenesisConfig may differ (eg cheat codes)

    function instantiateAxelarAmplifierGatewayImpl()
        public virtual
        returns (AxelarAmplifierGateway impl)
    {
        bytes memory gatewayImplConstructorArgs =
            abi.encode(previousSignersRetention, domainSeparator, minimumRotationDelay);
        impl = AxelarAmplifierGateway(
            create3Deploy(
                create3,
                type(AxelarAmplifierGateway).creationCode,
                gatewayImplConstructorArgs,
                implSalts.gatewayImplSalt
            )
        );
    }

    function instantiateAxelarAmplifierGateway(address impl)
        public virtual
        returns (AxelarAmplifierGateway proxy)
    {        
        bytes memory gatewayConstructorArgs = abi.encode(impl, gatewayOwner, gatewaySetupParams);
        proxy = AxelarAmplifierGateway(
            create3Deploy(
                create3, type(AxelarAmplifierGatewayProxy).creationCode, gatewayConstructorArgs, salts.gatewaySalt
            )
        );
    }

    function instantiateTokenManagerDeployer()
        public virtual
        returns (TokenManagerDeployer tmDeployer)
    {
        tmDeployer =
            TokenManagerDeployer(create3Deploy(create3, type(TokenManagerDeployer).creationCode, "", salts.tmdSalt));
    }

    function instantiateInterchainTokenImpl(address its_) public virtual returns (InterchainToken itImpl) {
        bytes memory itImplConstructorArgs = abi.encode(its_);
        itImpl = InterchainToken(
            create3Deploy(create3, type(InterchainToken).creationCode, itImplConstructorArgs, implSalts.itImplSalt)
        );
    }

    function instantiateInterchainTokenDeployer(
        
        address interchainTokenImpl_
    )
        public virtual
        returns (InterchainTokenDeployer itd)
    {
        bytes memory itdConstructorArgs = abi.encode(interchainTokenImpl_);
        itd = InterchainTokenDeployer(
            create3Deploy(create3, type(InterchainTokenDeployer).creationCode, itdConstructorArgs, salts.itdSalt)
        );
    }

    function instantiateTokenManagerImpl(address its_) public virtual returns (TokenManager tmImpl) {
        bytes memory tmConstructorArgs = abi.encode(its_);
        tmImpl = TokenManager(
            create3Deploy(create3, type(TokenManager).creationCode, tmConstructorArgs, implSalts.tmImplSalt)
        );
    }

    function instantiateTokenHandler() public virtual returns (TokenHandler th) {
        th = TokenHandler(create3Deploy(create3, type(TokenHandler).creationCode, "", salts.thSalt));
    }

    function instantiateAxelarGasServiceImpl()
        public virtual
        returns (AxelarGasService impl)
    {
        bytes memory gsImplConstructorArgs = abi.encode(gasCollector);
        impl = AxelarGasService(
            create3Deploy(create3, type(AxelarGasService).creationCode, gsImplConstructorArgs, implSalts.gsImplSalt)
        );
    }

    function instantiateAxelarGasService(address impl)
        public virtual
        returns (AxelarGasService proxy)
    {
        bytes memory gsConstructorArgs = abi.encode(impl, gsOwner, "");
        proxy = AxelarGasService(
            create3Deploy(create3, type(AxelarGasServiceProxy).creationCode, gsConstructorArgs, salts.gsSalt)
        );
    }

    function instantiateGatewayCaller(
        
        address gateway_,
        address axelarGasService_
    )
        public virtual
        returns (GatewayCaller gc)
    {
        bytes memory gcConstructorArgs = abi.encode(gateway_, axelarGasService_);
        gc = GatewayCaller(create3Deploy(create3, type(GatewayCaller).creationCode, gcConstructorArgs, salts.gcSalt));
    }

    function instantiateITSImpl(
        address tokenManagerDeployer_,
        address itDeployer_,
        address gateway_,
        address gasService_,
        address itFactory_,
        address tokenManagerImpl_,
        address tokenHandler_,
        address gatewayCaller_
    )
        public virtual
        returns (InterchainTokenService impl)
    {
        bytes memory itsImplConstructorArgs = abi.encode(
            tokenManagerDeployer_,
            itDeployer_,
            gateway_,
            gasService_,
            itFactory_,
            chainName_, // storage config
            tokenManagerImpl_,
            tokenHandler_,
            gatewayCaller_
        );
        impl = InterchainTokenService(
            create3Deploy(
                create3, type(InterchainTokenService).creationCode, itsImplConstructorArgs, implSalts.itsImplSalt
            )
        );
    }

    function instantiateITS(
        address impl
    )
        public virtual
        returns (InterchainTokenService proxy)
    {
        bytes memory itsConstructorArgs = abi.encode(impl, itsOwner, itsSetupParams);
        proxy = InterchainTokenService(
            create3Deploy(create3, type(InterchainProxy).creationCode, itsConstructorArgs, salts.itsSalt)
        );
    }

    function instantiateITFImpl(
        address its_
    )
        public virtual
        returns (InterchainTokenFactory impl)
    {
        bytes memory itfImplConstructorArgs = abi.encode(its_);
        impl = InterchainTokenFactory(
            create3Deploy(
                create3, type(InterchainTokenFactory).creationCode, itfImplConstructorArgs, implSalts.itfImplSalt
            )
        );
    }

    function instantiateITF(
        address impl
    )
        public virtual
        returns (InterchainTokenFactory proxy)
    {
        bytes memory itfConstructorArgs = abi.encode(impl, itfOwner, "");
        proxy = InterchainTokenFactory(
            create3Deploy(create3, type(InterchainProxy).creationCode, itfConstructorArgs, salts.itfSalt)
        );
    }

    function instantiateWTEL() public virtual returns (WTEL wtel) {
        wtel = WTEL(payable(create3Deploy(create3, type(WTEL).creationCode, '', salts.wtelSalt)));
    }

    function instantiateInterchainTEL(address its_) public virtual returns (InterchainTEL impl) {
        bytes memory iTELConstructorArgs = abi.encode(
            originTEL,
            linker,
            salts.registerCustomTokenSalt,
            originChainName_,
            its_,
            name_,
            symbol_,
            recoverableWindow_,
            owner_,
            baseERC20_,
            maxToClean
        );
        impl = InterchainTEL(
            payable(create3Deploy(create3, type(InterchainTEL).creationCode, iTELConstructorArgs, salts.itelSalt))
        );
    }

    function instantiateInterchainTELTokenManager(address its_, bytes32 customLinkedTokenId_) public virtual returns (TokenManager itelTM) {        
        bytes memory itelTMConstructorArgs = abi.encode(its_, uint256(itelTMType), customLinkedTokenId_, params);
        itelTM = TokenManager(
            create3Deploy(create3, type(TokenManagerProxy).creationCode, itelTMConstructorArgs, salts.itelTMSalt)
        );
    }

    /// @notice Registers origin TEL with ITS hub & deploys its TokenManager on its source chain
    /// @dev After execution, relayer detects & forwards ContractCall event to Axelar Network hub via GMP API
    /// @dev Once registered w/ ITS Hub, `msg.sender` can use same salt to link to more chains
    function eth_registerCustomTokenAndLinkToken(
        address originTel,
        address linker_,
        string memory destinationChain_,
        address destTel,
        ITokenManagerType.TokenManagerType tmType, 
        address tmOperator_,
        uint256 gasValue_,
        InterchainTokenFactory factory
    )
        public
        returns (bytes32 linkedTokenSalt, bytes32 linkedTokenId, TokenManager telTokenManager)
    {
        // Register origin TEL metadata with Axelar chain's ITS hub, this step requires gas prepayment
        factory.registerCustomToken{ value: gasValue_ }(salts.registerCustomTokenSalt, originTel, tmType, tmOperator_);

        linkedTokenSalt = factory.linkedTokenDeploySalt(linker_, salts.registerCustomTokenSalt);
        linkedTokenId = factory.linkToken{value: gasValue_}(salts.registerCustomTokenSalt, destinationChain_, AddressBytes.toBytes(destTel), tmType, AddressBytes.toBytes(tmOperator_), gasValue_);

        telTokenManager = TokenManager(address(factory.interchainTokenService().tokenManagerAddress(linkedTokenId)));
    }

    /// @dev Returns a single RECEIVE_FROM_HUB message for approval & execution
    function _craftITSMessage(string memory msgId, string memory srcChain, string memory srcAddress, address destAddress, bytes memory wrappedPayload) internal pure returns (Message memory) {
        bytes32 payloadHash = keccak256(wrappedPayload);
        return Message(srcChain, msgId, srcAddress, destAddress, payloadHash);
    }
}
