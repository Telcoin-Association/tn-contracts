// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { AxelarAmplifierGateway } from
    "@axelar-network/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol";
import { InterchainTokenService } from "@axelar-network/interchain-token-service/contracts/InterchainTokenService.sol";
import { InterchainTokenDeployer } from
    "@axelar-network/interchain-token-service/contracts/utils/InterchainTokenDeployer.sol";
import { InterchainTokenFactory } from "@axelar-network/interchain-token-service/contracts/InterchainTokenFactory.sol";
import { InterchainToken } from
    "@axelar-network/interchain-token-service/contracts/interchain-token/InterchainToken.sol";
import { TokenManagerDeployer } from "@axelar-network/interchain-token-service/contracts/utils/TokenManagerDeployer.sol";
import { TokenManager } from "@axelar-network/interchain-token-service/contracts/token-manager/TokenManager.sol";
import { TokenHandler } from "@axelar-network/interchain-token-service/contracts/TokenHandler.sol";
import { GatewayCaller } from "@axelar-network/interchain-token-service/contracts/utils/GatewayCaller.sol";
import { AxelarGasService } from "@axelar-network/axelar-cgp-solidity/contracts/gas-service/AxelarGasService.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { WTEL } from "../../src/WTEL.sol";
import { InterchainTEL } from "../../src/InterchainTEL.sol";
import { ITS } from "../Deployments.sol";
import { ITSConfig } from "../utils/ITSConfig.sol";
import { GenesisPrecompiler } from "./GenesisPrecompiler.sol";

/// @title ITSGenesis utility providing TN genesis-specific overrides of ITSUtils default instantiation fns
/// @notice Genesis target addresses for ITS suite & InterchainTEL must first be stored via `_setGenesisTargets()`
/// @dev All genesis fns return simulated deployments, copying state changes to genesis targets in storage
abstract contract ITSGenesis is ITSConfig, GenesisPrecompiler {
    /// @dev Sets this contract's state using ITS fetched from a `deployments.json` file
    function _setGenesisTargets(
        ITS memory genesisITSTargets, 
        address payable wtel, 
        address payable itel, 
        address itelTokenManager, 
        address payable safeSingleton, 
        address safeFactory, 
        address payable safe
    ) internal {
        gatewayImpl = AxelarAmplifierGateway(genesisITSTargets.AxelarAmplifierGatewayImpl);
        gateway = AxelarAmplifierGateway(genesisITSTargets.AxelarAmplifierGateway);
        tokenManagerDeployer = TokenManagerDeployer(genesisITSTargets.TokenManagerDeployer);
        interchainTokenImpl = InterchainToken(genesisITSTargets.InterchainTokenImpl);
        itDeployer = InterchainTokenDeployer(genesisITSTargets.InterchainTokenDeployer);
        tokenManagerImpl = TokenManager(genesisITSTargets.TokenManagerImpl);
        tokenHandler = TokenHandler(genesisITSTargets.TokenHandler);
        gasServiceImpl = AxelarGasService(genesisITSTargets.GasServiceImpl);
        gasService = AxelarGasService(genesisITSTargets.GasService);
        gatewayCaller = GatewayCaller(genesisITSTargets.GatewayCaller);
        itsImpl = InterchainTokenService(genesisITSTargets.InterchainTokenServiceImpl);
        its = InterchainTokenService(genesisITSTargets.InterchainTokenService);
        itFactoryImpl = InterchainTokenFactory(genesisITSTargets.InterchainTokenFactoryImpl);
        itFactory = InterchainTokenFactory(genesisITSTargets.InterchainTokenFactory);
        wTEL = WTEL(wtel);
        iTEL = InterchainTEL(itel);
        iTELTokenManager = TokenManager(itelTokenManager);
        safeImpl = Safe(safeSingleton);
        safeProxyFactory = SafeProxyFactory(safeFactory);
        governanceSafe = Safe(safe);
    }

    function instantiateAxelarAmplifierGatewayImpl()
        public virtual override
        returns (AxelarAmplifierGateway simulatedDeployment)
    {
        simulatedDeployment = super.instantiateAxelarAmplifierGatewayImpl();
        
        copyContractState(address(simulatedDeployment), address(gatewayImpl), new bytes32[](0));
    }

    function instantiateAxelarAmplifierGateway(address impl)
        public virtual override
        returns (AxelarAmplifierGateway simulatedDeployment)
    {        
        vm.startStateDiffRecording();
        simulatedDeployment = super.instantiateAxelarAmplifierGateway(impl);
        Vm.AccountAccess[] memory gatewayRecords = vm.stopAndReturnStateDiff();

        
        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), gatewayRecords);
        copyContractState(address(simulatedDeployment), address(gateway), slots);
    }

    function instantiateTokenManagerDeployer()
        public virtual override
        returns (TokenManagerDeployer simulatedDeployment)
    {
        simulatedDeployment = super.instantiateTokenManagerDeployer();
        
        copyContractState(address(simulatedDeployment), address(tokenManagerDeployer), new bytes32[](0));
    }

    function instantiateInterchainTokenImpl(address its_) public virtual override returns (InterchainToken simulatedDeployment) {
        simulatedDeployment = super.instantiateInterchainTokenImpl(its_);
        
        copyContractState(address(simulatedDeployment), address(interchainTokenImpl), new bytes32[](0));
    }

    function instantiateInterchainTokenDeployer(
        address interchainTokenImpl_
    )
        public virtual override
        returns (InterchainTokenDeployer simulatedDeployment)
    {
        simulatedDeployment = super.instantiateInterchainTokenDeployer(interchainTokenImpl_);
        
        copyContractState(address(simulatedDeployment), address(itDeployer), new bytes32[](0));
    }

    function instantiateTokenManagerImpl(address its_) public virtual override returns (TokenManager simulatedDeployment) {
        simulatedDeployment = super.instantiateTokenManagerImpl(its_);
        
        copyContractState(address(simulatedDeployment), address(tokenManagerImpl), new bytes32[](0));
    }

    function instantiateTokenHandler() public virtual override returns (TokenHandler simulatedDeployment) {
        simulatedDeployment = super.instantiateTokenHandler();
        
        copyContractState(address(simulatedDeployment), address(tokenHandler), new bytes32[](0));
    }

    function instantiateAxelarGasServiceImpl()
        public virtual override
        returns (AxelarGasService simulatedDeployment)
    {
        simulatedDeployment = super.instantiateAxelarGasServiceImpl();
        
        copyContractState(address(simulatedDeployment), address(gasServiceImpl), new bytes32[](0));
    }

    function instantiateAxelarGasService(address impl)
        public virtual override
        returns (AxelarGasService simulatedDeployment)
    {
        vm.startStateDiffRecording();
        simulatedDeployment = super.instantiateAxelarGasService(impl);
        Vm.AccountAccess[] memory gsRecords = vm.stopAndReturnStateDiff();

        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), gsRecords);
        copyContractState(address(simulatedDeployment), address(gasService), slots);
    }

    function instantiateGatewayCaller( 
        address gateway_,
        address axelarGasService_
    )
        public virtual override
        returns (GatewayCaller simulatedDeployment)
    {
        simulatedDeployment = super.instantiateGatewayCaller(gateway_, axelarGasService_);
        
        copyContractState(address(simulatedDeployment), address(gatewayCaller), new bytes32[](0));
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
        public virtual override
        returns (InterchainTokenService simulatedDeployment)
    {
        simulatedDeployment = super.instantiateITSImpl(
            tokenManagerDeployer_,
            itDeployer_,
            gateway_,
            gasService_,
            itFactory_,
            tokenManagerImpl_,
            tokenHandler_,
            gatewayCaller_
        );
        
        copyContractState(address(simulatedDeployment), address(itsImpl), new bytes32[](0));
    }

    function instantiateITS(
        address impl
    )
        public virtual override
        returns (InterchainTokenService simulatedDeployment)
    {
        vm.startStateDiffRecording();
        simulatedDeployment = super.instantiateITS(impl);
        Vm.AccountAccess[] memory itsRecords = vm.stopAndReturnStateDiff();

        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), itsRecords);
        copyContractState(address(simulatedDeployment), address(its), slots);
    }

    function instantiateITFImpl(
        address its_
    )
        public virtual override
        returns (InterchainTokenFactory simulatedDeployment)
    {
        simulatedDeployment = super.instantiateITFImpl(its_);
        
        copyContractState(address(simulatedDeployment), address(itFactoryImpl), new bytes32[](0));
    }

    function instantiateITF(
        address impl
    )
        public virtual override
        returns (InterchainTokenFactory simulatedDeployment)
    {
        vm.startStateDiffRecording();
        simulatedDeployment = super.instantiateITF(impl);
        Vm.AccountAccess[] memory itfRecords = vm.stopAndReturnStateDiff();

        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), itfRecords);
        copyContractState(address(simulatedDeployment), address(itFactory), slots);
    }

    function instantiateWTEL() public virtual override returns (WTEL simulatedDeployment) {
        simulatedDeployment = super.instantiateWTEL();
        
        copyContractState(address(simulatedDeployment), address(wTEL), new bytes32[](0));
    }

    function instantiateInterchainTEL(address its_) public virtual override returns (InterchainTEL simulatedDeployment) {
        vm.startStateDiffRecording();
        simulatedDeployment = super.instantiateInterchainTEL(its_);
        Vm.AccountAccess[] memory itelRecords = vm.stopAndReturnStateDiff();

        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), itelRecords);
        copyContractState(address(simulatedDeployment), address(iTEL), slots);
    }

    function instantiateInterchainTELTokenManager(address its_, bytes32 customLinkedTokenId) public virtual override returns (TokenManager simulatedDeployment) {
        vm.startStateDiffRecording();
        simulatedDeployment = super.instantiateInterchainTELTokenManager(its_, customLinkedTokenId);
        Vm.AccountAccess[] memory itelTMRecords = vm.stopAndReturnStateDiff();

        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), itelTMRecords);
        copyContractState(address(simulatedDeployment), address(iTELTokenManager), slots);
    }

    /// @notice Governance Safe infrastructure
    /// @dev Used as genesis precompiles for base fees, ITS permissioning, and system contract ownership

    function instantiateSafeImpl() public virtual returns (Safe simulatedDeployment) {
        vm.startStateDiffRecording();
        simulatedDeployment = new Safe();
        Vm.AccountAccess[] memory safeImplRecords = vm.stopAndReturnStateDiff();

        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), safeImplRecords);
        copyContractState(address(simulatedDeployment), address(safeImpl), slots);
    }

    function instantiateSafeProxyFactory() public virtual returns (SafeProxyFactory simulatedDeployment) {
        simulatedDeployment = new SafeProxyFactory();

        copyContractState(address(simulatedDeployment), address(safeProxyFactory), new bytes32[](0));
    }

    function instantiateGovernanceSafe() public virtual returns (Safe simulatedDeployment) {
        vm.startStateDiffRecording();

        address to; bytes memory data; address fallbackHandler;
        address paymentToken; uint256 payment; address paymentReceiver;
        bytes memory setupData = abi.encodeWithSelector(
            Safe.setup.selector, 
            safeOwners, safeThreshold, 
            to, data, fallbackHandler, paymentToken, payment, paymentReceiver);
        simulatedDeployment = Safe(payable(address(safeProxyFactory.createProxyWithNonce(address(safeImpl), setupData, 0x0))));

        Vm.AccountAccess[] memory safeRecords = vm.stopAndReturnStateDiff();
        bytes32[] memory slots = saveWrittenSlots(address(simulatedDeployment), safeRecords);
        copyContractState(address(simulatedDeployment), address(governanceSafe), slots);
    }
}