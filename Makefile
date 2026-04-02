.PHONY: update-artifacts

update-artifacts:
	forge build
	cp out/BlsG1.sol/BlsG1.json artifacts/
	cp out/ConsensusRegistry.sol/ConsensusRegistry.json artifacts/
	cp out/ERC1967Proxy.sol/ERC1967Proxy.json artifacts/
	cp out/Issuance.sol/Issuance.json artifacts/
	cp out/Stablecoin.sol/Stablecoin.json artifacts/
	cp out/StablecoinManager.sol/StablecoinManager.json artifacts/
	cp out/WorkerConfigs.sol/WorkerConfigs.json artifacts/
