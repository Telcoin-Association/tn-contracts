// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import { ConsensusRegistry } from "src/consensus/ConsensusRegistry.sol";
import { RewardInfo } from "src/interfaces/IStakeManager.sol";
import { BlsG1 } from "src/consensus/BlsG1.sol";
import { BlsG1Harness } from "../EIP2537/BlsG1Harness.sol";
import { Issuance } from "src/consensus/Issuance.sol";
import { GenesisPrecompiler } from "deployments/genesis/GenesisPrecompiler.sol";

contract ConsensusRegistryTestUtils is ConsensusRegistry, BlsG1Harness, GenesisPrecompiler {
    using BlsG1 for bytes;

    ConsensusRegistry public consensusRegistry;

    address public crOwner = address(0xc0ffee);
    address public validator1 = _addressFromPrivateKey(1);
    address public validator2 = _addressFromPrivateKey(2);
    address public validator3 = _addressFromPrivateKey(3);
    address public validator4 = _addressFromPrivateKey(4);

    ValidatorInfo validatorInfo1;
    ValidatorInfo validatorInfo2;
    ValidatorInfo validatorInfo3;
    ValidatorInfo validatorInfo4;

    ValidatorInfo[] initialValidators; // contains validatorInfo1-4
    BlsG1.ProofOfPossession[] initialBLSPops;

    address public sysAddress;

    // non-genesis validator for testing
    uint256 public validator5Secret = 5;
    address public validator5 = _addressFromPrivateKey(validator5Secret);
    bytes public validator5BlsPubkey = eip2537PointG2ToUncompressed(_blsEIP2537PubkeyFromSecret(validator5Secret));

    uint256 public telMaxSupply = 100_000_000_000e18;
    uint256 public registryGenesisBal;
    uint256 public stakeAmount_ = 1_000_000e18;
    uint256 public minWithdrawAmount_ = 1000e18;
    uint256 public epochIssuance_ = 25_806e18;
    uint32 public epochDuration_ = 24 hours;
    // `OZ::ERC721Upgradeable::mint()` supports up to ~14_300 fuzzed mint iterations
    uint256 public MAX_MINTABLE = 14_000;

    constructor()
        ConsensusRegistry(
            StakeConfig(stakeAmount_, minWithdrawAmount_, epochIssuance_, epochDuration_),
            _populateInitialValidators(),
            _populateinitialBLSPops(),
            crOwner
        )
    {
        vm.etch(issuance, type(Issuance).runtimeCode);
    }

    // convenience fn for constructor
    function _populateInitialValidators() internal returns (ValidatorInfo[] memory) {
        // provide initial validator set as the network will launch with at least four validators
        validatorInfo1 = ValidatorInfo(
            _blsDummyPubkeyFromSecret(1),
            validator1,
            uint32(0),
            uint32(0),
            ValidatorStatus.Active,
            false,
            false,
            uint8(0)
        );
        validatorInfo2 = ValidatorInfo(
            _blsDummyPubkeyFromSecret(2),
            validator2,
            uint32(0),
            uint32(0),
            ValidatorStatus.Active,
            false,
            false,
            uint8(0)
        );
        validatorInfo3 = ValidatorInfo(
            _blsDummyPubkeyFromSecret(3),
            validator3,
            uint32(0),
            uint32(0),
            ValidatorStatus.Active,
            false,
            false,
            uint8(0)
        );
        validatorInfo4 = ValidatorInfo(
            _blsDummyPubkeyFromSecret(4),
            validator4,
            uint32(0),
            uint32(0),
            ValidatorStatus.Active,
            false,
            false,
            uint8(0)
        );
        initialValidators.push(validatorInfo1);
        initialValidators.push(validatorInfo2);
        initialValidators.push(validatorInfo3);
        initialValidators.push(validatorInfo4);

        return initialValidators;
    }

    // convenience fn for constructor
    function _populateinitialBLSPops() internal returns (BlsG1.ProofOfPossession[] memory) {
        for (uint256 i; i < initialValidators.length; ++i) {
            uint256 secretI = i + 1;
            address validatorI = initialValidators[i].validatorAddress;
            bytes memory pubkey = eip2537PointG2ToUncompressed(_blsEIP2537PubkeyFromSecret(secretI));
            bytes memory messageI = proofOfPossessionMessage(pubkey, validatorI);
            bytes memory signature = eip2537PointG1ToUncompressed(_blsEIP2537SignatureFromSecret(secretI, messageI));

            initialBLSPops.push(BlsG1.ProofOfPossession(pubkey, signature));
        }

        return initialBLSPops;
    }

    function _sortAddresses(address[] memory arr) internal pure {
        uint256 length = arr.length;
        for (uint256 i; i < length; i++) {
            for (uint256 j; j < length - 1; j++) {
                if (arr[j] > arr[j + 1]) {
                    address temp = arr[j];
                    arr[j] = arr[j + 1];
                    arr[j + 1] = temp;
                }
            }
        }
    }

    /// @notice Never do this onchain in production!! Only for testing
    function _addressFromPrivateKey(uint256 pk) internal pure returns (address) {
        return vm.addr(pk);
    }

    function _fuzz_mint(uint24 numValidators) internal {
        for (uint256 i; i < numValidators; ++i) {
            // account for initial validators
            uint256 tokenId = i + 5;
            address newValidator = _addressFromPrivateKey(tokenId);

            // deal `stakeAmount` funds and prank governance NFT mint to `newValidator`
            vm.deal(newValidator, stakeAmount_);
            vm.prank(crOwner);
            consensusRegistry.mint(newValidator);
        }
    }

    function _fuzz_burn(uint24 numValidators, address[] memory committee) internal returns (uint256[] memory) {
        numValidators += 4; // include initial validators in burn list

        // leave 2 committee members
        address skipper = committee[0];
        address skippy = committee[1];
        uint256 numToBurn = numValidators - 2;

        // create list of token IDs to be burned
        uint256[] memory tokenIds = new uint256[](numValidators);
        for (uint256 i; i < numValidators; ++i) {
            tokenIds[i] = i + 1;
        }

        // shuffle array to simulate semi-random burn order
        bytes32 seed = keccak256(abi.encodePacked(numValidators));
        for (uint256 i; i < numValidators; ++i) {
            uint256 n = i + uint256(seed) % (numValidators - i);
            (tokenIds[i], tokenIds[n]) = (tokenIds[n], tokenIds[i]);
        }

        // burn tokens in the shuffled order, skipping 2 committee members
        uint256[] memory tempBurnedIds = new uint256[](numToBurn);
        uint256 counter;
        for (uint256 i; i < numValidators; ++i) {
            uint256 tokenId = tokenIds[i];
            address validatorToBurn = _addressFromPrivateKey(tokenId);

            // skip burning two committee members
            if (validatorToBurn == skipper || validatorToBurn == skippy) {
                continue;
            }

            vm.prank(crOwner);
            consensusRegistry.burn(validatorToBurn);
            tempBurnedIds[counter++] = tokenId;
        }

        // return trimmed array handling skips
        uint256[] memory burnedIds = new uint256[](counter);
        for (uint256 i; i < counter; ++i) {
            burnedIds[i] = tempBurnedIds[i];
        }

        return burnedIds;
    }

    function _fuzz_stake(uint24 numValidators, uint256 amount) internal {
        for (uint256 i; i < numValidators; ++i) {
            // recreate `newValidator`, accounting for initial validators
            uint256 secret = i + 5;
            address newValidator = _addressFromPrivateKey(secret);

            // generate new validator keys & signatures
            bytes memory newBLSPubkey = eip2537PointG2ToUncompressed(_blsEIP2537PubkeyFromSecret(secret));
            bytes memory message = proofOfPossessionMessage(newBLSPubkey, newValidator);
            bytes memory blsSignature = eip2537PointG1ToUncompressed(_blsEIP2537SignatureFromSecret(secret, message));

            // stake and activate
            vm.deal(newValidator, amount);
            vm.startPrank(newValidator);
            consensusRegistry.stake{ value: amount }(
                _blsDummyPubkeyFromSecret(secret), BlsG1.ProofOfPossession(newBLSPubkey, blsSignature)
            );
            vm.stopPrank();
        }
    }

    function _fuzz_activate(uint24 numValidators) internal {
        for (uint256 i; i < numValidators; ++i) {
            // recreate `newValidator`, accounting for initial validators
            uint256 tokenId = i + 5;
            address newValidator = _addressFromPrivateKey(tokenId);

            vm.prank(newValidator);
            consensusRegistry.activate();
        }
    }

    function _fuzz_computeCommitteeSize(
        uint256 numActive,
        uint256 numFuzzedValidators
    )
        internal
        pure
        returns (uint256)
    {
        // identify expected committee size
        uint256 committeeSize;
        if (numFuzzedValidators <= 6) {
            // 4 initial and 6 new validators would be under the 10 committee size
            committeeSize = numActive;
        } else {
            committeeSize = (numActive * 1e32) / 3 / 1e32 + 1;
        }

        return committeeSize;
    }

    function _fuzz_createFutureCommittee(
        uint256 numActive,
        uint256 committeeSize
    )
        internal
        pure
        returns (address[] memory)
    {
        // reloop to construct `futureCommittee` array
        address[] memory futureCommittee = new address[](committeeSize);
        uint256 committeeCounter;
        // `tokenId` is 1-indexed
        uint256 index = 1 + uint256(keccak256(abi.encode(committeeSize))) % committeeSize;
        // handle index overflow by wrapping around to first index
        uint256 nonOverflowIndex = 1 + numActive - committeeSize;
        index = index > nonOverflowIndex ? nonOverflowIndex : index;
        while (committeeCounter < futureCommittee.length) {
            // recreate `validator` address with ConsensusNFT in `setUp()` loop
            address validator = _addressFromPrivateKey(index);
            futureCommittee[committeeCounter] = validator;
            committeeCounter++;
            index++;
        }

        _sortAddresses(futureCommittee);

        return futureCommittee;
    }

    function _createTokenIdCommittee(uint256 committeeSize) internal pure returns (address[] memory) {
        address[] memory committee = new address[](committeeSize);
        for (uint256 i; i < committee.length; ++i) {
            // create dummy `validator` address equivalent to their `tokenId`
            uint256 tokenId = i + 1;
            address validator = address(uint160(tokenId));
            committee[i] = validator;
        }

        return committee;
    }

    function _fuzz_createRewardInfos(uint24 numRewardees)
        internal
        view
        returns (RewardInfo[] memory, uint256[] memory)
    {
        RewardInfo[] memory rewardInfos = new RewardInfo[](numRewardees);
        uint256 totalWeight;
        for (uint256 i; i < numRewardees; ++i) {
            address rewardee = _addressFromPrivateKey(i + 1);
            // 0-10000 is reasonable range of consensus blocks leaders can authorize per epoch
            uint256 uniqueSeed = i + numRewardees;
            uint256 consensusHeaderCount = uint256(uint256(keccak256(abi.encode(uniqueSeed))) % 10_000);

            rewardInfos[i] = RewardInfo(rewardee, consensusHeaderCount);
            totalWeight += stakeAmount_ * consensusHeaderCount;
        }
        uint256[] memory expectedRewards = new uint256[](numRewardees);
        for (uint256 i; i < rewardInfos.length; ++i) {
            if (rewardInfos[i].consensusHeaderCount == 0) {
                expectedRewards[i] = 0;
                continue;
            }
            uint256 weight = stakeAmount_ * rewardInfos[i].consensusHeaderCount;
            expectedRewards[i] = epochIssuance_ * weight / totalWeight;
        }

        return (rewardInfos, expectedRewards);
    }
}
