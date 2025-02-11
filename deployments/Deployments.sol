/// SPDX-License-Identifier MIT or Apache-2.0
pragma solidity ^0.8.26;

/// @notice Foundry decodes JSON data to Solidity structs using lexicographical ordering
/// therefore upper-case struct member names must come **BEFORE** lower-case ones!
struct Deployments {
    address ArachnidDeterministicDeployFactory;
    address AxelarAmplifierGateway;
    address AxelarAmplifierGatewayImpl;
    address ConsensusRegistry;
    address GitAttestationRegistry;
    address StablecoinImpl;
    address StablecoinManager;
    address StablecoinManagerImpl;
    address TANIssuanceHistory;
    address TANIssuancePlugin;
    address UniswapV2Factory;
    address UniswapV2Router02;
    address admin;
    address eAUD;
    address eCAD;
    address eCHF;
    address eEUR;
    address eGBP;
    address eHKD;
    address eJPY;
    address eMXN;
    address eNOK;
    address eSDR;
    address eSGD;
    address rwTEL;
    address sepoliaTEL;
    address wTEL;
    address wTEL_eAUD_Pool;
    address wTEL_eCAD_Pool;
    address wTEL_eCHF_Pool;
    address wTEL_eEUR_Pool;
    address wTEL_eGBP_Pool;
    address wTEL_eHKD_Pool;
    address wTEL_eJPY_Pool;
    address wTEL_eMXN_Pool;
    address wTEL_eNOK_Pool;
    address wTEL_eSDR_Pool;
    address wTEL_eSGD_Pool;
}

/// @dev Raw tx calldatas required to achieve desired create2 addresses for the faucet.
/// @dev Target for all listed calldatas is the Arachnid Deterministic Deploy Factory.
/// The canonical Arachnid create2 factory address can be found in `deployments.json::ArachnidDeterministicDeployFactory`
bytes constant DETERMINISTIC_FIRST_FAUCET_IMPL_DATA = hex"537461626c65636f696e4d616e6167657200000000000000000000000000000060a0604052306080523480156012575f80fd5b506080516129d46100395f395f81816118580152818161188101526119c201526129d45ff3fe6080604052600436106101e6575f3560e01c806369e2fda411610108578063a217fddf1161009d578063df668eca1161006d578063df668eca14610583578063e63ab1e9146105a3578063e9aea396146105d6578063eb3839a7146105f5578063f874225414610614575f80fd5b8063a217fddf146104f5578063ad3cb1cc14610508578063c057bd6b14610545578063d547741f14610564575f80fd5b806391d14854116100d857806391d1485414610484578063924855fa146104a3578063956794b1146104b75780639ef84173146104d6575f80fd5b806369e2fda414610410578063817204a4146104315780638456cb59146104515780638e13c58e14610465575f80fd5b80633f4ba83a1161017e5780634f9c2c261161014e5780634f9c2c261461039b57806352d1902d146103ba578063543f8c58146103ce5780635c975abb146103ed575f80fd5b80633f4ba83a1461032257806340c66f781461033657806345c7c793146103555780634f1ef28614610388575f80fd5b8063248a9ca3116101b9578063248a9ca3146102a35780632f2ff15d146102d05780633598e3dc146102ef57806336568abe14610303575f80fd5b806301ffc9a7146101ea578063104430b61461021e5780631a0d6c2e1461023f5780631a95e05d14610260575b5f80fd5b3480156101f5575f80fd5b506102096102043660046121d0565b610634565b60405190151581526020015b60405180910390f35b348015610229575f80fd5b5061023d610238366004612252565b61066a565b005b34801561024a575f80fd5b5061025361090b565b6040516102159190612397565b34801561026b575f80fd5b5061020961027a366004612441565b6001600160a01b03165f9081525f80516020612908833981519152602052604090205460ff1690565b3480156102ae575f80fd5b506102c26102bd36600461245c565b610b8d565b604051908152602001610215565b3480156102db575f80fd5b5061023d6102ea366004612473565b610bad565b3480156102fa575f80fd5b5061023d610bcf565b34801561030e575f80fd5b5061023d61031d366004612473565b610be1565b34801561032d575f80fd5b5061023d610c19565b348015610341575f80fd5b5061023d6103503660046124a1565b610c4e565b348015610360575f80fd5b506102c27faecf5761d3ba769b4631978eb26cb84eae66bcaca9c3f0f4ecde3feb2f4cf14481565b61023d610396366004612535565b610ced565b3480156103a6575f80fd5b506102c26103b5366004612441565b610d0c565b3480156103c5575f80fd5b506102c2610d35565b3480156103d9575f80fd5b5061023d6103e836600461245c565b610d50565b3480156103f8575f80fd5b505f805160206129688339815191525460ff16610209565b34801561041b575f80fd5b50610424610d7c565b60405161021591906125c1565b34801561043c575f80fd5b505f805160206128e8833981519152546102c2565b34801561045c575f80fd5b5061023d610dfd565b348015610470575f80fd5b5061023d61047f366004612692565b610e2f565b34801561048f575f80fd5b5061020961049e366004612473565b611012565b3480156104ae575f80fd5b5061023d611048565b3480156104c2575f80fd5b506102c26104d1366004612441565b611058565b3480156104e1575f80fd5b5061023d6104f0366004612692565b611081565b348015610500575f80fd5b506102c25f81565b348015610513575f80fd5b50610538604051806040016040528060058152602001640352e302e360dc1b81525081565b60405161021591906126d7565b348015610550575f80fd5b5061023d61055f3660046126e9565b611253565b34801561056f575f80fd5b5061023d61057e366004612473565b61151c565b34801561058e575f80fd5b506102c25f8051602061298883398151915281565b3480156105ae575f80fd5b506102c27f65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a81565b3480156105e1575f80fd5b5061023d6105f036600461272a565b611538565b348015610600575f80fd5b5061023d61060f36600461276d565b611565565b34801561061f575f80fd5b506102c25f805160206129a883398151915281565b5f6001600160e01b03198216637965db0b60e01b148061066457506301ffc9a760e01b6001600160e01b03198316145b92915050565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a008054600160401b810460ff1615906001600160401b03165f811580156106ae5750825b90505f826001600160401b031660011480156106c95750303b155b9050811580156106d7575080155b156106f55760405163f92ee8a960e01b815260040160405180910390fd5b845467ffffffffffffffff19166001178555831561071f57845460ff60401b1916600160401b1785555b8a891461073f57604051637ca922bb60e01b815260040160405180910390fd5b610747611048565b61075e5f805160206129a883398151915233611612565b505f5b89811015610800576107f88d8d8381811061077e5761077e612799565b90506020020160208101906107939190612441565b8c8c848181106107a5576107a5612799565b6107bb92602060609092020190810191506127ad565b8d8d858181106107cd576107cd612799565b905060600201602001358e8e868181106107e9576107e9612799565b90506060020160400135611538565b600101610761565b506108185f805160206129a8833981519152336116b3565b506108235f8f611612565b5061083b5f805160206129a88339815191528e611612565b505f5b8781101561089f576108967faecf5761d3ba769b4631978eb26cb84eae66bcaca9c3f0f4ecde3feb2f4cf1448a8a8481811061087c5761087c612799565b90506020020160208101906108919190612441565b611612565b5060010161083e565b506108b5865f805160206128e883398151915255565b83156108fb57845460ff60401b19168555604051600181527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d29060200160405180910390a15b5050505050505050505050505050565b60605f610916610d7c565b905080516001600160401b03811115610931576109316124cb565b60405190808252806020026020018201604052801561099457816020015b61098160405180608001604052805f6001600160a01b0316815260200160608152602001606081526020015f81525090565b81526020019060019003908161094f5790505b5091505f5b8151811015610b88575f8282815181106109b5576109b5612799565b60200260200101516001600160a01b03166306fdde036040518163ffffffff1660e01b81526004015f60405180830381865afa1580156109f7573d5f803e3d5ffd5b505050506040513d5f823e601f3d908101601f19168201604052610a1e91908101906127c8565b90505f838381518110610a3357610a33612799565b60200260200101516001600160a01b03166395d89b416040518163ffffffff1660e01b81526004015f60405180830381865afa158015610a75573d5f803e3d5ffd5b505050506040513d5f823e601f3d908101601f19168201604052610a9c91908101906127c8565b90505f848481518110610ab157610ab1612799565b60200260200101516001600160a01b031663313ce5676040518163ffffffff1660e01b8152600401602060405180830381865afa158015610af4573d5f803e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610b189190612830565b90506040518060800160405280868681518110610b3757610b37612799565b60200260200101516001600160a01b0316815260200184815260200183815260200182815250868581518110610b6f57610b6f612799565b6020026020010181905250505050806001019050610999565b505090565b5f9081525f80516020612948833981519152602052604090206001015490565b610bb682610b8d565b610bbf8161172c565b610bc98383611612565b50505050565b610bd7611736565b610bdf61177f565b565b6001600160a01b0381163314610c0a5760405163334bd91960e11b815260040160405180910390fd5b610c1482826116b3565b505050565b7f65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a610c438161172c565b610c4b61178f565b50565b5f805160206129a8833981519152610c658161172c565b6001600160a01b038316610cd9576040515f90339084908381818185875af1925050503d805f8114610cb2576040519150601f19603f3d011682016040523d82523d5f602084013e610cb7565b606091505b5050905080610bc957604051633acddfc160e21b815260040160405180910390fd5b610c146001600160a01b03841633846117ee565b610cf561184d565b610cfe826118f1565b610d0882826118fb565b5050565b6001600160a01b03165f9081525f80516020612908833981519152602052604090206001015490565b5f610d3e6119b7565b505f8051602061292883398151915290565b5f805160206129a8833981519152610d678161172c565b610d08825f805160206128e883398151915255565b60605f7f77dc539bf9c224afa178d31bf07d5109c2b5c5e56656e49b25e507fec3a69f00805460408051602080840282018101909252828152929350839190830182828015610df257602002820191905f5260205f20905b81546001600160a01b03168152600190910190602001808311610dd4575b505050505091505090565b7f65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a610e278161172c565b610c4b611a00565b610e37611a48565b805181906001600160a01b03161580610e5b575060208101516001600160a01b0316155b80610e6857506040810151155b80610e7e575060608101516001600160a01b0316155b80610e8b57506080810151155b15610eb2576040516326401ebb60e01b8152600401610ea990612847565b60405180910390fd5b5f80516020612988833981519152610ec98161172c565b610ed68360600151610d0c565b836080015184606001516001600160a01b03166318160ddd6040518163ffffffff1660e01b8152600401602060405180830381865afa158015610f1b573d5f803e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610f3f9190612830565b610f499190612877565b1115610f795760608301516040516318c0142960e11b81526001600160a01b039091166004820152602401610ea9565b610fa18585856040015186602001516001600160a01b0316611a78909392919063ffffffff16565b6060830151835160808501516040516308934a5f60e31b81526001600160a01b039283166004820152602481019190915291169063449a52f8906044015f604051808303815f87803b158015610ff5575f80fd5b505af1158015611007573d5f803e3d5ffd5b505050505050505050565b5f9182525f80516020612948833981519152602090815260408084206001600160a01b0393909316845291905290205460ff1690565b611050611736565b610bdf610bcf565b6001600160a01b03165f9081525f80516020612908833981519152602052604090206002015490565b611089611a48565b805181906001600160a01b031615806110ad575060208101516001600160a01b0316155b806110ba57506040810151155b806110d0575060608101516001600160a01b0316155b806110dd57506080810151155b156110fb576040516326401ebb60e01b8152600401610ea990612847565b5f805160206129888339815191526111128161172c565b61111f8360200151611058565b836040015184602001516001600160a01b03166318160ddd6040518163ffffffff1660e01b8152600401602060405180830381865afa158015611164573d5f803e3d5ffd5b505050506040513d601f19601f820116820180604052508101906111889190612830565b611192919061288a565b10156111c25760208301516040516318c0142960e11b81526001600160a01b039091166004820152602401610ea9565b6020830151604080850151905163079cc67960e41b81526001600160a01b03888116600483015260248201929092529116906379cc6790906044015f604051808303815f87803b158015611214575f80fd5b505af1158015611226573d5f803e3d5ffd5b505084516080860151606087015161124c94506001600160a01b03169250879190611a78565b5050505050565b61125b611a48565b805181906001600160a01b0316158061127f575060208101516001600160a01b0316155b8061128c57506040810151155b806112a2575060608101516001600160a01b0316155b806112af57506080810151155b156112cd576040516326401ebb60e01b8152600401610ea990612847565b5f805160206129888339815191526112e48161172c565b6112f18360200151611058565b836040015184602001516001600160a01b03166318160ddd6040518163ffffffff1660e01b8152600401602060405180830381865afa158015611336573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061135a9190612830565b611364919061288a565b10156113945760208301516040516318c0142960e11b81526001600160a01b039091166004820152602401610ea9565b6113a18360600151610d0c565b836080015184606001516001600160a01b03166318160ddd6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156113e6573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061140a9190612830565b6114149190612877565b11156114445760608301516040516318c0142960e11b81526001600160a01b039091166004820152602401610ea9565b6020830151604080850151905163079cc67960e41b81526001600160a01b03878116600483015260248201929092529116906379cc6790906044015f604051808303815f87803b158015611496575f80fd5b505af11580156114a8573d5f803e3d5ffd5b505050506060830151835160808501516040516308934a5f60e31b81526001600160a01b039283166004820152602481019190915291169063449a52f8906044015f604051808303815f87803b158015611500575f80fd5b505af1158015611512573d5f803e3d5ffd5b5050505050505050565b61152582610b8d565b61152e8161172c565b610bc983836116b3565b5f805160206129a883398151915261154f8161172c565b61155b85858585611ab1565b61124c8585611bcf565b7faecf5761d3ba769b4631978eb26cb84eae66bcaca9c3f0f4ecde3feb2f4cf14461158f8161172c565b826001600160a01b031663449a52f8836115b45f805160206128e88339815191525490565b6040516001600160e01b031960e085901b1681526001600160a01b03909216600483015260248201526044015f604051808303815f87803b1580156115f7575f80fd5b505af1158015611609573d5f803e3d5ffd5b50505050505050565b5f5f8051602061294883398151915261162b8484611012565b6116aa575f848152602082815260408083206001600160a01b03871684529091529020805460ff191660011790556116603390565b6001600160a01b0316836001600160a01b0316857f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d60405160405180910390a46001915050610664565b5f915050610664565b5f5f805160206129488339815191526116cc8484611012565b156116aa575f848152602082815260408083206001600160a01b0387168085529252808320805460ff1916905551339287917ff6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b9190a46001915050610664565b610c4b8133611beb565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a0054600160401b900460ff16610bdf57604051631afcd79f60e31b815260040160405180910390fd5b611787611736565b610bdf611c24565b611797611c44565b5f80516020612968833981519152805460ff191681557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa335b6040516001600160a01b03909116815260200160405180910390a150565b6040516001600160a01b03838116602483015260448201839052610c1491859182169063a9059cbb906064015b604051602081830303815290604052915060e01b6020820180516001600160e01b038381831617835250505050611c73565b306001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001614806118d357507f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03166118c75f80516020612928833981519152546001600160a01b031690565b6001600160a01b031614155b15610bdf5760405163703e46dd60e11b815260040160405180910390fd5b5f610d088161172c565b816001600160a01b03166352d1902d6040518163ffffffff1660e01b8152600401602060405180830381865afa925050508015611955575060408051601f3d908101601f1916820190925261195291810190612830565b60015b61197d57604051634c9c8ce360e01b81526001600160a01b0383166004820152602401610ea9565b5f8051602061292883398151915281146119ad57604051632a87526960e21b815260048101829052602401610ea9565b610c148383611cd4565b306001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001614610bdf5760405163703e46dd60e11b815260040160405180910390fd5b611a08611a48565b5f80516020612968833981519152805460ff191660011781557f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258336117d0565b5f805160206129688339815191525460ff1615610bdf5760405163d93c066560e01b815260040160405180910390fd5b6040516001600160a01b038481166024830152838116604483015260648201839052610bc99186918216906323b872dd9060840161181b565b5f805160206129a8833981519152611ac88161172c565b818311611b3d5760405162461bcd60e51b815260206004820152603d60248201527f537461626c65636f696e48616e646c65723a207570706572626f756e64206d7560448201527f73742062652067726561746572207468616e206c6f776572626f756e640000006064820152608401610ea9565b5f5f805160206129088339815191526001600160a01b0387165f8181526020838152604091829020805460ff19168a15159081178255600182018a905560029091018890558251938452908301528101869052606081018590529091507f84f12763861d318f97fe38a0e6f70b46f0566462d67561978f0f4dff814031df9060800160405180910390a1505050505050565b801515600103611be257610d0882611d29565b610d0882611dcb565b611bf58282611012565b610d085760405163e2517d3f60e01b81526001600160a01b038216600482015260248101839052604401610ea9565b611c2c611736565b5f80516020612968833981519152805460ff19169055565b5f805160206129688339815191525460ff16610bdf57604051638dfc202b60e01b815260040160405180910390fd5b5f611c876001600160a01b03841683611faa565b905080515f14158015611cab575080806020019051810190611ca9919061289d565b155b15610c1457604051635274afe760e01b81526001600160a01b0384166004820152602401610ea9565b611cdd82611fbe565b6040516001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b905f90a2805115611d2157610c148282612021565b610d08612093565b7f77dc539bf9c224afa178d31bf07d5109c2b5c5e56656e49b25e507fec3a69f0080546001810182555f8290527f7e20de35e2cca1b91743fd09589d05b1415d23ef62d96d86c8e1bc09ee225f0f0180546001600160a01b0384166001600160a01b0319909116811790915560408051918252517fc039c75cef0904723584eecbad08281b7298a16c9fadc7dbbb576359df79c1de9181900360200190a15050565b7f77dc539bf9c224afa178d31bf07d5109c2b5c5e56656e49b25e507fec3a69f008054604080516020808402820181019092528281525f929091849190830182828015611e3f57602002820191905f5260205f20905b81546001600160a01b03168152600190910190602001808311611e21575b505050505090505f5f1990505f5b8251811015611e9457846001600160a01b0316838281518110611e7257611e72612799565b60200260200101516001600160a01b031603611e8c578091505b600101611e4d565b505f198103611ec1576040516378f85f0760e11b81526001600160a01b0385166004820152602401610ea9565b5f60018351611ed0919061288a565b9050808214611f3357828181518110611eeb57611eeb612799565b6020026020010151845f018381548110611f0757611f07612799565b905f5260205f20015f6101000a8154816001600160a01b0302191690836001600160a01b031602179055505b8354849080611f4457611f446128b8565b5f8281526020908190205f19908301810180546001600160a01b03191690559091019091556040516001600160a01b03871681527f29ef6e5e7533f5e04f1729a119b0acf31837e10f8a66e61d22dedd180d0221e9910160405180910390a15050505050565b6060611fb783835f6120b2565b9392505050565b806001600160a01b03163b5f03611ff357604051634c9c8ce360e01b81526001600160a01b0382166004820152602401610ea9565b5f8051602061292883398151915280546001600160a01b0319166001600160a01b0392909216919091179055565b60605f80846001600160a01b03168460405161203d91906128cc565b5f60405180830381855af49150503d805f8114612075576040519150601f19603f3d011682016040523d82523d5f602084013e61207a565b606091505b509150915061208a85838361214b565b95945050505050565b3415610bdf5760405163b398979f60e01b815260040160405180910390fd5b6060814710156120d75760405163cd78605960e01b8152306004820152602401610ea9565b5f80856001600160a01b031684866040516120f291906128cc565b5f6040518083038185875af1925050503d805f811461212c576040519150601f19603f3d011682016040523d82523d5f602084013e612131565b606091505b509150915061214186838361214b565b9695505050505050565b6060826121605761215b826121a7565b611fb7565b815115801561217757506001600160a01b0384163b155b156121a057604051639996b31560e01b81526001600160a01b0385166004820152602401610ea9565b5080611fb7565b8051156121b75780518082602001fd5b604051630a12f52160e11b815260040160405180910390fd5b5f602082840312156121e0575f80fd5b81356001600160e01b031981168114611fb7575f80fd5b6001600160a01b0381168114610c4b575f80fd5b5f8083601f84011261221b575f80fd5b5081356001600160401b03811115612231575f80fd5b6020830191508360208260051b850101111561224b575f80fd5b9250929050565b5f805f805f805f805f60c08a8c03121561226a575f80fd5b8935612275816121f7565b985060208a0135612285816121f7565b975060408a01356001600160401b0381111561229f575f80fd5b6122ab8c828d0161220b565b90985096505060608a01356001600160401b038111156122c9575f80fd5b8a01601f81018c136122d9575f80fd5b80356001600160401b038111156122ee575f80fd5b8c6020606083028401011115612302575f80fd5b6020919091019550935060808a01356001600160401b03811115612324575f80fd5b6123308c828d0161220b565b9a9d999c50979a9699959894979660a00135949350505050565b5f5b8381101561236457818101518382015260200161234c565b50505f910152565b5f815180845261238381602086016020860161234a565b601f01601f19169290920160200192915050565b5f602082016020835280845180835260408501915060408160051b8601019250602086015f5b8281101561243557868503603f19018452815180516001600160a01b031686526020808201516080918801829052906123f89088018261236c565b905060408201518782036040890152612411828261236c565b606093840151989093019790975250945060209384019391909101906001016123bd565b50929695505050505050565b5f60208284031215612451575f80fd5b8135611fb7816121f7565b5f6020828403121561246c575f80fd5b5035919050565b5f8060408385031215612484575f80fd5b823591506020830135612496816121f7565b809150509250929050565b5f80604083850312156124b2575f80fd5b82356124bd816121f7565b946020939093013593505050565b634e487b7160e01b5f52604160045260245ffd5b604051601f8201601f191681016001600160401b0381118282101715612507576125076124cb565b604052919050565b5f6001600160401b03821115612527576125276124cb565b50601f01601f191660200190565b5f8060408385031215612546575f80fd5b8235612551816121f7565b915060208301356001600160401b0381111561256b575f80fd5b8301601f8101851361257b575f80fd5b803561258e6125898261250f565b6124df565b8181528660208385010111156125a2575f80fd5b816020840160208301375f602083830101528093505050509250929050565b602080825282518282018190525f918401906040840190835b818110156126015783516001600160a01b03168352602093840193909201916001016125da565b509095945050505050565b5f60a0828403121561261c575f80fd5b60405160a081016001600160401b038111828210171561263e5761263e6124cb565b604052905080823561264f816121f7565b8152602083013561265f816121f7565b602082015260408381013590820152606083013561267c816121f7565b6060820152608092830135920191909152919050565b5f805f60e084860312156126a4575f80fd5b83356126af816121f7565b925060208401356126bf816121f7565b91506126ce856040860161260c565b90509250925092565b602081525f611fb7602083018461236c565b5f8060c083850312156126fa575f80fd5b8235612705816121f7565b9150612714846020850161260c565b90509250929050565b8015158114610c4b575f80fd5b5f805f806080858703121561273d575f80fd5b8435612748816121f7565b935060208501356127588161271d565b93969395505050506040820135916060013590565b5f806040838503121561277e575f80fd5b8235612789816121f7565b91506020830135612496816121f7565b634e487b7160e01b5f52603260045260245ffd5b5f602082840312156127bd575f80fd5b8135611fb78161271d565b5f602082840312156127d8575f80fd5b81516001600160401b038111156127ed575f80fd5b8201601f810184136127fd575f80fd5b805161280b6125898261250f565b81815285602083850101111561281f575f80fd5b61208a82602083016020860161234a565b5f60208284031215612840575f80fd5b5051919050565b602080825260029082015261535360f01b604082015260600190565b634e487b7160e01b5f52601160045260245ffd5b8082018082111561066457610664612863565b8181038181111561066457610664612863565b5f602082840312156128ad575f80fd5b8151611fb78161271d565b634e487b7160e01b5f52603160045260245ffd5b5f82516128dd81846020870161234a565b919091019291505056fe77dc539bf9c224afa178d31bf07d5109c2b5c5e56656e49b25e507fec3a69f0138361881985b0f585e6124dca158a3af102bffba0feb9c42b0b40825f41a3300360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800cd5ed15c6e187e77e9aee88184c21f4f2182ab5827cb3b7e07fbedcd63f03300724f6a44d576143e18c60911798b2b15551ca96bd8f7cb7524b8fa36253a26d8339759585899103d2ace64958e37e18ccb0504652c81d4a1b8aa80fe2126ab95a164736f6c634300081a000a";
bytes constant DETERMINISTIC_FAUCET_PROXY_DATA = hex"537461626c65636f696e4d616e6167657200000000000000000000000000000060806040526040516103cd3803806103cd8339810160408190526100229161025e565b61002c8282610033565b5050610347565b61003c82610091565b6040516001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b905f90a280511561008557610080828261010c565b505050565b61008d61017f565b5050565b806001600160a01b03163b5f036100cb57604051634c9c8ce360e01b81526001600160a01b03821660048201526024015b60405180910390fd5b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc80546001600160a01b0319166001600160a01b0392909216919091179055565b60605f80846001600160a01b031684604051610128919061032c565b5f60405180830381855af49150503d805f8114610160576040519150601f19603f3d011682016040523d82523d5f602084013e610165565b606091505b5090925090506101768583836101a0565b95945050505050565b341561019e5760405163b398979f60e01b815260040160405180910390fd5b565b6060826101b5576101b0826101ff565b6101f8565b81511580156101cc57506001600160a01b0384163b155b156101f557604051639996b31560e01b81526001600160a01b03851660048201526024016100c2565b50805b9392505050565b80511561020f5780518082602001fd5b604051630a12f52160e11b815260040160405180910390fd5b634e487b7160e01b5f52604160045260245ffd5b5f5b8381101561025657818101518382015260200161023e565b50505f910152565b5f806040838503121561026f575f80fd5b82516001600160a01b0381168114610285575f80fd5b60208401519092506001600160401b038111156102a0575f80fd5b8301601f810185136102b0575f80fd5b80516001600160401b038111156102c9576102c9610228565b604051601f8201601f19908116603f011681016001600160401b03811182821017156102f7576102f7610228565b60405281815282820160200187101561030e575f80fd5b61031f82602083016020860161023c565b8093505050509250929050565b5f825161033d81846020870161023c565b9190910192915050565b607a806103535f395ff3fe6080604052600a600c565b005b60186014601a565b6050565b565b5f604b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc546001600160a01b031690565b905090565b365f80375f80365f845af43d5f803e8080156069573d5ff35b3d5ffdfea164736f6c634300081a000a000000000000000000000000857721c881fc26e4664a9685d8650c0505997672000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006a4104430b6000000000000000000000000c1612c97537c2cc62a11fc4516367ab6f62d4b23000000000000000000000000c1612c97537c2cc62a11fc4516367ab6f62d4b2300000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000005f5e100000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000025d45a942405834b963c84b66418514c81b2f8c70000000000000000000000005fe291dd7b6a35502a51814df5e51a461b9c085f0000000000000000000000003a60acd97fea737ddd3e8fb2070601c19ac22699000000000000000000000000f84548d35a90d8b107019478188a3791f3b8f6c10000000000000000000000005cc307482eaba4c03526c00b6d6f5e05949550d90000000000000000000000007e27fc84da5e35097982fda7b2c93e8ce4fb5817000000000000000000000000c8156af812714b8cedb540adec69fc104d99930b000000000000000000000000989251ff79b744736a91c617dde3d3b5da2c09ef000000000000000000000000356ccc8a7cbe1eadf0282e6c23278b0e67fb3f910000000000000000000000005404f8b4f4625cff045a3076bc28c250a71e4507000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000004000000000000000000000000e626ce81714cb7777b1bf8ad2323963fb3398ad5000000000000000000000000b3fabbd1d2edde4d9ced3ce352859ce1bebf7907000000000000000000000000a3478861957661b2d8974d9309646a71271d98b9000000000000000000000000e69151677e5aec0b4fc0a94bfcaf20f6f0f975eb00000000000000000000000000000000000000000000000000000000";
