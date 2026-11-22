# Canonical initcode

Byte-exact creation data for the Safe v1.3.0 and v1.5.0 suites and the ERC-4337
EntryPoints, captured from their original Ethereum mainnet deployments. Every address below was
re-derived from these bytes before they were committed, and each user checks the
file's keccak256 before using it, so a corrupted or tampered file fails loudly.

Genesis etches these contracts' runtime bytes, vendored in
`deployments/genesis/canonical-bytecode/`. The creation code here backs the proof that
the etch is right: the genesis tests under `test/genesis/` replay each original
deployment on a fresh chain that has only the deterministic deployers, and check that
it produces the same runtime bytes at the same address and writes exactly the
storage the generator writes, nothing more. The Safe v1.3.0 proxy factory's creation
code also lets the tests deploy its eip155 copy, which genesis leaves to anyone.

## Why the original creation code

These contracts are deployed on every major chain at the same address, and wallets,
SDKs, bundlers and indexers hardcode those addresses. The address is a function of
the deployer, the salt and the exact initcode, so only the original bytes, sent
through the original deployer with the original salt, reproduce it. Recompiling the
source would produce different bytes and a different address.

## Safe v1.3.0 (`safe-v1.3.0/`)

The nine contracts of the safe-deployments v1.3.0 `canonical` registry. Each file is
the initcode from the Ethereum deployment transaction to the Arachnid proxy
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`), all with salt `0x00…00`. The calldata
of those transactions is `salt ‖ initcode`; the files hold the initcode only.

| File | Canonical address | Ethereum deployment tx | keccak256(initcode) |
|---|---|---|---|
| `GnosisSafe.hex` | `0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552` | `0x0b04589bdc11585fb98f270b1bfeff0fb3bbb3c56d35b104f62d8115d6f7c57f` | `0x30632ce72e4de7408243bfe08d3359ce0f494543f08c113cc4d4232282bf6c6c` |
| `GnosisSafeL2.hex` | `0x3E5c63644E683549055b9Be8653de26E0B4CD36E` | `0xdb5826e72c53ef5b4d1a94dd928c44d6cdacbc6f0065a4c84ac7ebb23446ea48` | `0x49f30800a6ac5996a48b80c47ff20f19f8728812498a2a7fe75a14864fab6438` |
| `CompatibilityFallbackHandler.hex` | `0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4` | `0x6bdb485e2932acb12ad408402308dafe6d41b43dc8e2ec39683b78191d91c57f` | `0x272190de126b4577e187d9f00b9ca5daeae76d771965d734876891a51f9c43d8` |
| `MultiSend.hex` | `0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761` | `0xa7b8b01c792f44ced1ce8b310bcb6af68fc290faae6c002b9547a7574c649910` | `0x319ec670832dc89915c70968563439764e1f45db07ce205115fef547c4d7a7ba` |
| `MultiSendCallOnly.hex` | `0x40A2aCCbd92BCA938b02010E17A5b8929b49130D` | `0x679e32f3bffed89f1b886575acfa846d7f9140104c80b73fc4f7a2c0b44587de` | `0x35e699c3e43ec3e03a101730ab916c5e540893eaaf806451e929d138c3ff53b7` |
| `SignMessageLib.hex` | `0xA65387F16B013cf2Af4605Ad8aA5ec25a2cbA3a2` | `0x04e4f2b3156d23fa9ce6c0cf6ea2b166b5bb7075d2eb51e283d423fa3a05e1fe` | `0xf351650cab7419d02a85bc577276cc69272ea9ba117a56f599039531d1689962` |
| `CreateCall.hex` | `0x7cbB62EaA69F79e6873cD1ecB2392971036cFAa4` | `0x234d2d2ab5594830eb588a910dfca599a405eb0b3f5f939ba52b91728fa7da9c` | `0x81b71c6ca3958124fc3f1368afb83eff85b35d12725f55c65360842a19119e35` |
| `SimulateTxAccessor.hex` | `0x59AD6735bCd8152B84860Cb256dD9e96b85F69Da` | `0xfdc358835bc154697e1a473b176b9e51dea956796fb27a3db64e568a7496acfb` | `0xe5993412e711df6cc93d867252a993881b9e5ba1f9458be7b69e27499b52e232` |
| `GnosisSafeProxyFactory.hex` | `0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2` | `0x83476e9dc3493bd2889af168b3fdcd8946949a386725fd3a3b1cca5c999a3828` | `0x13d77c68fe7529013a9a57a295a785084b80e3d6ae9358c7f334752e0c8615f4` |

The same bytes were used to deploy the suite on the Adiri testnet, where the
resulting runtime code matched Ethereum's byte for byte.

Sent through the Safe Singleton Factory (`0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7`)
with salt 0 instead, the same files produce the suite's eip155 addresses, for example
`GnosisSafe` at `0x69f4D1788e39c87893C980c06EdF4b7f686e2938`, `GnosisSafeL2` at
`0xfb1bffC9d739B8D520DaF37dF666da4C687191EA` and `GnosisSafeProxyFactory` at
`0xC22834581EbC8527d974F8a1c97E1bEA4EF910BC`.

## Safe v1.5.0 (`safe-v1.5.0/`)

The 13 contracts of the safe-deployments v1.5.0 `canonical` registry.
Each file is the initcode from the Ethereum deployment transaction to the Safe Singleton Factory (`0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7`), all with salt `0x00…00`.
As with the Arachnid proxy, the calldata of those transactions is `salt ‖ initcode` and the files hold the initcode only.

| File | Canonical address | Ethereum deployment tx | keccak256(initcode) |
|---|---|---|---|
| `Safe.hex` | `0xFf51A5898e281Db6DfC7855790607438dF2ca44b` | `0xc39c8ef6e6146a2d38d3b1a6bc50965345c5802b19712827dbd85ef2208fcbd7` | `0x3c32e7eb3961c145eef8620b24e8b829e6d2062a5730629d6169319f29fc1d07` |
| `SafeL2.hex` | `0xEdd160fEBBD92E350D4D398fb636302fccd67C7e` | `0x0f822a2389a082a128a7bdf1e97fc1c58687d5fdba3c0b61f0a18e71dd43c215` | `0x4784b1a3de5d71a416f0f5d987aef075f63287002bd2de704a9e68e57ffee658` |
| `SafeProxyFactory.hex` | `0x14F2982D601c9458F93bd70B218933A6f8165e7b` | `0xecc1d594c48cf14ae7ccc3907a9dd815aefc03ec817e76b712cbbce36c03685f` | `0xd8803696e4c627ba4cab33cfab2625cf66c88f218c017306e392fcf88cc4e0c6` |
| `CompatibilityFallbackHandler.hex` | `0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4` | `0xf5fae864993491ab9d22a1a592756d46584e9dc4a2f0cb285a4a1f0aae314aa9` | `0xe7213ad39e55911aa31c9d631addd737170d46e9074db5a5cf60fc3f78d6e1c1` |
| `TokenCallbackHandler.hex` | `0x54e86d004d71a8D2112ec75FaCE57D730b0433F3` | `0x21bb1c2810c69c7ad369f1b0b56f09d487effa1b4105761c0a500ff89c743678` | `0xabaed42c0b2d8612d844777555608d819901cfeab4e294b0030ea970a6097e24` |
| `ExtensibleFallbackHandler.hex` | `0x85a8ca358D388530ad0fB95D0cb89Dd44Fc242c3` | `0x5679239fe985fbe9e85e8103f1a3e7e9b58116144e9086ede2157b4f0512b1d7` | `0xc71c1171c056d3f4ae6b3bc8db52704dc11752e2c4473c014fdecf1b001a1348` |
| `SafeToL2Setup.hex` | `0x900C7589200010D6C6eCaaE5B06EBe653bc2D82a` | `0x1114be8ecc3006171782d2f660a8b29e8e0b8e6cd5fa7b148024b215e66077a9` | `0xa20a5a96e47e6fe2e691c672028b1ef01deefdce4bf88a458f9749e56ab42b12` |
| `MultiSend.hex` | `0x218543288004CD07832472D464648173c77D7eB7` | `0x77b763ad049b1b91b07ea8aa056ab048c5183131e8a97da4ec712d0bd206a9cf` | `0x835a047eeb2db05847f2a0a80740fc993ff782957d2db7e093289244c3890df3` |
| `MultiSendCallOnly.hex` | `0xA83c336B20401Af773B6219BA5027174338D1836` | `0xbbd6b1dc77602741ee804eb98a13758f167b72e0436b5fb3b212a18c4004a247` | `0xc59d60d5dc7475d074dd19c49e892a39432d2bbe4cee98002d094240f6a619af` |
| `SignMessageLib.hex` | `0x4FfeF8222648872B3dE295Ba1e49110E61f5b5aa` | `0x2023edc10d8e393f5ecefcd1e6c1ac7bccaa266f6746a50e123e0b9e95ad608d` | `0x3bea4df2be1715fc6acb31d39a0f87215f9eed4972ace7936b3f6939a3b5ed7d` |
| `CreateCall.hex` | `0x2Ef5ECfbea521449E4De05EDB1ce63B75eDA90B4` | `0xb9a90d053c7283e04e8cabfea212fd1bbb8afc3771a9bae777641da39e84a1c0` | `0x075bef57cac49bbfdac62bcd02d8ec78ebd7aa747f0387b98e2afce08ceec9c8` |
| `SimulateTxAccessor.hex` | `0x07EfA797c55B5DdE3698d876b277aBb6B893654C` | `0x21bd8d49746b3e73ac1b4eaea86ad90067a0acf1f19e1dcd8ad1a70cce63ee1e` | `0x9fb40cd276a52c1d53843216c79fdd90be05eeb37ec0600bc4ca12f913835335` |
| `SafeMigration.hex` | `0x6439e7ABD8Bb915A5263094784C5CF561c4172AC` | `0x29f967374474daa2e9553f3aee0a83d51057649212afb4005b3b0a773d24e537` | `0xd40853463d2e6bbdd66743fe4d2605ade11f6ce0c8d89f5f30f9f0fb4f10c4dd` |

Ten went in Ethereum blocks 22774976 to 22774984 and 22780111 (2025-06-24 and 2025-06-25); `Safe`, `SafeL2` and `SafeMigration` went in blocks 22838493 to 22838495 (2025-07-03), from a different sender.
The sender does not enter the address: `keccak256(0xff ‖ factory ‖ salt ‖ keccak256(initcode))` over each file reproduces the canonical address.
Run as an `eth_call` contract creation, each file returns the runtime vendored in `deployments/genesis/canonical-bytecode/safe-v1.5.0/`, byte for byte except the `address(this)` immutables of `SafeToL2Setup`, `MultiSend`, `SimulateTxAccessor` and `SafeMigration`, which take the address of the simulated deployment.

The proxy creation code is not vendored here: it is embedded in `SafeProxyFactory`, which returns it from `proxyCreationCode()` (438 bytes, keccak256 `0x941b3e88811b2f33b8e26783c7407d2e978404581a21c9f07abf2cad9cb87e12`).

## ERC-4337 EntryPoint (`erc4337/`)

Initcode from the Ethereum deployment transactions to the Arachnid proxy. v0.6 uses the
zero salt like the Safe suite; v0.7 and v0.8 each use their own.

| File | Canonical address | Salt | Ethereum deployment tx | keccak256(initcode) |
|---|---|---|---|---|
| `EntryPointV06.hex` | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` | `0x0000000000000000000000000000000000000000000000000000000000000000` | `0x2635de77fc9fc90cea0eca67fff403cafb34b9d8d3303b5276e45a09de463d8b` | `0x7af81bb089cbbd117f52b96bebd684df6da9f4085c8d924358272f2506fe836b` |
| `EntryPointV07.hex` | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | `0x90d8084deab30c2a37c45e8d47f49f2f7965183cb6990a98943ef94940681de3` | `0x5c81ea86f6c54481d3e21c78675b4f1d985c1fa62b678dcdfdf7934ddd6e127e` | `0x30516d9cdbeabfaf62ea32d081a10ee3b95b92e5549cfc86353bbe85741c1404` |
| `EntryPointV08.hex` | `0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108` | `0x0a59dbff790c23c976a548690c27297883cc66b4c67024f9117b0238995e35e9` | `0xae4eafd1fd17e03b5200f6e2ecad4f669b41d9ba3a4fa0018e92cde985b33129` | `0x2a7c999e10f113d5f71f2abb9069a95091852afbd016309139559b9e47bb59dd` |

EntryPoint v0.8 fixes its EIP-712 chain id and domain separator at construction, so
its runtime bytes differ on every chain; v0.6, v0.7 and every SenderCreator helper
are byte-identical everywhere.

## Refreshing

These bytes never change: a different file would deploy to a different address and
defeat the purpose. To re-verify a file, take the deployment transaction's input from
an Ethereum archive node, strip the leading 32-byte salt, and compare keccak256 with
the table. Then derive the address with
`cast create2 --deployer 0x4e59b44847b379578588920cA78FbF26c0B4956C --salt <salt> --init-code-hash <hash>`.
For `safe-v1.5.0/` the deployer is the Safe Singleton Factory, `0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7`.
