# Canonical initcode for post-genesis deployments

Byte-exact creation data for third-party contracts that the mainnet scripts under
`script/mainnet/deploy/` land at their canonical cross-chain addresses after genesis.
Each file was captured from the original Ethereum mainnet deployment, and every
address below was re-derived from these bytes before they were committed. The
scripts check each file's keccak256 before using it, so a corrupted or tampered file
fails loudly.

The genesis counterpart, runtime bytecode etched at genesis, lives in
`deployments/genesis/canonical-bytecode/`.

## Why replay the original deployments

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

## CreateX (`createx/`)

`CreateX.presigned.hex` is CreateX's own presigned deployment transaction, the
3,000,000 gas limit variant published in the CreateX repository under
`scripts/presigned-createx-deployment-transactions/`. It is a pre-EIP-155 legacy
transaction (no chain id, `v = 28`) signed by `0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5`
at nonce 0, with a 100 gwei gas price, and creates
`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`.

| File | keccak256(raw signed transaction) |
|---|---|
| `CreateX.presigned.hex` | `0xb6274b80bc7cda162df89894c7748a5cb7ba2eaa6004183c41a1837c3b072f1e` |

The Adiri testnet already carries CreateX from this transaction, which shows that
Telcoin Network accepts unprotected legacy transactions.

## Refreshing

These bytes never change: a different file would deploy to a different address and
defeat the purpose. To re-verify a file, take the deployment transaction's input from
an Ethereum archive node, strip the leading 32-byte salt, and compare keccak256 with
the table. Then derive the address with
`cast compute-address --salt <salt> --init-code-hash <hash> 0x4e59b44847b379578588920cA78FbF26c0B4956C`.
