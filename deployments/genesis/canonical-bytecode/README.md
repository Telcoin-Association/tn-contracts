# Canonical runtime bytecode

Byte-exact runtime bytecode of the third-party contracts that genesis etches at
their canonical cross-chain addresses: the Safe v1.4.1 suite and the Safe passkey
module (files at the top level), and the Safe v1.3.0 suite, CreateX, the ERC-4337
EntryPoints, Permit2 and the Safe 4337 module (one subdirectory per batch). The
v1.4.1 suite comes first.

Byte-exact runtime bytecode of the canonical Safe v1.4.1 suite, captured from
the live Ethereum mainnet deployments with `cast code <address>` (2026-08-24)
and cross-verified byte-identical against Sepolia and Base. These bytes — not
locally compiled artifacts — are what the genesis generator etches at the
canonical addresses.

## Why vendored bytes instead of compiling from `lib/safe-contracts`

Safe's canonical v1.4.1 release was compiled with solc 0.7.6. Compiling the
same source with this repo's toolchain produces semantically equivalent but
byte-different contracts. That difference is not cosmetic:

- `SafeProxyFactory.createProxyWithNonce` derives the proxy address via
  CREATE2 over the factory's **embedded proxy creation code**. Different
  factory bytes ⇒ every Safe created through it lands at a different address
  than the identical creation call on Ethereum/Sepolia/Base/etc., breaking
  cross-chain counterfactual Safe addresses on Telcoin Network.
- Safe ecosystem tooling (protocol-kit SDK, Safe{Wallet}) assumes the
  canonical singletons/handlers at the canonical addresses with canonical
  behavior.

See `test/genesis/GenesisSafeCanonicalParity.t.sol` for the end-to-end proof:
with these bytes in place, a real multichain Safe creation replayed against
the genesis state reproduces its Ethereum address exactly.

## Contents

| File | Canonical address | keccak256(runtime) |
|---|---|---|
| `Safe.hex` | `0x41675C099F32341bf84BFc5382aF534df5C7461a` | `0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4` |
| `SafeL2.hex` | `0x29fcB43b46531BcA003ddC8FCB67FFE91900C762` | `0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff` |
| `SafeProxyFactory.hex` | `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67` | `0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317` |
| `CompatibilityFallbackHandler.hex` | `0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99` | `0x7c6007a5d711cea8dfd5d91f5940ec29c7f200fe511eb1fc1397b367af3c42f9` |
| `SafeToL2Setup.hex` | `0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54` | `0x2f25df28caf984366ee584e13241707e85dcd5a6ea0c14267928dafc1fd6274b` |
| `MultiSend.hex` | `0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526` | `0x0e4f7fc66550a322d1e7688e181b75e217e662a4f3f4d6a29b22bc61217c4b77` |
| `MultiSendCallOnly.hex` | `0x9641d764fc13c8B624c04430C7356C1C7C8102e2` | `0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939` |
| `SignMessageLib.hex` | `0xd53cd0aB83D845Ac265BE939c57F53AD838012c9` | `0x525c754a46b79e05543a59bb61e8de3c9eee0d955a59352409cbe67ea1077528` |
| `CreateCall.hex` | `0x9b35Af71d77eaf8d7e40252370304687390A1A52` | `0x2b3060c55fcb8275653e99ad511a71f67ba76934ed66a7d74d6e68b52afff889` |
| `SimulateTxAccessor.hex` | `0x3d4BA2E0884aa488718476ca2FB8Efc291A46199` | `0x91f82615581fc73b190b83d72e883608b25e392f72322035df1b13d51766cf8d` |
| `SafeSingletonFactory.hex` | `0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7` | `0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989` |
| `SafeMigration.hex` | `0x526643F69b81B008F46d95CD5ced5eC0edFFDaC6` | `0xc00d7921460cd5a05393e7772e634bd7d212f356356aa3a77f0120a9b8e25e99` |
| `SafeToL2Migration.hex` | `0xfF83F6335d8930cBad1c0D439A841f01888D9f69` | `0xa83e7be2fa20c96dc9575e3937239d552f3831ea437d7c96397eec8736f0cba0` |

This covers the full official
[safe-deployments](https://github.com/safe-global/safe-deployments/tree/main/src/assets/v1.4.1)
v1.4.1 registry — all 12 contracts, addresses matching the registry's
`canonical` deployment type — plus the Safe Singleton Factory that deployed
the suite on live chains. The two migration files were captured 2026-08-28
and verified byte-identical against Sepolia and the registry's `codeHash`
values.

The generator asserts these hashes before etching, so a corrupted or tampered
file fails loudly.

## Notes

- `SafeToL2Setup` (`SELF`), `MultiSend` (`multisendSingleton`),
  `SimulateTxAccessor` (`accessorSingleton`), `SafeMigration`
  (`MIGRATION_SINGLETON`) and `SafeToL2Migration` (`MIGRATION_SINGLETON`) bake
  `address(this)` into their runtime bytes as an immutable — each guards on it
  to force delegatecall-only use. Capturing deployed runtime code and placing
  it at the **same** address preserves that correctly; placing these bytes at
  any other address would be invalid. `SafeMigration` additionally bakes the
  `Safe`, `SafeL2` and `CompatibilityFallbackHandler` addresses as immutables;
  all three are predeploys at those canonical addresses, so its migration
  targets resolve on TN. `SignMessageLib` has no such immutable in v1.4.1
  despite the same delegatecall-only usage.
- `Safe.hex`/`SafeL2.hex` require the singleton's own `threshold` storage
  slot (slot 4) set to 1, mirroring their constructors — the generator does
  this; it prevents anyone from calling `setup` on the singleton itself.
- The genesis governance Safe is built on the **SafeL2** singleton: every
  counterfactual Safe on TN lands on SafeL2 via `SafeToL2Setup`
  (`block.chainid != 1`), and SafeL2's transaction events are what Safe
  Transaction Service indexes. The L1 `Safe` singleton remains a predeploy
  and the factory-default implementation.
- `SafeSingletonFactory` is Safe's deterministic CREATE2 factory (the
  deployer of all the above on live chains). Including it as a predeploy
  lets future canonical Safe contracts be added permissionlessly with
  byte-exact address parity, no fork needed.
- Nonces are set as if the deployments happened. Every contract in the suite
  gets nonce 1, the EIP-161 initial nonce for a contract account, which is what
  each carries on Ethereum/Sepolia/Base. It is load-bearing for `CreateCall`,
  whose `performCreate` does a CREATE from its own account, and for any Safe
  that delegatecalls it; the CREATE2 deployers ignore the nonce but carry the
  same value. Separately, the singleton factory's deployer EOA
  (`0xE1CB04A0…3cBC37`) gets nonce 1 to mark its nonce-0 presigned deployment
  tx as spent — the same treatment Multicall3's and Arachnid's deployers get,
  though note this one is not a Nick's-method keyless address: Safe holds the
  key and signs one deployment tx per chain.

## Safe passkey module (safe-modules `modules/passkey` v0.2.1)

Five more byte-exact runtimes, captured 2026-10-14 with `cast code <address>`
from Ethereum mainnet and verified byte-identical on Polygon and Base. They
give a Safe passkey (WebAuthn / P-256) owners at the same addresses as every
other EVM chain, so a counterfactual passkey signer address computed
off-chain is valid on Telcoin Network too.

| File | Canonical address | keccak256(runtime) | Deployer factory | Captured |
|---|---|---|---|---|
| `SafeWebAuthnSignerFactory.hex` | `0x1d31F259eE307358a26dFb23EB365939E8641195` | `0x655b1f71eedf5aa223c8a7f5fc70f140a6475259a030829bc731642e181e4853` | Safe Singleton Factory (`0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7`) | 2026-10-14 |
| `SafeWebAuthnSignerSingleton.hex` | `0x4E27b51350e6c2083EE19011120F50DAfEc5CA50` | `0x2f10c1deb6dc4c1756da418188d9a5c46ebb9c63080bc7906512f5e8539b2aff` | `SafeWebAuthnSignerFactory` (its constructor `CREATE`s it) | 2026-10-14 |
| `DaimoP256Verifier.hex` | `0xc2b78104907F722DABAc4C69f826a522B2754De4` | `0x3cd725b6ba67b40b7979190c41a015e82cf21e098eb61832ba623f8538bab7fc` | Arachnid deterministic deployer (`0x4e59b44847b379578588920cA78FbF26c0B4956C`) | 2026-10-14 |
| `FCLP256Verifier.hex` | `0xA86e0054C51E4894D88762a017ECc5E5235f5DBA` | `0xa493dea44e0b8e3b88da6da9fe4447abeefef94ab58ae0b2e001504a38203e80` | Safe Singleton Factory (`0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7`) | 2026-10-14 |
| `SafeWebAuthnSharedSigner.hex` | `0x94a4F6affBd8975951142c3999aEAB7ecee555c2` | `0xeaa32d0280053e2feea48a7c3fa15a535cd07c23ff60c9469cfa1999533e9332` | Safe Singleton Factory (`0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7`) | 2026-10-14 |

Runtime sizes are 2143, 2246, 3537, 5770 and 2954 bytes, in table order. The
deployer column comes from the explorer's creator field and was re-derived
independently: for each CREATE2 child, `keccak256(0xff ‖ deployer ‖ salt ‖
keccak256(initcode))` over the creation transaction's calldata reproduces the
canonical address (salt is `bytes32(0)` for all four), and the singleton equals
`CREATE(factory, nonce 1)`. The creation transactions on Ethereum mainnet:

| File | Creation transaction | Block / date |
|---|---|---|
| `SafeWebAuthnSignerFactory.hex`, `SafeWebAuthnSignerSingleton.hex` | `0x68afa7f01ed9d70c4cb26eeb852e3df3ba743a7865b1e02ff529cea786c5a274` | 20564015 / 2024-08-19 |
| `DaimoP256Verifier.hex` | `0xbc5be668ab62069f5ac227c23a8b8fd85dd95c3754f7faddb8330048192adf88` | 18308790 / 2023-10-08 |
| `FCLP256Verifier.hex` | `0xb0072084687a2b98288e92985c6bb8ef441c2e23ef0b87bd6a92d0b21ef785bd` | 20564013 / 2024-08-19 |
| `SafeWebAuthnSharedSigner.hex` | `0x6cfb47cf888a9a3a0f356df1b42ad8e1674a9d125e9b33c750c8818fa82fbb6f` | 20564017 / 2024-08-19 |

The generator asserts these hashes before etching, like the Safe suite above.
`test/genesis/GenesisPasskeyParity.t.sol` replays that genesis and proves the
signer-address parity: `getSigner` returns the address the Ethereum mainnet
factory returns for the same key and `verifiers`.

### Passkey module notes

- **The factory is etched with nonce 2; every other contract with nonce 1.**
  `SafeWebAuthnSignerFactory`'s constructor `CREATE`s the singleton, which on
  chain leaves the factory at nonce 2 and puts the singleton at
  `CREATE(factory, nonce 1)`. A contract account's EIP-161 initial nonce is 1; etch
  the factory at that nonce and any later `CREATE` from it would derive the
  singleton's address again and collide with it. Nonce 2 is the post-constructor state, so
  the next `CREATE` address is fresh. The factory's runtime contains no
  `CREATE`, only one `CREATE2` (proxy deployment in `createSigner`), and
  `CREATE2` ignores the nonce, so the value is for fidelity and collision
  safety, not behavior. Every `CREATE2` child bumps the creator's nonce on
  Ethereum (the factory is at nonce 429 today); Telcoin Network starts from 2
  and diverges from there, which is harmless for the same reason. The
  singleton, `DaimoP256Verifier`, `FCLP256Verifier` and
  `SafeWebAuthnSharedSigner` are at nonce 1 on mainnet and in genesis.
- **No new EOA nonce burn.** All five are `CREATE2` children, or (the
  singleton) a `CREATE` child, of contracts already in genesis: the factory
  and singleton, `FCLP256Verifier` and `SafeWebAuthnSharedSigner` come from the
  Safe Singleton Factory, `DaimoP256Verifier` from the Arachnid deployer. Both
  deployers are already predeploys, so nothing about the original sender EOAs
  needs marking as spent, unlike the Safe Singleton Factory's own deployer
  above.
- **Embedded addresses.** `SafeWebAuthnSharedSigner` bakes `address(this)`
  into its runtime exactly once, as an immutable compared against `ADDRESS` to
  force delegatecall-only use, so it is valid only at
  `0x94a4F6af…55c2`, the same constraint as `MultiSend` above. The factory
  embeds the singleton's address four times (its `SINGLETON` immutable), so the
  singleton must sit at exactly `0x4E27b513…CA50`. The singleton and both
  verifiers contain no address of any of the five.
- **The two verifiers are pure.** `DaimoP256Verifier` and `FCLP256Verifier`
  have no `SLOAD`/`SSTORE` in their code and no `CALL`, `DELEGATECALL` or
  `CREATE`; their only external interaction is `STATICCALL` to the MODEXP
  precompile (`0x05`), which the chain must keep enabled.
- **Which contracts the wallet uses.** The wallet's passkey owners are
  `SafeWebAuthnSignerFactory` proxies of `SafeWebAuthnSignerSingleton`, with
  `verifiers` set precompile-first: `uint176((0x0100 << 160) |
  DaimoP256Verifier)`. The signer calls the P-256 precompile at `0x…0100` when
  the chain has one and falls back to `DaimoP256Verifier` otherwise (Telcoin
  Network has no P-256 precompile today). `FCLP256Verifier` and
  `SafeWebAuthnSharedSigner` are vendored for Safe-ecosystem address parity
  only; the wallet never calls either.

## Safe v1.3.0 suite (`safe-v1.3.0/`)

The nine contracts of the safe-deployments v1.3.0 `canonical` registry, plus the
"eip155" copies of both singletons, MultiSend and MultiSendCallOnly. Captured
2026-11-04 with `eth_getCode` from Ethereum mainnet and verified byte-identical on
Polygon and Base.

| File | Address | keccak256(runtime) | Bytes |
|---|---|---|---|
| `GnosisSafe.hex` | `0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552`, eip155 `0x69f4D1788e39c87893C980c06EdF4b7f686e2938` | `0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e` | 22958 |
| `GnosisSafeL2.hex` | `0x3E5c63644E683549055b9Be8653de26E0B4CD36E`, eip155 `0xfb1bffC9d739B8D520DaF37dF666da4C687191EA` | `0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f` | 23800 |
| `GnosisSafeProxyFactory.hex` | `0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2` | `0x337d7f54be11b6ed55fef7b667ea5488db53db8320a05d1146aa4bd169a39a9b` | 3774 |
| `CompatibilityFallbackHandler.hex` | `0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4` | `0x03e69f7ce809e81687c69b19a7d7cca45b6d551ffdec73d9bb87178476de1abf` | 5492 |
| `MultiSend.hex` | `0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761` | `0x0208282bd262360d0320862c5ac70f375f5ed3b9d89a83a615b4d398415bdc83` | 629 |
| `MultiSend.eip155.hex` | `0x998739BFdAAdde7C933B942a68053933098f9EDa` | `0x81db0e4afdf5178583537b58c5ad403bd47a4ac7f9bde2442ef3e341d433126a` | 629 |
| `MultiSendCallOnly.hex` | `0x40A2aCCbd92BCA938b02010E17A5b8929b49130D`, eip155 `0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B` | `0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad` | 410 |
| `SignMessageLib.hex` | `0xA65387F16B013cf2Af4605Ad8aA5ec25a2cbA3a2` | `0x3ac65dea3cc9dd0d7b7b800f834e3d73415b4e944bb94555c3e4a08fb137e918` | 966 |
| `CreateCall.hex` | `0x7cbB62EaA69F79e6873cD1ecB2392971036cFAa4` | `0x8155d988823a4f6f1bcbc76a64af8e510c4ce68819290d43cf24956bd24dee82` | 1119 |
| `SimulateTxAccessor.hex` | `0x59AD6735bCd8152B84860Cb256dD9e96b85F69Da` | `0xb3fb9763869f2c09a2ac5a425d2dd6060bf7ef46b3899049d71a711e71e00f04` | 850 |

The canonical addresses were created through the Arachnid proxy with salt 0 in
May 2021 (SignMessageLib in October 2021); the eip155 copies through the Safe
Singleton Factory with salt 0, from the same creation code, in 2022 and 2023.
`deployments/canonical-initcode/README.md` lists the canonical creation
transactions and vendors their creation code; the eip155 ones are
`0x25b182f34baa23c122b081b249fb9da27f032e663e0a0ab3833be1c1c9266c3e` (GnosisSafe),
`0x4e763a9840ab3a6077ec93bd091164f058e83d4c4b5fe8dd36fbb65061e62240` (GnosisSafeL2),
`0x5593187ca889fe8a59a61567910d32fd2c2d37c771398401715f4533fe3144f8` (MultiSend) and
`0xb7e50e99238f867f51b3cb5a4ec4e6916bf5bbcb426995da5d45c6b2d41c7cce` (MultiSendCallOnly).

### Safe v1.3.0 notes

- **Why genesis.** The v1.3.0 proxy factories, unlike v1.4.1's, never check that
  the singleton has code, and anyone can deploy them: the canonical one through the
  Arachnid proxy, the eip155 one (`0xC22834581EbC8527d974F8a1c97E1bEA4EF910BC`)
  through the Safe Singleton Factory. A proxy created against an empty singleton
  runs its initializer against no code and sits at the victim's cross-chain address
  with `threshold == 0`, for whoever calls `setup` first once the singleton exists.
  With all four singletons in genesis that window never opens.
  `test/genesis/GenesisSafeV130Parity.t.sol` shows both sides.
- **One file per singleton, two addresses.** The singletons have no immutables, so
  their bytes are identical at both addresses, as are MultiSendCallOnly's.
  `MultiSend` (`multisendSingleton`) and `SimulateTxAccessor` (`accessorSingleton`)
  bake `address(this)` to force delegatecall-only use, so MultiSend's eip155 copy
  has its own file, differing only in that address. SimulateTxAccessor's eip155
  copy is not in genesis.
- **Storage.** Each of the four singletons gets `threshold = 1` (slot 4), the only
  write its constructor makes; nothing else in the suite stores anything. The replay
  test in `GenesisSafeV130Parity.t.sol` runs the original creation code and records
  exactly those writes.
- **Not in genesis.** The eip155 proxy factory, fallback handler
  (`0x017062a1dE2FE6b99BE3d9d37841FeD19F573804`), SignMessageLib, CreateCall and
  SimulateTxAccessor. With the singletons in place they can be deployed
  permissionlessly through the Safe Singleton Factory without risk.
- **Nonces.** Every account is at nonce 1. The canonical proxy factory is at a much
  higher nonce on Ethereum because `createProxy` uses `CREATE`; those proxies'
  addresses depend on each chain's history anyway, so Telcoin Network starts the
  factory fresh.

## CreateX (`createx/`)

| File | Address | keccak256(runtime) | Bytes |
|---|---|---|---|
| `CreateX.hex` | `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed` | `0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f` | 11838 |

Captured 2026-11-04 from Ethereum mainnet, identical on Polygon, Base and Arbitrum,
and identical to the copy the Adiri testnet carries. Created on Ethereum by
`0xceec66d7b71039b0de4ac870e23c10130d64db46911166a1b7a945c4576113e1` (block 18832552,
2023-12-21), the presigned transaction from `0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5`
at nonce 0.

- **Why genesis.** After genesis, only that presigned pre-EIP-155 transaction can
  reach the address. It needs the base fee at or under its 100 gwei gas price, a
  top-up to an EOA we do not control, and that EOA's nonce 0 still unspent.
- **Deployer EOA at nonce 1.** Genesis writes `0xeD456e05…F352b5` at nonce 1 to mark
  the presigned transaction as spent, the treatment the Safe Singleton Factory's
  deployer gets above. Like that one it is not a keyless address: CreateX's author
  holds the key (its Ethereum nonce is 21 today).
- **Immutables and storage.** The only immutable is `_SELF = address(this)`, valid
  at the canonical address. The constructor writes no storage. CreateX's
  `deployCreate` uses `CREATE` from its own nonce, which on Telcoin Network starts
  at 1.

## ERC-4337 EntryPoints (`erc4337/`)

| File | Address | keccak256(runtime) | Bytes |
|---|---|---|---|
| `EntryPointV06.hex` | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` | `0xc93c806e738300b5357ecdc2e971d6438d34d8e4e17b99b758b1f9cac91c8e70` | 23689 |
| `SenderCreatorV06.hex` | `0x7fc98430eAEdbb6070B35B39D798725049088348` | `0xae818091eaaf1b6175ee41472359a689f3823d0908a41e2e5c4ad508f2fc04a3` | 528 |
| `EntryPointV07.hex` | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | `0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58` | 16035 |
| `SenderCreatorV07.hex` | `0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C` | `0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689` | 451 |
| `EntryPointV08.hex` | `0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108` | `0x44e632a24c6f2600cbd5b5b8b4c2d372359112c8b5774297f5fd0a9e64f11f86` | 21738 |
| `SenderCreatorV08.hex` | `0x449ED7C3e6Fee6a97311d4b55475DF59C44AdD33` | `0xc69a1b3a000d570bc86eb096ee63a9014a17951ad616d720882ec61432b00fcf` | 1217 |

Captured 2026-11-04 from Ethereum mainnet. All six except EntryPoint v0.8 are
byte-identical on Polygon, Base and Arbitrum. Each EntryPoint came through the
Arachnid proxy (creation transactions and creation code in
`deployments/canonical-initcode/`), and its constructor created its SenderCreator in
the same transaction.

- **Nonce 2 for the EntryPoints.** Each constructor `CREATE`s its SenderCreator at
  `CREATE(entryPoint, nonce 1)`, leaving the EntryPoint at nonce 2, which is what
  Ethereum shows for all three. Genesis mirrors that so a later `CREATE` from an
  EntryPoint could never derive its SenderCreator's address again. The runtimes
  never `CREATE`, so this is fidelity rather than behavior. The SenderCreators are
  at nonce 1.
- **Baked addresses.** Each EntryPoint bakes its SenderCreator's address as an
  immutable and calls it to deploy accounts from `initCode`. The v0.8 SenderCreator
  bakes the EntryPoint's address and refuses any other caller.
- **Storage.** v0.6 and v0.7 get slot 2 = 1, OpenZeppelin `ReentrancyGuard._status`
  at `NOT_ENTERED` as their constructors leave it. v0.8 uses the transient-storage
  guard and stores nothing.
- **EntryPoint v0.8 and EIP-712.** v0.8 hashes user operations under EIP-712 and
  caches chain id 1 and the chain-1 domain separator (`0x1cb06c86…dc16a`) as
  immutables. Those two 32-byte words are the only difference between its Ethereum
  bytes and its bytes on Polygon, Base and Arbitrum: putting each chain's id and
  separator into the Ethereum bytes reproduces that chain's copy exactly. Genesis
  uses the Ethereum bytes, so `cast code` on Telcoin Network matches Ethereum, and
  the contract rebuilds its separator from `block.chainid` whenever it differs from
  the cached one, at a few hundred gas per hash. Telcoin Network has EIP-7702 live
  from genesis, which is what v0.8 adds over v0.7.

## Permit2 (`permit2/`)

| File | Address | keccak256(runtime) | Bytes |
|---|---|---|---|
| `Permit2.hex` | `0x000000000022D473030F116dDEE9F6B43aC78BA3` | `0xc67d1657868aa5146eaf24fb879fb1fdec3d2d493b3683a61c9c2f4fb2851131` | 9152 |

Captured 2026-11-04 from Ethereum mainnet. Created through the Arachnid proxy with
the canonical salt by `0xf2f1fe96c16ee674bb7fcee166be52465a418927d124f5f1d231b36eae65d377`
(block 15986406, 2022-11-17); the creation code is
`external/uniswap/precompiles/v4/Permit2Bytecode.sol`. Permit2 caches chain id 1 and
Ethereum's domain separator (`0x866a5aba…e3f28`) like EntryPoint v0.8, with the same
two-word difference on every other chain, and `DOMAIN_SEPARATOR()` rebuilds from
`block.chainid` when it differs. The constructor writes no storage.

## Safe 4337 module (`safe-4337-v0.3.0/`)

| File | Address | keccak256(runtime) | Bytes |
|---|---|---|---|
| `Safe4337Module.hex` | `0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226` | `0x2aea997c4e3cf0e2f333025372e219abcfde81c21fc2f8fb066414a5685dd3e0` | 8373 |
| `SafeModuleSetup.hex` | `0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47` | `0xaf2d170bb766d2773c3fa88717f5b3599827478074d3767d1dee55e5c2f3fbcb` | 547 |

safe-modules `modules/4337` v0.3.0, captured 2026-11-04 from Ethereum mainnet and
byte-identical on Polygon and Base. Both came through the Arachnid proxy with salt 0:
`0x2807658b0adb7f31df418beca951a9c358b8b3337dee2fbefb313423ad95ad32` (block 19704903,
2024-04-21) and `0x1e0c8986cdf927586becb27df4b579b98875ec4a221ad901a537e9af0d49acec`
(block 19565060, 2024-04-02). Together with the v1.4.1 suite and EntryPoint v0.7 they
let a Safe act as an ERC-4337 account: SafeModuleSetup enables the module during
`setup`, and the module serves as the Safe's fallback handler.

- `Safe4337Module` bakes `SUPPORTED_ENTRYPOINT`, EntryPoint v0.7, also in genesis. It
  computes its EIP-712 domain separator from `block.chainid` on every call, so its
  Ethereum bytes need no caveat. SafeModuleSetup bakes nothing. Neither stores
  anything.

## Re-verifying

```bash
# any file: compare against Ethereum mainnet (or Sepolia/Base — identical)
ADDR=0x41675C099F32341bf84BFc5382aF534df5C7461a
[ "$(cast code $ADDR --rpc-url $ETHEREUM_RPC_URL)" = "$(cat Safe.hex)" ] \
  && echo "byte-exact"
```

Compare with `$(...)` rather than piping into `diff`: `cast code` terminates its
output with a newline and these files do not, so `cast code … | diff - Safe.hex`
reports a difference even when the bytes are identical.

The recipe is the same for the passkey-module files; for example, the factory:

```bash
ADDR=0x1d31F259eE307358a26dFb23EB365939E8641195
[ "$(cast code $ADDR --rpc-url $ETHEREUM_RPC_URL)" = "$(cat SafeWebAuthnSignerFactory.hex)" ] \
  && echo "byte-exact"
```

Those five were also captured on Polygon and Base and are identical there.

Files in subdirectories take their path; for example, EntryPoint v0.7:

```bash
ADDR=0x0000000071727De22E5E9d8BAf0edAc6f37da032
[ "$(cast code $ADDR --rpc-url $ETHEREUM_RPC_URL)" = "$(cat erc4337/EntryPointV07.hex)" ] \
  && echo "byte-exact"
```

On a second chain the same check holds for every file except
`erc4337/EntryPointV08.hex` and `permit2/Permit2.hex`, which differ there only in the
cached chain id and domain separator described above. Storage can be compared too:
`cast storage $ADDR 4` on a Safe v1.3.0 singleton and `cast storage $ADDR 2` on
EntryPoint v0.6 or v0.7 return the value genesis writes.
