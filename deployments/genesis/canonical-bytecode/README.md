# Canonical Safe v1.4.1 runtime bytecode

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
