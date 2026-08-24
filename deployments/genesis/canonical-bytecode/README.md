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
| `SafeMigration.hex` | `0x526643F69b81B008F46d95CD5ced5eC0edFFDaC6` | `0xc00d7921460cd5a05393e7772e634bd7d212f356356aa3a77f0120a9b8e25e99` |
| `SafeToL2Migration.hex` | `0xfF83F6335d8930cBad1c0D439A841f01888D9f69` | `0xa83e7be2fa20c96dc9575e3937239d552f3831ea437d7c96397eec8736f0cba0` |
| `SafeSingletonFactory.hex` | `0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7` | `0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989` |

This covers the complete official
[safe-deployments](https://github.com/safe-global/safe-deployments/tree/main/src/assets/v1.4.1)
v1.4.1 registry (all 12 assets), plus the Safe Singleton Factory that deployed
them on live chains. Addresses match the registry's `canonical` deployment type.

The generator asserts these hashes before etching, so a corrupted or tampered
file fails loudly.

## Notes

- `SafeToL2Setup`, `MultiSend`, `SignMessageLib`, `SimulateTxAccessor`, and
  the migration contracts carry `address(this)` immutables baked into their
  runtime bytes (`SafeMigration` additionally bakes the Safe/SafeL2/handler
  addresses — all predeployed here). Capturing deployed runtime code and
  placing it at the **same** address preserves them correctly; placing these
  bytes at any other address would be invalid.
- `Safe.hex`/`SafeL2.hex` require the singleton's own `threshold` storage
  slot (slot 4) set to 1, mirroring their constructors — the generator does
  this; it prevents anyone from calling `setup` on the singleton itself.
- `SafeSingletonFactory` is Safe's deterministic CREATE2 factory (the
  deployer of all the above on live chains). Including it as a predeploy
  lets future canonical Safe contracts be added permissionlessly with
  byte-exact address parity, no fork needed.

## Re-verifying

```bash
# any file: compare against Ethereum mainnet (or Sepolia/Base — identical)
cast code 0x41675C099F32341bf84BFc5382aF534df5C7461a --rpc-url $ETHEREUM_RPC_URL \
  | diff - Safe.hex && echo "byte-exact"
```
