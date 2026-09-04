# 🔐 Blockchain WASM

Motor criptográfico de alto rendimiento para wallets Bitcoin, Ethereum y Tron, compilado en WebAssembly (WASM) con AssemblyScript y empaquetado con un wrapper TypeScript Zero-Allocation.

Reúne en un único binario optimizado toda la pila de criptografía de claves: **secp256k1** (field/point/GLV), **BIP-32 / BIP-39 / BIP-44** (HD wallets multi-moneda), multifirma **MuSig2 (BIP-327)**, firmas **Schnorr (BIP-340)** y **ECDSA** (con prefijos de mensaje Bitcoin/Ethereum), **ECDH**, direcciones **P2PKH / P2PKH-Uncompressed / P2SH-P2WPKH / P2WPKH / P2TR / ETH / TRON**, **WIF**, **PBKDF2-HMAC-SHA512** y hashing (**SHA-256 / Keccak-256 / RIPEMD-160 / BLAKE2b**) — con rendimiento extremo (~235K dir P2PKH-uncomp/s, ~207K dir ETH/s, ~190K dir Tron/s, ~56K getPublicKey/s, ~78K MuSig2 partialSign/s, ~2.9M SigAgg/s, ~2.1M compress/s) y **0 % de presión sobre el Garbage Collector (GC)**.

## 🚀 Características Principales

- ⚡ **Máximo Rendimiento**: núcleo secp256k1 (multiplicación de puntos con GLV + precomputación del generador) desplegado en WebAssembly; ~56K `getPublicKey`/s, ~235K dir/s (P2PKH uncompressed), ~207K ETH/s, ~190K Tron/s, ~78K MuSig2 partialSign/s, ~2.9M SigAgg/s, ~2.1M compress/s, con memoria completamente plana bajo carga.
- 🧹 **Zero-Alloc (Cero Alocaciones GC en WASM)**: alocador `arena` estático (`save/restore`) y regiones de I/O planas (`PARAM_IN` / `PARAM_OUT` de 4 KB) — `WASM memory.grow = 0 B` verificado bajo carga en todos los módulos; la única asignación es el `Uint8Array` de salida que se entrega al usuario.
- 🤝 **MuSig2 (BIP-327 Multi-Signature)**: esquema completo de multifirma Schnorr de 2 rondas compatible con Bitcoin Taproot. Agregación segura de claves con coeficientes $a_i$ resistentes al ataque *rogue-key*, nonces de 2 rondas (secnonce de 97 B, pubnonce de 66 B), firmas parciales $s_i$, verificación individual y agregación en firma BIP-340 de 64 bytes indistinguible de una firma ordinaria.
- 🌐 **Multiplataforma / Isomórfico**: funciona sin modificaciones en Node.js, Bun, Deno y Navegadores Web (Vite, Webpack, o directo vía CDN con [esm.sh](https://esm.sh/blockchain-wasm@latest)). CSPRNG con fail-fast si el entorno no expone Web Crypto.
- 🏦 **HD Wallets completas**:
  - **BIP-39**: generación de mnemónicos (entropía segura del host), mnemónico ↔ entropía, mnemónico → seed con passphrase opcional (PBKDF2-HMAC-SHA512), validación de checksum.
  - **BIP-32**: `HDKey` encadenable (`fromSeed → derivePath → neuter → toXpub`), derivación hardened/normal, deserialización e inspección de `xpub`/`xprv`, fingerprints y watch-only wallets.
  - **BIP-44**: derivación `m/purpose'/coin'/account'/change/index` desde seed o mnemónico con contraseña para Bitcoin (Legacy/SegWit/Taproot), Ethereum y Tron.
- ✍️ **Firmas**:
  - **MuSig2 (BIP-327)**: `keyAgg`, `nonceGen`, `nonceAgg`, `sessionInit`, `partialSign`, `partialVerify`, `partialSigAgg`, `signAll`.
  - **Schnorr (BIP-340)**: sign/verify, x-only pubkey, `aux_rand` seguro del host.
  - **ECDSA (secp256k1)**: sign/verify sobre hash o mensaje, con formatos Universal (SHA-256), Bitcoin (double-SHA256 con prefijo) y Ethereum (Keccak-256 con prefijo `personal_sign`); recuperación (`v`).
  - **Firma de mensajes de texto**: `signTextMessage` / `verifyTextMessage` para ECDSA y Schnorr.
- 📬 **Direcciones Multi-Cadena**: P2PKH (`1…`), P2PKH Uncompressed (`1…`), P2SH-P2WPKH (`3…`), P2WPKH (`bc1q…`), P2TR/Taproot (`bc1p…`), Ethereum (`0x…`, EIP-55) y Tron (`T…`, Base58Check con prefijo `0x41`).
- 🔑 **Claves & Utilidades**: WIF encode/decode (mainnet), compress/uncompress de pubkeys, validación de punto en curva, ECDH (secreto compartido).
- 🛡️ **Correctitud validada contra vectores oficiales**: BIP-327 (MuSig2), BIP-32 Test Vectors, BIP-39, BIP-340 (Schnorr), BIP-350 (Bech32m), SHA-256/Keccak-256/RIPEMD-160, PBKDF2-HMAC-SHA512, WIF y direcciones.
- 📦 **Binario Compacto**: un único `.wasm` optimizado (runtime stub).

## 📦 Instalación

```bash
npm install blockchain-wasm
```

O con Bun / Yarn / pnpm:

```bash
bun add blockchain-wasm
```

### 🌐 Uso en el navegador (CDN, sin bundler)

```html
<script type="module">
  import { BlockchainWasm, Bip39, Address, Musig2 } from "https://esm.sh/blockchain-wasm@latest"

  await BlockchainWasm.load() // carga el .wasm automáticamente

  const mnemonic = Bip39.generate(128)
  const seed = Bip39.mnemonicToSeed(mnemonic)
  // ...
</script>
```

## 💻 Guía de Uso

### 1. Inicializar la biblioteca

```typescript
import { BlockchainWasm } from "blockchain-wasm"

// Carga automática desde la URL por defecto (navegador / bundler / CDN)
await BlockchainWasm.load()

// O desde un buffer binario explícito (Node.js / Bun):
// import { readFileSync } from "node:fs"
// await BlockchainWasm.fromBuffer(readFileSync("node_modules/blockchain-wasm/dist/blockchain.wasm"))
```

### 2. MuSig2 (BIP-327) — Multifirma Schnorr de 2 Rondas

```typescript
import { Musig2, Schnorr, Secp256k1, getRandomBytes, bytesToHex } from "blockchain-wasm"

// 1. Claves de los participantes (soporta 33 B compressed estándar BIP-327 o 32 B x-only)
const priv1 = getRandomBytes(32)
const priv2 = getRandomBytes(32)
const pub1 = Secp256k1.getPublicKey(priv1, true) // 33 B compressed (o Schnorr.getPublicKey(priv1) para 32 B x-only)
const pub2 = Secp256k1.getPublicKey(priv2, true)

// 2. Agregación de Claves (KeyAgg con coeficientes a_i anti-rogue)
const { aggregatedPubkey: Q, gacc } = Musig2.keyAgg([pub1, pub2])
const coeffs = Musig2.keyAggCoeffs([pub1, pub2])

// 3. Ronda 1: Generación y Agregación de Nonces
const msg = new TextEncoder().encode("Transacción autorizada")
const secrand1 = getRandomBytes(32)
const secrand2 = getRandomBytes(32)

const nonce1 = Musig2.nonceGen(secrand1, pub1, priv1, msg)
const nonce2 = Musig2.nonceGen(secrand2, pub2, priv2, msg)
const aggNonce = Musig2.nonceAgg([nonce1.pubNonce, nonce2.pubNonce])

// 4. Inicialización de Sesión
const session = Musig2.sessionInit(aggNonce, Q, msg)

// 5. Ronda 2: Firmas Parciales y Verificación
const psig1 = Musig2.partialSign(session, gacc, nonce1.secNonce, priv1, coeffs[0])
const psig2 = Musig2.partialSign(session, gacc, nonce2.secNonce, priv2, coeffs[1])

// 6. Agregación de Firmas (SigAgg)
const s = Musig2.partialSigAgg([psig1, psig2])
const rx = session.slice(64, 96)
const finalSig = new Uint8Array(64)
finalSig.set(rx, 0)
finalSig.set(s, 32)

// 7. Cualquier validador Taproot estándar verifica la firma
console.log(Schnorr.verify(finalSig, msg, Q)) // → true
```

### 3. BIP-39 — Mnemónicos y Seed con Passphrase

```typescript
import { Bip39, bytesToHex } from "blockchain-wasm"

const mnemonic = Bip39.generate(256) // 24 palabras
console.log(Bip39.validate(mnemonic)) // → true

// Mnemónico a Seed con salt PBKDF2 opcional (password)
const seed = Bip39.mnemonicToSeed(mnemonic, "mi-password-secreto")
const entropy = Bip39.mnemonicToEntropy(mnemonic)
```

### 4. BIP-44 — Derivación Multi-Moneda (BTC, ETH, TRON)

```typescript
import { Bip44, Address, Secp256k1 } from "blockchain-wasm"

// Bitcoin Legacy: m/44'/0'/0'/0/0
const btcLeaf = Bip44.fromMnemonicDerive(mnemonic, "mi-password-secreto", 44, 0, 0, 0, 0)
const btcAddr = Address.p2pkh(btcLeaf.publicKey) // 1...

// Ethereum: m/44'/60'/0'/0/0
const ethLeaf = Bip44.fromMnemonicDerive(mnemonic, "mi-password-secreto", 44, 60, 0, 0, 0)
const ethAddr = Address.eth(ethLeaf.publicKey) // 0x...

// Tron: m/44'/195'/0'/0/0
const tronLeaf = Bip44.fromMnemonicDerive(mnemonic, "mi-password-secreto", 44, 195, 0, 0, 0)
const tronAddr = Address.tron(Secp256k1.getPublicKey(tronLeaf.privateKey, false)) // T...
```

### 5. BIP-32 — HD Keys y Watch-Only Wallets

```typescript
import { Bip32, Address } from "blockchain-wasm"

const master = Bip32.fromSeed(seed)
const account = master.derivePath("m/44'/0'/0'")
const xpub = account.neuter().toXpub() // xpub...

// Watch-Only: derivar direcciones públicas sin la clave privada
const watchAccount = Bip32.fromXpub(xpub)
const child0 = watchAccount.derive(0).derive(0) // m/44'/0'/0'/0/0
const receiveAddr = Address.p2pkh(child0.publicKey)
```

## ⚡ Resultados de Benchmark

Medido con `bun test/bench.ts` sobre procesador x86_64, claves distintas por iteración:

| Dominio / Módulo | Operación | Rendimiento (ops/s) |
| --- | --- | --- |
| **Secp256k1** | `getPublicKey` (compressed 33B) | **~56,500 ops/s** |
| **Secp256k1** | `getPublicKey` (uncompressed 65B) | **~57,500 ops/s** |
| **Secp256k1** | `compress` (65→33) | **~2,108,000 ops/s** |
| **Secp256k1** | `uncompress` (33→65) | **~22,800 ops/s** |
| **Address** | `p2pkhUncompressed` (Legacy 65B) | **~235,900 ops/s** |
| **Address** | `eth` (EIP-55) | **~207,100 ops/s** |
| **Address** | `tron` (Base58Check `T...`) | **~190,000 ops/s** |
| **Address** | `p2wpkh` (Native SegWit `bc1q...`) | **~22,300 ops/s** |
| **Address** | `p2tr` (Taproot `bc1p...`) | **~9,950 ops/s** |
| **End-to-End** | `priv → tron` | **~44,000 dir/s** |
| **End-to-End** | `priv → p2wpkh` | **~16,100 dir/s** |
| **End-to-End** | `priv → p2pkh` | **~15,400 dir/s** |
| **End-to-End** | `priv → eth` | **~15,300 dir/s** |
| **Schnorr** | `getPublicKey` (x-only 32B) | **~86,200 ops/s** |
| **Schnorr** | `sign` (BIP-340) | **~14,400 ops/s** |
| **Schnorr** | `verify` (BIP-340) | **~3,720 ops/s** |
| **MuSig2 (BIP-327)** | `partialSign` (psig 32B) | **~78,400 ops/s** |
| **MuSig2 (BIP-327)** | `partialVerify` ✅ | **~1,293 ops/s** |
| **MuSig2 (BIP-327)** | `partialSigAgg` (agregación de firmas) | **~2,925,000 ops/s** |
| **MuSig2 (BIP-327)** | `nonceGen` (97B sec / 66B pub) | **~10,100 ops/s** |
| **MuSig2 (BIP-327)** | `nonceAgg` (3 pubnonces → agg) | **~3,500 ops/s** |
| **MuSig2 (BIP-327)** | `sessionInit` | **~1,880 ops/s** |
| **MuSig2 (BIP-327)** | `keyAgg` (3 signers → Q) | **~1,316 ops/s** |
| **ECDSA** | `sign` (deterministic RFC 6979) | **~13,630 ops/s** |
| **ECDSA** | `verify` | **~3,610 ops/s** |
| **ECDSA** | `signMessage` (Bitcoin format) | **~14,560 ops/s** |
| **ECDSA** | `verifyTextMessage` (Ethereum) | **~4,321 ops/s** |
| **ECDH** | `sharedSecret` | **~3,286 ops/s** |
| **WIF** | `decode` | **~263,200 ops/s** |
| **WIF** | `encode` | **~192,200 ops/s** |
| **BIP-39** | `entropyToMnemonic` | **~851,400 ops/s** |
| **BIP-39** | `generate` (128 bits) | **~772,200 ops/s** |
| **BIP-39** | `validate` | **~454,400 ops/s** |
| **BIP-32** | `fromSeed` | **~407,900 ops/s** |
| **BIP-32** | `toXprv` | **~52,000 ops/s** |
| **BIP-32** | `derive` (1 nivel hardened) | **~16,600 ops/s** |
| **BIP-32** | `derivePath` (m/44'/0'/0') | **~4,886 ops/s** |
| **BIP-44** | `fromMnemonicDerive` (full pipeline) | **~421 ops/s** |

### 📊 Garantía de Memoria Zero-Alloc

| Parámetro | Valor |
| --- | --- |
| **WASM Memory Inicial** | 11 páginas (704 KB) |
| **WASM Memory Final** | 11 páginas (704 KB) |
| **WASM `memory.grow`** | **0 páginas (0 bytes)** — ✅ ZERO-GROW (Static Scratchpad) |
| **Bun JS Heap Δ** | **2.31 MB** (recolectable por GC) |

## 🛠️ Comandos de Desarrollo

```bash
# Compilar binario WASM (AssemblyScript) + bundle TypeScript (esbuild)
bun run release

# Ejecutar typecheck de TypeScript
bun typecheck

# Tests rápidos (suites directas)
bun test test/3.0.0/musig2.test.ts
bun test test/address.test.ts

# Benchmark de rendimiento
bun test/bench.ts
```

## 📜 Licencia

[Apache License 2.0](./LICENSE) © Edison Manrique
