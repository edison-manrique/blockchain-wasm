# 🔐 Blockchain WASM

Motor criptográfico de alto rendimiento para wallets Bitcoin, Ethereum y Tron, compilado en WebAssembly (WASM) con AssemblyScript y empaquetado con un wrapper TypeScript Zero-Allocation.

Reúne en un único binario optimizado toda la pila de criptografía de claves: **secp256k1** (field/point/GLV), **BIP-32 / BIP-39 / BIP-44** (HD wallets multi-moneda), firmas **Schnorr (BIP-340)** y **ECDSA** (con prefijos de mensaje Bitcoin/Ethereum), **ECDH**, direcciones **P2PKH / P2PKH-Uncompressed / P2SH-P2WPKH / P2WPKH / P2TR / ETH / TRON**, **WIF**, **PBKDF2-HMAC-SHA512** y hashing (**SHA-256 / Keccak-256 / RIPEMD-160**) — con rendimiento extremo (~235K dir P2PKH-uncomp/s, ~207K dir ETH/s, ~190K dir Tron/s, ~56K getPublicKey/s, ~2.1M compress/s) y **0 % de presión sobre el Garbage Collector (GC)**.

## 🚀 Características Principales

- ⚡ **Máximo Rendimiento**: núcleo secp256k1 (multiplicación de puntos con GLV + precomputación del generador) desplegado en WebAssembly; ~56K `getPublicKey`/s, ~235K dir/s (P2PKH uncompressed), ~207K ETH/s, ~190K Tron/s, ~2.1M compress/s, con memoria completamente plana bajo carga.
- 🧹 **Zero-Alloc (Cero Alocaciones GC en WASM)**: alocador `arena` estático (`save/restore`) y regiones de I/O planas (`PARAM_IN` / `PARAM_OUT` de 4 KB) — `WASM memory.grow = 0 B` verificado bajo carga en todos los módulos; la única asignación es el `Uint8Array` de salida que se entrega al usuario.
- 🌐 **Multiplataforma / Isomórfico**: funciona sin modificaciones en Node.js, Bun, Deno y Navegadores Web (Vite, Webpack, o directo vía CDN con [esm.sh](https://esm.sh/blockchain-wasm@latest)). CSPRNG con fail-fast si el entorno no expone Web Crypto.
- 🏦 **HD Wallets completas**:
  - **BIP-39**: generación de mnemónicos (entropía segura del host), mnemónico ↔ entropía, mnemónico → seed con passphrase opcional (PBKDF2-HMAC-SHA512), validación de checksum.
  - **BIP-32**: `HDKey` encadenable (`fromSeed → derivePath → neuter → toXpub`), derivación hardened/normal, deserialización e inspección de `xpub`/`xprv`, fingerprints y watch-only wallets.
  - **BIP-44**: derivación `m/purpose'/coin'/account'/change/index` desde seed o mnemónico con contraseña para Bitcoin (Legacy/SegWit/Taproot), Ethereum y Tron.
- ✍️ **Firmas**:
  - **Schnorr (BIP-340)**: sign/verify, x-only pubkey, `aux_rand` seguro del host.
  - **ECDSA (secp256k1)**: sign/verify sobre hash o mensaje, con formatos Universal (SHA-256), Bitcoin (double-SHA256 con prefijo) y Ethereum (Keccak-256 con prefijo `personal_sign`); recuperación (`v`).
  - **Firma de mensajes de texto**: `signTextMessage` / `verifyTextMessage` para ECDSA y Schnorr.
- 📬 **Direcciones Multi-Cadena**: P2PKH (`1…`), P2PKH Uncompressed (`1…`), P2SH-P2WPKH (`3…`), P2WPKH (`bc1q…`), P2TR/Taproot (`bc1p…`), Ethereum (`0x…`, EIP-55) y Tron (`T…`, Base58Check con prefijo `0x41`).
- 🔑 **Claves & Utilidades**: WIF encode/decode (mainnet), compress/uncompress de pubkeys, **validación de punto en curva opt-in** (`Secp256k1.isValid`), ECDH (secreto compartido).
- 🧼 **Seguridad opt-in**: `BlockchainWasm.wipeSecrets()` limpia el scratch WASM y `zeroize(...buffers)` las copias JS, sin coste para quien no los usa.
- 🔒 **Lock anti-corrupción**: operaciones atómicas con `WasmBusyError` en reentrada, `withScratch()`/`runExclusive()` para acceso de bajo nivel y carga *single-flight* segura en web/async.
- 🧱 **Error unificado**: todo fallo es `instanceof BlockchainWasmError` (`code`, `module`, `cause`, `toJSON()`).
- 🛡️ **Correctitud validada contra vectores oficiales**: BIP-32 Test Vectors, BIP-39, BIP-340 (Schnorr), BIP-350 (Bech32m), SHA-256/Keccak-256/RIPEMD-160, PBKDF2-HMAC-SHA512, WIF y direcciones.
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
  import { BlockchainWasm, Bip39, Address } from "https://esm.sh/blockchain-wasm@latest"

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
// await BlockchainWasm.fromBuffer(readFileSync("node_modules/blockchain-wasm/dist/blockchain-wasm.wasm"))
```

### 2. BIP-39 — Mnemónicos y Seed con Passphrase

```typescript
import { Bip39, bytesToHex } from "blockchain-wasm"

const mnemonic = Bip39.generate(256) // 24 palabras
console.log(Bip39.validate(mnemonic)) // → true

// Mnemónico a Seed con salt PBKDF2 opcional (password)
const seed = Bip39.mnemonicToSeed(mnemonic, "mi-password-secreto")
const entropy = Bip39.mnemonicToEntropy(mnemonic)
```

### 3. BIP-44 — Derivación Multi-Moneda (BTC, ETH, TRON)

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

### 4. BIP-32 — HD Keys y Watch-Only Wallets

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
| **Address** | `p2wpkh` (Native SegWit `bc1q...`) | **~469,000 ops/s** |
| **Address** | `p2tr` (Taproot `bc1p...`, requiere descomprimir) | **~8,700 ops/s** |
| **Secp256k1** | `isValid` (curva, **opt-in**) | **~37,000 ops/s** |
| **End-to-End** | `priv → tron` | **~44,000 dir/s** |
| **End-to-End** | `priv → p2wpkh` | **~16,100 dir/s** |
| **End-to-End** | `priv → p2pkh` | **~15,400 dir/s** |
| **End-to-End** | `priv → eth` | **~15,300 dir/s** |
| **Schnorr** | `getPublicKey` (x-only 32B) | **~86,200 ops/s** |
| **Schnorr** | `sign` (BIP-340) | **~14,400 ops/s** |
| **Schnorr** | `verify` (BIP-340) | **~3,720 ops/s** |
| **ECDSA** | `sign` (deterministic RFC 6979) | **~13,630 ops/s** |
| **ECDSA** | `verify` | **~3,610 ops/s** |
| **ECDSA** | `signMessage` (Bitcoin format) | **~14,560 ops/s** |
| **ECDSA** | `verifyTextMessage` (Ethereum) | **~4,321 ops/s** |
| **ECDH** | `sharedSecret` | **~10,400 ops/s** |
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

### 🧩 Overhead del wrapper

`bun run bench:wrapper` ejecuta el bundle publicado (`dist/index.js`) contra el binario
`dist/blockchain-wasm.wasm` y compara cada fachada con la llamada cruda al singleton
(A/B intercalado para cancelar la deriva térmica):

| Tramo | Overhead medido |
| --- | --- |
| Criptografía pesada (ECDSA/Schnorr/ECDH/BIP-44) | **~1–3 %** (ruido incluido) |
| Direcciones/WIF (hash + Base58/Bech32 en WASM) | **< 1 %** |
| Accesores triviales (`HDKey.depth`) | **~5 ns** por llamada |
| Codificación UTF-8 / decodificación de salidas | eliminada la construcción por llamada y la copia intermedia |

Las direcciones **no** validan pertenencia a la curva (el exp mod P de una clave
compressed cuesta ~27 µs y dominaba el coste de `p2pkh`). Solo se valida el formato y,
cuando el algoritmo necesita `Y` (`p2tr`, `eth`/`tron` con 33 B), se descomprime. Para
claves de fuentes no confiables hay un chequeo explícito y encadenable:

```ts
if (!Secp256k1.isValid(pub)) throw new Error("pubkey fuera de la curva")
const addr = Address.p2pkh(pub) // ~5 µs, sin sqrt oculto
```

El `sqrt` modular usa la cadena de adiciones de libsecp256k1 (253 cuadrados + 13
multiplicaciones, frente a ~500 operaciones antes) y las tablas wNAF de puntos
arbitrarios se normalizan en lote con **una** sola inversión modular. Por eso
`isValid` baja a ~27 µs, `p2tr` a ~115 µs y ECDH a ~96 µs en el benchmark.

`wipeSecrets()` y `zeroize()` siguen el mismo principio: se invocan cuando el proyecto
lo necesita, nunca en el hot path.

### 🔒 Concurrencia, lock y errores

El WASM tiene **un único scratch** (`PARAM_IN`/`PARAM_OUT` + work-worlds). Cada método
público toma un lock reentrante y lo libera en `finally`; si algo intenta usar el
scratch a la vez se lanza `WasmBusyError` en lugar de mezclar bytes. La carga es
**single-flight**: `load()` concurrentes comparten promesa e instancia (React
StrictMode/doble mount ya no crea dos módulos). Para trocear una operación con
`await` usa el mutex:

```ts
const out = await wasm.runExclusive(async (w) => {
  const a = w.getAllocator()
  a.writeInput(bytes, 0)
  const res = await fetch(/* … */) // otro runExclusive espera su turno
  return w.getExports().sha256_hash_raw(a.outPtr, a.inPtr, bytes.length)
})
```

Todos los errores heredan de **`BlockchainWasmError`** (`code`, `module`, `cause`,
`toJSON()`), así que basta un `catch`:

```ts
try {
  await BlockchainWasm.load()
  Address.p2pkh(pub)
} catch (err) {
  if (BlockchainWasmError.is(err)) console.error(err.code, err.module)
  else throw err
}
```

Especializaciones: `WasmError`, `NotInitializedError`, `MissingExportError`,
`InvalidArgumentError`, `WasmBusyError` y `EntropyError`.

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
bun run typecheck

# Precompilar en paralelo todos los artefactos de test (una vez)
#   --jobs=N  ·  --force  ·  --list  ·  --only=sha2  ·  --clear
bun run prebuild

# Suite completa (caché caliente: no compila nada)
bun test

# Primera ejecución desde cero (vacía el caché y recompila en paralelo)
bun run test:cold

# Suite en paralelo (varios procesos; benchmarks algo más ruidosos)
bun run test:parallel

# Un solo archivo
bun test test/address.test.ts

# Benchmark de rendimiento (binario release de dist/)
bun test/bench.ts

# Benchmark del WRAPPER compilado (dist/index.js + dist/blockchain-wasm.wasm)
#   mide fachada vs singleton para cuantificar el overhead del wrapper
bun run bench:wrapper
```

### ⚡ Caché de builds

Los tests comparten un caché L2 de binarios WASM en RAM disk (`R:\.wasm-cache-blockchain`
por defecto; fallback automático a `C:\Temp\wasm-ram` o `.wasm-cache/`). La clave se deriva del
argv de `asc` **y del grafo de imports de cada entrada**, así que editar un módulo solo
recompila las entradas que lo usan.

| Variable | Efecto |
| --- | --- |
| `WASM_RAMDISK` | Raíz alternativa para el caché |
| `WASM_CACHE_DIR` | Directorio de caché exacto |
| `WASM_CACHE_MAX_BYTES` | Límite de poda (por defecto 96 MB) |
| `WASM_NO_CACHE=1` | Desactiva el caché (mediciones en frío) |

Perfiles: `test` = `-O0` (correctitud), `test1`/`test+o1` = `-O1`, `bench` = `-O1`
(velocidad en tests), `release` = `-O3 --converge` (solo `dist/`), `fast`/`small` para
comparativas de tamaño.

## 📜 Licencia

[Apache License 2.0](./LICENSE) © Edison Manrique
