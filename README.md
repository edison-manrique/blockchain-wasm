# 🔐 Blockchain WASM

Motor criptográfico de alto rendimiento para wallets Bitcoin y Ethereum, compilado en WebAssembly (WASM) con AssemblyScript y empaquetado con un wrapper TypeScript Zero-Allocation.

Reúne en un único binario de ~212 KB toda la pila de criptografía de claves: **secp256k1** (field/point/GLV), **BIP-32 / BIP-39 / BIP-44** (HD wallets), firmas **Schnorr (BIP-340)** y **ECDSA** (con prefijos de mensaje Bitcoin/Ethereum), **ECDH**, direcciones **P2PKH / P2SH-P2WPKH / P2WPKH / P2TR / ETH**, **WIF**, **PBKDF2-HMAC-SHA512** y hashing (**SHA-256 / Keccak-256 / RIPEMD-160**) — con rendimiento extremo (~23K direcciones P2WPKH/s desde pubkey, ~9.8K direcciones/s end-to-end desde la clave privada, ~13.3K firmas Schnorr/s, ~2M compress/s) y **0 % de presión sobre el Garbage Collector (GC)**.

## 🚀 Características Principales

- ⚡ **Máximo Rendimiento**: núcleo secp256k1 (multiplicación de puntos con GLV + precomputación del generador) desplegado en WebAssembly; ~23K P2WPKH/s (desde pubkey), ~9.8K direcciones/s (end-to-end priv→address), ~13.3K Schnorr sign/s, ~2M compress/s, con memoria completamente plana bajo carga.
- 🧹 **Zero-Alloc (Cero Alocaciones GC)**: alocador `arena` estático (`memory.data` + `save/restore`) y regiones de I/O planas (`PARAM_IN` / `PARAM_OUT` de 4 KB) — `WASM Δ 0 B` verificado bajo carga en todos los módulos; la única asignación es el `Uint8Array` de salida que se entrega al usuario.
- 🌐 **Multiplataforma / Isomórfico**: funciona sin modificaciones en Node.js, Bun, Deno y Navegadores Web (Vite, Webpack, o directo vía CDN con [esm.sh](https://esm.sh/blockchain-wasm@latest)). CSPRNG con fail-fast si el entorno no expone Web Crypto.
- 🏦 **HD Wallets completas**:
  - **BIP-39**: generación de mnemónicos (entropía segura del host), mnemónico ↔ entropía, mnemónico → seed (PBKDF2-HMAC-SHA512), validación de checksum.
  - **BIP-32**: `HDKey` encadenable (`fromSeed → derivePath → neuter → toXpub`), derivación hardened/normal, xpub/xprv, fingerprints.
  - **BIP-44**: derivación `m/purpose'/coin'/account'/change/index` desde seed o mnemónico, xpub/xprv de cuenta.
- ✍️ **Firmas**:
  - **Schnorr (BIP-340)**: sign/verify, x-only pubkey, agregación de claves, `aux_rand` seguro del host.
  - **ECDSA (secp256k1)**: sign/verify sobre hash o mensaje, con formatos Universal (SHA-256), Bitcoin (double-SHA256 con prefijo) y Ethereum (Keccak-256 con prefijo `personal_sign`); recuperación (`v`).
  - **Firma de mensajes de texto**: `signTextMessage` / `verifyTextMessage` para ECDSA y Schnorr.
- 📬 **Direcciones**: P2PKH (`1…`), P2SH-P2WPKH (`3…`), P2WPKH (`bc1q…`), P2TR/Taproot (`bc1p…`) y Ethereum (`0x…`, EIP-55).
- 🔑 **Claves**: WIF encode/decode (mainnet), compress/uncompress de pubkeys, validación de punto en curva, ECDH (secreto compartido).
- 🛡️ **Correctitud validada contra vectores oficiales**: BIP-32 Test Vector 1, BIP-39, BIP-340 (Schnorr), SHA-256/Keccak-256/RIPEMD-160, PBKDF2-HMAC-SHA512, WIF y direcciones — suites por módulo + integración end-to-end.
- 📦 **Binario Compacto**: un único `.wasm` de ~212 KB optimizado (runtime stub).

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
  import { BlockchainWasm, Bip39, Address, Secp256k1 } from "https://esm.sh/blockchain-wasm@latest"

  await BlockchainWasm.load() // carga el .wasm automáticamente

  const mnemonic = Bip39.generate(128)
  const seed = Bip39.mnemonicToSeed(mnemonic)
  // ...
</script>
```

En el navegador, `BlockchainWasm.load()` resuelve el binario desde el CDN. En Node/Bun también puedes cargarlo desde un buffer explícito con `fromBuffer()`.

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

La carga se realiza una sola vez (singleton global). Después usa las fachadas de dominio (`Bip39`, `Bip32`, `Address`, `Schnorr`, …) directamente.

### 2. BIP-39 — Mnemónicos y seed

```typescript
import { Bip39, bytesToHex } from "blockchain-wasm"

const mnemonic = Bip39.generate(128) // 12 palabras (entropía segura del host)
console.log(Bip39.validate(mnemonic)) // → true

const seed = Bip39.mnemonicToSeed(mnemonic) // 64 B (PBKDF2-HMAC-SHA512)
const entropy = Bip39.mnemonicToEntropy(mnemonic)

console.log(bytesToHex(seed))
```

### 3. BIP-32 — HD Keys (encadenable)

```typescript
import { Bip32 } from "blockchain-wasm"

const master = Bip32.fromSeed(seed)

// Derivación encadenable
const account = master.derivePath("m/44'/0'/0'")
const xpub = account.neuter().toXpub() // xpub…
const xprv = account.toXprv() // xprv…

// Getters del xkey
console.log(account.depth, account.childIndex, account.isPrivate)
console.log(bytesToHex(account.publicKey)) // 33 B compressed
console.log(account.fingerprint())

// Restaurar desde xpub/xprv
const restored = Bip32.fromXpub(xpub)
```

### 4. BIP-44 — Derivación de cuentas y direcciones

```typescript
import { Bip44, Address } from "blockchain-wasm"

// m/44'/0'/0'/0/0
const leaf = Bip44.deriveKeys(seed, 44, 0, 0, 0, 0) // { privateKey, publicKey }

const btcLegacy = Address.p2pkh(leaf.publicKey) // 1…
const btcNested = Address.p2shP2wpkh(leaf.publicKey) // 3…
const btcSegwit = Address.p2wpkh(leaf.publicKey) // bc1q…
const btcTaproot = Address.p2tr(leaf.publicKey) // bc1p…
const eth = Address.eth(leaf.publicKey) // 0x… (EIP-55)

// xpub/xprv de cuenta
const accountXpub = Bip44.accountXpub(seed, 44, 0, 0)
```

### 5. Schnorr (BIP-340)

```typescript
import { Schnorr } from "blockchain-wasm"

const xonly = Schnorr.getPublicKey(leaf.privateKey) // 32 B x-only

// Firma sobre un hash de 32 B (aux_rand seguro del host si no se pasa)
const msg32 = new Uint8Array(32).fill(0x42)
const sig = Schnorr.sign(msg32, leaf.privateKey) // 64 B
console.log(Schnorr.verify(sig, msg32, xonly)) // → true

// Firma de mensaje de texto con formato
const sig2 = Schnorr.signTextMessage("Autorizo esta transacción", leaf.privateKey, 2 /* Ethereum */)
```

### 6. ECDSA (secp256k1)

```typescript
import { Ecdsa, SignatureFormat } from "blockchain-wasm"

// Sobre un hash de 32 B
const sig = Ecdsa.sign(msg32, leaf.privateKey) // { r, s, v }
console.log(Ecdsa.verify(msg32, sig, leaf.publicKey)) // → true

// Firma de mensaje de texto (personal_sign de Ethereum)
const firma = Ecdsa.signTextMessage("Autorizo esta transacción", leaf.privateKey, SignatureFormat.Ethereum)
const valida = Ecdsa.verifyTextMessage("Autorizo esta transacción", firma, leaf.publicKey, SignatureFormat.Ethereum)
console.log(valida) // → true
```

### 7. ECDH — Secreto compartido

```typescript
import { Ecdh } from "blockchain-wasm"

const secret = Ecdh.sharedSecret(leaf.privateKey, otraPublicKey) // 33 B compressed
```

### 8. WIF y claves públicas

```typescript
import { Wif, Secp256k1 } from "blockchain-wasm"

const wif = Wif.encode(leaf.privateKey) // WIF mainnet (K…/L…)
const { privateKey, compressed } = Wif.decode(wif)

const pub = Secp256k1.getPublicKey(leaf.privateKey) // 33 B compressed
const uncomp = Secp256k1.uncompress(pub) // 65 B
console.log(Secp256k1.isValid(pub)) // → true
```

### 9. PBKDF2 y CSPRNG

```typescript
import { Pbkdf2, getRandomBytes, EntropySource } from "blockchain-wasm"

const dk = Pbkdf2.sha512("password", "salt", 2048, 64) // PBKDF2-HMAC-SHA512
const random = getRandomBytes(32) // N bytes crypto-safe
const rng = new EntropySource() // fuente de entropía (inyectable para tests/HSM)
```

### 10. Utilidades

```typescript
import { bytesToHex, hexToBytes, toUint8Array, concatBytes } from "blockchain-wasm"

const hex = bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef])) // "deadbeef"
const bytes = hexToBytes("deadbeef") // Uint8Array(4)
const utf8 = toUint8Array("texto") // string → UTF-8
const joined = concatBytes(a, b, c)
```

## 📊 Benchmarks de Rendimiento

Pruebas ejecutadas en Bun 1.4.0 (JavaScriptCore) sobre x86-64 (win32), single-thread. Binario: 212.4 KB. Medida a tiempo fijo por operación con clave distinta en cada iteración (evita optimizaciones de cache por input fijo); camino público completo (incluye la copia de salida del wrapper y validaciones de seguridad en curva).

### Resumen destacado:

| Operación                       | Rendimiento   |
| ------------------------------- | ------------- |
| Secp256k1 `compress` (65→33)    | ~2.0 M ops/s  |
| BIP-39 `entropyToMnemonic`      | ~849 K ops/s  |
| BIP-39 `generate` (128 bits)    | ~767 K ops/s  |
| BIP-39 `validate`               | ~514 K ops/s  |
| BIP-32 `fromSeed`               | ~415 K ops/s  |
| WIF `decode`                    | ~275 K ops/s  |
| WIF `encode`                    | ~187 K ops/s  |
| Schnorr `getPublicKey` (x-only) | ~85 K ops/s   |
| Address `p2wpkh` (desde pubkey) | ~23 K ops/s   |
| Address `p2pkh` (desde pubkey)  | ~21 K ops/s   |
| End-to-end `priv → p2wpkh`      | ~9.8 K ops/s  |
| Schnorr `sign`                  | ~13.3 K ops/s |
| ECDSA `sign`                    | ~13.2 K ops/s |
| Schnorr/ECDSA `verify`          | ~3.1 K ops/s  |
| ECDH `sharedSecret`             | ~3.1 K ops/s  |
| BIP-44 `deriveKeys`             | ~2.7 K ops/s  |
| PBKDF2-SHA512 (2048 iters)      | ~487 ops/s    |

<details>
<summary>Ver métricas detalladas por módulo</summary>

**Secp256k1 (claves · clave distinta por iteración):**
| Operación | ops/s |
| --- | --- |
| getPublicKey (compressed) | 14,261 |
| getPublicKey (uncompressed) | 15,643 |
| compress (65→33) | 2,004,097 |
| uncompress (33→65) | 22,608 |
| isValid | 23,138 |

**Address (desde pubkey):**
| Operación | ops/s |
| --- | --- |
| p2pkh (1…) | 21,097 |
| p2shP2wpkh (3…) | 21,576 |
| p2wpkh (bc1q…) | 23,163 |
| p2tr (bc1p…) | 9,860 |
| eth (0x… EIP-55) | 21,231 |

**End-to-end (priv → address · direcciones/s):**
| Operación | ops/s |
| --- | --- |
| priv → p2pkh | 9,501 |
| priv → p2wpkh | 9,831 |
| priv → p2tr | 5,977 |
| priv → eth | 8,999 |

**WIF:**
| Operación | ops/s |
| --- | --- |
| encode | 187,393 |
| decode | 275,858 |

**Schnorr (BIP-340):**
| Operación | ops/s |
| --- | --- |
| getPublicKey (x-only) | 85,894 |
| sign | 13,308 |
| verify | 3,173 |

**ECDSA (secp256k1):**
| Operación | ops/s |
| --- | --- |
| sign (hash) | 13,276 |
| verify (hash) | 3,170 |
| signMessage (Bitcoin) | 13,301 |
| verifyMessage (Bitcoin) | 3,135 |
| signTextMessage (Ethereum) | 13,040 |
| verifyTextMessage (Ethereum) | 3,158 |

**ECDH:**
| Operación | ops/s |
| --- | --- |
| sharedSecret | 3,142 |

**PBKDF2-HMAC-SHA512:**
| Operación | ops/s |
| --- | --- |
| sha512 (2048 iters, 64 B) | 487 |

**BIP-39 (mnemónicos):**
| Operación | ops/s |
| --- | --- |
| mnemonicToSeed | 489 |
| generate (128 bits) | 767,299 |
| validate | 514,226 |
| entropyToMnemonic (16 B) | 849,076 |

**BIP-32 / HDKey:**
| Operación | ops/s |
| --- | --- |
| fromSeed | 415,589 |
| derive (1 nivel hardened) | 16,986 |
| derivePath (m/44'/0'/0') | 5,684 |
| toXpub | 13,420 |
| toXprv | 53,017 |
| neuter | 18,021 |

**BIP-44:**
| Operación | ops/s |
| --- | --- |
| deriveKeys (m/44'/0'/0'/0/0) | 2,754 |
| accountXpub (m/44'/0'/0') | 3,961 |

</details>

📌 **Lectura clave**: generar una dirección desde la pubkey ya derivada alcanza **~23K P2WPKH/s**; el flujo completo desde la clave privada (`priv → getPublicKey → address`) rinde **~9.8K direcciones/s** (P2WPKH). Las operaciones dominadas por multiplicación de puntos (Schnorr/ECDSA sign, ECDH, BIP-32 derive) se sitúan en **~3K–17K ops/s**, y las de hashing/encoding (compress, BIP-39 generate, WIF) superan las **cientos de miles a millones de ops/s**.

**Estrés zero-alloc (verificado por módulo):**

| Módulo    | Operación               | Rondas     | WASM Δ | Heap Δ   |
| --------- | ----------------------- | ---------- | ------ | -------- |
| Secp256k1 | getPublicKey / compress | 10K → 500K | 0 B    | < 512 KB |
| Address   | p2pkh / p2wpkh / p2tr   | 10K → 500K | 0 B    | < 512 KB |
| Schnorr   | sign + verify           | 10K → 500K | 0 B    | < 512 KB |
| ECDSA     | sign + verify           | 10K → 500K | 0 B    | < 512 KB |
| BIP-32    | derive / derivePath     | 10K → 500K | 0 B    | < 512 KB |

La memoria lineal del WASM nunca crece (`Δ 0 B`) bajo carga real — la garantía zero-alloc se cumple en todos los módulos, no solo en el caso feliz.

**Validación de correctitud (suites por módulo + integración):**

| Estándar / Dominio     | Cobertura                                                              |
| ---------------------- | ---------------------------------------------------------------------- |
| BIP-32 — Test Vector 1 | master xprv/xpub, derive hardened, derivePath, neuter, fingerprint     |
| BIP-39                 | generate, entropy↔mnemonic, mnemonic→seed, validate (checksum)         |
| BIP-44                 | deriveKeys, account xpub/xprv, fromMnemonic (consistencia con BIP-32)  |
| BIP-340 — Schnorr      | sign/verify (vectores oficiales), x-only, agregación, aux_rand         |
| ECDSA secp256k1        | sign/verify, messageHash (Universal/Bitcoin/Ethereum), signTextMessage |
| ECDH                   | secreto compartido, simetría, compressed == uncompressed               |
| Direcciones BTC/ETH    | P2PKH/P2SH/P2WPKH/P2TR/ETH (EIP-55), desde pubkey y desde priv         |
| WIF                    | encode/decode roundtrip (mainnet)                                      |
| Hashing                | SHA-256, Keccak-256, RIPEMD-160, PBKDF2-HMAC-SHA512 (vectores)         |
| Integración end-to-end | mnemonic → seed → BIP-44 → direcciones → firmas → WIF → BIP-32         |

## 🏗️ Arquitectura Zero-Allocation

- **Alocador `arena` estático**: 64 KB de trabajo criptográfico (`CRYPTO_WORK`) + regiones de hashing, BIP-32 y address, más 4 KB de entrada (`PARAM_IN`) + 4 KB de salida (`PARAM_OUT`), todo reservado en el `data segment` del WASM en tiempo de compilación (`memory.data`), con `save()` / `restore()` por operación — ninguna reserva toca el heap del runtime.
- **Singleton + `WasmAllocator`**: `BlockchainWasm` instancia el WASM una vez y expone un allocator que mantiene una única vista del heap cacheada (revalidada solo si la memoria crece); las fachadas de dominio escriben inputs y leen outputs sobre las regiones planas.
- **Fachadas de dominio estáticas**: `Secp256k1`, `Wif`, `Address`, `Ecdsa`, `Schnorr`, `Ecdh`, `Pbkdf2`, `Bip32`, `Bip44` validan la frontera (longitudes/formatos) y delegan en el singleton — sin estado, sin `new` en el hot path.
- **`HDKey` encadenable**: envuelve el xkey crudo (88 B) copiado del WASM; los getters leen vía los accessors del núcleo (el layout del xkey es detalle interno del WASM) y los métodos (`derive`/`derivePath`/`neuter`/…) devuelven una nueva `HDKey`.
- **CSPRNG host-side**: la entropía segura proviene del host (`crypto.getRandomValues`) y se inyecta zero-copia sobre la memoria del WASM (`EntropySource.*Into`); fail-fast si el entorno no expone Web Crypto. Inyectable para tests determinísticos / HSM.
- **Única asignación**: el `Uint8Array` de salida que se entrega al usuario (inevitable); todo lo demás vive en la arena.

Resultado verificado: `WASM Δ 0 B` y heap estable bajo carga en todos los módulos.

## 🛠️ Comandos de Desarrollo

```bash
# Compilar binario WASM (AssemblyScript) + bundle TypeScript (esbuild minificado)
bun run release

# Compilar solo el binario WASM
bun run asbuild          # release → dist/blockchain.wasm

# Tests (suites por módulo + integración)
bun test

# Benchmark de rendimiento (ops/s · clave distinta por iteración)
bun test/bench.ts
```

## 📁 Estructura del Proyecto

```text
blockchain-wasm/
 ├── assembly/                # Núcleo en AssemblyScript (→ WebAssembly)
 │   ├── index.ts             # Barrel global WASM (re-exports por dominio)
 │   ├── utils/               # memory.ts (arena), pubkey.ts, base58.ts, bech32.ts, wif.ts
 │   ├── hash/                # sha2/ (sha256/sha512/hmac/pbkdf2), keccak256.ts, ripemd160.ts
 │   ├── secp256k1/           # field/, scalar/, point/, generator/ (GLV), glv/, wnaf/
 │   ├── bips/                # bip32/ (ckd/xkey/serialize/path), bip39/, bip44.ts
 │   ├── signatures/          # ecdsa/ (sign/verify/rfc6979/message), schnorr/ (BIP-340)
 │   ├── address/             # btc.ts (P2PKH/P2SH/P2WPKH/P2TR), eth.ts (EIP-55)
 │   └── ecdh/                # ecdh.ts (secreto compartido)
 ├── src/                     # Wrapper en TypeScript
 │   ├── index.ts             # Punto de entrada público (re-exports selectivos)
 │   ├── blockchain-wasm.ts   # Singleton (load/fromUrl/fromBuffer) + API bajo nivel
 │   ├── allocator.ts         # WasmAllocator (vista de heap cacheada, zero-alloc)
 │   ├── secp256k1.ts         # Secp256k1 (getPublicKey/compress/uncompress/isValid)
 │   ├── wif.ts               # Wif (encode/decode)
 │   ├── address.ts           # Address (p2pkh/p2sh/p2wpkh/p2tr/eth)
 │   ├── ecdsa.ts             # Ecdsa (sign/verify/messageHash/signTextMessage)
 │   ├── schnorr.ts           # Schnorr (sign/verify/getPublicKey/aggregate/signTextMessage)
 │   ├── ecdh.ts              # Ecdh (sharedSecret)
 │   ├── pbkdf2.ts            # Pbkdf2 (sha512)
 │   ├── bip32.ts             # Bip32 + HDKey (encadenable)
 │   ├── bip44.ts             # Bip44 (deriveKeys/accountXpub/fromMnemonic…)
 │   ├── csprng.ts            # EntropySource (CSPRNG isomórfico, inyectable)
 │   ├── errors.ts            # WasmError + subclases
 │   └── types.ts             # Tipos + utilidades (bytesToHex/hexToBytes/…)
 ├── test/
 │   ├── bench.ts             # Benchmark de rendimiento (ops/s)
 │   └── wrapper/             # Suites por módulo + integración end-to-end
 ├── dist/                    # Build (generado)
 ├── asconfig.json            # Configuración de AssemblyScript
 ├── package.json
 ├── tsconfig.json
 ├── LICENSE                  # Apache-2.0
 └── README.md
```

## 📜 Licencia

[Apache License 2.0](./LICENSE) © Edison Manrique

_Exención de responsabilidad: este software se proporciona "tal cual" (AS IS), sin garantía de ningún tipo. Aunque implementa estándares ampliamente usados (BIP-32/39/44, BIP-340, ECDSA secp256k1, EIP-55), esta implementación no ha sido auditada formalmente y no debe emplearse en aplicaciones de seguridad crítica sin verificación independiente._
