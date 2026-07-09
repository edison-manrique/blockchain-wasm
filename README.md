# BlockchainWasm

[![npm](https://img.shields.io/npm/v/blockchain-wasm?color=63b3ed&label=npm)](https://www.npmjs.com/package/blockchain-wasm)
[![license](https://img.shields.io/npm/l/blockchain-wasm?color=68d391)](LICENSE)
[![size](https://img.shields.io/bundlephobia/minzip/blockchain-wasm)](https://bundlephobia.com/package/blockchain-wasm)

Biblioteca criptográfica de alto rendimiento que compila primitivas criptográficas avanzadas escritas en **AssemblyScript** a un binario **WebAssembly (WASM)** altamente optimizado.

Incluye un wrapper TypeScript con un asignador de memoria estático personalizado (*scratchpad*) para intercomunicar datos (`Uint8Array` y `string`) a través de la memoria lineal de WASM, sin depender de los bindings/loader de `asc` ni de exports `__new`, usando un runtime minimalista de máximo rendimiento.

## Instalación

```bash
npm i blockchain-wasm
```

## Características

| Categoría | Algoritmos |
|---|---|
| **Hash** | SHA-256, Keccak-256, HMAC-SHA-256, HMAC-SHA-512 |
| **Firma Digital** | ECDSA secp256k1 (Raw / Ethereum / Bitcoin), Schnorr BIP-340 |
| **Intercambio de Claves** | ECDH Diffie-Hellman secp256k1 |
| **Direcciones** | P2PKH, P2SH, P2WPKH (Bech32), P2TR (Bech32m), Ethereum EIP-55 |
| **Claves** | BIP-32 derivación jerárquica, WIF encode/decode |
| **Derivación** | PBKDF2-SHA-512 |
| **Utilidades** | Hex ↔ Bytes, Base64, concat, isSameBytes |

---

## Uso Rápido

```typescript
import { BlockchainWasm } from 'blockchain-wasm'

// Carga automática del módulo WASM
const wasm = await BlockchainWasm.load()

// ── SHA-256 ──────────────────────────────────────────────────
const datos = new TextEncoder().encode('¡Hola, WebAssembly!')
const hash = wasm.sha256(datos)
console.log('SHA-256:', wasm.bytesToHex(hash))
// → '89cbd75bc4d8136ac5a1b54619f73933a8cd55db7b686b470b3a5db083ccd527'

// ── ECDSA secp256k1 ─────────────────────────────────────────
const privKey = crypto.getRandomValues(new Uint8Array(32))
const pubKeyComp    = wasm.getPublicKeyCompressed(privKey)   // 33 bytes
const pubKeyUncomp  = wasm.getPublicKeyUncompressed(privKey) // 65 bytes

// Firmar un mensaje con prefijo Ethereum personal_sign
import { SignatureFormat } from 'blockchain-wasm'
const firma = wasm.signTextMessage('Autorizo esta transacción', privKey, SignatureFormat.Ethereum)
const valida = wasm.verifyTextMessage('Autorizo esta transacción', firma, pubKeyUncomp, SignatureFormat.Ethereum)
console.log('¿Válida?', valida) // → true

// ── Schnorr BIP-340 ─────────────────────────────────────────
const schnorrPub = wasm.getSchnorrPublicKey(privKey) // 32 bytes (x-only)
const msgHash    = wasm.sha256(new TextEncoder().encode('Taproot tx'))
const schnorrSig = wasm.signSchnorr(msgHash, privKey)
const schnorrOk  = wasm.verifySchnorr(msgHash, schnorrSig, schnorrPub)
console.log('Schnorr válida:', schnorrOk) // → true

// ── ECDH ────────────────────────────────────────────────────
const privAlice = crypto.getRandomValues(new Uint8Array(32))
const privBob   = crypto.getRandomValues(new Uint8Array(32))
const pubAlice  = wasm.getPublicKeyUncompressed(privAlice)
const pubBob    = wasm.getPublicKeyUncompressed(privBob)
const secretA   = wasm.sharedSecret(privAlice, pubBob)
const secretB   = wasm.sharedSecret(privBob, pubAlice)
console.log('ECDH iguales:', wasm.isSameBytes(secretA, secretB)) // → true

// ── Direcciones ─────────────────────────────────────────────
const pubComp = wasm.getPublicKeyCompressed(privKey)
console.log('Bitcoin P2PKH:  ', wasm.getBitcoinAddress(pubComp))
console.log('Bitcoin P2WPKH: ', wasm.getBitcoinP2WPKHAddress(pubComp))
console.log('Ethereum:       ', wasm.getEthereumAddress(pubKeyUncomp))
```

---

## API completa

### Carga del módulo

```typescript
// Carga automática (detecta la ruta del .wasm relativa al script)
const wasm = await BlockchainWasm.load()

// Desde URL explícita
const wasm = await BlockchainWasm.fromUrl('/assets/blockchain.wasm')

// Desde buffer (Node.js / Bun)
import { readFileSync } from 'fs'
const buf  = readFileSync('node_modules/blockchain-wasm/dist/blockchain.wasm')
const wasm = await BlockchainWasm.fromBuffer(buf)
```

### Hashing

| Método | Descripción |
|---|---|
| `sha256(data)` | SHA-256 de 32 bytes |
| `keccak256(data)` | Keccak-256 estilo Ethereum |
| `hmacSha256(key, data)` | HMAC-SHA-256 |
| `hmacSha512(key, data)` | HMAC-SHA-512 |

### ECDSA

| Método | Descripción |
|---|---|
| `ecdsaSign(hash32, privKey)` | Firma raw → `Uint8Array` de 65 bytes `[R\|S\|V]` |
| `ecdsaVerify(hash32, sig, pubKeyUncomp)` | Verifica contra llave descomprimida (65 bytes) |
| `signTextMessage(msg, privKey, format?)` | Firma mensaje de texto con prefijo (`Raw` / `Ethereum` / `Bitcoin`) |
| `verifyTextMessage(msg, sig, pubKeyUncomp, format?)` | Verifica firma de mensaje de texto |
| `getMessageHash(msg, format?)` | Obtiene el hash del mensaje con el formato indicado |

### Schnorr BIP-340

| Método | Descripción |
|---|---|
| `getSchnorrPublicKey(privKey)` | Clave pública x-only (32 bytes) |
| `signSchnorr(hash32, privKey, auxRand?)` | Firma BIP-340 (64 bytes). Si no se pasa `auxRand`, usa 32 ceros |
| `verifySchnorr(hash32, sig64, pubKey32)` | Verifica firma Schnorr |

### ECDH

| Método | Descripción |
|---|---|
| `sharedSecret(privKey, pubKeyUncomp)` | Secreto compartido de 32 bytes. La clave pública debe estar descomprimida (65 bytes) |

### Claves y Direcciones

| Método | Descripción |
|---|---|
| `getPublicKeyCompressed(privKey)` | Clave pública comprimida (33 bytes) |
| `getPublicKeyUncompressed(privKey)` | Clave pública descomprimida (65 bytes) |
| `compressPublicKey(pubKey65)` | Convierte 65 → 33 bytes |
| `uncompressPublicKey(pubKey33)` | Convierte 33 → 65 bytes |
| `getBitcoinAddress(pubKey)` | Dirección Legacy P2PKH |
| `getBitcoinP2SHAddress(pubKey)` | Dirección P2SH (SegWit anidado) |
| `getBitcoinP2WPKHAddress(pubKey)` | Dirección Native SegWit Bech32 |
| `getBitcoinP2TRAddress(pubKey)` | Dirección Taproot Bech32m |
| `getEthereumAddress(pubKey65)` | Dirección Ethereum EIP-55 (requiere llave descomprimida) |

### BIP-32 / WIF

| Método | Descripción |
|---|---|
| `bip32DerivePath(seed64, path)` | Deriva clave privada en la ruta HD |
| `bip32GetPublicKey(seed64, path)` | Deriva clave pública comprimida en la ruta HD |
| `toWIF(privKey)` | Codifica en Wallet Import Format |
| `fromWIF(wif)` | Decodifica WIF → clave privada de 32 bytes |

### Utilidades

| Método | Descripción |
|---|---|
| `pbkdf2Sha512(password, salt, iterations, keyLen)` | Derivación de clave PBKDF2 |
| `bytesToHex(data)` | Bytes → string hexadecimal |
| `hexToBytes(hex)` | String hex → `Uint8Array` |
| `bytesToBase64(data)` | Bytes → Base64 |
| `base64ToBytes(b64)` | Base64 → `Uint8Array` |
| `isSameBytes(a, b)` | Comparación en tiempo constante |
| `concatBytes(a, b)` | Concatena dos arreglos de bytes |

---

## Estructura del Proyecto

```
blockchain-wasm/
├── assembly/     # Código fuente AssemblyScript (primitivas criptográficas)
├── src/          # Wrapper TypeScript (BlockchainWasm + WasmAllocator)
├── dist/         # Salida compilada (index.js, index.d.ts, blockchain.wasm)
└── examples/     # Ejemplos interactivos HTML en español
```

## Licencia

MIT © Edison Manrique — ver [LICENSE](LICENSE)
