# 📦 CHANGELOG — blockchain-wasm

## [3.1.0] — release actual

> **Versión previa:** 2.1.0
> **Tipo de release:** _major_ — BIP-327 MuSig2 completo, nuevas cadenas (Tron), laboratorios interactivos y rendimiento verificado con medición de memoria.
> **Sin cambios rompedores de API pública.**

---

## ✨ Features nuevas

### FEAT-1 — BIP-327 MuSig2 (Multifirma Schnorr de 2 Rondas)

Motor completo de firma múltiple Schnorr compatible con Bitcoin Taproot, resistente al ataque _rogue-key_.

- **WASM:** `assembly/signatures/schnorr/musig2/` — `keyagg.ts`, `nonce.ts`, `sign.ts`, `index.ts`.
  - `musig2_key_agg` + coeficientes $a_i$ (HashAHAI determinísticos, anti-rogue).
  - `musig2_nonce_gen` → secnonce 97 B / pubnonce 66 B.
  - `musig2_nonce_agg` → aggnonce 66 B (maneja $R_2 = \infty$ → 33 ceros).
  - `musig2_session_init` → contexto de sesión 97 B.
  - `musig2_partial_sign`, `musig2_partial_verify`.
  - `musig2_partial_sig_agg` → $\sum s_i$ parciales en firma BIP-340 de 64 B.
- **Wrapper:** clase estática `Musig2` exportada — `keyAgg`, `keyAggCoeffs`, `nonceGen`, `nonceAgg`, `sessionInit`, `partialSign`, `partialVerify`, `partialSigAgg`, `signAll`.
- **Tests:** 15/15 vectores BIP-327 oficiales pasando (`keyAgg`, `nonceGen`, `nonceAgg`, `sign_verify`, `sig_agg`).
- **Playground:** `playground/multisig.html` — laboratorio interactivo Web Worker con n firmantes.

### FEAT-2 — Direcciones Tron (TRX) vía BIP-44

- Ruta estándar: `m/44'/195'/0'/0/i`.
- `Address.tron(pub65)` — `Keccak256(X‖Y)[12..32]` con prefijo `0x41` codificado en Base58Check → `T...`.
- `Bip44.COIN_TRON = 195` y soporte completo en `Bip44.fromMnemonicDerive`.

### FEAT-3 — Playground BIP-44 mejorado

- **Default Legacy Bitcoin** (`m/44'/0'/0'/0/i` P2PKH) en lugar de Nested SegWit.
- **Passphrase opcional** (salt PBKDF2 / 13ª o 25ª palabra) para mnemónico.
- **Paginación (5 por página)** con botones `◀ Anteriores 5` y `Siguientes 5 ▶`.
- **Tron** como moneda derivable en la interfaz.

### FEAT-4 — Laboratorio BIP-32 xpub & xprv (`playground/bip32.html`)

Reescrito como laboratorio educativo interactivo de 3 pestañas:

1. **Explorador de Árbol HD** — seed → `xprv` / `xpub` en cualquier ruta, con profundidad, fingerprint e índice.
2. **Cartera Watch-Only** — simulador real de derivación pública desde `xpub` sin claves privadas; demuestra por qué las rutas hardened (`'`) son imposibles con `xpub`.
3. **Anatomía de 78 Bytes** — desglose de los campos `Version / Depth / Parent FP / Child Index / Chain Code / Key Data` con regla de oro de seguridad hardened.

### FEAT-5 — Medición de Memoria en Benchmark

`test/bench.ts` ahora reporta:

- Páginas de memoria WASM antes y después de todos los benchmarks.
- Delta de WASM `memory.grow` — garantía **ZERO-GROW** verificada en cada ejecución.
- Delta del heap JS de Bun — impacto recolectable por GC.

---

## 🐛 Bugs corregidos

| ID     | Archivo                           | Fix                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------ | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| FIX-10 | `playground/encoding.html`        | Bech32m Taproot cross-check mostraba ❌ porque comparaba la clave interna $P$ (sin tweak) con `Address.p2tr` que aplica $Q = P + \text{TapTweak}(P)\cdot G$ (BIP-86). Ahora decodifica la dirección con `bechDecode` para extraer $Q$ y valida que `bechEncode("bc", 1, Q, "bech32m") === Address.p2tr(pub)` → muestra ✓ correctamente.                                                                                        |
| FIX-11 | `test/bench.ts` — `makeKeyStream` | El buffer compartido de la stream de claves era mutado en el mismo tick de JS entre la llamada a `getPublicKey` (que modifica el input buffer) y la subsiguiente llamada a `Address.eth/tron`, haciendo que se pasara una pubkey alterada de 33 B a `eth_address`/`tron_address` que exigen 65 B → `WasmError -1`. Corregido con `buf.slice()` (copia por iteración) y base scalar 32 bits (sin riesgo de overflow del campo). |
| FIX-12 | `playground/bip44.html`           | Default `purpose` en el `<select>` estaba marcado en `49` (Nested SegWit) en lugar de `44` (Legacy). Corregido con `selected` en la opción `44`.                                                                                                                                                                                                                                                                               |

---

## ⚡ Rendimiento (medido con `bun test/bench.ts` en x86_64)

| Operación                                 | Rendimiento          |
| ----------------------------------------- | -------------------- |
| `Secp256k1.getPublicKey` (compressed 33B) | **~54,000 ops/s**    |
| `Secp256k1.compress` (65→33)              | **~2,020,000 ops/s** |
| `Address.p2pkhUncompressed` (Legacy 65B)  | **~230,500 ops/s**   |
| `Address.eth` (EIP-55)                    | **~205,500 ops/s**   |
| `Address.tron` (Base58Check `T...`)       | **~188,300 ops/s**   |
| `End-to-End priv → tron`                  | **~41,800 dir/s**    |
| `End-to-End priv → p2wpkh`                | **~15,900 dir/s**    |
| `Schnorr.getPublicKey` (x-only 32B)       | **~80,300 ops/s**    |
| `Musig2.partialSign` (32B psig)           | **~75,100 ops/s**    |
| `Musig2.partialSigAgg` (3 firmantes)      | **~3,045,000 ops/s** |
| `Musig2.keyAgg` (3 firmantes → Q)         | **~1,200 ops/s**     |
| `BIP-39 generate` (128 bits)              | **~757,800 ops/s**   |
| `BIP-32 fromSeed`                         | **~422,400 ops/s**   |

**Garantía Zero-Alloc (verificada en benchmark completo):**

- WASM `memory.grow` = **0 páginas (0 bytes)**. 11 páginas estáticas (704 KB) — sin crecimiento.
- Bun Heap Δ ≈ 2.3 MB (recolectable por GC, no alocaciones WASM).

---

## 🧪 Validación de la release

| Área                   | Cobertura                                                                         | Resultado     |
| ---------------------- | --------------------------------------------------------------------------------- | ------------- |
| BIP-327 MuSig2         | 15 vectores oficiales: `keyAgg`, `nonceGen`, `nonceAgg`, `sign_verify`, `sig_agg` | ✅ 15/15 pass |
| BIP-340 Schnorr        | Vectores oficiales + firmas end-to-end                                            | ✅ pass       |
| Address (BTC/ETH/Tron) | 27 tests — P2PKH/P2SH/P2WPKH/P2TR/ETH/Tron                                        | ✅ 27/27 pass |
| BIP-44 multi-coin      | 19 tests — derivación seed, mnemónico, xpub/xprv, ETH                             | ✅ 19/19 pass |
| TypeScript typecheck   | `tsc --noEmit` sobre todo el codebase                                             | ✅ 0 errores  |
| Bech32m cross-check    | `bechEncode("bc", 1, Q_tweaked) === Address.p2tr(pub)`                            | ✅ match      |

---

## ⚠️ Compatibilidad

**API pública:** sin roturas. Adiciones:

- `Musig2` (nuevo): `keyAgg`, `keyAggCoeffs`, `nonceGen`, `nonceAgg`, `sessionInit`, `partialSign`, `partialVerify`, `partialSigAgg`, `signAll`.
- `Address.tron(pub65)` y `Address.fromPrivateKey(priv, "tron")` (ya disponible desde 2.1.0 a nivel WASM; ahora completo en playground y benchmark).
- `Bip44.COIN_TRON = 195`.

---

_Fin de la entrada 3.1.0._

---

## [2.1.0] — release anterior

> **Versión previa:** 2.0.0
> **Tipo de release:** _minor_ — features nuevas + fixes de seguridad y bugs.
> **Sin cambios rompedores de API pública** (ver §Compatibilidad).

---

## 🚨 Seguridad

| ID    | Severidad | Descripción                                                                                                                                                                                                                                                      | Corrección                                                                                                                                                    |
| ----- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-1 | **ALTA**  | `decompressXY` / `decompressToPoint` / `uncompressRaw` (`assembly/utils/pubkey.ts`) no verificaban `y² ≡ x³+7 (mod P)` tras el `sqrt`. Una X sin raíz válida producía un "punto" basura silencioso, aceptado por ECDSA verify, ECDH, BIP32 CKDpub y direcciones. | Ahora `decompressXY`/`decompressToPoint` retornan `bool` (verifican raíz y prefijo) y `uncompressRaw`/`compressRaw` rechazan puntos fuera de la curva (`-1`). |
| SEC-2 | **ALTA**  | Pubkeys **uncompressed (65 B)** entraban sin ninguna validación de curva en `ecdh_shared_secret`, `ecdsa_verify`, `compressRaw` y `eth_address`.                                                                                                                 | Nuevo helper `isOnCurveXY(x, y)`; todos los caminos de 64/65 B validan pertenencia a la curva antes de operar.                                                |
| SEC-3 | **MEDIA** | Las fachadas aceptaban cualquier privkey de 32 B (incluidos `0` o `≥ N`), produciendo pubkeys/firmas basura sin error.                                                                                                                                           | Nueva utilidad pura `isValidPrivateKey()` (0 < k < N) + validación en `Secp256k1`, `Wif`, `Ecdsa`, `Schnorr`, `Ecdh` y `Address`.                             |
| SEC-4 | **MEDIA** | Passphrase BIP39 > 1888 bytes UTF-8 desbordaba `HASH_WORK` (la sal se construye en el offset 2200 de 4096 B).                                                                                                                                                    | Nueva constante `MAX_PASSPHRASE_BYTES = 1888` + validación fail-fast en `Bip39.mnemonicToSeed` y `Bip44.fromMnemonic*`.                                       |

### Superficie protegida tras este release

| Módulo                                            | Comportamiento nuevo ante punto inválido                                  |
| ------------------------------------------------- | ------------------------------------------------------------------------- |
| `Secp256k1.uncompress / compress / isValid`       | Lanza `WasmError [secp256k1]` / `isValid → false`                         |
| `Ecdsa.verify / verifyMessage` (33 y 65 B)        | Retorna `false` (contrato 1\|0 preservado)                                |
| `Ecdh.sharedSecret` (33 y 65 B)                   | Lanza `WasmError [ecdh]` código `-2`                                      |
| `Bip32` CKDpub / `derivePath` desde xpub alterado | Lanza `WasmError [bip32]` código `-7` (`BIP32_ERR_PUBKEY_INVALID`, nuevo) |
| `Address.*` (P2PKH/P2SH/P2WPKH/P2TR/ETH)          | Lanza `WasmError [address]` código `-1`                                   |

---

## 🐛 Bugs corregidos

| ID    | Archivo                             | Fix                                                                                                                                                                                          |
| ----- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FIX-1 | `wrapper/blockchain-wasm.ts`        | `bip32Fingerprint()` pasaba el **xkey** (`a.inPtr`) a `bip32_fingerprint` en vez de la pubkey recién calculada (`a.outPtr`) → todos los fingerprints de usuario eran incorrectos.            |
| FIX-2 | `wrapper/blockchain-wasm.ts`        | `isValidPoint()` (65 B) comparaba Y con offset `32` en vez de `33` → el último byte de Y quedaba sin validar.                                                                                |
| FIX-3 | `assembly/signatures/ecdsa/sign.ts` | Canonical S (BIP-62): `cmp(s, n_half) >= 0` → `> 0`. Con `>=`, el caso límite `s == floor(N/2)` (válido) se convertía en un `s` no canónico.                                                 |
| FIX-4 | `wrapper/address.ts`                | `ts(2366)`: `switch` no exhaustivo tras ampliar `AddressType` → ahora cubre los 7 casos y compila sin error.                                                                                 |
| FIX-5 | `wrapper/types.ts`                  | Contrato `AsmExports`: `bip32_fingerprint(xkeyPtr)` renombrado a `bip32_fingerprint(pub33Ptr)` (el WASM espera una pubkey).                                                                  |
| FIX-6 | `wrapper/blockchain-wasm.ts`        | `buildImports`: `abort() {}` silencioso → ahora lanza `WasmError [runtime] código TRAP` con ubicación `file:line:col`.                                                                       |
| FIX-7 | `wrapper/ecdsa.ts`                  | `normalizeSig()` no validaba longitudes de `sig.r`/`sig.s` → ahora exige 32 B cada uno (`InvalidArgumentError [ecdsa]`).                                                                     |
| FIX-8 | docs                                | `wrapper/bip32.ts`: comentario de layout de xkey corregido (`depth@0, fp@4, idx@8, priv@12, chain@16, keyData@48`). `assembly/utils/memory.ts`: comentario `SCRATCH_SIZE` 72192 → **79360**. |
| FIX-9 | limpieza                            | Código muerto eliminado: `const child` en `bips/bip44.ts`; `buf`/`bufSafe` + comentarios de razonamiento en `utils/base58.ts`; escrituras muertas de `Z3` en `point/point.ts → double()`.    |

---

## ✨ Features nuevas

### FEAT-1 — Dirección Tron (TRX)

- **WASM:** nuevo `assembly/address/tron.ts` → `tron_address(outPtr, pubPtr, pubLen)`.
  Algoritmo: `Base58Check( 0x41 ‖ Keccak256(X‖Y)[12..32] )`. Acepta 33/64/65 B.
- **Wrapper:** `Address.tron(pubkey)` y `Address.fromPrivateKey(priv, "tron")`.
- **Constantes:** `TRON_PREFIX = 0x41` (WASM) y `Bip44.COIN_TRON = 195` (path `m/44'/195'/0'/0/0`).

### FEAT-2 — P2PKH legacy uncompressed explícito

- **WASM:** `btc_p2pkh_uncompressed(outPtr, pubPtr, pubLen)` — exige 65 B con prefijo `0x04`.
- **Wrapper:** `Address.p2pkhUncompressed(pubkey)` y `Address.fromPrivateKey(priv, "p2pkh-uncompressed")`.

### FEAT-3 — Nuevo código de error BIP32

- `BIP32_ERR_PUBKEY_INVALID = -7` (pubkey fuera de la curva en CKDpub), propagado hasta el wrapper y re-exportado en el barrel de `bips/bip32`.

### FEAT-4 — Utilidades públicas nuevas (wrapper)

- `isValidPrivateKey(bytes): boolean` y `MAX_PASSPHRASE_BYTES` exportados desde `index.ts`.

---

## 🔒 Endurecimiento de frontera (wrapper)

- Validación de rango de privkey en todas las fachadas que lo reciben (§SEC-3).
- Validación de passphrase BIP39 ≤ 1888 B (§SEC-4).
- `abort` del runtime ya no es silencioso (FIX-6).

---

## ⚠️ Compatibilidad y cambios de comportamiento

**API pública:** sin roturas. Solo adiciones (`Address.tron`, `Address.p2pkhUncompressed`,
`AddressType` ampliado, `COIN_TRON`, `isValidPrivateKey`, `MAX_PASSPHRASE_BYTES`).

**Cambios de comportamiento (solo para inputs inválidos que antes pasaban):**

1. Puntos fuera de la curva ahora se **rechazan** en firma/verificación/ECDH/derivación/direcciones.
2. Privkeys `0` o `≥ N` lanzan `InvalidArgumentError` en las fachadas.
3. Passphrases > 1888 B lanzan `InvalidArgumentError` (antes: corrupción silenciosa).
4. Un trap del WASM ahora lanza `WasmError [runtime] TRAP` (antes: fallo silencioso).

**Firmas internas del WASM (solo consumidores directos del binario):**
`decompressXY`, `decompressToPoint` y `pointAddPubkeys` pasan de `void` a `i32/bool`.
Llamadas existentes que ignoran el retorno siguen funcionando.

---

## 🧪 Validación de la release

| Área        | Vector / prueba                                                                       | Resultado |
| ----------- | ------------------------------------------------------------------------------------- | --------- |
| BIP-32      | Test Vector 1 (fingerprints tras FIX-1)                                               | ✅        |
| ECDSA       | RFC 6979 + canonical S (FIX-3)                                                        | ✅        |
| Schnorr     | Test vectors oficiales BIP-340                                                        | ✅        |
| BIP-39      | Vectores Trezor + passphrase límite 1888 B                                            | ✅        |
| Direcciones | BIP-84/BIP-86/EIP-55 conocidos                                                        | ✅        |
| Tron        | Dirección conocida desde pubkey de referencia                                         | ✅        |
| Curva       | `uncompress`/`isValid`/`verify`/`sharedSecret` con X o (X,Y) fuera de curva → rechazo | ✅        |
| Regresión   | `isValidPoint` con Y alterada en el último byte → `false`                             | ✅        |

---

_Fin de la entrada 2.1.0. Mantener el historial de versiones anteriores debajo de esta sección._
