# 📦 CHANGELOG — blockchain-wasm

## [2.1.0] — release actual

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
