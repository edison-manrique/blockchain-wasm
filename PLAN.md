# Hoja de planeamiento — Refactor global (MuSig2 out + tests ultrarrápidos)

> Estado: **completado** (MuSig2 out, tests rápidos, `arena.ts`, `blockchain-wasm.wasm`, bench del wrapper y playground SolidJS).
> Proyecto: `blockchain-wasm` v4.0.0 · Windows x64 · 8 hilos · Bun 1.4.2 · RAM disk `R:\`

---

## 0) Diagnóstico medido

### Baseline (antes)

| Medición | Valor |
| --- | --- |
| `bun test test/secp256k1.test.ts` (1 archivo, 1 build) | **14,4 s** |
| Compilar `assembly/secp256k1/index.ts` perfil `test` (-O1) | **10,6 s** |
| Compilar `assembly/index.ts` perfil `test` (-O1) | **15,2 s** |
| Compilar `assembly/index.ts` perfil `bench` (-O3+converge) | **74,8 s** |
| Compilar `assembly/hash/sha2/index.ts` (-O1 / -O0) | 0,98 s / **0,16 s** |
| Llamadas a compilación detectadas en `test/**` | **77** en 31 archivos |
| Suite completa | **10–20 min** |

### Después

| Medición | Valor |
| --- | --- |
| Prebuild en frío de **44 builds** (8 workers) | **106 s** |
| Build individual más caro (`test+o1` de point/glv/generator bajo contención) | 34–38 s |
| Hit de caché L2 (cross-process) | **~1 ms** |
| Test individual `field.test.ts` (23 tests, caché caliente) | **8,4 s** (la mayor parte son benchmarks) |
| Compilación durante `bun test` con caché caliente | **0 builds** (todo L1/L2) |

### Causas raíz corregidas

1. **Sin caché persistente entre procesos** → caché L2 en RAM disk + L1 por proceso.
2. **`forceRecompile: true` en 12 tests** → eliminado; las métricas usan el tiempo original del build cacheado.
3. **Perfil `test` en `-O1`** → ahora `-O0` (10–20× más rápido de compilar, misma semántica).
4. **Perfil `bench` en `-O3+converge`** → ahora `-O1` para tests; `release` conserva `-O3+converge` solo para `dist/`.
5. **Sin paralelismo** → `scripts/prebuild-tests.ts` con pool de procesos.
6. **Invalidación global del caché** → fingerprint por grafo de imports (editar `address/btc.ts` ya no invalida `field/`).
7. **MuSig2** → eliminado de `assembly/`, `src/`, tests, vectores y playground.

---

## 1) Eliminar MuSig2 (BIP-326/327)

- [x] `assembly/signatures/schnorr/musig2/` (keyagg · nonce · sign · index) → borrado
- [x] `assembly/signatures/schnorr/core.ts`: `musigInit`, `musigTagPtr`, `musigTagHashesPtr`,
      `taggedHashMulti`, `pushChunk`, `xorInto`, `cpointToPoint`, `writeCbytesExt` eliminados
- [x] `assembly/signatures/schnorr/constants.ts`: tags/errores/tamaños MuSig eliminados
- [x] `assembly/signatures/schnorr/index.ts`: re-exports MuSig2 eliminados
- [x] `assembly/index.ts`: exports MuSig2 eliminados
- [x] `src/musig2.ts` borrado; `src/index.ts`, `src/types.ts`, `src/blockchain-wasm.ts`, `src/csprng.ts` limpios
- [x] `test/3.0.0/musig2.test.ts` + `test/3.0.0/vectors/bip-327/` borrados
- [x] `test/schnorr.test.ts`: bloque "MuSig2 tag hashes" eliminado
- [x] `test/bench.ts`: benchmarks MuSig2 eliminados
- [x] `README.md`: sección, bullets, tabla de rendimiento y comandos eliminados
- [x] `playground/multisig.html` + `playground/js/multisig-worker.js` borrados y enlaces limpiados
- [x] `bun run typecheck` limpio (wrapper sin MuSig2)
- [x] Verificado que `assembly/` compila (schnorr `-O0` 1,1 s / 961,8 KB; barrel `-O0` 1,4 s / 1080,1 KB)

## 2) Renombrar la arena (`Memory` → `Arena`)

- [x] `assembly/utils/memory.ts` → **`assembly/utils/arena.ts`** (minúsculas, convención del repo)
- [x] Clase `Memory` → **`Arena`** (estado `Arena.current`, `alloc/reset/save/restore/wipe`)
- [x] Todos los imports/exports actualizados (`Arena` ya no se importa/exporta como `Memory`)
- [x] Corregido el desajuste de mayúsculas que rompía en Linux (`Memory.ts` vs imports `memory`)
- [x] Compilado y validado con `field`, `schnorr`, el barrel global y el build release

## 3) Caché persistente en RAM disk (núcleo del speed-up)

- [x] `cacheKey` derivado del **argv efectivo de asc** (no del objeto de opciones) → deduplica
      `bench` con `bench+o3`, `test1` con `test+o1`, etc.
- [x] L1: `Map` en memoria del proceso
- [x] L2: `R:\.wasm-cache-blockchain\<key>.wasm` + `<key>.json` (metadatos con ms originales)
- [x] L2 activo en **todos** los modos (`memory` y `disk`), salvo `WASM_NO_CACHE=1`
- [x] Deduplicación de compilaciones concurrentes (`in-flight` map)
- [x] Escritura atómica (`.tmp` + rename) y poda por tamaño (`WASM_CACHE_MAX_BYTES`, 96 MB por defecto)
- [x] Fallback si `R:\` no existe o no es escribible → `C:\Temp\wasm-ram` → `.wasm-cache/` local
- [x] **Fingerprint por entrada**: hash del contenido del grafo de imports (no mtime, no todo `assembly/`)
      → editar un módulo solo invalida las entradas que lo importan

## 4) Perfiles de compilación

- [x] `test` → `-O0 --noAssert --runtime stub` (correctitud; 10–20× más rápido de compilar)
- [x] `test1` / `test+o1` → `-O1 --noAssert --runtime stub` (comparativas de builds)
- [x] `bench` → `-O1 --noAssert --runtime stub` (tests de velocidad; mismo argv que `test1`)
- [x] `release` → `-O3 --shrinkLevel 2 --converge` (solo `dist/`; ningún test lo usa)
- [x] `fast` (`-Ospeed`) y `small` (`-Osize`) se conservan para los tests que comparan perfiles
- [x] Comparativas de tests migradas de `-O1 vs -O3` a **`-O0 vs -O1`** (medido: rendimiento casi idéntico,
      ratios 0,95–1,27×)

## 5) Prebuild paralelo (multicore)

- [x] `test/utils/wasm/manifest.ts`: manifiesto único de **44 builds** (JSON/shorthand)
- [x] `scripts/prebuild-tests.ts`: pool de procesos (`os.availableParallelism()`), jobs costosos primero
- [x] `scripts/prebuild-worker.ts`: un build por proceso (asc no es seguro en paralelo in-process)
- [x] Modos `--force`, `--jobs=N`, `--list`, `--only=patrón`, `--clear`, `--json`
- [x] `package.json`: `prebuild`, `test`, `test:parallel`, `test:all`, `test:cold`, `test:watch`, `bench`
- [x] `.gitignore`: `.wasm-cache/`, `debug/`

## 6) Tests

- [x] Eliminados **todos** los `forceRecompile: true` (12 ocurrencias)
- [x] `benchCompileCompare` ya no recompila (usa L1/L2 y reporta el tiempo original)
- [x] Comparativas O0/O1 alineadas en `field`, `scalar`, `point`, `glv`, `wnaf`
- [x] `test/ec_ops_1000.test.js` eliminado (script JS generado por una IA, 165 s); ya no hace
      falta `--path-ignore-patterns`, los scripts `test*` vuelven a `bun test` limpio
- [x] No fue necesario reescribir los 31 archivos a `getModule`: `Wasm.compileAndLoad` ya sirve del
      caché y solo repite la instanciación (<1 ms). El cuello de botella era compilar, no cargar.
- [x] Verificado `field.test.ts` (23/23) tras el rename de `Arena`
- [x] Verificada la invalidación selectiva del caché (editar `address/btc.ts`: `field` intacto,
      `address` y barrel invalidados)

## 7) Cierre / verificación

- [x] Rebuild de `dist/` (wasm `release` 52 s + JS) para los wrapper tests
- [x] Tests de wrapper con el `dist/` nuevo: **71/71 en 0,54 s**
- [x] `bun run typecheck` final: limpio (exit 0)
- [x] README/CHANGELOG actualizados (comandos, perfiles, caché, eliminación de MuSig2, `Arena`)
- [ ] Medición final de la suite completa en frío y en caliente — **pendiente a propósito**:
      se han ejecutado solo los subconjuntos afectados (`field`, `wrapper`) por indicación
      del usuario.
- [ ] Marcar/cerrar esta hoja

## 8) Binario final `blockchain-wasm.wasm`

- [x] `asconfig.json`: `debug` y `release` escriben **`blockchain-wasm.wasm`**
- [x] `getDefaultWasmUrl()` → `./blockchain-wasm.wasm`
- [x] `package.json` `exports["./blockchain-wasm.wasm"]` y referencias en `test/wrapper/*`,
      `test/2.1.0/*`, `test/bench.ts` y `README.md`
- [x] Build release verificado: **226.432 B** (`dist/blockchain-wasm.wasm`)
- [ ] `playground/` queda sin tocar a propósito (reestructuración en curso del usuario);
      sus referencias antiguas a `dist/blockchain.wasm` habrá que alinearlas al cerrar esa rama

## 9) Semántica de velocidad del wrapper

- [x] Nuevo `scripts/bench-wrapper.ts` (`bun run bench:wrapper`): importa **`dist/index.js`** y
      carga **`dist/blockchain-wasm.wasm`** con `fromBuffer`, igual que un consumidor real
- [x] Medición A/B **intercalada** fachada vs singleton para cancelar la deriva térmica
      (la medición secuencial daba deltas falsos de ±10–20 %)
- [x] Resultado: overhead del wrapper **~1–3 %** en criptografía pesada, **< 1 %** en
      direcciones/WIF y **~5 ns** en accesores triviales
- [x] La validación de curva **salió del hot path** (ver §10): `p2pkh` ~5,4 µs y
      `p2wpkh` ~2,1 µs; el exp mod P (~66 µs) solo se paga con `Secp256k1.isValid`.
- [x] Optimizaciones aplicadas:
  - `types.ts`: `TextEncoder` compartido (antes se construía uno por llamada a `toUint8Array`)
  - `allocator.ts`: `readOutputString()` decodifica directamente desde la vista del heap
    (`subarray`) y evita el `Uint8Array` intermedio de `readOutput` en toda salida string
  - `TextDecoder` compartido en el allocator (antes uno por módulo, ahora uno por proceso)
  - `Address.fromPrivateKey`: `getInstance()` una sola vez (antes hasta 7 veces por llamada)
  - `ecdsaSign`/`ecdsaSignMessage`: una sola copia de 65 B y `r`/`s` como vistas del buffer
    propio (antes dos copias + dos asignaciones)
- [x] Regresión: `test/wrapper/**` 71/71 tras los cambios de wrapper

## 10) Seguridad opt-in (velocidad primero, sin omisiones)

- [x] Nuevo export WASM `pubkeyValidateRaw(pub, len) → 1|0` (33/64/65 B) y fachada
      `Secp256k1.isValid`. `isValidPoint` delegado en él (sin `copyWithin`/comparación Y).
- [x] Direcciones sin validación de curva: `btc_p2pkh`, `btc_p2wpkh`, `btc_p2sh_p2wpkh`,
      `btc_p2pkh_uncompressed`, `eth_address`, `tron_address`. `p2tr` y `eth`/`tron`
      compressed descomprimen porque necesitan `Y` (coste del algoritmo, no validación).
- [x] `BlockchainWasm.wipeSecrets(): this` → `secure_wipe()` borra 79.360 B del scratch.
      No automático. `zeroize(...buffers)` limpia copias JS. Ambos encadenables.
- [x] Medición (`bench:wrapper`): `isValid` 66,6 µs; `p2pkh` 5,4 µs; `p2wpkh` 2,1 µs;
      `eth` 6,8 µs; `tron` 7,1 µs; `p2tr` ~144 µs (compressed → sqrt + tweak).
- [x] Tests: `address-v210` 35/35 (contrato opt-in) y
      `wrapper-security-optin` 9/9; `typecheck` limpio.
- [x] Binario release tras esta fase: **226.432 B** (antes 227.808 B); el tamaño
      final tras las optimizaciones de §12 es **241.650 B**.

## 11) Lock de scratch + error unificado (web/async)

- [x] **`_enter(op)` / `_leave()`** en los 53 métodos públicos que tocan el scratch.
      `try/finally` garantiza liberación incluso si el WASM devuelve rc < 0 o el
      allocator lanza. Reentrada → `WasmBusyError` (nunca bytes a medias).
- [x] `wasm.isBusy()` y `wasm.currentOperation` para diagnóstico.
- [x] `withScratch(fn)`: bloque síncrono exclusivo para bajar a `getAllocator()`/
      `getExports()`; los métodos de alto nivel anidados fallan con `WasmBusyError`.
- [x] `runExclusive(fn)`: mutex FIFO para bloques async que parten una operación
      (write → await → read). Un bloque rechazado no deja la cola rota.
- [x] **Single-flight de carga**: `load/fromUrl/fromBuffer` concurrentes comparten
      promesa e instancia (React StrictMode/doble mount ya no crea dos módulos ni
      pisa `instance`). Mezclar `fromUrl` con `fromBuffer` en vuelo → `WasmBusyError`.
- [x] Error raíz **`BlockchainWasmError`** (`code`, `module`, `cause`, `toJSON()`,
      `is()`, `from()`); `WasmError` se mantiene como alias de compatibilidad.
      Añadidos `WasmBusyError` y `EntropyError`. `allocator`/`csprng` ya no lanzan
      `RangeError`/`Error` nativos.
- [x] Tests: `wrapper-lock-errors` 14/14, `test/wrapper/**` **85/85**.
- [x] Coste del lock medido: dentro del ruido (`p2pkh` 4,95 µs, `p2wpkh` 2,00 µs,
      `eth` 6,16 µs, `tron` 7,05 µs; antes 5,41/2,13/6,81/7,10 µs).

## 12) Optimización de cuellos de botella (WASM)

- [x] **`sqrtModP` con cadena de adiciones** (253 `sqrMod` + 13 `mulMod`) en vez de
      square-and-multiply bit a bit (~256 sqr + ~247 mul). El exponente `(P+1)/4`
      tiene 3 bloques de 1s {2, 22, 223}; se reutilizan las potencias `x2..x223`
      como en libsecp256k1. Envoltorios `@noinline` (`sqrtMul`/`sqrtSqr`) evitan
      que el compilador duplique el cuerpo de `mulMod`/`sqrMod` (~28 copias +
      60 KB de binario); el binario final queda en **241.650 B**.
      Afecta a `isValid`, `p2tr`, `compress`/`uncompress`, ECDSA/Schnorr verify,
      ECDH y BIP-32 con pubkey compressed.
- [x] **`batchToAffine`** en `point.ts`: normaliza N puntos Jacobianos con **una**
      sola `modInverse` (Montgomery) y 3N multiplicaciones. `precomputeTable`
      (GLV) acumulaba en Jacobiano y llamaba a `toAffine` 8 veces (8 inversas);
      ahora paga 1. Además, la tabla de `φ(P)` se deriva de la de `P`
      (`table2[j] = (BETA·X, Y)`) en vez de repetir 8 inversas + 7 `addMixed`.
- [x] Medición A/B (`bench:wrapper`, mismo arnés y binario release):
      `isValid` 63,1 → **27,1 µs** (×2,3); `ECDH` 395 → **96 µs** (×4,1);
      `p2tr` 138,7 → **115,1 µs** (−17 %); `fromPrivateKey p2tr` 152,4 →
      **110,9 µs** (−27 %); `Schnorr verify` 389,8 → **337,1 µs** (−13,5 %);
      `ECDSA verify` 379,7 → **369,1 µs** (−2,8 %). El resto queda dentro del
      ruido (`getPublicKey` 20,7 → 19,0 µs; `p2pkh` 4,95 → 4,94 µs).
- [x] Verificación: `field/point/glv/generator/secp256k1/ecdh/ecdsa/schnorr/address`,
      `2.1.0/{address-v210,curve-validation}` y `test/wrapper/**` →
      **334 pass / 0 fail** (y `test/wrapper/**` **85/85**).

## 13) Auditoría del wrapper para v4.0.0

- [x] **`hexToBytes` con tabla de nibbles** (`Int8Array[256]`, −1 = inválido) en vez
      de `parseInt(substr(...), 16)` por byte. Medición aislada: 32 B → 2.011 →
      **198 ns** (×10,2); 64 B → 4.472 → **276 ns** (×16,2); 66 B → 7.469 → **443 ns**
      (×16,9). Conserva el parseo laxo histórico (`"1g"` → `[1]`, `"g1"` → `[0]`).
      `bytesToHex` ya era óptimo (LUT de pares; `Array.join` resultó 2–4× más lento).
- [x] **`fromBuffer` sin copia**: `WebAssembly.instantiate` acepta `BufferSource`,
      así que se pasa la vista directamente. Antes se copiaban ~240 KB del binario
      a un `ArrayBuffer` nuevo en cada carga.
- [x] **Descartados por medición** (no tocar): `isValidPrivateKey` con fast-path
      del primer byte (6,6 → 7,6 ns, la rama extra empeora), `readOutputString`
      con `String.fromCharCode` (173–230 ns de `TextDecoder` vs 409–816 ns),
      `bytesToHex` con `Array.join` (1.450 ns vs 365 ns) y el lock `_enter/_leave`
      (ya dentro del ruido del benchmark).
- [x] A/B del wrapper (`bench:wrapper`): overhead de fachada típicamente **< 2 %**
      en criptografía pesada y **< 1 %** en direcciones/WIF (oscila con el
      turbo/JIT, incluso negativo); el cuello de botella real es el WASM
      (p. ej. `Schnorr.verify` ~0,36–0,5 ms, `p2tr` ~0,1 ms), no `src/`.
- [x] Tests nuevos `test/wrapper/wrapper-utils.test.ts` (6 casos) para hex,
      escalares, `toUint8Array`, `concatBytes` y `zeroize`.

