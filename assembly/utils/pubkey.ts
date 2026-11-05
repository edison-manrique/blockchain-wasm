/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  pubkey.ts — Utilidades de clave pública secp256k1 (zero-alloc, compartido)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Consolida la lógica de curva sobre claves públicas que antes estaba
 * triplicada (sqrt mod P / descompresión): la usan `address/` y `bip32/` por
 * igual, sin dependencia jerárquica entre ambos.
 *
 * ── VALIDACIÓN DE CURVA (BLOQUE 1) ─────────────────────────────────────────
 * Toda descompresión VERIFICA pertenencia a la curva: tras sqrtModP se comprueba
 * y² ≡ x³+7 (mod P). Sin este chequeo, una X sin raíz cuadrada producía un
 * "punto" basura silencioso (P ≡ 3 mod 4 ⇒ a^((P+1)/4) devuelve basura para
 * no-residuos). Las entradas uncompressed se validan con isOnCurveXY.
 *
 *   sqrtModP(out32, a32)                          ← a^((P+1)/4) mod P
 *   isOnCurveXY(xLimbs32, yLimbs32) → bool        ← Y² ≡ X³+7 (limbs LE)
 *   decompressXY(outX32, outY32, pub33) → bool    ← false: prefijo o curva inválidos
 *   decompressToPoint(outPoint96, pub33) → bool   ← false: prefijo o curva inválidos
 *   pubkeyFromPrivkey(out33, priv32)              ← priv → compressed
 *   pubkeyUncompressedFromPrivkey(out65, priv32)  ← priv → uncompressed
 *   compressRaw(out33, pubPtr, pubLen) → i32      ← 65→33 / 33→33 validando curva | -1
 *   uncompressRaw(out65, pub33) → i32             ← 33→65 validando curva | -1
 *
 * ── ZONA DEL ARENA ─────────────────────────────────────────────────────────
 * CRYPTO_WORK (Arena.save/restore). Anidable con cualquier caller que use
 * CRYPTO_WORK (LIFO) o zonas disjuntas (HASH_WORK, BIP32_WORK, ADDRESS_WORK).
 *
 * ── CONTRATOS ──────────────────────────────────────────────────────────────
 * • decompressXY/decompressToPoint escriben outX/outPoint ANTES de validar;
 *   si retornan false el contenido es indefinido → el caller SIEMPRE chequea.
 * • compressRaw/uncompressRaw son aliasing-safe (out puede ser == entrada).
 * • isOnCurveXY espera limbs LE (formato interno de campo), NO bytes BE.
 */
import { P0, P1, P2, P3 } from "../secp256k1/constants"
import { Arena } from "./arena"
import { mulMod, sqrMod, add as fieldAdd, sub as fieldSub, fromBytesPtr, toBytesPtr } from "../secp256k1/field"
import { multiplyG } from "../secp256k1/generator"
import { toAffine } from "../secp256k1/point"

// ═══════════════════════════════════════════════════════════════════════════
// SQRT MOD P
// ═══════════════════════════════════════════════════════════════════════════
/**
 * Envoltorios NO inline para la cadena de sqrt. `mulMod`/`sqrMod` son
 * `@inline` y muy grandes; si la cadena los llamara directamente, el compilador
 * duplicaría ~28 copias del cuerpo (binario +60 KB, peor huella de I-cache).
 * Estas funciones se compilan una sola vez y la cadena paga solo un call.
 */
// @ts-ignore
@noinline
function sqrtMul(res: usize, a: usize, b: usize): void {
  mulMod(res, a, b)
}
// @ts-ignore
@noinline
function sqrtSqr(res: usize, a: usize): void {
  sqrMod(res, a)
}

/**
 * out32 = a^((P+1)/4) mod P.
 *
 * `(P+1)/4` tiene 3 bloques de 1s de longitudes {2, 22, 223}. En lugar de un
 * square-and-multiply bit a bit (~247 mulMod), se usa la cadena de adiciones
 * de libsecp256k1: 253 sqrMod + 13 mulMod (~47% menos operaciones de campo).
 * El coste dominaba `isValid`, `p2tr`, `compress`/`uncompress` y ECDH/Schnorr.
 */
export function sqrtModP(out32: usize, a32: usize): void {
  const ctx = Arena.save()
  const x2 = Arena.alloc(32)
  const x3 = Arena.alloc(32)
  const x6 = Arena.alloc(32)
  const x9 = Arena.alloc(32)
  const x11 = Arena.alloc(32)
  const x22 = Arena.alloc(32)
  const x44 = Arena.alloc(32)
  const x88 = Arena.alloc(32)
  const x176 = Arena.alloc(32)
  const x220 = Arena.alloc(32)
  const x223 = Arena.alloc(32)
  const t1 = Arena.alloc(32)

  // x2  = a^(2^2 − 1) = a^3
  sqrtSqr(x2, a32)
  sqrtMul(x2, x2, a32)

  // x3  = a^(2^3 − 1) = a^7
  sqrtSqr(x3, x2)
  sqrtMul(x3, x3, a32)

  // x6  = a^(2^6 − 1)
  memory.copy(x6, x3, 32)
  for (let j: i32 = 0; j < 3; j++) sqrtSqr(x6, x6)
  sqrtMul(x6, x6, x3)

  // x9  = a^(2^9 − 1)
  memory.copy(x9, x6, 32)
  for (let j: i32 = 0; j < 3; j++) sqrtSqr(x9, x9)
  sqrtMul(x9, x9, x3)

  // x11 = a^(2^11 − 1)
  memory.copy(x11, x9, 32)
  for (let j: i32 = 0; j < 2; j++) sqrtSqr(x11, x11)
  sqrtMul(x11, x11, x2)

  // x22 = a^(2^22 − 1)
  memory.copy(x22, x11, 32)
  for (let j: i32 = 0; j < 11; j++) sqrtSqr(x22, x22)
  sqrtMul(x22, x22, x11)

  // x44 = a^(2^44 − 1)
  memory.copy(x44, x22, 32)
  for (let j: i32 = 0; j < 22; j++) sqrtSqr(x44, x44)
  sqrtMul(x44, x44, x22)

  // x88 = a^(2^88 − 1)
  memory.copy(x88, x44, 32)
  for (let j: i32 = 0; j < 44; j++) sqrtSqr(x88, x88)
  sqrtMul(x88, x88, x44)

  // x176 = a^(2^176 − 1)
  memory.copy(x176, x88, 32)
  for (let j: i32 = 0; j < 88; j++) sqrtSqr(x176, x176)
  sqrtMul(x176, x176, x88)

  // x220 = a^(2^220 − 1)
  memory.copy(x220, x176, 32)
  for (let j: i32 = 0; j < 44; j++) sqrtSqr(x220, x220)
  sqrtMul(x220, x220, x44)

  // x223 = a^(2^223 − 1)
  memory.copy(x223, x220, 32)
  for (let j: i32 = 0; j < 3; j++) sqrtSqr(x223, x223)
  sqrtMul(x223, x223, x3)

  // Ensamblado final: 223 + 23, +22, +6, +2 y 2 squarings.
  memory.copy(t1, x223, 32)
  for (let j: i32 = 0; j < 23; j++) sqrtSqr(t1, t1)
  sqrtMul(t1, t1, x22)
  for (let j: i32 = 0; j < 6; j++) sqrtSqr(t1, t1)
  sqrtMul(t1, t1, x2)
  sqrtSqr(t1, t1)
  sqrtSqr(out32, t1)

  Arena.restore(ctx)
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDACIÓN DE PERTENENCIA A LA CURVA
// ═══════════════════════════════════════════════════════════════════════════
/**
 * Verifica Y² ≡ X³ + 7 (mod P) para coordenadas afines en LIMBS LE (32 B c/u).
 * Aliasing-safe: x/y pueden apuntar a cualquier zona (PARAM_IN, ADDRESS_WORK,
 * CRYPTO_WORK previo…); los temporales se alojan después (bump, sin solape).
 */
export function isOnCurveXY(xLimbs32: usize, yLimbs32: usize): bool {
  const ctx = Arena.save()
  const lhs = Arena.alloc(32) // Y²
  const rhs = Arena.alloc(32) // X³ + 7
  const seven = Arena.alloc(32)
  // lhs = Y²
  sqrMod(lhs, yLimbs32)
  // rhs = X³ + 7
  sqrMod(rhs, xLimbs32)
  mulMod(rhs, rhs, xLimbs32)
  store<u64>(seven, 7)
  store<u64>(seven, 0, 8)
  store<u64>(seven, 0, 16)
  store<u64>(seven, 0, 24)
  fieldAdd(rhs, rhs, seven)
  const ok: bool = memory.compare(lhs, rhs, 32) == 0
  Arena.restore(ctx)
  return ok
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDACIÓN OPT-IN DE CLAVE PÚBLICA (export independiente)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * Valida formato y pertenencia a la curva de una pubkey (33/65/64 B).
 *
 * Es un chequeo EXPLÍCITO: las funciones de dirección ya NO lo ejecutan para
 * no penalizar el hot path (el sqrt modular de una clave compressed cuesta
 * ~40–60 µs). Los llamadores que necesiten seguridad estricta lo invocan aquí.
 *
 * @returns 1 = válida; 0 = prefijo/longitud inválidos o punto fuera de curva.
 */
export function pubkeyValidateRaw(pubPtr: usize, pubLen: u32): i32 {
  const ctx = Arena.save()
  const x = Arena.alloc(32)
  const y = Arena.alloc(32)
  const xy = pubLen == 65 ? pubPtr + 1 : pubPtr
  let ok = false
  if (pubLen == 33) {
    const prefix = load<u8>(pubPtr)
    if (prefix == 0x02 || prefix == 0x03) ok = decompressXY(x, y, pubPtr)
  } else if (pubLen == 65) {
    if (load<u8>(pubPtr) == 0x04) ok = isOnCurveBytes(x, y, xy)
  } else if (pubLen == 64) {
    ok = isOnCurveBytes(x, y, xy)
  }
  Arena.restore(ctx)
  return ok ? 1 : 0
}

/** X‖Y (64 B BE) → limbs y comprobación Y² ≡ X³+7. */
// @ts-ignore
@inline
function isOnCurveBytes(x: usize, y: usize, xy64: usize): bool {
  fromBytesPtr(x, xy64)
  fromBytesPtr(y, xy64 + 32)
  return isOnCurveXY(x, y)
}

// ═══════════════════════════════════════════════════════════════════════════
// DESCOMPRESIÓN (con verificación de curva)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * Descomprime una pubkey compressed (33 B) a coordenadas afines (x, y).
 * Ajusta la paridad de Y según el prefijo (0x02 → par, 0x03 → impar).
 * outX y outY DEBEN ser punteros distintos (32 B cada uno).
 *
 * @returns true = punto válido en la curva; false = prefijo inválido o X sin
 *          raíz cuadrada válida (y² ≢ x³+7). En false, outX/outY son basura.
 */
export function decompressXY(outX32: usize, outY32: usize, pub33Ptr: usize): bool {
  const prefix = load<u8>(pub33Ptr)
  if (prefix != 0x02 && prefix != 0x03) return false
  const ctx = Arena.save()
  const ySq = Arena.alloc(32)
  const chk = Arena.alloc(32)
  const seven = Arena.alloc(32)
  const prime = Arena.alloc(32)
  // X directo en la salida
  fromBytesPtr(outX32, pub33Ptr + 1)
  // ySq = X³ + 7 mod P
  sqrMod(ySq, outX32)
  mulMod(ySq, ySq, outX32)
  store<u64>(seven, 7)
  store<u64>(seven, 0, 8)
  store<u64>(seven, 0, 16)
  store<u64>(seven, 0, 24)
  fieldAdd(ySq, ySq, seven)
  // Y = sqrt(ySq)
  sqrtModP(outY32, ySq)
  // ✅ VALIDACIÓN: y² ≡ x³+7 (mod P). Si X no está en la curva, sqrt devuelve
  // basura y su cuadrado no coincide con ySq → rechazar.
  sqrMod(chk, outY32)
  if (memory.compare(chk, ySq, 32) != 0) {
    Arena.restore(ctx)
    return false
  }
  // Ajuste de paridad
  const calcIsOdd: bool = (load<u64>(outY32) & 1) == 1
  const wantOdd: bool = prefix == 0x03
  if (calcIsOdd != wantOdd) {
    store<u64>(prime, P0)
    store<u64>(prime, P1, 8)
    store<u64>(prime, P2, 16)
    store<u64>(prime, P3, 24)
    fieldSub(outY32, prime, outY32)
  }
  Arena.restore(ctx)
  return true
}

/**
 * Descomprime una pubkey compressed (33 B) a Jacobiano [X|Y|Z=1] (96 B).
 * @returns true = válido; false = prefijo inválido o punto fuera de la curva
 *          (en cuyo caso outPoint96 es basura y NO debe usarse).
 */
export function decompressToPoint(outPoint96: usize, pub33Ptr: usize): bool {
  if (!decompressXY(outPoint96, outPoint96 + 32, pub33Ptr)) return false
  store<u64>(outPoint96 + 64, 1)
  store<u64>(outPoint96 + 72, 0)
  store<u64>(outPoint96 + 80, 0)
  store<u64>(outPoint96 + 88, 0)
  return true
}

// ═══════════════════════════════════════════════════════════════════════════
// PRIV → PUB
// ═══════════════════════════════════════════════════════════════════════════
/** priv (32 B BE) → compressed pubkey (33 B) en out33. */
export function pubkeyFromPrivkey(out33: usize, privPtr32: usize): void {
  const ctx = Arena.save()
  const scalar = Arena.alloc(32)
  const point = Arena.alloc(96)
  const affine = Arena.alloc(64)
  fromBytesPtr(scalar, privPtr32)
  multiplyG(point, scalar)
  toAffine(affine, point)
  const yIsOdd: bool = (load<u64>(affine + 32) & 1) != 0
  store<u8>(out33, yIsOdd ? 0x03 : 0x02)
  toBytesPtr(affine, out33 + 1)
  Arena.restore(ctx)
}

/** priv (32 B BE) → uncompressed pubkey (65 B = 0x04‖X‖Y) en out65. */
export function pubkeyUncompressedFromPrivkey(out65: usize, privPtr32: usize): void {
  const ctx = Arena.save()
  const scalar = Arena.alloc(32)
  const point = Arena.alloc(96)
  const affine = Arena.alloc(64)
  fromBytesPtr(scalar, privPtr32)
  multiplyG(point, scalar)
  toAffine(affine, point)
  store<u8>(out65, 0x04)
  toBytesPtr(affine, out65 + 1)      // X
  toBytesPtr(affine + 32, out65 + 33) // Y
  Arena.restore(ctx)
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPRESS / UNCOMPRESS (con validación de curva)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * Comprime una pubkey a 33 B validando pertenencia a la curva.
 *   • 33 B → re-valida el punto (lift de X + y²≡x³+7) y copia.
 *   • 65 B → valida (X,Y) en la curva y comprime.
 * Aliasing-safe: out33 puede ser == pubPtr.
 * @returns 33, o -1 si formato/prefijo inválido o punto fuera de la curva.
 */
export function compressRaw(out33: usize, pubPtr: usize, pubLen: u32): i32 {
  if (pubLen == 33) {
    const p = load<u8>(pubPtr)
    if (p != 0x02 && p != 0x03) return -1
    // Re-validación completa: X debe levantar un punto real de la curva
    const ctx = Arena.save()
    const x = Arena.alloc(32)
    const y = Arena.alloc(32)
    const ok: bool = decompressXY(x, y, pubPtr)
    Arena.restore(ctx)
    if (!ok) return -1
    memory.copy(out33, pubPtr, 33)
    return 33
  }
  if (pubLen != 65 || load<u8>(pubPtr) != 0x04) return -1
  // Validar (X, Y) en la curva ANTES de comprimir
  const ctx = Arena.save()
  const x = Arena.alloc(32)
  const y = Arena.alloc(32)
  fromBytesPtr(x, pubPtr + 1)  // X (BE → limbs)
  fromBytesPtr(y, pubPtr + 33) // Y (BE → limbs)
  const ok: bool = isOnCurveXY(x, y)
  Arena.restore(ctx)
  if (!ok) return -1
  const isOdd: bool = (load<u8>(pubPtr + 64) & 1) != 0
  store<u8>(out33, isOdd ? 0x03 : 0x02)
  memory.copy(out33 + 1, pubPtr + 1, 32)
  return 33
}

/**
 * Descomprime una pubkey compressed (33 B) a 65 B (0x04‖X‖Y), validando que
 * X levante un punto real de la curva (y² ≡ x³+7).
 * Aliasing-safe: out65 puede ser == pub33Ptr (la lectura ocurre antes del write).
 * @returns 65, o -1 si prefijo inválido o X fuera de la curva.
 */
export function uncompressRaw(out65: usize, pub33Ptr: usize): i32 {
  const prefix = load<u8>(pub33Ptr)
  if (prefix != 0x02 && prefix != 0x03) return -1
  const ctx = Arena.save()
  const xLimbs = Arena.alloc(32)
  const yLimbs = Arena.alloc(32)
  if (!decompressXY(xLimbs, yLimbs, pub33Ptr)) {
    Arena.restore(ctx)
    return -1 // ✅ X fuera de la curva
  }
  store<u8>(out65, 0x04)
  toBytesPtr(xLimbs, out65 + 1)  // X → bytes BE
  toBytesPtr(yLimbs, out65 + 33) // Y → bytes BE
  Arena.restore(ctx)
  return 65
}