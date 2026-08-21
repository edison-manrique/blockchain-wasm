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
 * CRYPTO_WORK (Memory.save/restore). Anidable con cualquier caller que use
 * CRYPTO_WORK (LIFO) o zonas disjuntas (HASH_WORK, BIP32_WORK, ADDRESS_WORK).
 *
 * ── CONTRATOS ──────────────────────────────────────────────────────────────
 * • decompressXY/decompressToPoint escriben outX/outPoint ANTES de validar;
 *   si retornan false el contenido es indefinido → el caller SIEMPRE chequea.
 * • compressRaw/uncompressRaw son aliasing-safe (out puede ser == entrada).
 * • isOnCurveXY espera limbs LE (formato interno de campo), NO bytes BE.
 */
import { P0, P1, P2, P3 } from "../secp256k1/constants"
import { Memory } from "./memory"
import { mulMod, sqrMod, add as fieldAdd, sub as fieldSub, fromBytesPtr, toBytesPtr } from "../secp256k1/field"
import { multiplyG } from "../secp256k1/generator"
import { toAffine } from "../secp256k1/point"

// (P+1)/4 en 4 limbs u64 little-endian (P ≡ 3 mod 4 ⇒ sqrt = a^((P+1)/4))
const EXP_P14_0: u64 = 0xffffffffbfffff0c
const EXP_P14_1: u64 = 0xffffffffffffffff
const EXP_P14_2: u64 = 0xffffffffffffffff
const EXP_P14_3: u64 = 0x3fffffffffffffff

// ═══════════════════════════════════════════════════════════════════════════
// SQRT MOD P
// ═══════════════════════════════════════════════════════════════════════════
/** out32 = a^((P+1)/4) mod P (square-and-multiply, LSB-first). */
export function sqrtModP(out32: usize, a32: usize): void {
  const ctx = Memory.save()
  const exp = Memory.alloc(32)
  const base = Memory.alloc(32)
  store<u64>(exp, EXP_P14_0)
  store<u64>(exp, EXP_P14_1, 8)
  store<u64>(exp, EXP_P14_2, 16)
  store<u64>(exp, EXP_P14_3, 24)
  memory.copy(base, a32, 32)
  store<u64>(out32, 1)
  store<u64>(out32, 0, 8)
  store<u64>(out32, 0, 16)
  store<u64>(out32, 0, 24)
  for (let bit: i32 = 0; bit < 256; bit++) {
    const word = load<u64>(exp + <usize>((bit >> 6) << 3))
    if ((word >> (<u64>(bit & 63))) & 1) {
      mulMod(out32, out32, base)
    }
    sqrMod(base, base)
  }
  Memory.restore(ctx)
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
  const ctx = Memory.save()
  const lhs = Memory.alloc(32) // Y²
  const rhs = Memory.alloc(32) // X³ + 7
  const seven = Memory.alloc(32)
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
  Memory.restore(ctx)
  return ok
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
  const ctx = Memory.save()
  const ySq = Memory.alloc(32)
  const chk = Memory.alloc(32)
  const seven = Memory.alloc(32)
  const prime = Memory.alloc(32)
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
    Memory.restore(ctx)
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
  Memory.restore(ctx)
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
  const ctx = Memory.save()
  const scalar = Memory.alloc(32)
  const point = Memory.alloc(96)
  const affine = Memory.alloc(64)
  fromBytesPtr(scalar, privPtr32)
  multiplyG(point, scalar)
  toAffine(affine, point)
  const yIsOdd: bool = (load<u64>(affine + 32) & 1) != 0
  store<u8>(out33, yIsOdd ? 0x03 : 0x02)
  toBytesPtr(affine, out33 + 1)
  Memory.restore(ctx)
}

/** priv (32 B BE) → uncompressed pubkey (65 B = 0x04‖X‖Y) en out65. */
export function pubkeyUncompressedFromPrivkey(out65: usize, privPtr32: usize): void {
  const ctx = Memory.save()
  const scalar = Memory.alloc(32)
  const point = Memory.alloc(96)
  const affine = Memory.alloc(64)
  fromBytesPtr(scalar, privPtr32)
  multiplyG(point, scalar)
  toAffine(affine, point)
  store<u8>(out65, 0x04)
  toBytesPtr(affine, out65 + 1)      // X
  toBytesPtr(affine + 32, out65 + 33) // Y
  Memory.restore(ctx)
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
    const ctx = Memory.save()
    const x = Memory.alloc(32)
    const y = Memory.alloc(32)
    const ok: bool = decompressXY(x, y, pubPtr)
    Memory.restore(ctx)
    if (!ok) return -1
    memory.copy(out33, pubPtr, 33)
    return 33
  }
  if (pubLen != 65 || load<u8>(pubPtr) != 0x04) return -1
  // Validar (X, Y) en la curva ANTES de comprimir
  const ctx = Memory.save()
  const x = Memory.alloc(32)
  const y = Memory.alloc(32)
  fromBytesPtr(x, pubPtr + 1)  // X (BE → limbs)
  fromBytesPtr(y, pubPtr + 33) // Y (BE → limbs)
  const ok: bool = isOnCurveXY(x, y)
  Memory.restore(ctx)
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
  const ctx = Memory.save()
  const xLimbs = Memory.alloc(32)
  const yLimbs = Memory.alloc(32)
  if (!decompressXY(xLimbs, yLimbs, pub33Ptr)) {
    Memory.restore(ctx)
    return -1 // ✅ X fuera de la curva
  }
  store<u8>(out65, 0x04)
  toBytesPtr(xLimbs, out65 + 1)  // X → bytes BE
  toBytesPtr(yLimbs, out65 + 33) // Y → bytes BE
  Memory.restore(ctx)
  return 65
}