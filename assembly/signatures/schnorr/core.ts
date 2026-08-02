/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr/core.ts — Primitivas BIP-340 (tagged hash, mod N, lift_x)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   taggedHash(out32, tagId, m1, len1, m2?, len2?, m3?, len3?)
 *       = SHA256( tagH ‖ tagH ‖ m1 ‖ m2 ‖ m3 )
 *     Construye el buffer concatenado en CRYPTO_WORK y usa sha256_hash_raw
 *     one-shot (SIN la API interna frágil de SHA256).
 *
 *   scalarFromPtrModN(res, ptr)  → ptr (32 B BE) a escalar mod N (limbs LE)
 *
 *   liftX(outPoint96, xPtr32) → bool
 *       Levanta una coordenada x (limbs LE) a punto Jacobiano [X|Y|Z=1] con
 *       Y PAR (x-only BIP-340). Verifica y² == x³+7 (rechaza x sin raíz).
 *       Reusa sqrtModP de ../pubkey (sqrt mod P único, sin duplicar).
 *
 * Todo zero-alloc: temporales en CRYPTO_WORK (Memory.save/restore, LIFO).
 */
import { Memory } from "../../utils/memory"
import { P0, P1, P2, P3 } from "../../secp256k1/constants"
import { sqrMod, mulMod, add as fieldAdd, sub as fieldSub, fromBytesPtr } from "../../secp256k1/field"
import { isGreaterOrEqualN, subN } from "../../secp256k1/scalar"
import { sha256_hash_raw } from "../../hash/sha2"
import { sqrtModP } from "../../utils/pubkey"
import { TAG_HASHES } from "./constants"

// ═══════════════════════════════════════════════════════════════════════════
// TAGGED HASH  —  SHA256( tagH ‖ tagH ‖ m1 ‖ m2 ‖ m3 )
// ═══════════════════════════════════════════════════════════════════════════

export function taggedHash(
  out32: usize,
  tagId: i32,
  m1: usize,
  len1: isize,
  m2: usize = 0,
  len2: isize = 0,
  m3: usize = 0,
  len3: isize = 0
): void {
  const ctx = Memory.save()
  const total: usize = <usize>(64 + len1 + len2 + len3)
  const buf = Memory.alloc(total)

  // tagH ‖ tagH  (64 bytes, copiados byte a byte desde el StaticArray)
  const off: usize = <usize>(tagId * 32)
  for (let i: usize = 0; i < 32; i++) {
    const b: u8 = unchecked(TAG_HASHES[<i32>(off + i)])
    store<u8>(buf + i, b)
    store<u8>(buf + 32 + i, b)
  }

  // m1 ‖ m2 ‖ m3
  let p: usize = 64
  memory.copy(buf + p, m1, <usize>len1)
  p += <usize>len1
  if (len2 > 0) {
    memory.copy(buf + p, m2, <usize>len2)
    p += <usize>len2
  }
  if (len3 > 0) {
    memory.copy(buf + p, m3, <usize>len3)
  }

  sha256_hash_raw(out32, buf, <isize>total)
  Memory.restore(ctx)
}

// ═══════════════════════════════════════════════════════════════════════════
// BYTES (BE) → ESCALAR mod N
// ═══════════════════════════════════════════════════════════════════════════

/** res = int(ptr[0..32] big-endian) mod N, en limbs LE. */
export function scalarFromPtrModN(res: usize, ptr: usize): void {
  fromBytesPtr(res, ptr) // BE → limbs LE
  while (isGreaterOrEqualN(res)) {
    subN(res, res)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// LIFT_X  —  x (limbs LE) → punto Jacobiano [X|Y|Z=1] con Y par
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Levanta x a un punto de la curva con Y par (BIP-340 x-only).
 * Retorna false si x no tiene raíz cuadrada válida (punto fuera de la curva).
 * outPoint96 debe apuntar a 96 bytes.
 */
export function liftX(outPoint96: usize, xPtr32: usize): bool {
  const ctx = Memory.save()
  const c = Memory.alloc(32)
  const seven = Memory.alloc(32)
  const y = Memory.alloc(32)
  const ySq = Memory.alloc(32)
  const prime = Memory.alloc(32)

  // c = x³ + 7 mod P
  sqrMod(c, xPtr32)
  mulMod(c, c, xPtr32)
  store<u64>(seven, 7)
  store<u64>(seven, 0, 8)
  store<u64>(seven, 0, 16)
  store<u64>(seven, 0, 24)
  fieldAdd(c, c, seven)

  // y = c^((P+1)/4) mod P
  sqrtModP(y, c)

  // Verificar y² == c (si no, x no está en la curva)
  sqrMod(ySq, y)
  if (memory.compare(ySq, c, 32) != 0) {
    Memory.restore(ctx)
    return false
  }

  // Forzar Y par (x-only BIP-340)
  if ((load<u64>(y) & 1) != 0) {
    store<u64>(prime, P0)
    store<u64>(prime, P1, 8)
    store<u64>(prime, P2, 16)
    store<u64>(prime, P3, 24)
    fieldSub(y, prime, y)
  }

  // Jacobiano [X | Y | Z=1]
  memory.copy(outPoint96, xPtr32, 32)
  memory.copy(outPoint96 + 32, y, 32)
  store<u64>(outPoint96 + 64, 1)
  store<u64>(outPoint96 + 72, 0)
  store<u64>(outPoint96 + 80, 0)
  store<u64>(outPoint96 + 88, 0)

  Memory.restore(ctx)
  return true
}
