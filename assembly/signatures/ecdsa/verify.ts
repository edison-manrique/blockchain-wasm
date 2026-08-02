/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdsa/verify.ts — Verificación ECDSA secp256k1 (zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   ecdsa_verify(hashPtr32, sigPtr64, pubPtr, pubLen) → 1 | 0
 *       sigPtr64 = r(32 BE) ‖ s(32 BE).  v no se usa en verify.
 *       Acepta pubkey compressed (33 B, 0x02/0x03 → decompressToPoint) y
 *       uncompressed (65 B, 0x04) — mejora sobre el TODO del original.
 *
 *   R = u1·G + u2·Q,  con u1·G vía multiplyG y u2·Q vía glv.mul.
 *   válido ⟺ R.x mod N == r.
 *
 * Zero-alloc: temporales en CRYPTO_WORK (Memory.save/restore, LIFO).
 */
import { Memory } from "../../utils/memory"
import { fromBytesPtr, isZero, cmp } from "../../secp256k1/field"
import { mulMod as scalarMul, modInverse as scalarInv, isGreaterOrEqualN } from "../../secp256k1/scalar"
import { multiplyG } from "../../secp256k1/generator"
import { addPoint, toAffine, isInfinity } from "../../secp256k1/point"
import { mul as glvMul } from "../../secp256k1/glv"
import { decompressToPoint } from "../../utils/pubkey"
import { reduceScalar } from "./rfc6979"

export function ecdsa_verify(hashPtr32: usize, sigPtr64: usize, pubPtr: usize, pubLen: u32): i32 {
  const ctx = Memory.save()
  const r = Memory.alloc(32)
  const s = Memory.alloc(32)
  const z = Memory.alloc(32)
  const Q = Memory.alloc(96)
  const s_inv = Memory.alloc(32)
  const u1 = Memory.alloc(32)
  const u2 = Memory.alloc(32)
  const P1 = Memory.alloc(96)
  const P2 = Memory.alloc(96)
  const R = Memory.alloc(96)
  const v = Memory.alloc(32)

  // r, s, z = hash mod N
  fromBytesPtr(r, sigPtr64)
  fromBytesPtr(s, sigPtr64 + 32)
  fromBytesPtr(z, hashPtr32)
  reduceScalar(z)

  // r, s ∈ [1, N−1]
  if (isZero(r) || isGreaterOrEqualN(r) || isZero(s) || isGreaterOrEqualN(s)) {
    Memory.restore(ctx)
    return 0
  }

  // Q = pubkey (compressed → descomprimir | uncompressed → directo)
  if (pubLen == 33) {
    const p0 = load<u8>(pubPtr)
    if (p0 != 0x02 && p0 != 0x03) {
      Memory.restore(ctx)
      return 0
    }
    decompressToPoint(Q, pubPtr)
  } else if (pubLen == 65) {
    if (load<u8>(pubPtr) != 0x04) {
      Memory.restore(ctx)
      return 0
    }
    fromBytesPtr(Q, pubPtr + 1) // X
    fromBytesPtr(Q + 32, pubPtr + 33) // Y
    store<u64>(Q + 64, 1) // Z = 1
    store<u64>(Q + 72, 0)
    store<u64>(Q + 80, 0)
    store<u64>(Q + 88, 0)
  } else {
    Memory.restore(ctx)
    return 0
  }

  // u1 = z·s⁻¹,  u2 = r·s⁻¹
  scalarInv(s_inv, s)
  scalarMul(u1, z, s_inv)
  scalarMul(u2, r, s_inv)

  // R = u1·G + u2·Q
  multiplyG(P1, u1)
  glvMul(P2, Q, u2)
  addPoint(R, P1, P2)

  if (isInfinity(R)) {
    Memory.restore(ctx)
    return 0
  }

  // v = R.x mod N;  válido ⟺ v == r
  toAffine(R, R)
  memory.copy(v, R, 32)
  reduceScalar(v)

  const ok: i32 = cmp(v, r) == 0 ? 1 : 0
  Memory.restore(ctx)
  return ok
}
