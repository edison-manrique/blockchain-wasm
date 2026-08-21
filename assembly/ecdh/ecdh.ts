/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdh/ecdh.ts — ECDH secp256k1 (zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   ecdh_shared_secret(out33, privPtr32, pubPtr, pubLen) → 33 | <0
 *       Shared secret = compressed(d·Q) = (02/03 ‖ X) de d·Q.
 *       Acepta pubkey compressed (33 B, 0x02/0x03 → decompressToPoint) y
 *       uncompressed (65 B, 0x04) — mejora sobre el original (solo uncompressed).
 *
 * ── VALIDACIÓN DE CURVA (BLOQUE 2) ─────────────────────────────────────────
 * • 33 B: decompressToPoint verifica prefijo + y² ≡ x³+7 (mod P) → false si
 *   la X no levanta un punto real. Antes se aceptaban puntos fuera de curva.
 * • 65 B: isOnCurveXY(X, Y) verifica pertenencia a la curva. Antes NO se
 *   validaba nada (un atacante podía inyectar cualquier (X,Y)).
 *
 * Usa toAffine (reemplaza la normalización z_inv/z_inv²/z_inv³ manual del
 * original) y glv.mul para d·Q.
 *
 * ── ZONA DEL ARENA ─────────────────────────────────────────────────────────
 * Zero-alloc: Q/d/P en CRYPTO_WORK (Memory.save/restore); glv.mul / toAffine /
 * decompressToPoint / isOnCurveXY usan CRYPTO_WORK internamente (anidación
 * LIFO segura).
 */
import { Memory } from "../utils/memory"
import { fromBytesPtr, toBytesPtr } from "../secp256k1/field"
import { toAffine, isInfinity } from "../secp256k1/point"
import { mul as glvMul } from "../secp256k1/glv"
import { decompressToPoint, isOnCurveXY } from "../utils/pubkey"

// ── Códigos de error (retorno i32; 0 = OK) ────────────────────────────────
export const ECDH_OK: i32 = 0
export const ECDH_ERR_PRIV_LEN: i32 = -1 // privkey ≠ 32 B (lo valida el wrapper)
export const ECDH_ERR_PUB_FORMAT: i32 = -2 // pubkey malformada / fuera de la curva
export const ECDH_ERR_INFINITY: i32 = -3 // d·Q en el infinito

export function ecdh_shared_secret(out33: usize, privPtr32: usize, pubPtr: usize, pubLen: u32): i32 {
  const ctx = Memory.save()
  const Q = Memory.alloc(96)
  const d = Memory.alloc(32)
  const P = Memory.alloc(96)

  // Q = pubkey (compressed → descomprimir | uncompressed → directo), VALIDADA
  if (pubLen == 33) {
    const p0 = load<u8>(pubPtr)
    if (p0 != 0x02 && p0 != 0x03) {
      Memory.restore(ctx)
      return ECDH_ERR_PUB_FORMAT
    }
    // ✅ VALIDACIÓN: prefijo + y² ≡ x³+7 (rechaza X fuera de la curva)
    if (!decompressToPoint(Q, pubPtr)) {
      Memory.restore(ctx)
      return ECDH_ERR_PUB_FORMAT
    }
  } else if (pubLen == 65) {
    if (load<u8>(pubPtr) != 0x04) {
      Memory.restore(ctx)
      return ECDH_ERR_PUB_FORMAT
    }
    fromBytesPtr(Q, pubPtr + 1)       // X → limbs LE
    fromBytesPtr(Q + 32, pubPtr + 33) // Y → limbs LE
    // ✅ VALIDACIÓN: (X, Y) debe pertenecer a la curva
    if (!isOnCurveXY(Q, Q + 32)) {
      Memory.restore(ctx)
      return ECDH_ERR_PUB_FORMAT
    }
    store<u64>(Q + 64, 1) // Z = 1
    store<u64>(Q + 72, 0)
    store<u64>(Q + 80, 0)
    store<u64>(Q + 88, 0)
  } else {
    Memory.restore(ctx)
    return ECDH_ERR_PUB_FORMAT
  }

  // d = priv;  P = d·Q
  fromBytesPtr(d, privPtr32)
  glvMul(P, Q, d)
  if (isInfinity(P)) {
    Memory.restore(ctx)
    return ECDH_ERR_INFINITY
  }

  // P afín: X en P[0..32), Y en P[32..64)
  toAffine(P, P)

  // compressed: 0x02/0x03 según paridad de Y, ‖ X (BE)
  const yLsb: u8 = <u8>(load<u64>(P + 32) & 1)
  store<u8>(out33, yLsb ? 0x03 : 0x02)
  toBytesPtr(P, out33 + 1)

  Memory.restore(ctx)
  return 33
}