/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr/aggregate.ts — Agregación naive de claves (zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   schnorr_aggregate_pubkeys(out32, pubsPtr, count)  → 32 | <0
 *       pubsPtr = count × 32 B (x-only, big-endian). Σ liftX(pub_i).
 *
 *   schnorr_aggregate_privkeys(out32, privsPtr, count) → 32 | <0
 *       privsPtr = count × 32 B (big-endian). Σ d_i con ajuste de paridad
 *       (si d_i·G tiene Y odd → d_i ← N−d_i), para que coincida con la
 *       agregación pública (liftX fuerza Y par). Ajuste final de paridad.
 *
 * ⚠️ AGREGACIÓN NAIVE (suma simple, SIN coeficientes de MuSig/BIP-326).
 *    Vulnerable a rogue-key attack; úsala solo cuando las claves se generen
 *    de forma confiable o con prueba de posesión. Se porta tal cual el código
 *    original. La propiedad  get_pubkey(agg_priv) == agg_pub  se cumple por
 *    construcción (ajustes de paridad consistentes con liftX).
 *
 * Todo zero-alloc: temporales en CRYPTO_WORK (Memory.save/restore, LIFO).
 */
import { Memory } from "../../utils/memory"
import { N0, N1, N2, N3 } from "../../secp256k1/constants"
import { fromBytesPtr, toBytesPtr } from "../../secp256k1/field"
import { add as scalarAdd, sub as scalarSub } from "../../secp256k1/scalar"
import { multiplyG } from "../../secp256k1/generator"
import { addPoint, toAffine, isInfinity } from "../../secp256k1/point"
import { liftX } from "./core"
import { SCHNORR_ERR_COUNT, SCHNORR_ERR_PUBKEY, SCHNORR_ERR_INFINITY } from "./constants"

// ═══════════════════════════════════════════════════════════════════════════
// AGREGACIÓN DE CLAVES PÚBLICAS
// ═══════════════════════════════════════════════════════════════════════════

export function schnorr_aggregate_pubkeys(out32: usize, pubsPtr: usize, count: u32): i32 {
  if (count == 0) return SCHNORR_ERR_COUNT

  const ctx = Memory.save()
  const P_agg = Memory.alloc(96)
  const tempP = Memory.alloc(96)
  const px = Memory.alloc(32)

  for (let i: u32 = 0; i < count; i++) {
    fromBytesPtr(px, pubsPtr + <usize>(i << 5))
    if (!liftX(tempP, px)) {
      Memory.restore(ctx)
      return SCHNORR_ERR_PUBKEY
    }
    if (i == 0) {
      memory.copy(P_agg, tempP, 96)
    } else {
      addPoint(P_agg, P_agg, tempP)
    }
  }

  if (isInfinity(P_agg)) {
    Memory.restore(ctx)
    return SCHNORR_ERR_INFINITY
  }

  toAffine(P_agg, P_agg)
  toBytesPtr(P_agg, out32)

  Memory.restore(ctx)
  return 32
}

// ═══════════════════════════════════════════════════════════════════════════
// AGREGACIÓN DE CLAVES PRIVADAS
// ═══════════════════════════════════════════════════════════════════════════

export function schnorr_aggregate_privkeys(out32: usize, privsPtr: usize, count: u32): i32 {
  if (count == 0) return SCHNORR_ERR_COUNT

  const ctx = Memory.save()
  const sum = Memory.alloc(32)
  const d = Memory.alloc(32)
  const P = Memory.alloc(96)
  const N = Memory.alloc(32)

  store<u64>(sum, 0)
  store<u64>(sum, 0, 8)
  store<u64>(sum, 0, 16)
  store<u64>(sum, 0, 24)
  store<u64>(N, N0)
  store<u64>(N, N1, 8)
  store<u64>(N, N2, 16)
  store<u64>(N, N3, 24)

  for (let i: u32 = 0; i < count; i++) {
    fromBytesPtr(d, privsPtr + <usize>(i << 5))
    multiplyG(P, d)
    toAffine(P, P)
    // Si d·G tiene Y odd, liftX usaría −(d·G); negamos d para que coincida
    if ((load<u64>(P + 32) & 1) != 0) {
      scalarSub(d, N, d)
    }
    scalarAdd(sum, sum, d)
  }

  // Ajuste final de paridad (consistencia con x-only; no afecta a sign)
  multiplyG(P, sum)
  toAffine(P, P)
  if ((load<u64>(P + 32) & 1) != 0) {
    scalarSub(sum, N, sum)
  }

  toBytesPtr(sum, out32)

  Memory.restore(ctx)
  return 32
}
