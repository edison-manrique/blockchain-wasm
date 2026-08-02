/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdsa/sign.ts — Firma ECDSA secp256k1 (zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   ecdsa_sign(out65, hashPtr32, privPtr32) → 65 | <0
 *       out65 = r(32 BE) ‖ s(32 BE) ‖ recId(1).
 *       Nonce k determinístico (RFC 6979 vía generateK).
 *       Canonical S (BIP-62): si s > N/2 → s = N−s y recId ^= 1.
 *       recId = paridad de R.y (bit 0), flippeado si se canoniza s.
 *
 * Usa toAffine (más limpio que el z_inv manual del original).
 * Zero-alloc: temporales en CRYPTO_WORK (Memory.save/restore, LIFO).
 */
import { Memory } from "../../utils/memory"
import { N0, N1, N2, N3 } from "../../secp256k1/constants"
import { fromBytesPtr, toBytesPtr, isZero, cmp, subRaw } from "../../secp256k1/field"
import { mulMod as scalarMul, add as scalarAdd, modInverse as scalarInv } from "../../secp256k1/scalar"
import { multiplyG } from "../../secp256k1/generator"
import { toAffine, isInfinity } from "../../secp256k1/point"
import { generateK, reduceScalar } from "./rfc6979"
import {
  N_HALF_0,
  N_HALF_1,
  N_HALF_2,
  N_HALF_3,
  ECDSA_ERR_R_ZERO,
  ECDSA_ERR_S_ZERO,
  ECDSA_ERR_K_INF
} from "./constants"

export function ecdsa_sign(out65: usize, hashPtr32: usize, privPtr32: usize): i32 {
  const ctx = Memory.save()
  const z = Memory.alloc(32)
  const d = Memory.alloc(32)
  const k = Memory.alloc(32)
  const R = Memory.alloc(96)
  const r = Memory.alloc(32)
  const k_inv = Memory.alloc(32)
  const rd = Memory.alloc(32)
  const z_rd = Memory.alloc(32)
  const s = Memory.alloc(32)
  const n_half = Memory.alloc(32)
  const N = Memory.alloc(32)

  store<u64>(N, N0)
  store<u64>(N, N1, 8)
  store<u64>(N, N2, 16)
  store<u64>(N, N3, 24)
  store<u64>(n_half, N_HALF_0)
  store<u64>(n_half, N_HALF_1, 8)
  store<u64>(n_half, N_HALF_2, 16)
  store<u64>(n_half, N_HALF_3, 24)

  // z = hash mod N;  d = priv
  fromBytesPtr(z, hashPtr32)
  reduceScalar(z)
  fromBytesPtr(d, privPtr32)

  // k = RFC 6979 (determinístico, 0 < k < N)
  generateK(k, hashPtr32, privPtr32)

  // R = k·G → afín
  multiplyG(R, k)
  if (isInfinity(R)) {
    Memory.restore(ctx)
    return ECDSA_ERR_K_INF
  }
  toAffine(R, R)

  // r = R.x mod N
  memory.copy(r, R, 32)
  reduceScalar(r)
  if (isZero(r)) {
    Memory.restore(ctx)
    return ECDSA_ERR_R_ZERO
  }

  // recId = paridad de R.y
  let recId: u8 = 0
  if ((load<u64>(R + 32) & 1) != 0) recId |= 1

  // s = k⁻¹·(z + r·d) mod N
  scalarInv(k_inv, k)
  scalarMul(rd, r, d)
  scalarAdd(z_rd, z, rd)
  scalarMul(s, k_inv, z_rd)
  if (isZero(s)) {
    Memory.restore(ctx)
    return ECDSA_ERR_S_ZERO
  }

  // canonical S (BIP-62): si s > N/2 → s = N−s, recId ^= 1
  if (cmp(s, n_half) >= 0) {
    subRaw(s, N, s)
    recId ^= 1
  }

  // out = r ‖ s ‖ recId
  toBytesPtr(r, out65)
  toBytesPtr(s, out65 + 32)
  store<u8>(out65 + 64, recId)

  Memory.restore(ctx)
  return 65
}
