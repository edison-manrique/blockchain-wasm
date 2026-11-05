/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr/sign.ts — Firma Schnorr BIP-340 (zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   schnorr_get_pubkey(out32, privPtr32) → 32
 *       x-only pubkey (32 B BE) = X de priv·G.
 *
 *   schnorr_sign(out64, msgPtr, msgLen, privPtr32, auxPtr32) → 64 | <0
 *       Firma BIP-340 (64 B = rx ‖ s). auxPtr32 = aux_rand (32 B).
 *       Retorna SCHNORR_ERR_K_ZERO si el nonce k resulta 0.
 *
 * Convención BIP-340: se trabaja con x-only (Y par). Si P.y (o R.y) es odd,
 * se niega el escalar (d ← N−d, k ← N−k) para que la firma sea válida.
 *
 * Todo zero-alloc: temporales en CRYPTO_WORK (Arena.save/restore, LIFO).
 */
import { Arena } from "../../utils/arena"
import { N0, N1, N2, N3 } from "../../secp256k1/constants"
import { fromBytesPtr, toBytesPtr } from "../../secp256k1/field"
import { mulMod as scalarMul, add as scalarAdd, sub as scalarSub, isZero } from "../../secp256k1/scalar"
import { multiplyG } from "../../secp256k1/generator"
import { toAffine } from "../../secp256k1/point"
import { taggedHash, scalarFromPtrModN } from "./core"
import { TAG_AUX, TAG_NONCE, TAG_CHALLENGE, SCHNORR_ERR_K_ZERO } from "./constants"

// ═══════════════════════════════════════════════════════════════════════════
// X-ONLY PUBLIC KEY
// ═══════════════════════════════════════════════════════════════════════════

/** out32 = x_only(priv·G) en bytes big-endian. Retorna 32. */
export function schnorr_get_pubkey(out32: usize, privPtr32: usize): i32 {
  const ctx = Arena.save()
  const d = Arena.alloc(32)
  const P = Arena.alloc(96)

  fromBytesPtr(d, privPtr32)
  multiplyG(P, d)
  toAffine(P, P)
  toBytesPtr(P, out32) // X → bytes BE

  Arena.restore(ctx)
  return 32
}

// ═══════════════════════════════════════════════════════════════════════════
// SIGN
// ═══════════════════════════════════════════════════════════════════════════

export function schnorr_sign(out64: usize, msgPtr: usize, msgLen: isize, privPtr32: usize, auxPtr32: usize): i32 {
  const ctx = Arena.save()
  const d_ = Arena.alloc(32)
  const P = Arena.alloc(96)
  const d = Arena.alloc(32)
  const pxPtr = Arena.alloc(32)
  const dPtr = Arena.alloc(32)
  const auxHash = Arena.alloc(32)
  const tPtr = Arena.alloc(32)
  const rand = Arena.alloc(32)
  const k_ = Arena.alloc(32)
  const R = Arena.alloc(96)
  const kVal = Arena.alloc(32)
  const rxPtr = Arena.alloc(32)
  const eHash = Arena.alloc(32)
  const eVal = Arena.alloc(32)
  const s = Arena.alloc(32)
  const N = Arena.alloc(32)

  store<u64>(N, N0)
  store<u64>(N, N1, 8)
  store<u64>(N, N2, 16)
  store<u64>(N, N3, 24)

  // d' = priv;  P = d'·G → afín
  fromBytesPtr(d_, privPtr32)
  multiplyG(P, d_)
  toAffine(P, P)

  // d = d' si P.y par, else N − d'
  if ((load<u64>(P + 32) & 1) == 0) {
    memory.copy(d, d_, 32)
  } else {
    scalarSub(d, N, d_)
  }

  // px = x_only(P) (BE);  dPtr = d (BE)
  toBytesPtr(P, pxPtr)
  toBytesPtr(d, dPtr)

  // t = dPtr ⊕ taggedHash("aux", auxRand)
  taggedHash(auxHash, TAG_AUX, auxPtr32, 32)
  for (let i: usize = 0; i < 32; i++) {
    store<u8>(tPtr + i, <u8>(load<u8>(dPtr + i) ^ load<u8>(auxHash + i)))
  }

  // rand = taggedHash("nonce", t ‖ px ‖ msg);  k' = rand mod N
  taggedHash(rand, TAG_NONCE, tPtr, 32, pxPtr, 32, msgPtr, msgLen)
  scalarFromPtrModN(k_, rand)
  if (isZero(k_)) {
    Arena.restore(ctx)
    return SCHNORR_ERR_K_ZERO
  }

  // R = k'·G → afín;  k = k' si R.y par, else N − k'
  multiplyG(R, k_)
  toAffine(R, R)
  if ((load<u64>(R + 32) & 1) == 0) {
    memory.copy(kVal, k_, 32)
  } else {
    scalarSub(kVal, N, k_)
  }

  // rx = x_only(R) (BE)
  toBytesPtr(R, rxPtr)

  // e = taggedHash("challenge", rx ‖ px ‖ msg) mod N
  taggedHash(eHash, TAG_CHALLENGE, rxPtr, 32, pxPtr, 32, msgPtr, msgLen)
  scalarFromPtrModN(eVal, eHash)

  // s = (k + e·d) mod N
  scalarMul(s, eVal, d)
  scalarAdd(s, kVal, s)

  // sig = rx ‖ s
  memory.copy(out64, rxPtr, 32)
  toBytesPtr(s, out64 + 32)

  Arena.restore(ctx)
  return 64
}
