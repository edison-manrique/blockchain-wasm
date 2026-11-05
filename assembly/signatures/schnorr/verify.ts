/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr/verify.ts — Verificación Schnorr BIP-340 (zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   schnorr_verify(sigPtr, sigLen, msgPtr, msgLen, pubPtr, pubLen) → 1 | 0
 *       1 = firma válida, 0 = inválida (por cualquier razón: formato, s≥N,
 *       r≥P, punto fuera de curva, R infinito, R.y odd, R.x ≠ r).
 *
 *   R = s·G + (−e)·P,  con s·G vía multiplyG y (−e)·P vía glv.mul (GLV).
 *
 * Todo zero-alloc: temporales en CRYPTO_WORK (Arena.save/restore, LIFO).
 */
import { Arena } from "../../utils/arena"
import { N0, N1, N2, N3 } from "../../secp256k1/constants"
import { fromBytesPtr, isGreaterOrEqualP } from "../../secp256k1/field"
import { sub as scalarSub, isGreaterOrEqualN } from "../../secp256k1/scalar"
import { multiplyG } from "../../secp256k1/generator"
import { addPoint, toAffine, isInfinity } from "../../secp256k1/point"
import { mul as glvMul } from "../../secp256k1/glv"
import { taggedHash, scalarFromPtrModN, liftX } from "./core"
import { TAG_CHALLENGE } from "./constants"

export function schnorr_verify(
  sigPtr: usize,
  sigLen: isize,
  msgPtr: usize,
  msgLen: isize,
  pubPtr: usize,
  pubLen: isize
): i32 {
  // Formato
  if (sigLen != 64 || pubLen != 32) return 0

  const ctx = Arena.save()
  const P = Arena.alloc(96)
  const px = Arena.alloc(32)
  const rNum = Arena.alloc(32)
  const sNum = Arena.alloc(32)
  const eHash = Arena.alloc(32)
  const eVal = Arena.alloc(32)
  const N = Arena.alloc(32)
  const minusE = Arena.alloc(32)
  const R = Arena.alloc(96)
  const tempP = Arena.alloc(96)

  // P = lift_x(pub);  inválido si pub no está en la curva
  fromBytesPtr(px, pubPtr)
  if (!liftX(P, px)) {
    Arena.restore(ctx)
    return 0
  }

  // r = sig[0..32], s = sig[32..64]  (limbs LE)
  fromBytesPtr(rNum, sigPtr)
  fromBytesPtr(sNum, sigPtr + 32)

  if (isGreaterOrEqualN(sNum)) {
    Arena.restore(ctx)
    return 0 // s ≥ N
  }
  if (isGreaterOrEqualP(rNum)) {
    Arena.restore(ctx)
    return 0 // r ≥ P
  }

  // e = taggedHash("challenge", r ‖ pub ‖ msg) mod N
  //   (r y pub son los bytes BE originales de la firma y la pubkey)
  taggedHash(eHash, TAG_CHALLENGE, sigPtr, 32, pubPtr, 32, msgPtr, msgLen)
  scalarFromPtrModN(eVal, eHash)

  // −e mod N
  store<u64>(N, N0)
  store<u64>(N, N1, 8)
  store<u64>(N, N2, 16)
  store<u64>(N, N3, 24)
  scalarSub(minusE, N, eVal)

  // R = s·G + (−e)·P
  multiplyG(R, sNum)
  glvMul(tempP, P, minusE)
  addPoint(R, R, tempP)
  toAffine(R, R)

  if (isInfinity(R)) {
    Arena.restore(ctx)
    return 0 // R en el infinito
  }
  if ((load<u64>(R + 32) & 1) != 0) {
    Arena.restore(ctx)
    return 0 // R.y odd
  }
  if (memory.compare(R, rNum, 32) != 0) {
    Arena.restore(ctx)
    return 0 // R.x ≠ r
  }

  Arena.restore(ctx)
  return 1
}
