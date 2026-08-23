/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  musig2/nonce.ts — Nonce generation & aggregation (BIP-327 estricto)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   musig2_nonce_gen(out_k64, out_r66, ...) → MUSIG_OK | <0
 *       pubnonce = cbytes(R₁) ‖ cbytes(R₂)  = 66 B  (33 + 33 compressed)
 *       secnonce = k₁ ‖ k₂                  = 64 B  (k originales, sin negar)
 *
 *   musig2_nonce_agg(out_r66, noncesPtr, count) → MUSIG_OK | <0
 *       aggnonce = cbytes_ext(R₁) ‖ cbytes_ext(R₂) = 66 B  (∞ → 33 ceros)
 *       NO falla si R₁ o R₂ son ∞ (BIP-327 permite aggnonce infinito).
 *
 * v3.1: cumplimiento BIP-327 (compressed points, aggnonce puede ser ∞,
 *       k no se niega en nonce_gen — la negación ocurre en partial_sign
 *       según la paridad del nonce FINAL de la sesión).
 *
 * Zero-alloc: CRYPTO_WORK (Memory.save/restore, LIFO).
 */
import { Memory } from "../../../utils/memory"
import { N0, N1, N2, N3 } from "../../../secp256k1/constants"
import { toBytesPtr } from "../../../secp256k1/field"
import { isZero } from "../../../secp256k1/scalar"
import { multiplyG } from "../../../secp256k1/generator"
import { addPoint, isInfinity, setInfinity } from "../../../secp256k1/point"
import {
  taggedHash,
  scalarFromPtrModN,
  pushChunk,
  musigTagPtr,
  taggedHashMulti,
  xorInto,
  cpointToPoint,
  writeCbytesExt
} from "../core"
import {
  TAG_MUSIG_AUX,
  TAG_MUSIG_NONCE,
  MUSIG_OK,
  MUSIG_ERR_COUNT,
  MUSIG_ERR_PUBKEY,
  MUSIG_ERR_NONCE,
  MUSIG_ERR_SIG,
  MUSIG_PUBNONCE_SIZE,
  MUSIG_MAX_SIGNERS
} from "../constants"

// ═══════════════════════════════════════════════════════════════════════════
// NONCE GENERATION (BIP-327 §4.1)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * Genera (secnonce, pubnonce) para un signer.
 *
 * @param out_k64  secnonce: k₁‖k₂ (64 B, BE c/u) — k originales, sin negar.
 * @param out_r66  pubnonce: cbytes(R₁)‖cbytes(R₂) (66 B, compressed 33+33).
 */
export function musig2_nonce_gen(
  out_k97: usize, // ✅ 97 bytes
  out_r66: usize,
  secrand32: usize,
  skPtr: usize,
  pk33: usize, // ✅ 33 bytes
  aggotherpkPtr: usize,
  msgPtr: usize,
  msgLen: i32,
  extPtr: usize,   // ✅ extra_in ptr (0 si no hay)
  extLen: i32      // ✅ extra_in len (0 si no hay)
): i32 {
  if (msgLen < 0 || msgLen > 2048) return MUSIG_ERR_SIG
  if (extLen < 0 || extLen > 2048) return MUSIG_ERR_SIG
  const ctx = Memory.save()

  const rand = Memory.alloc(32)
  memory.copy(rand, secrand32, 32)
  if (isZero(rand)) {
    Memory.restore(ctx)
    return MUSIG_ERR_NONCE
  }

  if (skPtr != 0) {
    const auxH = Memory.alloc(32)
    const descAux = Memory.alloc(16)
    pushChunk(descAux, 0, skPtr, 32)
    taggedHashMulti(auxH, musigTagPtr(TAG_MUSIG_AUX), descAux, 1)
    xorInto(rand, auxH, 32)
  }

  // ✅ BIP-327 Estricto: Construcción del buffer con prefijos de longitud
  const hasOther: bool = aggotherpkPtr != 0
  const hasMsg: bool = msgPtr != 0
  const hasExt: bool = extPtr != 0 && extLen > 0
  const mPrefLen: usize = hasMsg ? <usize>(9 + msgLen) : 1
  const ePrefLen: usize = hasExt ? <usize>(4 + extLen) : 4
  const total: usize = 32 + 1 + 33 + 1 + (hasOther ? 32 : 0) + mPrefLen + ePrefLen
  const buf = Memory.alloc(total)
  let off: usize = 0

  memory.copy(buf, rand, 32)
  off += 32
  store<u8>(buf + off, 33)
  off += 1 // bytes(1, len(pk))
  memory.copy(buf + off, pk33, 33)
  off += 33

  if (hasOther) {
    store<u8>(buf + off, 32)
    off += 1 // bytes(1, len(aggpk))
    memory.copy(buf + off, aggotherpkPtr, 32)
    off += 32
  } else {
    store<u8>(buf + off, 0)
    off += 1
  }

  if (hasMsg) {
    store<u8>(buf + off, 1)
    off += 1 // m_prefixed prefix
    const ml: u64 = <u64>msgLen
    for (let i = 0; i < 8; i++) {
      store<u8>(buf + off + <usize>i, <u8>((ml >> (<u64>((7 - i) * 8))) & 0xff))
    }
    off += 8
    if (msgLen > 0) {
      memory.copy(buf + off, msgPtr, <usize>msgLen)
      off += <usize>msgLen
    }
  } else {
    store<u8>(buf + off, 0)
    off += 1 // m_prefixed = bytes(1, 0)
  }

  // bytes(4, len(extra_in)) + extra_in
  if (hasExt) {
    const el: u32 = <u32>extLen
    store<u8>(buf + off,     <u8>((el >> 24) & 0xff))
    store<u8>(buf + off + 1, <u8>((el >> 16) & 0xff))
    store<u8>(buf + off + 2, <u8>((el >>  8) & 0xff))
    store<u8>(buf + off + 3, <u8>( el        & 0xff))
    off += 4
    memory.copy(buf + off, extPtr, <usize>extLen)
    off += <usize>extLen
  } else {
    store<u32>(buf + off, 0)
    off += 4 // bytes(4, 0)
  }

  const desc = Memory.alloc(32)
  const cnt = Memory.alloc(1)
  const h = Memory.alloc(32)
  const k = Memory.alloc(32)
  const R = Memory.alloc(96)
  const N = Memory.alloc(32)
  store<u64>(N, N0)
  store<u64>(N, N1, 8)
  store<u64>(N, N2, 16)
  store<u64>(N, N3, 24)

  pushChunk(desc, 0, buf, <u32>total)
  pushChunk(desc, 1, cnt, 1)

  for (let i = 0; i < 2; i++) {
    store<u8>(cnt, <u8>i)
    taggedHashMulti(h, musigTagPtr(TAG_MUSIG_NONCE), desc, 2)
    scalarFromPtrModN(k, h)
    if (isZero(k)) {
      Memory.restore(ctx)
      return MUSIG_ERR_NONCE
    }
    multiplyG(R, k)
    toBytesPtr(k, out_k97 + <usize>(i << 5))
    writeCbytesExt(out_r66 + <usize>(i * 33), R)
  }

  // ✅ BIP-327 v1.0.0-rc.2: Append pk to secnonce
  memory.copy(out_k97 + 64, pk33, 33)

  Memory.restore(ctx)
  return MUSIG_OK
}

// ═══════════════════════════════════════════════════════════════════════════
// NONCE AGGREGATION (BIP-327 §4.2)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * Agrega nonces públicos de todos los signers.
 *
 * @param out_r66   aggnonce: cbytes_ext(R₁)‖cbytes_ext(R₂) = 66 B.
 *                  Si R₁ o R₂ son ∞ → 33 bytes de ceros (válido en BIP-327).
 * @param noncesPtr Array de pubnonces (stride 66).
 */
export function musig2_nonce_agg(out_r66: usize, noncesPtr: usize, count: u32): i32 {
  if (count == 0 || count > MUSIG_MAX_SIGNERS) return MUSIG_ERR_COUNT
  const ctx = Memory.save()

  const R1 = Memory.alloc(96)
  const R2 = Memory.alloc(96)
  const T = Memory.alloc(96)

  setInfinity(R1)
  setInfinity(R2)

  for (let i: u32 = 0; i < count; i++) {
    const base = noncesPtr + <usize>(i * <u32>MUSIG_PUBNONCE_SIZE) // stride 66

    // ✅ BIP-327: R_{i,1} = cpoint(pubnonce[0:33])
    if (!cpointToPoint(T, base)) {
      Memory.restore(ctx)
      return MUSIG_ERR_PUBKEY
    }
    addPoint(R1, R1, T)

    // ✅ BIP-327: R_{i,2} = cpoint(pubnonce[33:66])
    if (!cpointToPoint(T, base + 33)) {
      Memory.restore(ctx)
      return MUSIG_ERR_PUBKEY
    }
    addPoint(R2, R2, T)
  }

  // ✅ BIP-327: aggnonce PUEDE ser ∞ (no falla aquí; session_init usa G).
  // writeCbytesExt mapea ∞ → 33 bytes de ceros.
  writeCbytesExt(out_r66, R1)
  writeCbytesExt(out_r66 + 33, R2)

  Memory.restore(ctx)
  return MUSIG_OK
}
