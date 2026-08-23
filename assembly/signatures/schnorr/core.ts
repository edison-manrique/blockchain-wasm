/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr/core.ts — Primitivas BIP-340 + MuSig2 (tagged hash, mod N, lift_x)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * v3.1: Añadidos cpointToPoint / writeCbytesExt para serialización BIP-327
 *       compressed (33 B = prefijo + X).
 */
import { Memory } from "../../utils/memory"
import { P0, P1, P2, P3 } from "../../secp256k1/constants"
import {
  sqrMod, mulMod,
  add as fieldAdd, sub as fieldSub,
  fromBytesPtr, toBytesPtr, isGreaterOrEqualP
} from "../../secp256k1/field"
import { isGreaterOrEqualN, subN } from "../../secp256k1/scalar"
import { sha256_hash_raw } from "../../hash/sha2"
import { sqrtModP } from "../../utils/pubkey"
// ✅ v3.1: imports para cpointToPoint / writeCbytesExt
import {
  toAffine, negate, setInfinity, isInfinity, setGenerator
} from "../../secp256k1/point"

import {
  TAG_HASHES,
  MUSIG_TAG_KEYAGG_LIST, MUSIG_TAG_KEYAGG_LIST_LEN,
  MUSIG_TAG_KEYAGG_COEFF, MUSIG_TAG_KEYAGG_COEFF_LEN,
  MUSIG_TAG_AUX, MUSIG_TAG_AUX_LEN,
  MUSIG_TAG_NONCE, MUSIG_TAG_NONCE_LEN,
  MUSIG_TAG_NONCECOEF, MUSIG_TAG_NONCECOEF_LEN
} from "./constants"

// ═══════════════════════════════════════════════════════════════════════════
// TAGGED HASH BIP-340
// ═══════════════════════════════════════════════════════════════════════════
export function taggedHash(
  out32: usize, tagId: i32,
  m1: usize, len1: isize,
  m2: usize = 0, len2: isize = 0,
  m3: usize = 0, len3: isize = 0
): void {
  const ctx = Memory.save()
  const total: usize = <usize>(64 + len1 + len2 + len3)
  const buf = Memory.alloc(total)
  const off: usize = <usize>(tagId * 32)
  for (let i: usize = 0; i < 32; i++) {
    const b: u8 = unchecked(TAG_HASHES[<i32>(off + i)])
    store<u8>(buf + i, b)
    store<u8>(buf + 32 + i, b)
  }
  let p: usize = 64
  memory.copy(buf + p, m1, <usize>len1)
  p += <usize>len1
  if (len2 > 0) { memory.copy(buf + p, m2, <usize>len2); p += <usize>len2 }
  if (len3 > 0) { memory.copy(buf + p, m3, <usize>len3) }
  sha256_hash_raw(out32, buf, <isize>total)
  Memory.restore(ctx)
}

// ═══════════════════════════════════════════════════════════════════════════
// TAG HASHES MuSig2 (lazy init, buffer estático 160 B)
// ═══════════════════════════════════════════════════════════════════════════
const MUSIG_TAG_HASHES: usize = memory.data(160)
let musigReady: bool = false

export function musigInit(): void {
  if (musigReady) return
  const ctx = Memory.save()
  const tmp = Memory.alloc(64)
  for (let i: usize = 0; i < MUSIG_TAG_KEYAGG_LIST_LEN; i++)
    store<u8>(tmp + i, unchecked(MUSIG_TAG_KEYAGG_LIST[<i32>i]))
  sha256_hash_raw(MUSIG_TAG_HASHES + 0, tmp, <isize>MUSIG_TAG_KEYAGG_LIST_LEN)

  for (let i: usize = 0; i < MUSIG_TAG_KEYAGG_COEFF_LEN; i++)
    store<u8>(tmp + i, unchecked(MUSIG_TAG_KEYAGG_COEFF[<i32>i]))
  sha256_hash_raw(MUSIG_TAG_HASHES + 32, tmp, <isize>MUSIG_TAG_KEYAGG_COEFF_LEN)

  for (let i: usize = 0; i < MUSIG_TAG_AUX_LEN; i++)
    store<u8>(tmp + i, unchecked(MUSIG_TAG_AUX[<i32>i]))
  sha256_hash_raw(MUSIG_TAG_HASHES + 64, tmp, <isize>MUSIG_TAG_AUX_LEN)

  for (let i: usize = 0; i < MUSIG_TAG_NONCE_LEN; i++)
    store<u8>(tmp + i, unchecked(MUSIG_TAG_NONCE[<i32>i]))
  sha256_hash_raw(MUSIG_TAG_HASHES + 96, tmp, <isize>MUSIG_TAG_NONCE_LEN)

  for (let i: usize = 0; i < MUSIG_TAG_NONCECOEF_LEN; i++)
    store<u8>(tmp + i, unchecked(MUSIG_TAG_NONCECOEF[<i32>i]))
  sha256_hash_raw(MUSIG_TAG_HASHES + 128, tmp, <isize>MUSIG_TAG_NONCECOEF_LEN)

  musigReady = true
  Memory.restore(ctx)
}

// @ts-ignore
@inline
export function musigTagPtr(tagId: i32): usize {
  if (!musigReady) musigInit()
  return MUSIG_TAG_HASHES + <usize>(tagId << 5)
}

export function musigTagHashesPtr(): usize {
  if (!musigReady) musigInit()
  return MUSIG_TAG_HASHES
}

// ═══════════════════════════════════════════════════════════════════════════
// TAGGED HASH MULTI-CHUNK (MuSig2)
// ═══════════════════════════════════════════════════════════════════════════
export const CHUNK_DESC_SIZE: usize = 16

// @ts-ignore
@inline
export function pushChunk(descPtr: usize, n: i32, ptr: usize, len: u32): void {
  const off = descPtr + <usize>(n << 4)
  store<u64>(off, <u64>ptr)
  store<u32>(off + 8, len)
}

export function taggedHashMulti(out32: usize, tagHash32Ptr: usize, descPtr: usize, nChunks: i32): void {
  const ctx = Memory.save()
  let total: usize = 64
  for (let i = 0; i < nChunks; i++) {
    total += <usize>load<u32>(descPtr + <usize>(i << 4) + 8)
  }
  const buf = Memory.alloc(total)
  for (let i: usize = 0; i < 32; i++) {
    const b: u8 = load<u8>(tagHash32Ptr + i)
    store<u8>(buf + i, b)
    store<u8>(buf + 32 + i, b)
  }
  let p: usize = 64
  for (let i = 0; i < nChunks; i++) {
    const off = descPtr + <usize>(i << 4)
    const cptr: usize = <usize>load<u64>(off)
    const clen: usize = <usize>load<u32>(off + 8)
    memory.copy(buf + p, cptr, clen)
    p += clen
  }
  sha256_hash_raw(out32, buf, <isize>total)
  Memory.restore(ctx)
}

export function xorInto(dst: usize, src: usize, len: usize): void {
  let i: usize = 0
  while (i + 8 <= len) {
    store<u64>(dst + i, load<u64>(dst + i) ^ load<u64>(src + i))
    i += 8
  }
  while (i < len) {
    store<u8>(dst + i, <u8>(load<u8>(dst + i) ^ load<u8>(src + i)))
    i++
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// BYTES (BE) → ESCALAR mod N
// ═══════════════════════════════════════════════════════════════════════════
export function scalarFromPtrModN(res: usize, ptr: usize): void {
  fromBytesPtr(res, ptr)
  while (isGreaterOrEqualN(res)) { subN(res, res) }
}

// ═══════════════════════════════════════════════════════════════════════════
// LIFT_X — x (limbs LE) → Jacobiano [X|Y|Z=1] con Y par
// ═══════════════════════════════════════════════════════════════════════════
export function liftX(outPoint96: usize, xPtr32: usize): bool {
  const ctx = Memory.save()
  if (isGreaterOrEqualP(xPtr32)) {
    Memory.restore(ctx)
    return false
  }
  const c = Memory.alloc(32)
  const seven = Memory.alloc(32)
  const y = Memory.alloc(32)
  const ySq = Memory.alloc(32)
  const prime = Memory.alloc(32)
  sqrMod(c, xPtr32)
  mulMod(c, c, xPtr32)
  store<u64>(seven, 7)
  store<u64>(seven, 0, 8)
  store<u64>(seven, 0, 16)
  store<u64>(seven, 0, 24)
  fieldAdd(c, c, seven)
  sqrtModP(y, c)
  sqrMod(ySq, y)
  if (memory.compare(ySq, c, 32) != 0) {
    Memory.restore(ctx); return false
  }
  if ((load<u64>(y) & 1) != 0) {
    store<u64>(prime, P0); store<u64>(prime, P1, 8)
    store<u64>(prime, P2, 16); store<u64>(prime, P3, 24)
    fieldSub(y, prime, y)
  }
  memory.copy(outPoint96, xPtr32, 32)
  memory.copy(outPoint96 + 32, y, 32)
  store<u64>(outPoint96 + 64, 1)
  store<u64>(outPoint96 + 72, 0)
  store<u64>(outPoint96 + 80, 0)
  store<u64>(outPoint96 + 88, 0)
  Memory.restore(ctx)
  return true
}

// ═══════════════════════════════════════════════════════════════════════════
// ✅ v3.1: CPOINT / CBYTES_EXT — serialización compressed (BIP-327)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * cpointToPoint: deserializa compressed point (33 B) a Jacobiano (96 B).
 * Implementa cpoint_ext del BIP-327: bytes(33, 0) → punto en el infinito.
 * Valida prefijo (0x02/0x03) y pertenencia a la curva vía liftX.
 * Ajusta la paridad de Y según el prefijo.
 *
 * @returns true = punto válido; false = prefijo inválido o X fuera de curva.
 */
export function cpointToPoint(out96: usize, ptr33: usize): bool {
  const ctx = Memory.save()
  const prefix = load<u8>(ptr33)

  // cpoint_ext: 33 ceros → punto en el infinito (BIP-327 §4.2)
  if (prefix == 0x00) {
    let allZero = true
    for (let i: usize = 1; i < 33; i++) {
      if (load<u8>(ptr33 + i) != 0) { allZero = false; break }
    }
    if (allZero) {
      setInfinity(out96)
      Memory.restore(ctx)
      return true
    }
    Memory.restore(ctx)
    return false // prefijo 0x00 pero bytes no-cero → inválido
  }

  if (prefix != 0x02 && prefix != 0x03) {
    Memory.restore(ctx)
    return false
  }

  const x = Memory.alloc(32)
  fromBytesPtr(x, ptr33 + 1)
  if (!liftX(out96, x)) {
    Memory.restore(ctx)
    return false
  }

  // Ajustar Y según prefijo (liftX devuelve Y par; si prefijo=0x03 → negar)
  const yIsOdd = (load<u64>(out96 + 32) & 1) != 0
  const wantOdd = prefix == 0x03
  if (yIsOdd != wantOdd) {
    negate(out96, out96)
  }

  Memory.restore(ctx)
  return true
}

/**
 * writeCbytesExt: serializa Jacobiano (96 B) a compressed (33 B).
 * Implementa cbytes_ext del BIP-327: ∞ → bytes(33, 0).
 */
export function writeCbytesExt(out33: usize, p96: usize): void {
  if (isInfinity(p96)) {
    memory.fill(out33, 0, 33)
    return
  }
  const ctx = Memory.save()
  const affine = Memory.alloc(64)
  toAffine(affine, p96)
  const yIsOdd = (load<u64>(affine + 32) & 1) != 0
  store<u8>(out33, yIsOdd ? 0x03 : 0x02)
  toBytesPtr(affine, out33 + 1)
  Memory.restore(ctx)
}