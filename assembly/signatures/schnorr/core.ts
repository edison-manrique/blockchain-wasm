/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr/core.ts — Primitivas BIP-340 (tagged hash, mod N, lift_x)
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Arena } from "../../utils/arena"
import { P0, P1, P2, P3 } from "../../secp256k1/constants"
import {
  sqrMod, mulMod,
  add as fieldAdd, sub as fieldSub,
  fromBytesPtr, isGreaterOrEqualP
} from "../../secp256k1/field"
import { isGreaterOrEqualN, subN } from "../../secp256k1/scalar"
import { sha256_hash_raw } from "../../hash/sha2"
import { sqrtModP } from "../../utils/pubkey"

import { TAG_HASHES } from "./constants"

// ═══════════════════════════════════════════════════════════════════════════
// TAGGED HASH BIP-340
// ═══════════════════════════════════════════════════════════════════════════
export function taggedHash(
  out32: usize, tagId: i32,
  m1: usize, len1: isize,
  m2: usize = 0, len2: isize = 0,
  m3: usize = 0, len3: isize = 0
): void {
  const ctx = Arena.save()
  const total: usize = <usize>(64 + len1 + len2 + len3)
  const buf = Arena.alloc(total)
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
  Arena.restore(ctx)
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
  const ctx = Arena.save()
  if (isGreaterOrEqualP(xPtr32)) {
    Arena.restore(ctx)
    return false
  }
  const c = Arena.alloc(32)
  const seven = Arena.alloc(32)
  const y = Arena.alloc(32)
  const ySq = Arena.alloc(32)
  const prime = Arena.alloc(32)
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
    Arena.restore(ctx); return false
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
  Arena.restore(ctx)
  return true
}
