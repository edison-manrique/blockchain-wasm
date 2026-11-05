/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip32/hash.ts — Helpers de hashing para BIP32 (zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Wrappers finos sobre sha2 y ripemd160 que operan con punteros y usan
 * BIP32_WORK como scratch (temporales de 32/20 B). Sin heap, sin alloc.
 *
 *   hmacSha512(out64, keyPtr, kLen, dataPtr, dLen)
 *   hash160(out20, inPtr, len)          ← RIPEMD160(SHA256(x))
 *   fingerprint(pub33Ptr) → u32         ← primeros 4 bytes de hash160 (BE)
 */
import { sha256_hash_raw, sha512_hmac_raw } from "../../hash/sha2"
import { ripemd160_hash_raw } from "../../hash/ripemd160"
import { BIP32_WORK_PTR, align8 } from "../../utils/arena"
import { BW_SHA256_TMP, BW_HASH160_TMP } from "./constants"

/**
 * HMAC-SHA512: out64 = HMAC(key, data). 64 bytes de salida.
 * Wrapper directo de sha512_hmac_raw (que usa HASH_WORK internamente).
 */
// @ts-ignore
@inline
export function hmacSha512(out64: usize, keyPtr: usize, kLen: u32, dataPtr: usize, dLen: u32): void {
  sha512_hmac_raw(out64, keyPtr, <i32>kLen, dataPtr, <i32>dLen)
}

/**
 * hash160: out20 = RIPEMD160(SHA256(in)). 20 bytes de salida.
 * Usa BW_SHA256_TMP (32 B) como temporal intermedio.
 * ⚠️ out20 NO debe ser == BIP32_WORK_PTR + BW_SHA256_TMP (solape).
 */
export function hash160(out20: usize, inPtr: usize, len: u32): void {
  const work = align8(BIP32_WORK_PTR)
  sha256_hash_raw(work + BW_SHA256_TMP, inPtr, <isize>len)
  ripemd160_hash_raw(out20, work + BW_SHA256_TMP, 32)
}

/**
 * fingerprint: primeros 4 bytes de hash160(pubkey) como u32 big-endian.
 * Usado para parentFingerprint en la derivación BIP32.
 */
export function fingerprint(pub33Ptr: usize): u32 {
  const work = align8(BIP32_WORK_PTR)
  hash160(work + BW_HASH160_TMP, pub33Ptr, 33)
  return (
    (<u32>load<u8>(work + BW_HASH160_TMP + 0) << 24) |
    (<u32>load<u8>(work + BW_HASH160_TMP + 1) << 16) |
    (<u32>load<u8>(work + BW_HASH160_TMP + 2) << 8) |
    (<u32>load<u8>(work + BW_HASH160_TMP + 3))
  )
}