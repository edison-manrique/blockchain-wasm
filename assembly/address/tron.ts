/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  address/tron.ts — Dirección Tron (TRX) zero-alloc
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   tron_address(outPtr, pubPtr, pubLen) → longitud ASCII | <0
 *
 * Algoritmo:
 *   1. Obtener 64 bytes de pubkey sin prefijo (X‖Y)
 *      • 65 B (0x04‖X‖Y) → bytes 1..64
 *      • 33 B compressed → descomprimir y usar bytes 1..64
 *      • 64 B raw (X‖Y) → usar directamente
 *   2. Keccak256(64 B) → 32 bytes
 *   3. Tomar últimos 20 bytes + prefijo 0x41 (Tron mainnet) → 21 B payload
 *   4. Base58Check(payload) → string ASCII (empieza con 'T')
 *
 * Buffers: ADDRESS_WORK (disjunto de HASH_WORK que usa Base58Check).
 */
import { ADDRESS_WORK_PTR, align8, Memory } from "../utils/memory"
import { keccak256_hash_raw } from "../hash/keccak256"
import { uncompressRaw, isOnCurveXY } from "../utils/pubkey"
import { fromBytesPtr } from "../secp256k1/field"
import { base58check_encode_raw, base58_indices_to_ascii } from "../utils/base58"
import {
  AW_TWEAK, AW_PAYLOAD, AW_ETH_UNCOMP,
  ADDR_ERR_PUBKEY, TRON_PREFIX
} from "./constants"

// helper (antes de tron_address):
// @ts-ignore
@inline
function validateXY(xy64: usize): bool {
  const ctx = Memory.save()
  const x = Memory.alloc(32)
  const y = Memory.alloc(32)
  fromBytesPtr(x, xy64)
  fromBytesPtr(y, xy64 + 32)
  const ok: bool = isOnCurveXY(x, y)
  Memory.restore(ctx)
  return ok
}

export function tron_address(outPtr: usize, pubPtr: usize, pubLen: u32): i32 {
  const work = align8(ADDRESS_WORK_PTR)

  // 1. pureKey = 64 bytes de pubkey sin prefijo
  let pureKeyPtr: usize
  if (pubLen == 65 && load<u8>(pubPtr) == 0x04) {
    if (!validateXY(pubPtr + 1)) return ADDR_ERR_PUBKEY // ✅ HARDENING
    pureKeyPtr = pubPtr + 1
  } else if (pubLen == 64) {
    if (!validateXY(pubPtr)) return ADDR_ERR_PUBKEY // ✅ HARDENING
    pureKeyPtr = pubPtr
  } else if (pubLen == 33) {
    const p = load<u8>(pubPtr)
    if (p != 0x02 && p != 0x03) return ADDR_ERR_PUBKEY
    if (uncompressRaw(work + AW_ETH_UNCOMP, pubPtr) < 0) return ADDR_ERR_PUBKEY
    pureKeyPtr = work + AW_ETH_UNCOMP + 1
  } else {
    return ADDR_ERR_PUBKEY
  }

  // 2. khash = Keccak256(pureKey) → 32 B en AW_TWEAK
  keccak256_hash_raw(work + AW_TWEAK, pureKeyPtr, 64)

  // 3. payload = 0x41 ‖ khash[12..32]   (21 bytes)
  store<u8>(work + AW_PAYLOAD, TRON_PREFIX)
  memory.copy(work + AW_PAYLOAD + 1, work + AW_TWEAK + 12, 20)

  // 4. Base58Check encode → ASCII en outPtr
  const idxLen: u32 = base58check_encode_raw(outPtr, work + AW_PAYLOAD, 21)
  if (idxLen == 0) return -1
  base58_indices_to_ascii(outPtr, idxLen)
  return <i32>idxLen
}