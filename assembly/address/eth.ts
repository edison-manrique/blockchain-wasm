/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  address/eth.ts — Dirección Ethereum (zero-alloc, solo punteros)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   eth_address(outPtr, pubPtr, pubLen) → 42
 *
 * addr = "0x" + últimos 20 bytes de Keccak256(pubkey_64_sin_prefijo), con
 * checksum EIP-55 (capitalizar cada letra a-f cuyo nibble del hash sea ≥ 8).
 *
 * Acepta pubkey uncompressed (64 B / 65 B con 0x04) o compressed (33 B, que se
 * descomprime internamente). Escribe "0x…" (42 B ASCII) en outPtr.
 */
import { ADDRESS_WORK_PTR, align8 } from "../utils/memory"
import { keccak256_hash_raw } from "../hash/keccak256"
import { uncompressRaw } from "../utils/pubkey"
import { AW_SHA256_TMP, AW_TWEAK, AW_ETH_HEX, AW_ETH_UNCOMP, ADDR_ERR_PUBKEY } from "./constants"

// "0123456789abcdef"
const HEX_LO: StaticArray<u8> = [
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
]

export function eth_address(outPtr: usize, pubPtr: usize, pubLen: u32): i32 {
  const work = align8(ADDRESS_WORK_PTR)

  // 1. pureKey = 64 bytes de pubkey sin prefijo
  let pureKeyPtr: usize
  if (pubLen == 65 && load<u8>(pubPtr) == 0x04) {
    pureKeyPtr = pubPtr + 1
  } else if (pubLen == 64) {
    pureKeyPtr = pubPtr
  } else if (pubLen == 33) {
    // compressed → descomprimir a AW_ETH_UNCOMP y usar +1
    if (uncompressRaw(work + AW_ETH_UNCOMP, pubPtr) < 0) return ADDR_ERR_PUBKEY
    pureKeyPtr = work + AW_ETH_UNCOMP + 1
  } else {
    return ADDR_ERR_PUBKEY
  }

  // 2. khash = Keccak256(pureKey) → 32 B en AW_TWEAK (reutilizado; ETH no usa taproot)
  keccak256_hash_raw(work + AW_TWEAK, pureKeyPtr, 64)

  // 3. últimos 20 bytes (khash[12..32]) → hex lowercase en AW_ETH_HEX (40 B)
  for (let i: u32 = 0; i < 20; i++) {
    const b: u8 = load<u8>(work + AW_TWEAK + 12 + i)
    store<u8>(work + AW_ETH_HEX + <usize>(2 * i), unchecked(HEX_LO[<i32>(b >> 4)]))
    store<u8>(work + AW_ETH_HEX + <usize>(2 * i + 1), unchecked(HEX_LO[<i32>(b & 0x0f)]))
  }

  // 4. checksum EIP-55 = Keccak256(hexAscii lowercase) → 32 B en AW_SHA256_TMP
  keccak256_hash_raw(work + AW_SHA256_TMP, work + AW_ETH_HEX, 40)

  // 5. "0x" + 40 chars con capitalización EIP-55
  store<u8>(outPtr, 0x30) // '0'
  store<u8>(outPtr + 1, 0x78) // 'x'
  for (let i: u32 = 0; i < 40; i++) {
    let c: u8 = load<u8>(work + AW_ETH_HEX + i)
    const hashByte: u8 = load<u8>(work + AW_SHA256_TMP + <usize>(i >> 1))
    const hashNibble: u32 = (i & 1) == 0 ? <u32>(hashByte >> 4) : <u32>(hashByte & 0x0f)
    if (c >= 0x61 && c <= 0x66 && hashNibble >= 8) {
      c = <u8>(c - 32) // a-f → A-F
    }
    store<u8>(outPtr + 2 + i, c)
  }

  return 42
}
