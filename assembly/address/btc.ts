/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  address/btc.ts — Direcciones Bitcoin (zero-alloc, solo punteros)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   btc_p2pkh(outPtr, pubPtr, pubLen)        → P2PKH  (Base58Check, "1…")
 *   btc_p2sh_p2wpkh(outPtr, pubPtr, pubLen)  → P2SH-P2WPKH (Base58Check, "3…")
 *   btc_p2wpkh(outPtr, pubPtr, pubLen)       → P2WPKH (Bech32, "bc1q…")
 *   btc_p2tr(outPtr, pubPtr, pubLen)         → P2TR/Taproot (Bech32m, "bc1p…")
 *
 * Aceptan pubkey compressed (33 B) o uncompressed (65 B). Cada función escribe
 * el string ASCII completo en outPtr y retorna su longitud (o < 0 si error).
 *
 * ⚡ SEGURIDAD OPCIONAL: solo se valida el FORMATO (prefijo) y, cuando el
 * algoritmo lo exige, se descomprime el punto (P2TR/Bech32 necesitan Y).
 * La pertenencia a la curva NO se comprueba aquí: es un chequeo explícito
 * (`pubkeyValidateRaw`, `Secp256k1.isValid`) para no pagar el sqrt modular en
 * cada dirección. Los llamadores que reciban claves de fuentes no confiables
 * deben validarlas antes.
 *
 * Buffers en ADDRESS_WORK; hashing en HASH_WORK; curva en CRYPTO_WORK. Disjuntos.
 */
import { ADDRESS_WORK_PTR, align8, Arena } from "../utils/arena"
import { sha256_hash_raw } from "../hash/sha2"
import { ripemd160_hash_raw } from "../hash/ripemd160"
import { base58check_encode_raw, base58_indices_to_ascii } from "../utils/base58"
import {
  bech32_encode_raw, convert_bits_raw, bech32_charset_to_ascii,
  BECH32_CONST, BECH32M_CONST
} from "../utils/bech32"
import { decompressXY } from "../utils/pubkey"
import { fromBytesPtr, toBytesPtr } from "../secp256k1/field"
import { multiplyG } from "../secp256k1/generator"
import { addPoint, toAffine } from "../secp256k1/point"
import {
  AW_SHA256_TMP, AW_RIPEMD_TMP, AW_PAYLOAD, AW_BECH32_DATA, AW_XBUF,
  AW_TAPROOT_MSG, AW_TWEAK, AW_P, AW_T, AW_Q,
  VER_P2PKH, VER_P2SH, TAP_TWEAK_TAG_HASH,
  ADDR_ERR_PUBKEY, ADDR_ERR_CONVERT
} from "./constants"

// ═══════════════════════════════════════════════════════════════════════════
// HELPER: hash160 = RIPEMD160(SHA256(x))
// ═══════════════════════════════════════════════════════════════════════════

// @ts-ignore
@inline
function hash160Raw(out20: usize, inPtr: usize, len: u32): void {
  const work = align8(ADDRESS_WORK_PTR)
  sha256_hash_raw(work + AW_SHA256_TMP, inPtr, <isize>len)
  ripemd160_hash_raw(out20, work + AW_SHA256_TMP, 32)
}

// @ts-ignore
@inline
function validPubPrefix(pubPtr: usize, pubLen: u32): bool {
  if (pubLen == 33) {
    const p = load<u8>(pubPtr)
    return p == 0x02 || p == 0x03
  }
  if (pubLen == 65) return load<u8>(pubPtr) == 0x04
  return false
}

// ═══════════════════════════════════════════════════════════════════════════
// P2PKH  —  Base58Check( 0x00 ‖ hash160(pub) )
// ═══════════════════════════════════════════════════════════════════════════

export function btc_p2pkh(outPtr: usize, pubPtr: usize, pubLen: u32): i32 {
  const work = align8(ADDRESS_WORK_PTR)
  if (!validPubPrefix(pubPtr, pubLen)) return ADDR_ERR_PUBKEY
  hash160Raw(work + AW_RIPEMD_TMP, pubPtr, pubLen)
  store<u8>(work + AW_PAYLOAD, VER_P2PKH) // 0x00
  memory.copy(work + AW_PAYLOAD + 1, work + AW_RIPEMD_TMP, 20)
  const idxLen: u32 = base58check_encode_raw(outPtr, work + AW_PAYLOAD, 21)
  if (idxLen == 0) return -1
  base58_indices_to_ascii(outPtr, idxLen)
  return <i32>idxLen
}

// ═══════════════════════════════════════════════════════════════════════════
// P2SH-P2WPKH  —  Base58Check( 0x05 ‖ hash160( 0x00 0x14 ‖ hash160(pub) ) )
// ═══════════════════════════════════════════════════════════════════════════

export function btc_p2sh_p2wpkh(outPtr: usize, pubPtr: usize, pubLen: u32): i32 {
  const work = align8(ADDRESS_WORK_PTR)
  if (!validPubPrefix(pubPtr, pubLen)) return ADDR_ERR_PUBKEY

  // redeemScript = 0x00 0x14 ‖ hash160(pub)   (22 B)
  hash160Raw(work + AW_RIPEMD_TMP, pubPtr, pubLen)
  store<u8>(work + AW_PAYLOAD, 0x00)
  store<u8>(work + AW_PAYLOAD + 1, 0x14)
  memory.copy(work + AW_PAYLOAD + 2, work + AW_RIPEMD_TMP, 20)

  // scriptHash = hash160(redeemScript)
  hash160Raw(work + AW_RIPEMD_TMP, work + AW_PAYLOAD, 22)

  // payload = 0x05 ‖ scriptHash
  store<u8>(work + AW_PAYLOAD, VER_P2SH) // 0x05
  memory.copy(work + AW_PAYLOAD + 1, work + AW_RIPEMD_TMP, 20)

  const idxLen: u32 = base58check_encode_raw(outPtr, work + AW_PAYLOAD, 21)
  if (idxLen == 0) return -1
  base58_indices_to_ascii(outPtr, idxLen)
  return <i32>idxLen
}

// ═══════════════════════════════════════════════════════════════════════════
// P2WPKH  —  Bech32( "bc", witness_v0 ‖ convertBits(hash160(pub)) )
// ═══════════════════════════════════════════════════════════════════════════

export function btc_p2wpkh(outPtr: usize, pubPtr: usize, pubLen: u32): i32 {
  const work = align8(ADDRESS_WORK_PTR)
  if (!validPubPrefix(pubPtr, pubLen)) return ADDR_ERR_PUBKEY

  hash160Raw(work + AW_RIPEMD_TMP, pubPtr, pubLen) // 20 B

  // convert 8→5 en AW_BECH32_DATA+1; witness v0 en [0]
  const convLen: i32 = convert_bits_raw(work + AW_BECH32_DATA + 1, work + AW_RIPEMD_TMP, 20, 8, 5, true)
  if (convLen < 0) return ADDR_ERR_CONVERT
  store<u8>(work + AW_BECH32_DATA, 0) // witness v0

  // hrp "bc" (para el checksum) en AW_XBUF
  store<u8>(work + AW_XBUF, 0x62)     // 'b'
  store<u8>(work + AW_XBUF + 1, 0x63) // 'c'

  // string final: "bc1" + charset(data+checksum)
  store<u8>(outPtr, 0x62)     // 'b'
  store<u8>(outPtr + 1, 0x63) // 'c'
  store<u8>(outPtr + 2, 0x31) // '1'

  const dataLen: u32 = <u32>convLen + 1
  const idxLen: i32 = bech32_encode_raw(outPtr + 3, work + AW_XBUF, 2, work + AW_BECH32_DATA, dataLen, BECH32_CONST)
  if (idxLen <= 0) return -1
  bech32_charset_to_ascii(outPtr + 3, <u32>idxLen)
  return 3 + idxLen
}

// ═══════════════════════════════════════════════════════════════════════════
// P2TR (Taproot, BIP-341)  —  Bech32m( "bc", witness_v1 ‖ x_only(Q) )
//   Q = P + int(SHA256( tagHash ‖ tagHash ‖ x_only(P) )) · G,  con P de Y par
// ═══════════════════════════════════════════════════════════════════════════

export function btc_p2tr(outPtr: usize, pubPtr: usize, pubLen: u32): i32 {
  const work = align8(ADDRESS_WORK_PTR)
  if (!validPubPrefix(pubPtr, pubLen)) return ADDR_ERR_PUBKEY

  const ctx = Arena.save()
  const tBig = Arena.alloc(32)
  const affine = Arena.alloc(64)

  // 1. x-only con prefijo 0x02 (levanta P con Y par, como exige BIP-341)
  store<u8>(work + AW_XBUF, 0x02)
  memory.copy(work + AW_XBUF + 1, pubPtr + 1, 32)

  // 2. P = lift_x(x) con Y par → Jacobiano [X|Y|Z=1]
  // ✅ FIX (BLOQUE 3): verificar que x levanta un punto real de la curva.
  //    Válido para entrada compressed Y uncompressed (AW_XBUF fuerza el lift
  //    con Y par sobre la misma X en ambos casos).
  if (!decompressXY(work + AW_P, work + AW_P + 32, work + AW_XBUF)) {
    Arena.restore(ctx)
    return ADDR_ERR_PUBKEY
  }
  store<u64>(work + AW_P + 64, 1)
  store<u64>(work + AW_P + 72, 0)
  store<u64>(work + AW_P + 80, 0)
  store<u64>(work + AW_P + 88, 0)

  // 3. msg = tagHash ‖ tagHash ‖ x_only(P)   (96 B)
  for (let i: i32 = 0; i < 32; i++) {
    const b: u8 = unchecked(TAP_TWEAK_TAG_HASH[i])
    store<u8>(work + AW_TAPROOT_MSG + <usize>i, b)
    store<u8>(work + AW_TAPROOT_MSG + <usize>(32 + i), b)
  }
  memory.copy(work + AW_TAPROOT_MSG + 64, work + AW_XBUF + 1, 32)

  // 4. tweak = SHA256(msg)   (single SHA-256, NO double)
  sha256_hash_raw(work + AW_TWEAK, work + AW_TAPROOT_MSG, 96)

  // 5. T = tweak · G
  fromBytesPtr(tBig, work + AW_TWEAK)
  multiplyG(work + AW_T, tBig)

  // 6. Q = P + T
  addPoint(work + AW_Q, work + AW_P, work + AW_T)

  // 7. x_only(Q) en bytes (reutiliza AW_XBUF; el x de P ya fue consumido en el msg)
  toAffine(affine, work + AW_Q)
  toBytesPtr(affine, work + AW_XBUF)

  // 8. convert 8→5 + witness v1
  const convLen: i32 = convert_bits_raw(work + AW_BECH32_DATA + 1, work + AW_XBUF, 32, 8, 5, true)
  if (convLen < 0) {
    Arena.restore(ctx)
    return ADDR_ERR_CONVERT
  }
  store<u8>(work + AW_BECH32_DATA, 1) // witness v1

  // 9. hrp "bc" (reutiliza AW_XBUF) + string final "bc1" + bech32m
  store<u8>(work + AW_XBUF, 0x62)
  store<u8>(work + AW_XBUF + 1, 0x63)
  store<u8>(outPtr, 0x62)
  store<u8>(outPtr + 1, 0x63)
  store<u8>(outPtr + 2, 0x31)

  const dataLen: u32 = <u32>convLen + 1
  const idxLen: i32 = bech32_encode_raw(outPtr + 3, work + AW_XBUF, 2, work + AW_BECH32_DATA, dataLen, BECH32M_CONST)
  if (idxLen <= 0) {
    Arena.restore(ctx)
    return -1
  }
  bech32_charset_to_ascii(outPtr + 3, <u32>idxLen)

  Arena.restore(ctx)
  return 3 + idxLen
}

// ═══════════════════════════════════════════════════════════════════════════
// P2PKH UNCOMPRESSED (legacy, 65 B obligatorio)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * P2PKH desde clave pública SIN COMPRIMIR (65 B, prefijo 0x04).
 * Rechaza claves compressed (33 B) con ADDR_ERR_PUBKEY.
 * Útil para interoperabilidad con sistemas legacy que exigen uncompressed.
 */
export function btc_p2pkh_uncompressed(outPtr: usize, pubPtr: usize, pubLen: u32): i32 {
  const work = align8(ADDRESS_WORK_PTR)
  // Solo acepta 65 B con prefijo 0x04
  if (pubLen != 65 || load<u8>(pubPtr) != 0x04) return ADDR_ERR_PUBKEY
  hash160Raw(work + AW_RIPEMD_TMP, pubPtr, pubLen)
  store<u8>(work + AW_PAYLOAD, VER_P2PKH) // 0x00
  memory.copy(work + AW_PAYLOAD + 1, work + AW_RIPEMD_TMP, 20)
  const idxLen: u32 = base58check_encode_raw(outPtr, work + AW_PAYLOAD, 21)
  if (idxLen == 0) return -1
  base58_indices_to_ascii(outPtr, idxLen)
  return <i32>idxLen
}