/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  wif/index.ts — Wallet Import Format (WIF) zero-alloc
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * WIF = Base58Check(0x80 ‖ privkey[32] ‖ [0x01 si compressed])
 * Bitcoin mainnet: uncompressed empieza con '5', compressed con 'K' o 'L'.
 *
 * ── ARQUITECTURA (zero-alloc, solo punteros) ──────────────────────────────
 * • Sin Uint8Array, sin new, sin strings, sin heap.
 * • Payload temporal en HASH_WORK + 400 (34 B, no interfiere con base58check
 *   que usa [0..353]).
 * • Llama a base58check_encode_raw / base58check_decode_raw (módulo base58).
 * • El wrapper TS convierte índices ↔ ASCII y construye el string.
 *
 * ── API (punteros) ────────────────────────────────────────────────────────
 *   wif_encode_raw(outIdxPtr, privKeyPtr, compressed) → outLen
 *     Construye payload WIF y lo codifica como índices base58 en outIdxPtr.
 *     Retorna el número de índices escritos.
 *
 *   wif_decode_raw(outKeyPtr, srcIdxPtr, srcLen) → flags | -1
 *     Decodifica índices base58, verifica checksum + prefix + sufijo.
 *     Escribe 32 bytes de clave privada en outKeyPtr.
 *     Retorna: 1 = uncompressed, 2 = compressed, -1 = inválido.
 *
 * ── USO DESDE TS ──────────────────────────────────────────────────────────
 *   // Encode:
 *   wasm.write(IN, privKey32)
 *   const len = wasm.exports.wif_encode_raw(OUT, IN, 1)  // compressed
 *   wasm.exports.base58_indices_to_ascii(OUT, len)
 *   const wif = new TextDecoder().decode(wasm.read(OUT, len))
 *
 *   // Decode:
 *   wasm.write(IN, TextEncoder.encode(wifString))
 *   wasm.exports.base58_ascii_to_indices(IN, wifString.length)
 *   const flags = wasm.exports.wif_decode_raw(OUT, IN, wifString.length)
 *   const compressed = flags === 2
 *   const key = wasm.read(OUT, 32)
 */
import { HASH_WORK_PTR, align8 } from "./arena"
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "./arena"
import { base58check_encode_raw, base58check_decode_raw } from "./base58"
// ✅ Re-exportar para que el test pueda acceder desde el mismo módulo WASM
export { base58_indices_to_ascii, base58_ascii_to_indices, base58check_encode_raw } from "./base58"

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTES
// ═══════════════════════════════════════════════════════════════════════════

const WIF_VERSION: u8 = 0x80
const COMPRESSED_SUFFIX: u8 = 0x01
const PRIVKEY_LEN: usize = 32

/** Offset seguro en HASH_WORK para el payload temporal (34 B).
 *  base58check usa [0..353]; nosotros usamos [400..433]. */
const WIF_PAYLOAD_OFF: usize = 400

// ═══════════════════════════════════════════════════════════════════════════
// WIF ENCODE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Codifica una clave privada de 32 bytes como índices Base58Check (WIF).
 *
 * @param outIdxPtr  Buffer de salida para índices base58 (reservar ≥ 55 B).
 * @param privKeyPtr Puntero a 32 bytes de clave privada.
 * @param compressed true (1) = sufijo 0x01, false (0) = sin sufijo.
 * @returns Número de índices escritos en outIdxPtr.
 */
export function wif_encode_raw(outIdxPtr: usize, privKeyPtr: usize, compressed: bool): u32 {
  const scratch = align8(HASH_WORK_PTR)
  const payload = scratch + WIF_PAYLOAD_OFF // [400..433] — seguro

  // Construir payload: [0x80, privkey(32), (0x01)]
  store<u8>(payload, WIF_VERSION)
  memory.copy(payload + 1, privKeyPtr, PRIVKEY_LEN)

  let payloadLen: u32 = 33 // 1 + 32
  if (compressed) {
    store<u8>(payload + 33, COMPRESSED_SUFFIX)
    payloadLen = 34
  }

  // Base58Check encode (usa HASH_WORK[0..353] internamente, no pisa [400..])
  return base58check_encode_raw(outIdxPtr, payload, payloadLen)
}

// ═══════════════════════════════════════════════════════════════════════════
// WIF DECODE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decodifica índices Base58Check (WIF) a clave privada de 32 bytes.
 *
 * @param outKeyPtr  Buffer de salida para 32 bytes de clave privada.
 * @param srcIdxPtr  Puntero a índices base58 (ya convertidos desde ASCII).
 * @param srcLen     Número de índices.
 * @returns 1 = uncompressed, 2 = compressed, -1 = inválido.
 */
export function wif_decode_raw(outKeyPtr: usize, srcIdxPtr: usize, srcLen: u32): i32 {
  const scratch = align8(HASH_WORK_PTR)
  const payload = scratch + WIF_PAYLOAD_OFF // [400..433] — para el resultado decodificado

  // Base58Check decode → payload en [400..] (verifica checksum internamente)
  const decodedLen = base58check_decode_raw(payload, srcIdxPtr, srcLen)
  if (decodedLen < 0) return -1 // checksum inválido o demasiado corto

  // Validar prefix (debe ser 0x80 mainnet)
  if (load<u8>(payload) != WIF_VERSION) return -1

  // Validar longitud: 33 (uncompressed) o 34 (compressed)
  if (decodedLen == 33) {
    // Uncompressed: [0x80, key(32)]
    memory.copy(outKeyPtr, payload + 1, PRIVKEY_LEN)
    return 1
  }

  if (decodedLen == 34) {
    // Compressed: [0x80, key(32), 0x01]
    if (load<u8>(payload + 33) != COMPRESSED_SUFFIX) return -1
    memory.copy(outKeyPtr, payload + 1, PRIVKEY_LEN)
    return 2
  }

  return -1 // longitud inesperada
}
