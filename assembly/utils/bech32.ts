/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bech32/index.ts — Bech32 / Bech32m (BIP-173 / BIP-350) zero-alloc
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Codificación Bech32/Bech32m para direcciones SegWit (Bitcoin):
 *   • Bech32  (BIP-173): witness v0 (P2WPKH, P2WSH). Const = 1.
 *   • Bech32m (BIP-350): witness v1+ (P2TR/Taproot). Const = 0x2bc830a3.
 *
 * ── ARQUITECTURA (zero-alloc, solo punteros) ──────────────────────────────
 * • Sin Uint8Array, sin new, sin strings, sin heap.
 * • Work buffer en HASH_WORK[0..511] (512 B, suficiente para hrp ≤ 83 + data ≤ 200).
 * • El caller provee HRP como bytes ASCII y data como grupos de 5 bits.
 * • Salida: índices de charset (0-31) que el wrapper TS mapea a caracteres.
 *
 * ── LAYOUT en HASH_WORK ───────────────────────────────────────────────────
 *   [0..511]  work buffer (polymod input: hrp_exp + data + 6)
 *
 * ── API ───────────────────────────────────────────────────────────────────
 *   bech32_encode_raw(outPtr, hrpPtr, hrpLen, dataPtr, dataLen, enc) → outLen
 *   bech32_decode_raw(outDataPtr, outDataLenPtr, hrpPtr, srcPtr, srcLen) → enc | -1
 *   convert_bits_raw(outPtr, srcPtr, srcLen, fromBits, toBits, pad) → outLen | -1
 *   bech32_charset_to_ascii(idxPtr, len)
 *   bech32_ascii_to_charset(srcPtr, len) → 0 | -1
 */
import { HASH_WORK_PTR, align8 } from "./arena"

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTES
// ═══════════════════════════════════════════════════════════════════════════

export const BECH32_CONST: u32 = 1
export const BECH32M_CONST: u32 = 0x2bc830a3

// prettier-ignore
/** Charset Bech32: "qpzry9x8gf2tvdw0s3jn54khce6mua7l" */
const CHARSET: StaticArray<u8> = [
  0x71, 0x70, 0x7a, 0x72, 0x79, 0x39, 0x78, 0x38, // q p z r y 9 x 8
  0x67, 0x66, 0x32, 0x74, 0x76, 0x64, 0x77, 0x30, // g f 2 t v d w 0
  0x73, 0x33, 0x6a, 0x6e, 0x35, 0x34, 0x6b, 0x68, // s 3 j n 5 4 k h
  0x63, 0x65, 0x36, 0x6d, 0x75, 0x61, 0x37, 0x6c  // c e 6 m u a 7 l
]
// prettier-ignore
/** Tabla inversa: ASCII → índice (0-31), o 255 si inválido. 128 entradas. */
const CHARSET_REV: StaticArray<u8> = [
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
   15, 255,  10,  17,  21,  20,  26,  30,   7,   5, 255, 255, 255, 255, 255, 255, // '0'-'9'
  255,  29, 255,  24,  13,  25,   9,   8,  23, 255,  18,  22,  31,  27,  19, 255, // 'A'-'O'
    1,   0,   3,  16,  11,  28,  12,  14,   6,   4,   2, 255, 255, 255, 255, 255, // 'P'-'Z'
  255,  29, 255,  24,  13,  25,   9,   8,  23, 255,  18,  22,  31,  27,  19, 255, // 'a'-'o'
    1,   0,   3,  16,  11,  28,  12,  14,   6,   4,   2, 255, 255, 255, 255, 255  // 'p'-'z'
]

/** Generadores BCH (Bose-Chaudhuri-Hocquenghem) para el checksum. */
const GEN0: u32 = 0x3b6a57b2
const GEN1: u32 = 0x26508e6d
const GEN2: u32 = 0x1ea119fa
const GEN3: u32 = 0x3d4233dd
const GEN4: u32 = 0x2a1462b3

// ═══════════════════════════════════════════════════════════════════════════
// POLYMOD (checksum BCH)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Calcula el polymod BCH sobre values[0..len).
 * Opera sobre un buffer de bytes (valores 0-31).
 */
function polymod(ptr: usize, len: usize): u32 {
  let chk: u32 = 1
  for (let i: usize = 0; i < len; i++) {
    const v = <u32>load<u8>(ptr + i)
    const top = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    if (top & 1) chk ^= GEN0
    if (top & 2) chk ^= GEN1
    if (top & 4) chk ^= GEN2
    if (top & 8) chk ^= GEN3
    if (top & 16) chk ^= GEN4
  }
  return chk
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCODE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Codifica HRP + data (grupos de 5 bits) como índices de charset Bech32.
 *
 * @param outPtr    Salida: índices de charset (0-31) para data+checksum.
 *                  El caller construye: hrp + "1" + charset[outPtr[i]].
 *                  Reservar ≥ dataLen + 6 bytes.
 * @param hrpPtr    HRP como bytes ASCII (ej: "bc" = [0x62, 0x63]).
 * @param hrpLen    Longitud del HRP.
 * @param dataPtr   Data como grupos de 5 bits (valores 0-31).
 * @param dataLen   Número de grupos de 5 bits.
 * @param enc       Constante: BECH32_CONST (1) o BECH32M_CONST (0x2bc830a3).
 * @returns         Número de índices escritos (dataLen + 6), o 0 si error.
 */
export function bech32_encode_raw(
  outPtr: usize,
  hrpPtr: usize,
  hrpLen: u32,
  dataPtr: usize,
  dataLen: u32,
  enc: u32
): u32 {
  if (hrpLen == 0 || hrpLen > 83) return 0
  if (dataLen == 0) return 0

  const work = align8(HASH_WORK_PTR)

  // Construir: hrp_expand || data || [0,0,0,0,0,0]
  // hrp_expand = [hrp[i]>>5] || [0] || [hrp[i]&31]  (longitud: hrpLen*2 + 1)
  const hrpExpLen: usize = <usize>hrpLen * 2 + 1
  let pos: usize = 0

  // HRP high bits
  for (let i: u32 = 0; i < hrpLen; i++) {
    const c = <u32>load<u8>(hrpPtr + i)
    if (c < 33 || c > 126) return 0 // HRP inválido
    store<u8>(work + pos, <u8>(c >> 5))
    pos++
  }
  // Separador
  store<u8>(work + pos, 0)
  pos++
  // HRP low bits
  for (let i: u32 = 0; i < hrpLen; i++) {
    const c = <u32>load<u8>(hrpPtr + i)
    store<u8>(work + pos, <u8>(c & 31))
    pos++
  }
  // Data
  for (let i: u32 = 0; i < dataLen; i++) {
    store<u8>(work + pos, load<u8>(dataPtr + i))
    pos++
  }
  // 6 bytes de cero (para el checksum)
  for (let i: u32 = 0; i < 6; i++) {
    store<u8>(work + pos, 0)
    pos++
  }

  // Calcular checksum
  const mod = polymod(work, pos) ^ enc

  // Escribir data en outPtr
  for (let i: u32 = 0; i < dataLen; i++) {
    store<u8>(outPtr + i, load<u8>(dataPtr + i))
  }

  // Escribir checksum (6 grupos de 5 bits, MSB primero)
  for (let i: u32 = 0; i < 6; i++) {
    store<u8>(outPtr + dataLen + i, <u8>((mod >> (5 * (5 - i))) & 31))
  }

  return dataLen + 6
}

// ═══════════════════════════════════════════════════════════════════════════
// DECODE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decodifica y verifica una secuencia Bech32 (hrp + separator + data+checksum).
 *
 * @param outDataPtr    Salida: data (grupos de 5 bits, SIN checksum).
 * @param outDataLenPtr Salida: se escribe la longitud de data.
 * @param hrpPtr        HRP como bytes ASCII.
 * @param hrpLen        Longitud del HRP.
 * @param srcPtr        Data+checksum como índices de charset (0-31).
 * @param srcLen        Longitud de data+checksum (debe ser ≥ 6).
 * @returns             BECH32_CONST o BECH32M_CONST si es válido, -1 si error.
 */
export function bech32_decode_raw(
  outDataPtr: usize,
  outDataLenPtr: usize,
  hrpPtr: usize,
  hrpLen: u32,
  srcPtr: usize,
  srcLen: u32
): i32 {
  if (hrpLen == 0 || hrpLen > 83) return -1
  if (srcLen < 6) return -1

  const work = align8(HASH_WORK_PTR)
  const hrpExpLen: usize = <usize>hrpLen * 2 + 1
  let pos: usize = 0

  // HRP expand
  for (let i: u32 = 0; i < hrpLen; i++) {
    const c = <u32>load<u8>(hrpPtr + i)
    if (c < 33 || c > 126) return -1
    store<u8>(work + pos, <u8>(c >> 5))
    pos++
  }
  store<u8>(work + pos, 0)
  pos++
  for (let i: u32 = 0; i < hrpLen; i++) {
    const c = <u32>load<u8>(hrpPtr + i)
    store<u8>(work + pos, <u8>(c & 31))
    pos++
  }

  // Data + checksum
  for (let i: u32 = 0; i < srcLen; i++) {
    const v = load<u8>(srcPtr + i)
    if (v >= 32) return -1 // valor inválido
    store<u8>(work + pos, v)
    pos++
  }

  // Verificar polymod
  const mod = polymod(work, pos)
  if (mod != BECH32_CONST && mod != BECH32M_CONST) return -1

  // Copiar data (sin los 6 bytes de checksum)
  const dataLen = srcLen - 6
  for (let i: u32 = 0; i < dataLen; i++) {
    store<u8>(outDataPtr + i, load<u8>(srcPtr + i))
  }
  store<u32>(outDataLenPtr, dataLen)

  return <i32>mod // 1 = bech32, 0x2bc830a3 = bech32m
}

// ═══════════════════════════════════════════════════════════════════════════
// CONVERT BITS (8↔5)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Convierte entre tamaños de grupo de bits (ej: 8→5 para encode, 5→8 para decode).
 *
 * @param outPtr    Buffer de salida (reservar suficiente).
 * @param srcPtr    Buffer de entrada.
 * @param srcLen    Número de valores de entrada.
 * @param fromBits  Bits por grupo de entrada (ej: 8).
 * @param toBits    Bits por grupo de salida (ej: 5).
 * @param pad       true = pad con ceros si sobran bits; false = error si sobran.
 * @returns         Número de valores escritos, o -1 si error.
 */
export function convert_bits_raw(
  outPtr: usize,
  srcPtr: usize,
  srcLen: u32,
  fromBits: u32,
  toBits: u32,
  pad: bool
): i32 {
  const maxv: u32 = (1 << toBits) - 1
  let acc: u32 = 0
  let bits: u32 = 0
  let outLen: u32 = 0

  for (let i: u32 = 0; i < srcLen; i++) {
    const value = <u32>load<u8>(srcPtr + i)
    if (value >> fromBits != 0) return -1 // valor excede fromBits
    acc = (acc << fromBits) | value
    bits += fromBits
    while (bits >= toBits) {
      bits -= toBits
      store<u8>(outPtr + outLen, <u8>((acc >> bits) & maxv))
      outLen++
    }
  }

  if (pad) {
    if (bits > 0) {
      store<u8>(outPtr + outLen, <u8>((acc << (toBits - bits)) & maxv))
      outLen++
    }
  } else {
    if (bits >= fromBits) return -1
    if ((acc << (toBits - bits)) & maxv) return -1
  }

  return <i32>outLen
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS: charset ↔ ASCII
// ═══════════════════════════════════════════════════════════════════════════

/** Convierte índices (0-31) a caracteres ASCII del charset Bech32 (in-place). */
export function bech32_charset_to_ascii(idxPtr: usize, len: u32): void {
  for (let i: u32 = 0; i < len; i++) {
    const idx = load<u8>(idxPtr + i)
    store<u8>(idxPtr + i, unchecked(CHARSET[idx]))
  }
}

/** Convierte caracteres ASCII a índices del charset (0-31) (in-place).
 *  Acepta mayúsculas y minúsculas. Retorna -1 si hay carácter inválido. */
export function bech32_ascii_to_charset(srcPtr: usize, len: u32): i32 {
  for (let i: u32 = 0; i < len; i++) {
    const c = load<u8>(srcPtr + i)
    if (c >= 128) return -1
    const idx = unchecked(CHARSET_REV[c])
    if (idx == 255) return -1
    store<u8>(srcPtr + i, idx)
  }
  return 0
}

// ═══════════════════════════════════════════════════════════════════════════
// RE-EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

export { PARAM_IN_PTR, PARAM_OUT_PTR } from "./arena"
