/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  base58/index.ts — Base58 & Base58Check (Bitcoin encoding)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Base58: alfabeto de 58 caracteres (sin 0, O, I, l). Usado en Bitcoin para
 * direcciones (Base58Check), WIF, xpub/xprv.
 *
 * ── ARQUITECTURA (alineada con SHA-2 / RIPEMD-160 / Keccak-256) ──────────
 * • Trabajo sobre HASH_WORK_PTR (layout fijo, zero-alloc).
 * • Alfabeto y tabla inversa como StaticArray<u8> (data segment).
 * • CERO Memory.alloc / Memory.save / Memory.restore.
 * • CERO heap, CERO memory.grow.
 * • Base58Check usa sha256_hash_raw (módulo sha2, mismo HASH_WORK — seguro
 *   porque base58 NO usa HASH_WORK durante la llamada a sha256: el buffer
 *   de trabajo ya fue consumido antes de llamar al hash).
 *
 * ── LAYOUT en HASH_WORK (320 bytes) ──────────────────────────────────────
 *   [0..255]   work buffer (encode/decode: máx 256 B para inputs ≤ 185 B)
 *   [256..287] hash1 (32 B, para Base58Check)
 *   [288..319] hash2 (32 B, para Base58Check)
 *
 * ── API ───────────────────────────────────────────────────────────────────
 *   base58_encode_raw(outIdxPtr, srcPtr, srcLen) → outLen
 *   base58_decode_raw(outPtr, srcIdxPtr, srcLen) → outLen | -1
 *   base58check_encode_raw(outIdxPtr, payloadPtr, payloadLen) → outLen
 *   base58check_decode_raw(outPtr, srcIdxPtr, srcLen) → outLen | -1
 *
 * El wrapper TS convierte índices (0–57) ↔ caracteres ASCII.
 */
import { HASH_WORK_PTR, align8, PARAM_IN_PTR, PARAM_OUT_PTR } from "./memory"
import { sha256_hash_raw } from "../hash/sha2"
export { PARAM_IN_PTR, PARAM_OUT_PTR }

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTES
// ═══════════════════════════════════════════════════════════════════════════

/** Alfabeto Base58 (Bitcoin): "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" */
// prettier-ignore
const ALPHABET: StaticArray<u8> = [
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, // 1-9
  0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,       // A-H
  0x4a, 0x4b, 0x4c, 0x4d, 0x4e,                         // J-N
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, // P-Z
  0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, // a-k
  0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a // m-z
]

/**
 * Tabla inversa: ASCII → índice (0–57), o 255 si inválido.
 * 128 entradas (ASCII completo). Generada con:
 *   for i in range(128): table[i] = ALPHABET.index(chr(i)) if chr(i) in ALPHABET else 255
 */
// prettier-ignore
const CHAR_TO_IDX: StaticArray<u8> = [
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x00-0x0F
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x10-0x1F
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x20-0x2F
  255,   0,   1,   2,   3,   4,   5,   6,   7,   8, 255, 255, 255, 255, 255, 255, // 0x30-0x3F ✅ FIX
  255,   9,  10,  11,  12,  13,  14,  15,  16, 255,  17,  18,  19,  20,  21, 255, // 0x40-0x4F
   22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32, 255, 255, 255, 255, 255, // 0x50-0x5F
  255,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43, 255,  44,  45,  46, // 0x60-0x6F
   47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57, 255, 255, 255, 255, 255  // 0x70-0x7F
]

// ═══════════════════════════════════════════════════════════════════════════
// NÚCLEO: Base58 encode/decode
// ═══════════════════════════════════════════════════════════════════════════

/**
 * [ENCODE] Convierte src[0..srcLen) (base256) a índices base58 en outIdxPtr.
 * Retorna el número de índices escritos (incluye 0 por ceros líderes → '1').
 * El caller reserva outIdxPtr con tamaño ≥ srcLen * 138/100 + 1.
 */
export function base58_encode_raw(outIdxPtr: usize, srcPtr: usize, srcLen: u32): u32 {
  if (srcLen == 0) return 0

  const scratch = align8(HASH_WORK_PTR)
  const b58 = scratch // work buffer (256 B)

  // Contar ceros líderes (→ índice 0, que el wrapper mapea a '1')
  let zeroes: u32 = 0
  let pbegin: u32 = 0
  while (pbegin < srcLen && load<u8>(srcPtr + pbegin) == 0) {
    pbegin++
    zeroes++
  }

  // Buffer de trabajo para la conversión base256 → base58
  const size: u32 = ((srcLen - pbegin) * 138) / 100 + 1
  memory.fill(b58, 0, size)

  let length: u32 = 0
  while (pbegin < srcLen) {
    let carry: u32 = load<u8>(srcPtr + pbegin)
    let i: u32 = 0
    let it: i32 = <i32>size - 1
    while ((carry != 0 || i < length) && it >= 0) {
      carry += <u32>load<u8>(b58 + <usize>it) * 256
      store<u8>(b58 + <usize>it, <u8>(carry % 58))
      carry = carry / 58
      it--
      i++
    }
    length = i
    pbegin++
  }

  // Saltar ceros líderes en el resultado base58
  let it2: u32 = size - length
  while (it2 < size && load<u8>(b58 + it2) == 0) {
    it2++
  }

  // Escribir: primero los `zeroes` (→ 0), luego los dígitos base58
  let outPos: u32 = 0
  for (let i: u32 = 0; i < zeroes; i++) {
    store<u8>(outIdxPtr + outPos, 0)
    outPos++
  }
  while (it2 < size) {
    store<u8>(outIdxPtr + outPos, load<u8>(b58 + it2))
    outPos++
    it2++
  }

  return outPos
}

/**
 * [DECODE] Convierte índices base58 en srcIdxPtr[0..srcLen) a bytes en outPtr.
 * Retorna el número de bytes escritos, o -1 si hay un índice inválido (≥ 58).
 * El caller reserva outPtr con tamaño ≥ srcLen * 733/1000 + 1.
 */
export function base58_decode_raw(outPtr: usize, srcIdxPtr: usize, srcLen: u32): i32 {
  if (srcLen == 0) return 0

  const scratch = align8(HASH_WORK_PTR)
  const b256 = scratch // work buffer (256 B)

  // Contar índices 0 líderes (→ ceros líderes en el resultado)
  let zeroes: u32 = 0
  let pbegin: u32 = 0
  while (pbegin < srcLen && load<u8>(srcIdxPtr + pbegin) == 0) {
    pbegin++
    zeroes++
  }

  // Buffer de trabajo para la conversión base58 → base256
  const size: u32 = ((srcLen - pbegin) * 733) / 1000 + 1
  memory.fill(b256, 0, size)

  let length: u32 = 0
  while (pbegin < srcLen) {
    const idx = load<u8>(srcIdxPtr + pbegin)
    if (idx >= 58) return -1 // índice inválido
    let carry: u32 = idx
    let i: u32 = 0
    let it: i32 = <i32>size - 1
    while ((carry != 0 || i < length) && it >= 0) {
      carry += <u32>load<u8>(b256 + <usize>it) * 58
      store<u8>(b256 + <usize>it, <u8>(carry % 256))
      carry = carry / 256
      it--
      i++
    }
    length = i
    pbegin++
  }

  // Saltar ceros líderes en b256
  let it2: u32 = size - length
  while (it2 < size && load<u8>(b256 + it2) == 0) {
    it2++
  }

  // Escribir: ceros líderes + bytes
  let outPos: u32 = 0
  for (let i: u32 = 0; i < zeroes; i++) {
    store<u8>(outPtr + outPos, 0)
    outPos++
  }
  while (it2 < size) {
    store<u8>(outPtr + outPos, load<u8>(b256 + it2))
    outPos++
    it2++
  }

  return <i32>outPos
}

// ═══════════════════════════════════════════════════════════════════════════
// NÚCLEO: Base58Check (checksum = double-SHA256[0..4])
// ═══════════════════════════════════════════════════════════════════════════

/**
 * [BASE58CHECK ENCODE] payload ‖ checksum(4 B) → índices base58.
 * checksum = SHA256(SHA256(payload))[0..4].
 *
 * Layout seguro en HASH_WORK (sin solape con el work buffer del encode):
 *   [0..255]   b58 work buffer (usado por base58_encode_raw)
 *   [256..287] hash1 (32 B)
 *   [288..319] hash2 (32 B)
 *   [320..320+payloadLen+3] payload + checksum (leído por base58_encode_raw)
 *
 * Para payloads ≤ 185 B: size ≤ 256, así b58 nunca pisa [256..].
 */
export function base58check_encode_raw(outIdxPtr: usize, payloadPtr: usize, payloadLen: u32): u32 {
  const scratch = align8(HASH_WORK_PTR)
  const hash1 = scratch + 256
  const hash2 = scratch + 288
  const bufFinal = scratch + 320
  // Construir payload ‖ checksum en zona segura (no solapa con b58)
  memory.copy(bufFinal, payloadPtr, payloadLen)
  sha256_hash_raw(hash1, payloadPtr, payloadLen)
  sha256_hash_raw(hash2, hash1, 32)
  memory.copy(bufFinal + payloadLen, hash2, 4)
  return base58_encode_raw(outIdxPtr, bufFinal, payloadLen + 4)
}

/**
 * [BASE58CHECK DECODE] índices base58 → payload (verifica checksum).
 * Retorna el número de bytes del payload, o -1 si es inválido.
 * El caller reserva outPtr con tamaño ≥ srcLen * 733/1000 + 1.
 */
export function base58check_decode_raw(outPtr: usize, srcIdxPtr: usize, srcLen: u32): i32 {
  const scratch = align8(HASH_WORK_PTR)
  const hash1 = scratch + 256
  const hash2 = scratch + 288

  // Decodificar base58 → bytes en outPtr (el caller lo reserva)
  const decodedLen = base58_decode_raw(outPtr, srcIdxPtr, srcLen)
  if (decodedLen < 4) return -1

  const payloadLen = <u32>decodedLen - 4

  // double-SHA256 del payload (ya está en outPtr[0..payloadLen])
  sha256_hash_raw(hash1, outPtr, payloadLen)
  sha256_hash_raw(hash2, hash1, 32)

  // Verificar checksum (constant-time, 4 bytes)
  let diff: u32 = 0
  for (let i: u32 = 0; i < 4; i++) {
    diff |= <u32>(load<u8>(outPtr + payloadLen + i) ^ load<u8>(hash2 + i))
  }
  if (diff != 0) return -1

  return <i32>payloadLen
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS: conversión índices ↔ ASCII (para el wrapper TS)
// ═══════════════════════════════════════════════════════════════════════════

/** Convierte índices base58 en outIdxPtr[0..len) a ASCII en el mismo buffer. */
export function base58_indices_to_ascii(idxPtr: usize, len: u32): void {
  for (let i: u32 = 0; i < len; i++) {
    const idx = load<u8>(idxPtr + i)
    store<u8>(idxPtr + i, unchecked(ALPHABET[idx]))
  }
}

/** Convierte ASCII en srcPtr[0..len) a índices base58 en el mismo buffer.
 *  Retorna -1 si hay un carácter inválido. */
export function base58_ascii_to_indices(srcPtr: usize, len: u32): i32 {
  for (let i: u32 = 0; i < len; i++) {
    const c = load<u8>(srcPtr + i)
    if (c >= 128) return -1
    const idx = unchecked(CHAR_TO_IDX[c])
    if (idx == 255) return -1
    store<u8>(srcPtr + i, idx)
  }
  return 0
}
