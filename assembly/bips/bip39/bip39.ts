/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip39/index.ts — BIP39 zero-alloc (mnemonic ↔ entropy ↔ seed)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Implementación completa de BIP39 sobre punteros, sin heap, sin strings en
 * WASM, sin throw. Usa sha256_hash_raw (checksum) y sha512_pbkdf2_raw (seed).
 *
 * ── WORDLIST (zero-alloc) ─────────────────────────────────────────────────
 * WORDLIST_EN se deja como string literal (data segment; leerlo no alloc).
 * bip39_init() construye UNA tabla de 2049 offsets (u16) en memory.data
 * (reserva ESTÁTICA, no heap, no memory.grow). Búsqueda binaria palabra→índice
 * comparando bytes; índice→palabra leyendo el string por rango de offsets.
 *
 * ── LAYOUT en HASH_WORK (zonas auxiliares disjuntas) ──────────────────────
 *   [0..~1640]   usado por sha256 / pbkdf2 internamente
 *   [2048..2080] AUX   = hash SHA-256 (checksum)
 *   [2112..2144] VTMP  = entropy descartable (validate)
 *   [2200..2408] SALT  = "mnemonic" + passphrase
 *
 * ── CÓDIGOS DE ERROR (retorno i32 negativo) ───────────────────────────────
 *   -1 = longitud de entropy inválida
 *   -2 = palabra fuera de la wordlist
 *   -3 = checksum / word-count inválido
 *   -4 = mnemonic vacío
 *
 * ── API ──────────────────────────────────────────────────────────────────
 *   bip39_init()
 *   bip39_entropy_to_mnemonic(outPtr, entPtr, entLen) → mnLen | -1
 *     Escribe el mnemonic como UTF-8 con espacios en outPtr.
 *   bip39_mnemonic_to_entropy(outPtr, mnPtr, mnLen) → entLen | -1..-4
 *     mnPtr = mnemonic UTF-8 (sin split; WASM itera espacios).
 *   bip39_mnemonic_to_seed(outPtr, mnPtr, mnLen, passPtr, passLen) → 64
 *   bip39_validate_mnemonic(mnPtr, mnLen) → bool
 */
import { HASH_WORK_PTR, align8 } from "../../utils/arena"
import { sha256_hash_raw, sha512_pbkdf2_raw } from "../../hash/sha2"
import { WORDLIST_EN } from "./wordlist_en"


// ═══════════════════════════════════════════════════════════════════════════
// OFFSETS DE LA WORDLIST (reserva estática, NO heap)
// ═══════════════════════════════════════════════════════════════════════════

/** OFF[k] = índice en WORDLIST_EN donde empieza la palabra k (ASCII ⇒ chars==bytes). */
const OFF_PTR: usize = memory.data(2049 << 1) // 4098 bytes
let _initialized: bool = false
let _wordCount: u32 = 0

const AUX_OFF: usize = 2048
const VTMP_OFF: usize = 2112
const SALT_OFF: usize = 2200

/** Construye la tabla de offsets una sola vez. Sin heap (itera el literal). */
export function bip39_init(): void {
  if (_initialized) return
  const len: i32 = WORDLIST_EN.length
  let n: u32 = 0
  store<u16>(OFF_PTR, 0) // palabra 0 empieza en 0
  for (let i: i32 = 0; i < len; i++) {
    if (WORDLIST_EN.charCodeAt(i) == 32) {
      n++
      store<u16>(OFF_PTR + (<usize>n << 1), <u16>(i + 1))
    }
  }
  _wordCount = n + 1
  _initialized = true
}

// @ts-ignore
@inline function ensureInit(): void {
  if (!_initialized) bip39_init()
}

// @ts-ignore
@inline function wordStart(k: u32): u32 {
  return <u32>load<u16>(OFF_PTR + (<usize>k << 1))
}
// @ts-ignore
@inline function wordEnd(k: u32): u32 {
  return k + 1 < _wordCount
    ? <u32>load<u16>(OFF_PTR + (<usize>(k + 1) << 1)) - 1
    : <u32>WORDLIST_EN.length
}

/** Copia la palabra k (bytes ASCII) a outPtr. Retorna su longitud. */
function wordBytes(k: u32, outPtr: usize): u32 {
  const s = wordStart(k)
  const e = wordEnd(k)
  const wlen = e - s
  for (let i: u32 = 0; i < wlen; i++) {
    store<u8>(outPtr + i, <u8>(WORDLIST_EN.charCodeAt(<i32>(s + i)) & 0xff))
  }
  return wlen
}

/** Compara input[0..len) con la palabra k. Retorna <0, 0, >0. */
function cmpWord(ptr: usize, len: u32, k: u32): i32 {
  const s = wordStart(k)
  const e = wordEnd(k)
  const wlen = e - s
  const m: u32 = len < wlen ? len : wlen
  for (let i: u32 = 0; i < m; i++) {
    const a: i32 = <i32>load<u8>(ptr + i)
    const b: i32 = WORDLIST_EN.charCodeAt(<i32>(s + i)) & 0xff
    if (a != b) return a - b
  }
  if (len < wlen) return -1
  if (len > wlen) return 1
  return 0
}

/** Búsqueda binaria palabra→índice. Retorna 0..2047 o -1. */
function findWord(ptr: usize, len: u32): i32 {
  let lo: i32 = 0
  let hi: i32 = <i32>_wordCount
  while (lo < hi) {
    const mid: i32 = (lo + hi) >> 1
    const c = cmpWord(ptr, len, <u32>mid)
    if (c == 0) return mid
    if (c < 0) hi = mid
    else lo = mid + 1
  }
  return -1
}

// ═══════════════════════════════════════════════════════════════════════════
// ENTROPY → MNEMONIC
// ═══════════════════════════════════════════════════════════════════════════

/** Escribe el mnemonic (UTF-8 con espacios) en outPtr. Retorna mnLen o -1. */
export function bip39_entropy_to_mnemonic(outPtr: usize, entPtr: usize, entLen: u32): i32 {
  ensureInit()
  if (!(entLen == 16 || entLen == 20 || entLen == 24 || entLen == 28 || entLen == 32)) return -1

  const scratch = align8(HASH_WORK_PTR)
  const aux = scratch + AUX_OFF
  sha256_hash_raw(aux, entPtr, <isize>entLen) // checksum

  const checksumBits: u32 = entLen >> 2
  const totalBits: u32 = entLen * 8 + checksumBits
  const wordCount: u32 = totalBits / 11

  let pos: u32 = 0
  let bitOffset: u32 = 0
  for (let i: u32 = 0; i < wordCount; i++) {
    let index: u32 = 0
    for (let bit: u32 = 0; bit < 11; bit++) {
      const byteIdx: u32 = bitOffset >> 3
      const bitIdx: u32 = 7 - (bitOffset & 7)
      const val: u32 =
        byteIdx < entLen ? <u32>load<u8>(entPtr + byteIdx) : <u32>load<u8>(aux + (byteIdx - entLen))
      index = (index << 1) | ((val >> bitIdx) & 1)
      bitOffset++
    }
    if (i > 0) {
      store<u8>(outPtr + pos, 0x20)
      pos++
    }
    pos += wordBytes(index, outPtr + pos)
  }
  return <i32>pos
}

// ═══════════════════════════════════════════════════════════════════════════
// MNEMONIC → ENTROPY
// ═══════════════════════════════════════════════════════════════════════════

/** Decodifica mnemonic (UTF-8) → entropy en outPtr. Retorna entLen o -1..-4. */
export function bip39_mnemonic_to_entropy(outPtr: usize, mnPtr: usize, mnLen: u32): i32 {
  ensureInit()
  if (mnLen == 0) return -4

  // ── Pasada 1: contar palabras y validar ──
  let wordCount: u32 = 1
  for (let i: u32 = 0; i < mnLen; i++) {
    if (load<u8>(mnPtr + i) == 32) wordCount++
  }
  if (!(wordCount == 12 || wordCount == 15 || wordCount == 18 || wordCount == 21 || wordCount == 24))
    return -3

  const totalBits: u32 = wordCount * 11
  const checksumBits: u32 = totalBits / 33
  const entropyBytes: u32 = (totalBits - checksumBits) >> 3

  memory.fill(outPtr, 0, entropyBytes)
  let provided: u32 = 0
  let bitOffset: u32 = 0

  // ── Pasada 2: búsqueda + bit-packing ──
  let start: u32 = 0
  for (let i: u32 = 0; i <= mnLen; i++) {
    const end: bool = i == mnLen || load<u8>(mnPtr + i) == 32
    if (end && i > start) {
      const wlen: u32 = i - start
      const idx: i32 = findWord(mnPtr + start, wlen)
      if (idx < 0) return -2
      for (let bit: i32 = 10; bit >= 0; bit--) {
        if ((idx >> bit) & 1) {
          const byteIdx: u32 = bitOffset >> 3
          const bitIdx: u32 = 7 - (bitOffset & 7)
          const mask: u32 = 1 << bitIdx
          if (byteIdx < entropyBytes) {
            store<u8>(outPtr + byteIdx, <u8>(<u32>load<u8>(outPtr + byteIdx) | mask))
          } else if (byteIdx == entropyBytes) {
            provided |= mask
          }
        }
        bitOffset++
      }
      start = i + 1
    }
  }

  // ── Checksum ──
  const scratch = align8(HASH_WORK_PTR)
  sha256_hash_raw(scratch + AUX_OFF, outPtr, <isize>entropyBytes)
  const expected: u32 = <u32>load<u8>(scratch + AUX_OFF)
  const mask: u32 = 0xff << (8 - checksumBits)
  if ((provided & mask) != (expected & mask)) return -3

  return <i32>entropyBytes
}

// ═══════════════════════════════════════════════════════════════════════════
// MNEMONIC → SEED (PBKDF2-HMAC-SHA512, 2048 iters)
// ═══════════════════════════════════════════════════════════════════════════

/** Escribe 64 bytes de seed en outPtr. password=mnemonic, salt="mnemonic"+pass. */
export function bip39_mnemonic_to_seed(
  outPtr: usize,
  mnPtr: usize,
  mnLen: u32,
  passPtr: usize,
  passLen: u32
): i32 {
  ensureInit()
  const scratch = align8(HASH_WORK_PTR)
  const salt = scratch + SALT_OFF

  // "mnemonic" (8 bytes) + passphrase
  store<u8>(salt + 0, 0x6d) // m
  store<u8>(salt + 1, 0x6e) // n
  store<u8>(salt + 2, 0x65) // e
  store<u8>(salt + 3, 0x6d) // m
  store<u8>(salt + 4, 0x6f) // o
  store<u8>(salt + 5, 0x6e) // n
  store<u8>(salt + 6, 0x69) // i
  store<u8>(salt + 7, 0x63) // c
  if (passLen > 0) memory.copy(salt + 8, passPtr, passLen)

  sha512_pbkdf2_raw(outPtr, mnPtr, <i32>mnLen, salt, <i32>(8 + passLen), 2048, 64)
  return 64
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDACIÓN
// ═══════════════════════════════════════════════════════════════════════════

/** true si el mnemonic es válido (word-count + palabras + checksum). */
export function bip39_validate_mnemonic(mnPtr: usize, mnLen: u32): bool {
  const scratch = align8(HASH_WORK_PTR)
  return bip39_mnemonic_to_entropy(scratch + VTMP_OFF, mnPtr, mnLen) >= 0
}