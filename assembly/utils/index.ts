import { LocalArena } from "./LocalArena"

// =========================================================================
// LOOKUP TABLES (Segmento de datos — Cero asignaciones en heap)
// =========================================================================
const HEX_ENC_HI = new StaticArray<u8>(256)
const HEX_ENC_LO = new StaticArray<u8>(256)
const HEX_DEC = new StaticArray<u8>(128)
const B64_ENC = new StaticArray<u8>(64)
const B64_DEC = new StaticArray<u8>(128)

function initTables(): void {
  // HEX ENC/DEC
  for (let i: i32 = 0; i < 256; i++) {
    let hi = <u8>(i >> 4)
    let lo = <u8>(i & 0x0f)
    unchecked(HEX_ENC_HI[i] = hi < 10 ? 0x30 + hi : 0x57 + hi)
    unchecked(HEX_ENC_LO[i] = lo < 10 ? 0x30 + lo : 0x57 + lo)
  }
  for (let i: i32 = 0; i < 128; i++) unchecked(HEX_DEC[i] = 0xff)
  for (let i: i32 = 0; i < 10; i++)  unchecked(HEX_DEC[0x30 + i] = <u8>i)
  for (let i: i32 = 0; i < 6; i++) {
    unchecked(HEX_DEC[0x61 + i] = <u8>(10 + i))
    unchecked(HEX_DEC[0x41 + i] = <u8>(10 + i))
  }

  // BASE64 ENC/DEC
  for (let i: i32 = 0; i < 26; i++) unchecked(B64_ENC[i] = <u8>(0x41 + i))
  for (let i: i32 = 0; i < 26; i++) unchecked(B64_ENC[i + 26] = <u8>(0x61 + i))
  for (let i: i32 = 0; i < 10; i++) unchecked(B64_ENC[i + 52] = <u8>(0x30 + i))
  unchecked(B64_ENC[62] = 0x2b)
  unchecked(B64_ENC[63] = 0x2f)

  for (let i: i32 = 0; i < 128; i++) unchecked(B64_DEC[i] = 0xff)
  for (let i: i32 = 0; i < 64; i++)  unchecked(B64_DEC[unchecked(B64_ENC[i])] = <u8>i)
}
initTables()

// =========================================================================
// >> HEXADECIMAL (Zero-Alloc & Raw Pointers)
// =========================================================================

/**
 * Escribe hex directamente en un puntero. Máximo rendimiento.
 */
// @ts-ignore
@inline
function _bytesToHexRaw(dataPtr: usize, dataLen: usize, outPtr: usize): void {
  for (let i: usize = 0; i < dataLen; i++) {
    const b = load<u8>(dataPtr + i)
    store<u8>(outPtr + (i << 1), unchecked(HEX_ENC_HI[b]))
    store<u8>(outPtr + (i << 1) + 1, unchecked(HEX_ENC_LO[b]))
  }
}

export function bytesToHexInto(data: Uint8Array, out: Uint8Array): i32 {
  _bytesToHexRaw(data.dataStart, <usize>data.length, out.dataStart)
  return data.length << 1
}

/**
 * Utiliza el Arena Allocator para el buffer temporal. 
 * Solo fugará el String final (requerido por el Host).
 */
export function bytesToHex(data: Uint8Array): string {
  const dataLen = <usize>data.length
  if (dataLen == 0) return ""
  const outLen = dataLen << 1

  const marker = LocalArena.save()
  const ptr = LocalArena.alloc(outLen) // Asignación ultra-rápida en Arena
  
  _bytesToHexRaw(data.dataStart, dataLen, ptr)
  
  // String.UTF8.decodeUnsafe toma punteros puros. ¡Cero fugas aquí!
  const result = String.UTF8.decodeUnsafe(ptr, <usize>outLen)
  
  LocalArena.restore(marker) // Liberamos el buffer temporal inmediatamente
  return result
}

export function hexToBytesInto(hex: string, out: Uint8Array): i32 {
  let offset: i32 = 0
  let strLen = hex.length
  if (strLen >= 2 && hex.charCodeAt(0) == 0x30 && (hex.charCodeAt(1) == 0x78 || hex.charCodeAt(1) == 0x58)) {
    offset = 2
    strLen -= 2
  }
  const byteLen = strLen >> 1
  const outStart = out.dataStart
  for (let i: i32 = 0; i < byteLen; i++) {
    const hiChar = hex.charCodeAt(offset + (i << 1))
    const loChar = hex.charCodeAt(offset + (i << 1) + 1)
    store<u8>(outStart + i, (unchecked(HEX_DEC[hiChar & 0x7f]) << 4) | unchecked(HEX_DEC[loChar & 0x7f]))
  }
  return byteLen
}

export function hexToBytes(hex: string): Uint8Array {
  let strLen = hex.length
  if (strLen >= 2 && hex.charCodeAt(0) == 0x30 && (hex.charCodeAt(1) == 0x78 || hex.charCodeAt(1) == 0x58)) {
    strLen -= 2
  }
  const byteLen = strLen >> 1
  const out = new Uint8Array(byteLen)
  hexToBytesInto(hex, out)
  return out
}

// =========================================================================
// >> BASE64 (Zero-Alloc & Raw Pointers)
// =========================================================================
// @ts-ignore
@inline
function _bytesToBase64Raw(dataPtr: usize, dataLen: usize, outPtr: usize): i32 {
  let i: usize = 0
  let outIdx: usize = 0
  const triples = dataLen / 3

  for (let t: usize = 0; t < triples; t++) {
    const n = (<u32>load<u8>(dataPtr + i++) << 16) | (<u32>load<u8>(dataPtr + i++) << 8) | <u32>load<u8>(dataPtr + i++)
    store<u8>(outPtr + outIdx++, B64_ENC[(n >> 18) & 0x3f])
    store<u8>(outPtr + outIdx++, B64_ENC[(n >> 12) & 0x3f])
    store<u8>(outPtr + outIdx++, B64_ENC[(n >> 6) & 0x3f])
    store<u8>(outPtr + outIdx++, B64_ENC[n & 0x3f])
  }

  const remainder = dataLen - i
  if (remainder == 1) {
    const n = <u32>load<u8>(dataPtr + i)
    store<u8>(outPtr + outIdx++, B64_ENC[n >> 2])
    store<u8>(outPtr + outIdx++, B64_ENC[(n << 4) & 0x3f])
    store<u8>(outPtr + outIdx++, 0x3d)
    store<u8>(outPtr + outIdx++, 0x3d)
  } else if (remainder == 2) {
    const n = (<u32>load<u8>(dataPtr + i) << 8) | <u32>load<u8>(dataPtr + i + 1)
    store<u8>(outPtr + outIdx++, B64_ENC[n >> 10])
    store<u8>(outPtr + outIdx++, B64_ENC[(n >> 4) & 0x3f])
    store<u8>(outPtr + outIdx++, B64_ENC[(n << 2) & 0x3f])
    store<u8>(outPtr + outIdx++, 0x3d)
  }
  return <i32>outIdx
}

export function bytesToBase64Into(data: Uint8Array, out: Uint8Array): i32 {
  return _bytesToBase64Raw(data.dataStart, <usize>data.length, out.dataStart)
}

export function bytesToBase64(data: Uint8Array): string {
  const dataLen = <usize>data.length
  if (dataLen == 0) return ""
  const outLen = ((dataLen + 2) / 3) * 4

  const marker = LocalArena.save()
  const ptr = LocalArena.alloc(outLen)
  
  const written = _bytesToBase64Raw(data.dataStart, dataLen, ptr)
  const result = String.UTF8.decodeUnsafe(ptr, <usize>written)
  
  LocalArena.restore(marker)
  return result
}

export function base64ToBytesInto(base64: string, out: Uint8Array): i32 {
  let strLen = base64.length
  if (strLen == 0) return 0
  
  let padding: i32 = 0
  if (base64.charCodeAt(strLen - 1) == 0x3d) padding++
  if (base64.charCodeAt(strLen - 2) == 0x3d) padding++

  const outLen = ((strLen * 3) >> 2) - padding
  const outStart = out.dataStart
  let i: i32 = 0
  let outIdx: i32 = 0
  const quads = strLen >> 2

  for (let q: i32 = 0; q < quads; q++) {
    const a = <u32>unchecked(B64_DEC[base64.charCodeAt(i++) & 0x7f])
    const b = <u32>unchecked(B64_DEC[base64.charCodeAt(i++) & 0x7f])
    const c = <u32>unchecked(B64_DEC[base64.charCodeAt(i++) & 0x7f])
    const d = <u32>unchecked(B64_DEC[base64.charCodeAt(i++) & 0x7f])
    const n: u32 = (a << 18) | (b << 12) | (c << 6) | d
    
    if (outIdx < outLen) store<u8>(outStart + outIdx++, <u8>(n >> 16))
    if (outIdx < outLen) store<u8>(outStart + outIdx++, <u8>(n >> 8))
    if (outIdx < outLen) store<u8>(outStart + outIdx++, <u8>n)
  }
  return outLen
}

export function base64ToBytes(base64: string): Uint8Array {
  const strLen = base64.length
  if (strLen == 0) return new Uint8Array(0)
  
  let padding: i32 = 0
  if (base64.charCodeAt(strLen - 1) == 0x3d) padding++
  if (base64.charCodeAt(strLen - 2) == 0x3d) padding++

  const outLen = ((strLen * 3) >> 2) - padding
  const out = new Uint8Array(outLen)
  base64ToBytesInto(base64, out)
  return out
}


// =========================================================================
// >> COMPARISON & UTILS (Zero-Alloc)
// =========================================================================

export function isSameBytes(a: Uint8Array, b: Uint8Array): bool {
  const len = a.length
  if (len != b.length) return false
  const aPtr = a.dataStart
  const bPtr = b.dataStart
  let diff: u32 = 0
  for (let i: i32 = 0; i < len; i++) {
    diff |= <u32>load<u8>(aPtr + i) ^ <u32>load<u8>(bPtr + i)
  }
  return diff == 0
}

export function concatBytesInto(a: Uint8Array, b: Uint8Array, out: Uint8Array): void {
  memory.copy(out.dataStart, a.dataStart, a.length)
  memory.copy(out.dataStart + a.length, b.dataStart, b.length)
}

export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  memory.copy(out.dataStart, a.dataStart, a.length)
  memory.copy(out.dataStart + a.length, b.dataStart, b.length)
  return out
}

/**
 * Libera un objeto de la memoria. 
 * Útil cuando se usa el --runtime stub para evitar fugas masivas.
 */
// @ts-ignore
@inline
export function freeObject<T>(obj: T): void {
  if (obj) heap.free(changetype<usize>(obj))
}