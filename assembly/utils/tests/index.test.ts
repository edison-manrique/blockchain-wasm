/**
 * Utils WASM Test Suite
 * Tests hex and base64 conversions with verified vectors.
 */

import { bytesToHex, hexToBytes, bytesToBase64, base64ToBytes, isSameBytes, concatBytes } from ".."

function expectHex(bytes: Uint8Array, expected: string): bool {
  return bytesToHex(bytes) == expected
}

function expectBytes(actual: Uint8Array, expected: Uint8Array): bool {
  return isSameBytes(actual, expected)
}

// ═══════════════════════════════════════
// bytesToHex
// ═══════════════════════════════════════

export function test_hex_encode_empty(): bool {
  return bytesToHex(new Uint8Array(0)) == ""
}

export function test_hex_encode_single(): bool {
  const bytes = new Uint8Array(1)
  bytes[0] = 0xab
  return bytesToHex(bytes) == "ab"
}

export function test_hex_encode_zeros(): bool {
  return expectHex(new Uint8Array(4), "00000000")
}

export function test_hex_encode_ff(): bool {
  const bytes = new Uint8Array(3)
  bytes[0] = 0xff
  bytes[1] = 0xff
  bytes[2] = 0xff
  return expectHex(bytes, "ffffff")
}

export function test_hex_encode_mixed(): bool {
  const bytes = new Uint8Array(6)
  bytes[0] = 0xde
  bytes[1] = 0xad
  bytes[2] = 0xbe
  bytes[3] = 0xef
  bytes[4] = 0xca
  bytes[5] = 0xfe
  return expectHex(bytes, "deadbeefcafe")
}

export function test_hex_encode_all_nibbles(): bool {
  const bytes = new Uint8Array(8)
  bytes[0] = 0x01
  bytes[1] = 0x23
  bytes[2] = 0x45
  bytes[3] = 0x67
  bytes[4] = 0x89
  bytes[5] = 0xab
  bytes[6] = 0xcd
  bytes[7] = 0xef
  return expectHex(bytes, "0123456789abcdef")
}

// SHA-256 of "" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
export function test_hex_encode_sha256(): bool {
  const data: StaticArray<u8> = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41,
    0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
  ]
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) bytes[i] = unchecked(data[i])
  return expectHex(bytes, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
}

// ═══════════════════════════════════════
// hexToBytes
// ═══════════════════════════════════════

export function test_hex_decode_empty(): bool {
  return hexToBytes("").length == 0
}

export function test_hex_decode_single(): bool {
  const bytes = hexToBytes("ab")
  return bytes.length == 1 && bytes[0] == 0xab
}

export function test_hex_decode_deadbeef(): bool {
  const bytes = hexToBytes("deadbeef")
  return bytes.length == 4 && bytes[0] == 0xde && bytes[1] == 0xad && bytes[2] == 0xbe && bytes[3] == 0xef
}

export function test_hex_decode_uppercase(): bool {
  const bytes = hexToBytes("DEADBEEF")
  return bytes.length == 4 && bytes[0] == 0xde && bytes[1] == 0xad && bytes[2] == 0xbe && bytes[3] == 0xef
}

export function test_hex_decode_0x_prefix(): bool {
  const bytes = hexToBytes("0xdeadbeef")
  return bytes.length == 4 && bytes[0] == 0xde && bytes[1] == 0xad && bytes[2] == 0xbe && bytes[3] == 0xef
}

export function test_hex_roundtrip(): bool {
  const original: StaticArray<u8> = [0x00, 0x01, 0x7f, 0x80, 0xff, 0xde, 0xad, 0xbe]
  const bytes = new Uint8Array(8)
  for (let i = 0; i < 8; i++) bytes[i] = unchecked(original[i])
  const hex = bytesToHex(bytes)
  const decoded = hexToBytes(hex)
  return expectBytes(decoded, bytes)
}

export function test_hex_roundtrip_32(): bool {
  // 32-byte key roundtrip
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) bytes[i] = <u8>(i * 7 + 13)
  const hex = bytesToHex(bytes)
  const decoded = hexToBytes(hex)
  return expectBytes(decoded, bytes)
}

// ═══════════════════════════════════════
// bytesToBase64
// ═══════════════════════════════════════

export function test_b64_encode_empty(): bool {
  return bytesToBase64(new Uint8Array(0)) == ""
}

// "Hello" → "SGVsbG8="
export function test_b64_encode_hello(): bool {
  const data: StaticArray<u8> = [0x48, 0x65, 0x6c, 0x6c, 0x6f]
  const bytes = new Uint8Array(5)
  for (let i = 0; i < 5; i++) bytes[i] = unchecked(data[i])
  return bytesToBase64(bytes) == "SGVsbG8="
}

// "Hi" → "SGk="
export function test_b64_encode_2bytes(): bool {
  const bytes = new Uint8Array(2)
  bytes[0] = 0x48
  bytes[1] = 0x69
  return bytesToBase64(bytes) == "SGk="
}

// "A" → "QQ=="
export function test_b64_encode_1byte(): bool {
  const bytes = new Uint8Array(1)
  bytes[0] = 0x41
  return bytesToBase64(bytes) == "QQ=="
}

// "Man" → "TWFu" (no padding)
export function test_b64_encode_3bytes(): bool {
  const data: StaticArray<u8> = [0x4d, 0x61, 0x6e]
  const bytes = new Uint8Array(3)
  for (let i = 0; i < 3; i++) bytes[i] = unchecked(data[i])
  return bytesToBase64(bytes) == "TWFu"
}

// [0,0,0] → "AAAA"
export function test_b64_encode_zeros(): bool {
  return bytesToBase64(new Uint8Array(3)) == "AAAA"
}

// [0xff, 0xff, 0xff] → "////"
export function test_b64_encode_ffs(): bool {
  const bytes = new Uint8Array(3)
  bytes[0] = 0xff
  bytes[1] = 0xff
  bytes[2] = 0xff
  return bytesToBase64(bytes) == "////"
}

// ═══════════════════════════════════════
// base64ToBytes
// ═══════════════════════════════════════

export function test_b64_decode_empty(): bool {
  return base64ToBytes("").length == 0
}

// "SGVsbG8=" → "Hello"
export function test_b64_decode_hello(): bool {
  const bytes = base64ToBytes("SGVsbG8=")
  return (
    bytes.length == 5 &&
    bytes[0] == 0x48 &&
    bytes[1] == 0x65 &&
    bytes[2] == 0x6c &&
    bytes[3] == 0x6c &&
    bytes[4] == 0x6f
  )
}

// "QQ==" → [0x41]
export function test_b64_decode_1byte(): bool {
  const bytes = base64ToBytes("QQ==")
  return bytes.length == 1 && bytes[0] == 0x41
}

// "TWFu" → "Man"
export function test_b64_decode_no_padding(): bool {
  const bytes = base64ToBytes("TWFu")
  return bytes.length == 3 && bytes[0] == 0x4d && bytes[1] == 0x61 && bytes[2] == 0x6e
}

export function test_b64_roundtrip(): bool {
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) bytes[i] = <u8>(i * 11 + 3)
  const b64 = bytesToBase64(bytes)
  const decoded = base64ToBytes(b64)
  return expectBytes(decoded, bytes)
}

export function test_b64_roundtrip_64(): bool {
  // 64-byte seed-like data
  const bytes = new Uint8Array(64)
  for (let i = 0; i < 64; i++) bytes[i] = <u8>(i ^ 0xa5)
  const b64 = bytesToBase64(bytes)
  const decoded = base64ToBytes(b64)
  return expectBytes(decoded, bytes)
}

// ═══════════════════════════════════════
// isSameBytes
// ═══════════════════════════════════════

export function test_same_equal(): bool {
  const a = new Uint8Array(4)
  const b = new Uint8Array(4)
  a[0] = 1
  a[1] = 2
  a[2] = 3
  a[3] = 4
  b[0] = 1
  b[1] = 2
  b[2] = 3
  b[3] = 4
  return isSameBytes(a, b) == true
}

export function test_same_different(): bool {
  const a = new Uint8Array(4)
  const b = new Uint8Array(4)
  a[0] = 1
  a[1] = 2
  a[2] = 3
  a[3] = 4
  b[0] = 1
  b[1] = 2
  b[2] = 3
  b[3] = 5
  return isSameBytes(a, b) == false
}

export function test_same_different_length(): bool {
  return isSameBytes(new Uint8Array(3), new Uint8Array(4)) == false
}

// ═══════════════════════════════════════
// concatBytes
// ═══════════════════════════════════════

export function test_concat(): bool {
  const a = new Uint8Array(2)
  a[0] = 0xde
  a[1] = 0xad
  const b = new Uint8Array(2)
  b[0] = 0xbe
  b[1] = 0xef
  const c = concatBytes(a, b)
  return c.length == 4 && c[0] == 0xde && c[1] == 0xad && c[2] == 0xbe && c[3] == 0xef
}
