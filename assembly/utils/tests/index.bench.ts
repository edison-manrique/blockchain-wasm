import { bytesToHex, hexToBytes, bytesToBase64, base64ToBytes } from ".."
export * from "./index.test"

export function benchmark_hex_encode(count: i32): void {
  const data = new Uint8Array(32)
  for (let i = 0; i < 32; i++) data[i] = <u8>i
  for (let i = 0; i < count; i++) {
    bytesToHex(data)
  }
}

export function benchmark_hex_decode(count: i32): void {
  const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  for (let i = 0; i < count; i++) {
    hexToBytes(hex)
  }
}

export function benchmark_b64_encode(count: i32): void {
  const data = new Uint8Array(64)
  for (let i = 0; i < 64; i++) data[i] = <u8>i
  for (let i = 0; i < count; i++) {
    bytesToBase64(data)
  }
}

export function benchmark_b64_decode(count: i32): void {
  const b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="
  for (let i = 0; i < count; i++) {
    base64ToBytes(b64)
  }
}
