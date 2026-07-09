/**
 * PBKDF2 WASM Benchmark Suite
 */
import { pbkdf2_sha512 } from ".."

export * from "./index.test"

function utf8ToBytes(s: string): Uint8Array {
  return Uint8Array.wrap(String.UTF8.encode(s))
}

export function benchmark_pbkdf2(count: i32): void {
  const password = utf8ToBytes("benchmark password test")
  const salt = utf8ToBytes("mnemonic")
  for (let i = 0; i < count; i++) {
    pbkdf2_sha512(password, salt, 2048, 64)
  }
}
