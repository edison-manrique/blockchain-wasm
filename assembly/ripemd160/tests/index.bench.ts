import { ripemd160 } from ".."
export * from "./index.test"

export function benchmark_ripemd160_64k(iterations: i32): void {
  const message = new Uint8Array(1024 * 64)
  for (let i = 0; i < 1024 * 64; i++) message[i] = <u8>(i & 0xff)

  for (let i = 0; i < iterations; i++) {
    ripemd160(message)
  }
}

export function benchmark_ripemd160_1mb(iterations: i32): void {
  const message = new Uint8Array(1024 * 1024)
  for (let i = 0; i < 1024 * 1024; i++) message[i] = <u8>(i & 0xff)

  for (let i = 0; i < iterations; i++) {
    ripemd160(message)
  }
}

export function benchmark_ripemd160_10mb(iterations: i32): void {
  const message = new Uint8Array(1024 * 1024 * 10)
  for (let i = 0; i < 1024 * 1024 * 10; i++) message[i] = <u8>(i & 0xff)

  for (let i = 0; i < iterations; i++) {
    ripemd160(message)
  }
}
