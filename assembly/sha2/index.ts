export { Sha256 } from "./sha256"
export { Sha512 } from "./sha512"
export { SHA256_HASH_BYTES, SHA512_HASH_BYTES } from "./constants"
export { Sha256SIMD } from "./sha256-simd"
export { Sha512SIMD } from "./sha512-simd"

import { Sha256 } from "./sha256"
import { Sha512 } from "./sha512"
import { Sha256SIMD, InternalSIMD as InternalSIMDSha256 } from "./sha256-simd"
import { Sha512SIMD, InternalSIMD512 as InternalSIMDSha512 } from "./sha512-simd"
import { Internal as Internal256 } from "./sha256"
import { Internal as Internal512 } from "./sha512"

export function hash256(data: Uint8Array): Uint8Array {
  return Sha256.hash(data)
}

export function hash256SIMD(data: Uint8Array): Uint8Array {
  return Sha256SIMD.hash(data)
}

export function hash512(data: Uint8Array): Uint8Array {
  return Sha512.hash(data)
}

export function hash512SIMD(data: Uint8Array): Uint8Array {
  return Sha512SIMD.hash(data)
}

export function hmac256(data: Uint8Array, key: Uint8Array): Uint8Array {
  return Sha256.hmac(data, key)
}

export function hmac512(data: Uint8Array, key: Uint8Array): Uint8Array {
  return Sha512.hmac(data, key)
}

/**
 * Zero-copy hashing for maximum performance.
 * Data must already be in WASM memory at ptr.
 */
export function hash256Direct(ptr: usize, len: isize): Uint8Array {
  let out = new Uint8Array(32)
  Internal256._hash_raw(out.dataStart, ptr, len)
  return out
}

export function hash256SIMDDirect(ptr: usize, len: isize): Uint8Array {
  let out = new Uint8Array(32)
  InternalSIMDSha256._hash_raw(out.dataStart, ptr, len)
  return out
}

export function hash512Direct(ptr: usize, len: isize): Uint8Array {
  let out = new Uint8Array(64)
  Internal512._hash_raw(out.dataStart, ptr, len)
  return out
}

export function hash512SIMDDirect(ptr: usize, len: isize): Uint8Array {
  let out = new Uint8Array(64)
  InternalSIMDSha512._hash_raw(out.dataStart, ptr, len)
  return out
}

/**
 * Direct hashing into a provided output pointer.
 */
export function hash256DirectPtr(outPtr: usize, inPtr: usize, len: isize): void {
  Internal256._hash_raw(outPtr, inPtr, len)
}

export function hash256SIMDDirectPtr(outPtr: usize, inPtr: usize, len: isize): void {
  InternalSIMDSha256._hash_raw(outPtr, inPtr, len)
}

export function hash512DirectPtr(outPtr: usize, inPtr: usize, len: isize): void {
  Internal512._hash_raw(outPtr, inPtr, len)
}

export function hash512SIMDDirectPtr(outPtr: usize, inPtr: usize, len: isize): void {
  InternalSIMDSha512._hash_raw(outPtr, inPtr, len)
}

/**
 * Returns true if the environment supports SIMD instructions.
 * This is a constant that can be checked at runtime.
 */
export const HAS_SIMD: bool = ASC_FEATURE_SIMD

/**
 * Returns true if the environment supports Atomic operations (Threads).
 */
export const HAS_THREADS: bool = ASC_FEATURE_THREADS
