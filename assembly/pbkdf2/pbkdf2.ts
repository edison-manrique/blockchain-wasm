/**
 * ⚡ PBKDF2-HMAC-SHA512 — Optimized for WASM & Zero-Allocation in Loop
 */

import { Internal as Sha512Internal, Sha512 } from "../sha2/sha512"
import { Memory } from "../utils/Memory"

// SHA-512 constants
const BLOCK: i32 = 128
const HASH: i32 = 64

/**
 * PBKDF2 using HMAC-SHA512.
 *
 * @param password  - The password bytes.
 * @param salt      - The salt bytes.
 * @param iterations - Number of iterations (e.g. 2048 for BIP39).
 * @param dkLen     - Desired derived key length in bytes (e.g. 64 for BIP39).
 * @returns The derived key as a Uint8Array.
 */
export function pbkdf2_sha512(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: i32,
  dkLen: i32
): Uint8Array {
  const scratch = Memory.save()

  // 1. Buffers (Allocated from scratch memory as raw pointers)
  const ipadPtr = Memory.alloc(BLOCK)
  const opadPtr = Memory.alloc(BLOCK)
  const U_ptr = Memory.alloc(HASH)
  const saltBlockLen = salt.length + 4
  const saltBlockPtr = Memory.alloc(saltBlockLen)
  
  // States for SHA-512 (pre-computed ipad/opad)
  const ipadStatePtr = Memory.alloc(192) // 64 state + 128 buffer
  const opadStatePtr = Memory.alloc(192)
  
  // Working states for current HMAC call
  const stInnerPtr = Memory.alloc(192)
  const stOuterPtr = Memory.alloc(192)
  const paddedPtr = Memory.alloc(256) // Buffer for _hashFinal_ptr
  const outHMAC_ptr = Memory.alloc(HASH)

  // derivedKey is the only persistent allocation
  const derivedKey = new Uint8Array(dkLen)

  // HMAC preparation: Precompute ipad/opad
  let keyPtr: usize
  let keyLen: i32
  let keyToFree: Uint8Array | null = null

  if (password.length > BLOCK) {
    keyToFree = Sha512.hash(password)
    keyPtr = keyToFree.dataStart
    keyLen = HASH
  } else {
    keyPtr = password.dataStart
    keyLen = password.length
  }

  for (let i = 0; i < BLOCK; i++) {
    const k: u8 = i < keyLen ? load<u8>(keyPtr + i) : 0
    store<u8>(ipadPtr + i, k ^ 0x36)
    store<u8>(opadPtr + i, k ^ 0x5c)
  }

  // Pre-initialize ipadState/opadState
  Sha512Internal._hashInit_ptr(ipadStatePtr)
  Sha512Internal._hashUpdate_ptr(ipadStatePtr, ipadPtr, BLOCK, 0)
  
  Sha512Internal._hashInit_ptr(opadStatePtr)
  Sha512Internal._hashUpdate_ptr(opadStatePtr, opadPtr, BLOCK, 0)

  const numBlocks = (dkLen + HASH - 1) / HASH
  memory.copy(saltBlockPtr, salt.dataStart, salt.length)

  for (let blockIdx: i32 = 1; blockIdx <= numBlocks; blockIdx++) {
    const idxOff = salt.length
    store<u8>(saltBlockPtr + idxOff + 0, <u8>((blockIdx >>> 24) & 0xff))
    store<u8>(saltBlockPtr + idxOff + 1, <u8>((blockIdx >>> 16) & 0xff))
    store<u8>(saltBlockPtr + idxOff + 2, <u8>((blockIdx >>> 8) & 0xff))
    store<u8>(saltBlockPtr + idxOff + 3, <u8>(blockIdx & 0xff))

    // U_1 = HMAC(ipadState, opadState, salt || INT)
    hmac_precomputed_ptr(
        ipadStatePtr, opadStatePtr, 
        saltBlockPtr, saltBlockLen, 
        outHMAC_ptr, 
        stInnerPtr, stOuterPtr, paddedPtr
    )
    
    // T is temporary for XOR accumulation
    const T_ptr = Memory.alloc(HASH)
    memory.copy(T_ptr, outHMAC_ptr, HASH)
    memory.copy(U_ptr, outHMAC_ptr, HASH)

    // U_2 ... U_c
    for (let iter: i32 = 1; iter < iterations; iter++) {
      hmac_precomputed_ptr(
          ipadStatePtr, opadStatePtr, 
          U_ptr, HASH, 
          outHMAC_ptr, 
          stInnerPtr, stOuterPtr, paddedPtr
      )
      memory.copy(U_ptr, outHMAC_ptr, HASH)
      xor64(T_ptr, U_ptr)
    }

    const offset = (blockIdx - 1) * HASH
    const copyLen = min(HASH, dkLen - offset)
    memory.copy(derivedKey.dataStart + offset, T_ptr, copyLen)
  }

  // Final Cleanup
  Memory.restore(scratch)
  
  if (keyToFree) {
     heap.free(changetype<usize>(keyToFree.buffer))
  }

  return derivedKey
}

/**
 * Performs HMAC using pre-computed states, entirely via raw pointers.
 * Zero-allocation.
 */
// @ts-ignore
@inline
function hmac_precomputed_ptr(
  ipadState: usize,
  opadState: usize,
  messagePtr: usize,
  messageLen: i32,
  outPtr: usize,
  stI: usize,
  stO: usize,
  padded: usize
): void {
  // Inner hash
  memory.copy(stI, ipadState, 192)
  let r = Sha512Internal._hashUpdate_ptr(stI, messagePtr, messageLen, 0)
  Sha512Internal._hashFinal_ptr(stI, padded, outPtr, BLOCK + messageLen, r)

  // Outer hash
  memory.copy(stO, opadState, 192)
  r = Sha512Internal._hashUpdate_ptr(stO, outPtr, HASH, 0)
  Sha512Internal._hashFinal_ptr(stO, padded, outPtr, BLOCK + HASH, r)
}

// @ts-ignore
@inline
function xor64(dst: usize, src: usize): void {
  store<u64>(dst + 0, load<u64>(dst + 0) ^ load<u64>(src + 0))
  store<u64>(dst + 8, load<u64>(dst + 8) ^ load<u64>(src + 8))
  store<u64>(dst + 16, load<u64>(dst + 16) ^ load<u64>(src + 16))
  store<u64>(dst + 24, load<u64>(dst + 24) ^ load<u64>(src + 24))
  store<u64>(dst + 32, load<u64>(dst + 32) ^ load<u64>(src + 32))
  store<u64>(dst + 40, load<u64>(dst + 40) ^ load<u64>(src + 40))
  store<u64>(dst + 48, load<u64>(dst + 48) ^ load<u64>(src + 48))
  store<u64>(dst + 56, load<u64>(dst + 56) ^ load<u64>(src + 56))
}
