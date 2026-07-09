/**
 * ⚡ BIP32 — Hierarchical Deterministic Wallets (WASM)
 *
 * MEMORY-OPTIMIZED for --runtime stub (no GC):
 * - Static pre-allocated buffers for HMAC data, IL/IR split
 * - Memory.save()/restore() for all EC operations
 * - Zero intermediate Uint8Array allocations in hot paths
 * - Only the result HDKey/pubkey/privkey allocates
 */

import { Sha512, Sha256 } from "../sha2"
import { hash as ripemd160_hash } from "../ripemd160"
import { BigInt256, Scalar256, GeneratorTable, Point } from "./utils"
import { Memory } from "../utils/Memory"

// ═══════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════

const HARDENED_OFFSET: u32 = 0x80000000

// "Bitcoin seed" as static bytes — no allocation
const BITCOIN_SEED: StaticArray<u8> = [66, 105, 116, 99, 111, 105, 110, 32, 115, 101, 101, 100]

// (P+1)/4 for sqrt mod P
const EXP_P14_0: u64 = 0xffffffffbfffff0c
const EXP_P14_1: u64 = 0xffffffffffffffff
const EXP_P14_2: u64 = 0xffffffffffffffff
const EXP_P14_3: u64 = 0x3fffffffffffffff

// ═══════════════════════════════════════════════════════
// PRE-ALLOCATED STATIC BUFFERS (reused across calls)
// These never grow — they live for the module lifetime.
// ═══════════════════════════════════════════════════════

// "Bitcoin seed" as Uint8Array (allocated once)
const SEED_KEY: Uint8Array = _staticFromArray(BITCOIN_SEED, 12)

// Buffer for HMAC data (37 bytes = max(1 + 32 + 4, 33 + 4))
const _hmacData: Uint8Array = new Uint8Array(37)

// Buffer for HMAC result (64 bytes)
const _hmacResult: Uint8Array = new Uint8Array(64)

// Temporary 32-byte buffers for IL/IR split
const _IL: Uint8Array = new Uint8Array(32)
const _IR: Uint8Array = new Uint8Array(32)

// Temporary for hash160 intermediate SHA-256 result
const _sha256Tmp: Uint8Array = new Uint8Array(32)

// Temporary 20-byte buffer for hash160 result
const _hash160Tmp: Uint8Array = new Uint8Array(20)

// Temporary 33-byte buffer for compressed pubkey
const _pubkeyTmp: Uint8Array = new Uint8Array(33)

function _staticFromArray(src: StaticArray<u8>, len: i32): Uint8Array {
  const result = new Uint8Array(len)
  for (let i = 0; i < len; i++) result[i] = unchecked(src[i])
  return result
}

// ═══════════════════════════════════════════════════════
// HMAC-SHA512 — uses pre-allocated buffers
// Sha512.hmac(message, key) — note parameter order
// ═══════════════════════════════════════════════════════

/**
 * HMAC-SHA512 writing result into the _hmacResult static buffer.
 * Caller must copy out before next call.
 */
function hmacSha512Into(key: Uint8Array, data: Uint8Array, dataLen: i32): void {
  // We need a view of the right length for Sha512.hmac
  const msg = dataLen == data.length ? data : data.subarray(0, dataLen)
  const result = Sha512.hmac(msg, key)
  memory.copy(_hmacResult.dataStart, result.dataStart, 64)
}

// ═══════════════════════════════════════════════════════
// HASH160 = RIPEMD160(SHA256(data)) — reuses static bufs
// Returns fingerprint u32 (first 4 bytes)
// ═══════════════════════════════════════════════════════

function getFingerprint(pub: Uint8Array): u32 {
  // SHA-256 into static buffer
  const sha = Sha256.hash(pub)
  memory.copy(_sha256Tmp.dataStart, sha.dataStart, 32)

  // RIPEMD-160 into static buffer
  const rip = ripemd160_hash(_sha256Tmp)
  memory.copy(_hash160Tmp.dataStart, rip.dataStart, 20)

  return (
    (<u32>unchecked(_hash160Tmp[0]) << 24) |
    (<u32>unchecked(_hash160Tmp[1]) << 16) |
    (<u32>unchecked(_hash160Tmp[2]) << 8) |
    <u32>unchecked(_hash160Tmp[3])
  )
}

// ═══════════════════════════════════════════════════════
// u32 Big-Endian helpers (inline, zero alloc)
// ═══════════════════════════════════════════════════════

// @ts-ignore
@inline
function writeU32BE(buf: Uint8Array, offset: i32, value: u32): void {
  unchecked(buf[offset] = <u8>((value >> 24) & 0xff))
  unchecked(buf[offset + 1] = <u8>((value >> 16) & 0xff))
  unchecked(buf[offset + 2] = <u8>((value >> 8) & 0xff))
  unchecked(buf[offset + 3] = <u8>(value & 0xff))
}

// ═══════════════════════════════════════════════════════
// Get compressed pubkey from privkey (uses Memory)
// Writes into _pubkeyTmp (33 bytes). Caller must copy out.
// ═══════════════════════════════════════════════════════

function pubkeyFromPrivkeyInto(privKey: Uint8Array): void {
  const ctxPtr = Memory.save()

  const priv_ptr = Memory.alloc(32)
  BigInt256.fromBytes(priv_ptr, privKey)

  const pub_ptr = Memory.alloc(96)
  GeneratorTable.multiply(pub_ptr, priv_ptr)

  // Jacobian → Affine → Compressed into _pubkeyTmp
  const z_inv = Memory.alloc(32)
  BigInt256.modInverse(z_inv, pub_ptr + 64)
  const z_inv2 = Memory.alloc(32)
  BigInt256.sqrMod(z_inv2, z_inv)
  const x_aff = Memory.alloc(32)
  BigInt256.mulMod(x_aff, pub_ptr, z_inv2)
  const z_inv3 = Memory.alloc(32)
  BigInt256.mulMod(z_inv3, z_inv2, z_inv)
  const y_aff = Memory.alloc(32)
  BigInt256.mulMod(y_aff, pub_ptr + 32, z_inv3)

  const yIsOdd = (load<u64>(y_aff) & 1) != 0
  _pubkeyTmp[0] = yIsOdd ? 0x03 : 0x02
  BigInt256.toBytes(x_aff, _pubkeyTmp.subarray(1, 33))

  Memory.restore(ctxPtr)
}

/**
 * Public API: returns NEW 33-byte compressed pubkey.
 */
function pubkeyFromPrivkey(privKey: Uint8Array): Uint8Array {
  pubkeyFromPrivkeyInto(privKey)
  const result = new Uint8Array(33)
  memory.copy(result.dataStart, _pubkeyTmp.dataStart, 33)
  return result
}

// ═══════════════════════════════════════════════════════
// Point decompression → Jacobian (Memory only)
// ═══════════════════════════════════════════════════════

function decompressToJacobian(pub: Uint8Array, outPtr: usize): void {
  const px = outPtr
  BigInt256.fromBytes(px, pub.subarray(1, 33))

  const ySq = Memory.alloc(32)
  BigInt256.sqrMod(ySq, px)
  BigInt256.mulMod(ySq, ySq, px)

  const seven = Memory.alloc(32)
  store<u64>(seven, 7, 0)
  store<u64>(seven, 0, 8)
  store<u64>(seven, 0, 16)
  store<u64>(seven, 0, 24)
  BigInt256.add(ySq, ySq, seven)

  const exp = Memory.alloc(32)
  store<u64>(exp, EXP_P14_0, 0)
  store<u64>(exp, EXP_P14_1, 8)
  store<u64>(exp, EXP_P14_2, 16)
  store<u64>(exp, EXP_P14_3, 24)

  const base = Memory.alloc(32)
  memory.copy(base, ySq, 32)

  const py = outPtr + 32
  store<u64>(py, 1, 0)
  store<u64>(py, 0, 8)
  store<u64>(py, 0, 16)
  store<u64>(py, 0, 24)

  for (let bit = 0; bit < 256; bit++) {
    const word = load<u64>(exp + ((bit >> 6) << 3))
    if ((word >> (bit & 63)) & 1) {
      BigInt256.mulMod(py, py, base)
    }
    BigInt256.sqrMod(base, base)
  }

  const prefix = unchecked(pub[0])
  const calcIsOdd = (load<u64>(py, 0) & 1) == 1
  const wantOdd = prefix == 0x03
  if (calcIsOdd != wantOdd) {
    const prime = Memory.alloc(32)
    store<u64>(prime, BigInt256.P0, 0)
    store<u64>(prime, BigInt256.P1, 8)
    store<u64>(prime, BigInt256.P2, 16)
    store<u64>(prime, BigInt256.P3, 24)
    BigInt256.sub(py, prime, py)
  }

  const pz = outPtr + 64
  store<u64>(pz, 1, 0)
  store<u64>(pz, 0, 8)
  store<u64>(pz, 0, 16)
  store<u64>(pz, 0, 24)
}

// ═══════════════════════════════════════════════════════
// addPubkeys: parent_pub + G*IL → compressed pubkey
// Result written into _pubkeyTmp
// ═══════════════════════════════════════════════════════

function addPubkeysInto(parentPub: Uint8Array, scalarIL: Uint8Array): void {
  const ctxPtr = Memory.save()

  const ilBig = Memory.alloc(32)
  BigInt256.fromBytes(ilBig, scalarIL)
  const ilPoint = Memory.alloc(96)
  GeneratorTable.multiply(ilPoint, ilBig)

  const parentPoint = Memory.alloc(96)
  decompressToJacobian(parentPub, parentPoint)

  const resultPoint = Memory.alloc(96)
  Point.add(resultPoint, ilPoint, parentPoint)

  const z_inv = Memory.alloc(32)
  BigInt256.modInverse(z_inv, resultPoint + 64)
  const z_inv2 = Memory.alloc(32)
  BigInt256.sqrMod(z_inv2, z_inv)
  const x_aff = Memory.alloc(32)
  BigInt256.mulMod(x_aff, resultPoint, z_inv2)
  const z_inv3 = Memory.alloc(32)
  BigInt256.mulMod(z_inv3, z_inv2, z_inv)
  const y_aff = Memory.alloc(32)
  BigInt256.mulMod(y_aff, resultPoint + 32, z_inv3)

  const yIsOdd = (load<u64>(y_aff) & 1) != 0
  _pubkeyTmp[0] = yIsOdd ? 0x03 : 0x02
  BigInt256.toBytes(x_aff, _pubkeyTmp.subarray(1, 33))

  Memory.restore(ctxPtr)
}

// ═══════════════════════════════════════════════════════
// Scalar add mod N — uses Memory, writes to _IL
// ═══════════════════════════════════════════════════════

function scalarAddModNInto(a: Uint8Array, b: Uint8Array, out: Uint8Array): void {
  const ctxPtr = Memory.save()
  const aPtr = Memory.alloc(32)
  const bPtr = Memory.alloc(32)
  const resPtr = Memory.alloc(32)
  BigInt256.fromBytes(aPtr, a)
  BigInt256.fromBytes(bPtr, b)
  Scalar256.add(resPtr, aPtr, bPtr)
  BigInt256.toBytes(resPtr, out)
  Memory.restore(ctxPtr)
}

function isScalarInvalid(k: Uint8Array): bool {
  const ctxPtr = Memory.save()
  const kPtr = Memory.alloc(32)
  BigInt256.fromBytes(kPtr, k)
  const zero = Scalar256.isZero(kPtr)
  const gteN = Scalar256.isGreaterOrEqualN(kPtr)
  Memory.restore(ctxPtr)
  return zero || gteN
}

// ═══════════════════════════════════════════════════════
// splitHmacResult — splits _hmacResult into IL (32) + IR (32)
// Copies into the provided output buffers. Zero alloc.
// ═══════════════════════════════════════════════════════

// @ts-ignore
@inline
function splitHmacResult(outIL: Uint8Array, outIR: Uint8Array): void {
  memory.copy(outIL.dataStart, _hmacResult.dataStart, 32)
  memory.copy(outIR.dataStart, _hmacResult.dataStart + 32, 32)
}

// ═══════════════════════════════════════════════════════
// Extended Key representation
// ═══════════════════════════════════════════════════════

export class HDKey {
  depth: u8
  parentFingerprint: u32
  childIndex: u32
  chainCode: Uint8Array // 32 bytes
  keyData: Uint8Array   // 32 bytes (private) or 33 bytes (compressed public)
  isPrivate: bool

  constructor(
    depth: u8,
    parentFingerprint: u32,
    childIndex: u32,
    chainCode: Uint8Array,
    keyData: Uint8Array,
    isPrivate: bool
  ) {
    this.depth = depth
    this.parentFingerprint = parentFingerprint
    this.childIndex = childIndex
    this.chainCode = chainCode
    this.keyData = keyData
    this.isPrivate = isPrivate
  }

  /**
   * Creates a master key from a 64-byte BIP39 seed.
   * Allocations: 2 x Uint8Array(32) for IL/IR (stored in HDKey) + 1 HDKey
   */
  static fromSeed(seed: Uint8Array): HDKey {
    if (seed.length != 64) {
      throw new Error("BIP32: Seed must be 64 bytes")
    }

    // HMAC into static buffer — no HMAC result allocation
    hmacSha512Into(SEED_KEY, seed, 64)

    // Copy IL/IR into new arrays (these are stored in the HDKey, so must be owned)
    const IL = new Uint8Array(32)
    const IR = new Uint8Array(32)
    splitHmacResult(IL, IR)

    if (isScalarInvalid(IL)) {
      throw new Error("BIP32: Invalid master key")
    }

    return new HDKey(0, 0, 0, IR, IL, true)
  }

  getPublicKey(): Uint8Array {
    if (this.isPrivate) {
      return pubkeyFromPrivkey(this.keyData)
    }
    return this.keyData
  }

  getFingerprint(): u32 {
    if (this.isPrivate) {
      pubkeyFromPrivkeyInto(this.keyData)
      return getFingerprint(_pubkeyTmp)
    }
    return getFingerprint(this.keyData)
  }

  derive(index: u32): HDKey {
    if (this.isPrivate) {
      return this.ckdPriv(index)
    } else {
      return this.ckdPub(index)
    }
  }

  derivePath(path: string): HDKey {
    let key: HDKey = this
    let start: i32 = 0
    const len = path.length

    // Skip "m/" or "M/"
    if (len > 0 && (path.charCodeAt(0) == 0x6d || path.charCodeAt(0) == 0x4d)) {
      start = 1
      if (start < len && path.charCodeAt(start) == 0x2f) start++
    }

    // Parse path segments manually — no split() allocation
    let segStart = start
    while (segStart < len) {
      let segEnd = segStart
      while (segEnd < len && path.charCodeAt(segEnd) != 0x2f) segEnd++

      if (segEnd > segStart) {
        let hardened = false
        let numEnd = segEnd
        const lastChar = path.charCodeAt(segEnd - 1)
        if (lastChar == 0x27 || lastChar == 0x68 || lastChar == 0x48) { // ' h H
          hardened = true
          numEnd = segEnd - 1
        }

        // Parse number manually — no parseInt allocation
        let idx: u32 = 0
        for (let c = segStart; c < numEnd; c++) {
          idx = idx * 10 + <u32>(path.charCodeAt(c) - 0x30)
        }

        const finalIndex: u32 = hardened ? idx + HARDENED_OFFSET : idx
        key = key.derive(finalIndex)
      }

      segStart = segEnd + 1
    }

    return key
  }

  /**
   * CKDpriv — private child derivation.
   * Uses static _hmacData buffer (37 bytes) to avoid allocation.
   * Only allocates: 2 x Uint8Array(32) for new key's IL/IR + 1 HDKey
   */
  private ckdPriv(index: u32): HDKey {
    const isHardened = index >= HARDENED_OFFSET

    if (isHardened) {
      // 0x00 || private_key (32) || index (4) = 37 bytes
      _hmacData[0] = 0x00
      memory.copy(_hmacData.dataStart + 1, this.keyData.dataStart, 32)
      writeU32BE(_hmacData, 33, index)
    } else {
      // pubkey compressed (33) || index (4) = 37 bytes
      pubkeyFromPrivkeyInto(this.keyData)
      memory.copy(_hmacData.dataStart, _pubkeyTmp.dataStart, 33)
      writeU32BE(_hmacData, 33, index)
    }

    // HMAC into static buffer
    hmacSha512Into(this.chainCode, _hmacData, 37)
    splitHmacResult(_IL, _IR)

    if (isScalarInvalid(_IL)) {
      throw new Error("BIP32: Invalid child key (IL)")
    }

    // childKey = (IL + parentKey) mod N — into _IL itself
    const childKey = new Uint8Array(32)
    scalarAddModNInto(_IL, this.keyData, childKey)

    if (isScalarInvalid(childKey)) {
      throw new Error("BIP32: Derived key is 0 or >= N")
    }

    // New chain code (must be owned by HDKey)
    const newChain = new Uint8Array(32)
    memory.copy(newChain.dataStart, _IR.dataStart, 32)

    // Fingerprint uses static _pubkeyTmp
    const fp = this.getFingerprint()

    return new HDKey(this.depth + 1, fp, index, newChain, childKey, true)
  }

  /**
   * CKDpub — public child derivation.
   */
  private ckdPub(index: u32): HDKey {
    if (index >= HARDENED_OFFSET) {
      throw new Error("BIP32: Cannot derive hardened child from public key")
    }

    // pubkey compressed (33) || index (4) = 37 bytes
    memory.copy(_hmacData.dataStart, this.keyData.dataStart, 33)
    writeU32BE(_hmacData, 33, index)

    hmacSha512Into(this.chainCode, _hmacData, 37)
    splitHmacResult(_IL, _IR)

    if (isScalarInvalid(_IL)) {
      throw new Error("BIP32: Invalid child key (IL >= N)")
    }

    // childPub = point(IL) + parentPub — result into _pubkeyTmp
    addPubkeysInto(this.keyData, _IL)
    const childPub = new Uint8Array(33)
    memory.copy(childPub.dataStart, _pubkeyTmp.dataStart, 33)

    const newChain = new Uint8Array(32)
    memory.copy(newChain.dataStart, _IR.dataStart, 32)

    const fp = this.getFingerprint()

    return new HDKey(this.depth + 1, fp, index, newChain, childPub, false)
  }

  neuter(): HDKey {
    if (!this.isPrivate) return this
    return new HDKey(this.depth, this.parentFingerprint, this.childIndex, this.chainCode, this.getPublicKey(), false)
  }
}

// ═══════════════════════════════════════════════════════
// BIP44 PATH HELPERS
// ═══════════════════════════════════════════════════════

export function deriveAccount(master: HDKey, purpose: u32, coinType: u32, account: u32): HDKey {
  return master
    .derive(purpose + HARDENED_OFFSET)
    .derive(coinType + HARDENED_OFFSET)
    .derive(account + HARDENED_OFFSET)
}

export function deriveAddress(
  master: HDKey, purpose: u32, coinType: u32,
  account: u32, change: u32, addressIndex: u32
): HDKey {
  return deriveAccount(master, purpose, coinType, account).derive(change).derive(addressIndex)
}

export function derivePrivateKey(
  master: HDKey, purpose: u32, coinType: u32,
  account: u32, change: u32, addressIndex: u32
): Uint8Array {
  return deriveAddress(master, purpose, coinType, account, change, addressIndex).keyData
}

export function derivePublicKey(
  master: HDKey, purpose: u32, coinType: u32,
  account: u32, change: u32, addressIndex: u32
): Uint8Array {
  return deriveAddress(master, purpose, coinType, account, change, addressIndex).getPublicKey()
}
