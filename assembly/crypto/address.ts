import { Sha256 } from "../sha2"
import { hash as ripemd160_hash } from "../ripemd160"
import { encodeCheck } from "../base58"
import { keccak256 } from "../keccak256"
import { Memory } from "../utils/Memory"
import { BigInt256, GeneratorTable, Point } from "./utils"

/**
 * Generates a Bitcoin address from a raw SECP256k1 public key.
 *
 * @param pubKey The public key bytes.
 *               Can be compressed (33 bytes) starting with 0x02/0x03,
 *               or uncompressed (65 bytes) starting with 0x04.
 * @returns The Base58Check encoded Bitcoin address (starting with '1').
 */
export function getBitcoinAddress(pubKey: Uint8Array): string {
  // 1. Perform SHA-256 hashing on the public key
  const sha256_hash = Sha256.hash(pubKey)

  // 2. Perform RIPEMD-160 hashing on the result of SHA-256
  const ripemd160 = ripemd160_hash(sha256_hash)

  // 3. Add version byte in front of RIPEMD-160 hash (0x00 for Main Network P2PKH)
  const payload = new Uint8Array(21)
  payload[0] = pubKey.length === 33 ? 0x00 : 0x00 // Uncompressed/compressed gets 0x00 in standard P2PKH

  for (let i = 0; i < 20; i++) {
    payload[i + 1] = ripemd160[i]
  }

  return encodeCheck(payload)
}

/**
 * Generates a Bitcoin P2SH (nested Segwit) address.
 */
export function getBitcoinP2SHAddress(pubKey: Uint8Array): string {
  // P2SH of P2WPKH
  // Script: 0x00 0x14 <RIPEMD160(SHA256(pubKey))>
  const sha256_hash = Sha256.hash(pubKey)
  const ripemd160 = ripemd160_hash(sha256_hash)

  const redeemScript = new Uint8Array(22)
  redeemScript[0] = 0x00
  redeemScript[1] = 0x14 // length 20
  for (let i = 0; i < 20; i++) redeemScript[i + 2] = ripemd160[i]

  const scriptHash = ripemd160_hash(Sha256.hash(redeemScript))

  const payload = new Uint8Array(21)
  payload[0] = 0x05 // P2SH prefix
  for (let i = 0; i < 20; i++) payload[i + 1] = scriptHash[i]

  return encodeCheck(payload)
}

/**
 * Generates a Bitcoin P2WPKH (Bech32 Native Segwit) address.
 */
import { encodeBech32, convertBits } from "./bech32"

export function getBitcoinP2WPKHAddress(pubKey: Uint8Array): string {
  const sha256_hash = Sha256.hash(pubKey)
  const ripemd160 = ripemd160_hash(sha256_hash)

  // Convert 8-bit to 5-bit
  const converted = convertBits(ripemd160, 8, 5, true)
  if (!converted) return ""

  // Prepend witness version (0 for P2WPKH)
  const data = new Uint8Array(converted.length + 1)
  data[0] = 0
  for (let i = 0; i < converted.length; i++) data[i + 1] = converted[i]

  return encodeBech32("bc", data, 1) // Bech32 encoding uses constant 1
}

/**
 * Generates a Bitcoin P2TR (Bech32m Taproot) address.
 * Simplified assumption for isolated public key (Internal Key = Output Key).
 * By BIP-341, output key is Q = P + int(hash_TapTweak(bytes(P)))G
 */
export function getBitcoinP2TRAddress(pubKey: Uint8Array): string {
  let px = Memory.alloc(32)
  let py = Memory.alloc(32)
  let isOdd = false

  const ctx = Memory.save()

  if (pubKey.length === 65) {
    BigInt256.fromBytes(px, pubKey.subarray(1, 33))
    BigInt256.fromBytes(py, pubKey.subarray(33, 65))
    isOdd = (pubKey[64] & 1) === 1
  } else if (pubKey.length === 33) {
    // Must implement fallback if they pass compressed to evaluate odd parity
    // Currently CLI passes compressed. This means we don't have python's easy lift_x.
    BigInt256.fromBytes(px, pubKey.subarray(1, 33))

    // Compute y^2 = x^3 + 7
    let ySq = Memory.alloc(32)
    BigInt256.sqrMod(ySq, px)
    BigInt256.mulMod(ySq, ySq, px)

    let seven = Memory.alloc(32)
    store<u64>(seven, 7, 0)
    store<u64>(seven, 0, 8)
    store<u64>(seven, 0, 16)
    store<u64>(seven, 0, 24)
    BigInt256.add(ySq, ySq, seven)

    // Calculate y = ySq ^ ((P+1)/4)
    let exp = Memory.alloc(32)
    store<u64>(exp, 0xffffffffbfffff0c, 0)
    store<u64>(exp, 0xffffffffffffffff, 8)
    store<u64>(exp, 0xffffffffffffffff, 16)
    store<u64>(exp, 0x3fffffffffffffff, 24)

    // In-house ModPow
    let base = Memory.alloc(32)
    memory.copy(base, ySq, 32)

    let res = Memory.alloc(32)
    store<u64>(res, 1, 0)
    store<u64>(res, 0, 8)
    store<u64>(res, 0, 16)
    store<u64>(res, 0, 24)

    for (let bit = 0; bit < 256; bit++) {
      let wordIdx = bit >> 6 // bit / 64
      let bitIdx = bit & 63 // bit % 64
      let word = load<u64>(exp + (wordIdx << 3))

      if ((word >> bitIdx) & 1) {
        BigInt256.mulMod(res, res, base)
      }
      BigInt256.sqrMod(base, base)
    }

    memory.copy(py, res, 32)
    let calcIsOdd = (load<u64>(py, 0) & 1) === 1
    isOdd = pubKey[0] === 0x03

    // If parity mismatch, py = P - py
    if (calcIsOdd !== isOdd) {
      let prime = Memory.alloc(32)
      store<u64>(prime, BigInt256.P0, 0)
      store<u64>(prime, BigInt256.P1, 8)
      store<u64>(prime, BigInt256.P2, 16)
      store<u64>(prime, BigInt256.P3, 24)
      BigInt256.sub(py, prime, py)
    }
  } else {
    Memory.restore(ctx)
    return "NOT_SUPPORTED"
  }

  // TapTweak tag is "TapTweak".
  // SHA256("TapTweak") = e80fe1639c9ca050e3af1b39c143c63e429cbceb15d940fbb5c5a1f4af57c5e9

  const tagHash = new Uint8Array(32)
  tagHash[0] = 0xe8
  tagHash[1] = 0x0f
  tagHash[2] = 0xe1
  tagHash[3] = 0x63
  tagHash[4] = 0x9c
  tagHash[5] = 0x9c
  tagHash[6] = 0xa0
  tagHash[7] = 0x50
  tagHash[8] = 0xe3
  tagHash[9] = 0xaf
  tagHash[10] = 0x1b
  tagHash[11] = 0x39
  tagHash[12] = 0xc1
  tagHash[13] = 0x43
  tagHash[14] = 0xc6
  tagHash[15] = 0x3e
  tagHash[16] = 0x42
  tagHash[17] = 0x9c
  tagHash[18] = 0xbc
  tagHash[19] = 0xeb
  tagHash[20] = 0x15
  tagHash[21] = 0xd9
  tagHash[22] = 0x40
  tagHash[23] = 0xfb
  tagHash[24] = 0xb5
  tagHash[25] = 0xc5
  tagHash[26] = 0xa1
  tagHash[27] = 0xf4
  tagHash[28] = 0xaf
  tagHash[29] = 0x57
  tagHash[30] = 0xc5
  tagHash[31] = 0xe9

  const msg = new Uint8Array(96)
  for (let i = 0; i < 32; i++) msg[i] = tagHash[i]
  for (let i = 0; i < 32; i++) msg[32 + i] = tagHash[i]

  // Extract xOnly bytes manually to avoid allocation
  const xBytesArr = new Uint8Array(32)
  BigInt256.toBytes(px, xBytesArr)
  for (let i = 0; i < 32; i++) msg[64 + i] = xBytesArr[i]

  // BIP340 tweak uses single SHA256, NOT double SHA256!
  const tweak = Sha256.hash(msg) // Use single Sha256.hash instead of hash256!

  // Before adding Tweak, if P has odd Y, we negate P! (BIP 340 logic for taproot)
  if (isOdd) {
    let prime = Memory.alloc(32)
    store<u64>(prime, BigInt256.P0, 0)
    store<u64>(prime, BigInt256.P1, 8)
    store<u64>(prime, BigInt256.P2, 16)
    store<u64>(prime, BigInt256.P3, 24)
    BigInt256.sub(py, prime, py)
  }

  let pz = Memory.alloc(32)
  store<u64>(pz, 1, 0)
  store<u64>(pz, 0, 8)
  store<u64>(pz, 0, 16)
  store<u64>(pz, 0, 24)

  let P_pt = Memory.alloc(96)
  memory.copy(P_pt, px, 32)
  memory.copy(P_pt + 32, py, 32)
  memory.copy(P_pt + 64, pz, 32)

  // G * t
  let T_pt = Memory.alloc(96)
  let tBig = Memory.alloc(32)
  BigInt256.fromBytes(tBig, tweak)
  GeneratorTable.multiply(T_pt, tBig)

  // Q = P + T
  let Q = Memory.alloc(96)
  Point.add(Q, P_pt, T_pt)

  // Normalize Q to affine
  let zPtr = Q + 64
  let zInv = Memory.alloc(32)
  BigInt256.modInverse(zInv, zPtr)
  let zInv2 = Memory.alloc(32)
  BigInt256.sqrMod(zInv2, zInv)
  let finalX = Memory.alloc(32)
  BigInt256.mulMod(finalX, Q, zInv2)

  let qxBytes = new Uint8Array(32)
  BigInt256.toBytes(finalX, qxBytes)

  Memory.restore(ctx)

  const converted = convertBits(qxBytes, 8, 5, true)
  if (!converted) return ""

  const data = new Uint8Array(converted.length + 1)
  data[0] = 1 // Witness v1
  for (let i = 0; i < converted.length; i++) data[i + 1] = converted[i]

  return encodeBech32("bc", data, 0x2bc830a3) // Bech32m checksum constant
}

/**
 * Generates an Ethereum address from a raw SECP256k1 public key.
 *
 * @param pubKey The uncompressed public key bytes (64 or 65 bytes).
 *               If 65 bytes and starts with 0x04, the 0x04 is removed.
 * @returns The hex encoded Ethereum address (starting with '0x').
 */
export function getEthereumAddress(pubKey: Uint8Array): string {
  let pureKey: Uint8Array

  if (pubKey.length == 65 && pubKey[0] == 0x04) {
    pureKey = new Uint8Array(64)
    for (let i = 0; i < 64; i++) {
      pureKey[i] = pubKey[i + 1]
    }
  } else if (pubKey.length == 64) {
    pureKey = pubKey
  } else {
    // Compressed key not supported directly for Eth derivation, needs decompression
    // For now we assume we get the 64/65 byte uncompressed key
    pureKey = pubKey
  }

  // 1. Keccak-256 hash of the 64-byte uncompressed public key
  const khash = keccak256(pureKey)

  const HEX_CHARS = "0123456789abcdef"
  let addressHex = ""

  // Straight to hex mapping
  for (let i = 12; i < 32; i++) {
    let b = khash[i]
    addressHex += HEX_CHARS.charAt(b >> 4) + HEX_CHARS.charAt(b & 0x0f)
  }

  // EIP-55 Checksum
  // Encode address array back into text to hash it
  const addressBytes = new Uint8Array(40)
  for (let i = 0; i < 40; i++) {
    addressBytes[i] = addressHex.charCodeAt(i)
  }
  const hashChecksum = keccak256(addressBytes)

  let result = "0x"
  for (let i = 0; i < 40; i++) {
    let char = addressHex.charAt(i)
    let hashByte = hashChecksum[i >> 1]
    let hashNibble = i % 2 === 0 ? hashByte >> 4 : hashByte & 0x0f

    // if digit, append. if letter and hashNibble >= 8 make it upper
    if (char >= "a" && char <= "f") {
      if (hashNibble >= 8) {
        result += String.fromCharCode(char.charCodeAt(0) - 32) // uppercase
      } else {
        result += char
      }
    } else {
      result += char
    }
  }

  return result
}

export function getPublicKeyUncompressed(privKey: Uint8Array): Uint8Array {
  const ctx = Memory.save()

  const privBig = Memory.alloc(32)
  BigInt256.fromBytes(privBig, privKey)

  const pub = Memory.alloc(96)
  // Using GeneratorTable for fast generation
  GeneratorTable.multiply(pub, privBig)

  const bytes = new Uint8Array(65)
  bytes[0] = 0x04

  const z_ptr = pub + 64
  const z_inv = Memory.alloc(32)
  BigInt256.modInverse(z_inv, z_ptr)

  const z_inv_2_red = Memory.alloc(32)
  BigInt256.sqrMod(z_inv_2_red, z_inv)

  const z_inv_3 = Memory.alloc(32)
  BigInt256.mulMod(z_inv_3, z_inv_2_red, z_inv)

  const x_aff = Memory.alloc(32)
  BigInt256.mulMod(x_aff, pub, z_inv_2_red)

  const y_aff = Memory.alloc(32)
  BigInt256.mulMod(y_aff, pub + 32, z_inv_3)

  BigInt256.toBytes(x_aff, bytes.subarray(1, 33))
  BigInt256.toBytes(y_aff, bytes.subarray(33, 65))

  Memory.restore(ctx)
  return bytes
}

export function getPublicKeyCompressed(privKey: Uint8Array): Uint8Array {
  const uncompressed = getPublicKeyUncompressed(privKey)
  const bytes = new Uint8Array(33)

  const isOddY = (uncompressed[64] & 1) != 0
  bytes[0] = isOddY ? 0x03 : 0x02
  for (let i = 0; i < 32; i++) {
    bytes[i + 1] = uncompressed[i + 1]
  }
  return bytes
}

/**
 * Compresses an uncompressed public key (65 bytes).
 * If already compressed, returns it as is.
 */
export function compressPublicKey(pubKey: Uint8Array): Uint8Array {
  if (pubKey.length === 33) return pubKey
  if (pubKey.length !== 65 || pubKey[0] !== 0x04) {
    return new Uint8Array(0) // Invalid public key
  }

  const bytes = new Uint8Array(33)
  const isOddY = (pubKey[64] & 1) != 0
  bytes[0] = isOddY ? 0x03 : 0x02
  for (let i = 0; i < 32; i++) {
    bytes[i + 1] = pubKey[i + 1]
  }
  return bytes
}

/**
 * Uncompresses a compressed public key (33 bytes) into full form (65 bytes).
 * If already uncompressed, returns it as is.
 */
export function uncompressPublicKey(pubKey: Uint8Array): Uint8Array {
  if (pubKey.length === 65) return pubKey
  if (pubKey.length !== 33 || (pubKey[0] !== 0x02 && pubKey[0] !== 0x03)) {
    return new Uint8Array(0) // Invalid compressed key
  }

  const ctx = Memory.save()

  // y^2 = x^3 + 7
  const px = Memory.alloc(32)
  BigInt256.fromBytes(px, pubKey.subarray(1, 33))

  let ySq = Memory.alloc(32)
  BigInt256.sqrMod(ySq, px)
  BigInt256.mulMod(ySq, ySq, px)

  let seven = Memory.alloc(32)
  store<u64>(seven, 7, 0)
  store<u64>(seven, 0, 8)
  store<u64>(seven, 0, 16)
  store<u64>(seven, 0, 24)
  BigInt256.add(ySq, ySq, seven)

  // y = ySq ^ ((P+1)/4)
  let exp = Memory.alloc(32)
  store<u64>(exp, 0xffffffffbfffff0c, 0)
  store<u64>(exp, 0xffffffffffffffff, 8)
  store<u64>(exp, 0xffffffffffffffff, 16)
  store<u64>(exp, 0x3fffffffffffffff, 24)

  let base = Memory.alloc(32)
  memory.copy(base, ySq, 32)

  let py = Memory.alloc(32)
  store<u64>(py, 1, 0)
  store<u64>(py, 0, 8)
  store<u64>(py, 0, 16)
  store<u64>(py, 0, 24)

  for (let bit = 0; bit < 256; bit++) {
    let wordIdx = bit >> 6
    let bitIdx = bit & 63
    let word = load<u64>(exp + (wordIdx << 3))

    if ((word >> bitIdx) & 1) {
      BigInt256.mulMod(py, py, base)
    }
    BigInt256.sqrMod(base, base)
  }

  let isOdd = pubKey[0] === 0x03
  let calcIsOdd = (load<u64>(py, 0) & 1) === 1

  if (calcIsOdd !== isOdd) {
    let prime = Memory.alloc(32)
    store<u64>(prime, BigInt256.P0, 0)
    store<u64>(prime, BigInt256.P1, 8)
    store<u64>(prime, BigInt256.P2, 16)
    store<u64>(prime, BigInt256.P3, 24)
    BigInt256.sub(py, prime, py)
  }

  const bytes = new Uint8Array(65)
  bytes[0] = 0x04
  for (let i = 0; i < 32; i++) bytes[i + 1] = pubKey[i + 1]
  BigInt256.toBytes(py, bytes.subarray(33, 65))

  Memory.restore(ctx)
  return bytes
}
