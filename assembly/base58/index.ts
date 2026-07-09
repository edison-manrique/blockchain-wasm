/*
 * Base58 & Base58Check Encoding/Decoding
 */

import { hash256 } from "../sha2"

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

function getAlphabetMap(): Int16Array {
  let map = new Int16Array(128)
  map.fill(-1)
  for (let i = 0; i < 58; i++) {
    map[ALPHABET.charCodeAt(i)] = i as i16
  }
  return map
}

// Map characters to values for fast decoding
const ALPHABET_MAP = getAlphabetMap()

/**
 * Encodes a Uint8Array into a Base58 string.
 */
export function encode(source: Uint8Array): string {
  if (source.length == 0) return ""

  let zeroes = 0
  let pbegin = 0
  let pend = source.length

  // Count leading zeros
  while (pbegin < pend && source[pbegin] == 0) {
    pbegin++
    zeroes++
  }

  // Allocate enough space in big-endian base58 representation
  // size = log(256)/log(58) ~ 1.3656
  let size = ((pend - pbegin) * 138) / 100 + 1
  let b58 = new Uint8Array(size)

  let length = 0
  while (pbegin < pend) {
    let carry: u32 = source[pbegin]
    let i = 0

    // Apply "b58 = b58 * 256 + ch"
    for (let it1 = size - 1; (carry != 0 || i < length) && it1 >= 0; it1--, i++) {
      carry += (b58[it1] as u32) * 256
      b58[it1] = (carry % 58) as u8
      carry = carry / 58
    }

    length = i
    pbegin++
  }

  // Skip leading zeroes in base58 result
  let it2 = size - length
  while (it2 < size && b58[it2] == 0) {
    it2++
  }

  // Translate the result into a string
  let str = new Array<string>(zeroes + (size - it2))
  for (let i = 0; i < zeroes; i++) {
    str[i] = "1"
  }

  let sIdx = zeroes
  while (it2 < size) {
    str[sIdx++] = ALPHABET.charAt(b58[it2++])
  }

  return str.join("")
}

/**
 * Decodes a Base58 string into a Uint8Array.
 * Returns null if the string contains invalid characters.
 */
export function decode(str: string): Uint8Array | null {
  if (str.length == 0) return new Uint8Array(0)

  let zeroes = 0
  let pbegin = 0
  let pend = str.length

  // Count leading "1"s
  while (pbegin < pend && str.charAt(pbegin) == "1") {
    zeroes++
    pbegin++
  }

  // Allocate enough space in big-endian base256 representation
  // size = log(58)/log(256) ~ 0.732
  let size = ((pend - pbegin) * 733) / 1000 + 1
  let b256 = new Uint8Array(size)

  let length = 0
  while (pbegin < pend) {
    let charCode = str.charCodeAt(pbegin)
    // Invalid character
    if (charCode >= 128 || ALPHABET_MAP[charCode] == -1) {
      return null
    }

    let carry: u32 = ALPHABET_MAP[charCode]
    let i = 0
    for (let it1 = size - 1; (carry != 0 || i < length) && it1 >= 0; it1--, i++) {
      carry += (b256[it1] as u32) * 58
      b256[it1] = (carry % 256) as u8
      carry = carry / 256
    }

    length = i
    pbegin++
  }

  // Skip leading zeroes in b256
  let it2 = size - length
  while (it2 < size && b256[it2] == 0) {
    it2++
  }

  let res = new Uint8Array(zeroes + (size - it2))
  for (let i = 0; i < size - it2; i++) {
    res[zeroes + i] = b256[it2 + i]
  }
  return res
}

/**
 * Base58Check Encoding
 * Encodes a Uint8Array with a 4-byte double-SHA256 checksum.
 */
export function encodeCheck(payload: Uint8Array): string {
  // compute first SHA256
  let hash1 = hash256(payload)
  // compute second SHA256
  let hash2 = hash256(hash1)

  // extract first 4 bytes for checksum
  let checksum = hash2.slice(0, 4)

  // create new array [payload, checksum]
  let payloadWithChecksum = new Uint8Array(payload.length + 4)

  for (let i = 0; i < payload.length; i++) {
    payloadWithChecksum[i] = payload[i]
  }

  for (let i = 0; i < 4; i++) {
    payloadWithChecksum[payload.length + i] = checksum[i]
  }

  return encode(payloadWithChecksum)
}

/**
 * Base58Check Decoding
 * Decodes a string, verifying the double-SHA256 checksum.
 * Returns null if invalid base58 characters, too short, or checksum fails.
 */
export function decodeCheck(str: string): Uint8Array | null {
  let decoded = decode(str)
  if (!decoded || decoded.length < 4) return null

  let payloadLen = decoded.length - 4
  let payload = decoded.slice(0, payloadLen)
  let checksum = decoded.slice(payloadLen)

  // compute expected checksum
  let hash1 = hash256(payload)
  let hash2 = hash256(hash1)
  let expectedChecksum = hash2.slice(0, 4)

  // verify checksum
  for (let i = 0; i < 4; i++) {
    if (checksum[i] != expectedChecksum[i]) {
      return null
    }
  }

  return payload
}
