import { encodeCheck, decodeCheck } from "../base58"

/**
 * Converts a 32-byte private key into Wallet Import Format (WIF).
 *
 * @param privKey The 32-byte private key.
 * @param compressed Whether the associated public key is compressed. Defaults to true.
 * @returns The WIF string.
 */
export function toWIF(privKey: Uint8Array, compressed: boolean = true): string {
  if (privKey.length != 32) {
    return "" // Invalid private key length
  }

  const payloadLen = compressed ? 34 : 33
  const payload = new Uint8Array(payloadLen)
  payload[0] = 0x80 // Mainnet private key prefix

  for (let i = 0; i < 32; i++) {
    payload[i + 1] = privKey[i]
  }

  if (compressed) {
    payload[33] = 0x01 // Compressed suffix
  }

  return encodeCheck(payload)
}

/**
 * Decodes a Wallet Import Format (WIF) string back into a 32-byte private key.
 *
 * @param wif The WIF string.
 * @returns The 32-byte private key, or null if the string is invalid or checksum fails.
 */
export function fromWIF(wif: string): Uint8Array | null {
  const payload = decodeCheck(wif)
  if (!payload || payload.length == 0) return null

  // Verify prefix
  if (payload[0] != 0x80) return null

  // Verify length (33 for uncompressed [1 byte prefix + 32 byte key], 34 for compressed [+ 1 byte suffix])
  if (payload.length != 33 && payload.length != 34) return null

  // Verify compressed suffix if length is 34
  if (payload.length == 34 && payload[33] != 0x01) return null

  const privKey = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    privKey[i] = payload[i + 1]
  }

  return privKey
}
