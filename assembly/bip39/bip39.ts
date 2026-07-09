/**
 * ⚡ BIP39 — Mnemonic Code for Generating Deterministic Keys (WASM)
 *
 * Full AssemblyScript implementation of BIP39 (https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).
 *
 * - Entropy → Mnemonic (with SHA-256 checksum)
 * - Mnemonic → Entropy (with checksum validation)
 * - Mnemonic → Seed (PBKDF2-HMAC-SHA512, 2048 iterations)
 * - Mnemonic generation (from random entropy)
 * - Mnemonic validation
 *
 * Uses the existing SHA-256 engine for checksums and PBKDF2-SHA512 for seed derivation.
 */

import { Sha256 } from "../sha2/sha256"
import { pbkdf2_sha512 } from "../pbkdf2"
import { WORDLIST_EN } from "./wordlist_en"

// ═══════════════════════════════════════════════════════
// WORDLIST CACHE (lazy-initialized on first use)
// ═══════════════════════════════════════════════════════

let _words: string[] | null = null
let _wordmap: Map<string, i32> | null = null

function getWords(): string[] {
  if (_words === null) {
    _words = WORDLIST_EN.split(" ")
  }
  return _words!
}

function getWordMap(): Map<string, i32> {
  if (_wordmap === null) {
    const words = getWords()
    _wordmap = new Map<string, i32>()
    for (let i = 0; i < words.length; i++) {
      _wordmap!.set(unchecked(words[i]), i)
    }
  }
  return _wordmap!
}

// ═══════════════════════════════════════════════════════
// CORE: Entropy → Mnemonic
// ═══════════════════════════════════════════════════════

/**
 * Converts entropy bytes to a BIP39 mnemonic phrase.
 *
 * @param entropy - 16, 20, 24, 28, or 32 bytes of entropy.
 * @returns Space-separated mnemonic words.
 */
export function entropyToMnemonic(entropy: Uint8Array): string {
  const entLen = entropy.length
  if (entLen < 16 || entLen > 32 || (entLen & 3) != 0) {
    throw new Error("Invalid entropy: must be 16-32 bytes and a multiple of 4")
  }

  // SHA-256 checksum
  const hash = Sha256.hash(entropy)

  const checksumBits: i32 = entLen >> 2
  const wordCount: i32 = (entLen * 8 + checksumBits) / 11

  const words = getWords()
  const parts = new Array<string>(wordCount)

  let bitOffset: i32 = 0
  for (let i: i32 = 0; i < wordCount; i++) {
    let index: i32 = 0
    for (let bit: i32 = 0; bit < 11; bit++) {
      const byteIdx = bitOffset >> 3
      const bitIdx: u8 = <u8>(7 - (bitOffset & 7))

      const val: u8 = byteIdx < entLen ? unchecked(entropy[byteIdx]) : unchecked(hash[byteIdx - entLen])

      index = (index << 1) | (((<i32>val) >> (<i32>bitIdx)) & 1)
      bitOffset++
    }
    unchecked((parts[i] = unchecked(words[index])))
  }

  return parts.join(" ")
}

// ═══════════════════════════════════════════════════════
// CORE: Mnemonic → Entropy
// ═══════════════════════════════════════════════════════

/**
 * Converts a BIP39 mnemonic phrase back to its original entropy.
 * Validates the checksum.
 *
 * @param mnemonic - Space-separated mnemonic words.
 * @returns The original entropy as a Uint8Array.
 * @throws Error if words are invalid or checksum fails.
 */
export function mnemonicToEntropy(mnemonic: string): Uint8Array {
  const wordArr = mnemonic.split(" ")
  const numWords = wordArr.length

  // Validate word count: must be 12, 15, 18, 21, or 24
  if (numWords % 3 != 0 || numWords < 12 || numWords > 24) {
    throw new Error("Invalid mnemonic: word count must be 12, 15, 18, 21, or 24")
  }

  const wordmap = getWordMap()

  // Total bits from words
  const totalBits: i32 = numWords * 11
  const checksumBits: i32 = totalBits / 33
  const entropyBits: i32 = totalBits - checksumBits
  const entropyBytes: i32 = entropyBits >> 3

  // Pack 11-bit indices into bytes
  const entropy = new Uint8Array(entropyBytes)
  let providedChecksumByte: u8 = 0
  let bitOffset: i32 = 0

  for (let w = 0; w < numWords; w++) {
    const word = unchecked(wordArr[w])
    if (!wordmap.has(word)) {
      throw new Error('Invalid mnemonic: word "' + word + '" not in wordlist')
    }
    const index = wordmap.get(word)

    for (let bit: i32 = 10; bit >= 0; bit--) {
      if ((index >> bit) & 1) {
        const byteIdx = bitOffset >> 3
        const bitIdx: i32 = 7 - (bitOffset & 7)
        const bitMask: u8 = <u8>((<i32>1) << bitIdx)
        if (byteIdx < entropyBytes) {
          unchecked((entropy[byteIdx] = entropy[byteIdx] | bitMask))
        } else if (byteIdx == entropyBytes) {
          providedChecksumByte |= bitMask
        }
      }
      bitOffset++
    }
  }

  // Compute expected checksum
  const hash = Sha256.hash(entropy)
  const expectedChecksumByte: u8 = unchecked(hash[0])

  // Compare only the relevant high bits
  const mask: u8 = <u8>((<i32>0xff) << (8 - checksumBits))
  if ((providedChecksumByte & mask) != (expectedChecksumByte & mask)) {
    throw new Error("Invalid mnemonic checksum")
  }

  return entropy
}

// ═══════════════════════════════════════════════════════
// CORE: Mnemonic → Seed (PBKDF2)
// ═══════════════════════════════════════════════════════

/**
 * Derives a 64-byte seed from a BIP39 mnemonic using PBKDF2-HMAC-SHA512.
 *
 * @param mnemonic - The mnemonic phrase.
 * @param passphrase - Optional passphrase (default: empty string).
 * @returns 64-byte seed.
 */
export function mnemonicToSeed(mnemonic: string, passphrase: string = ""): Uint8Array {
  const password = Uint8Array.wrap(String.UTF8.encode(mnemonic))
  const salt = Uint8Array.wrap(String.UTF8.encode("mnemonic" + passphrase))
  return pbkdf2_sha512(password, salt, 2048, 64)
}

// ═══════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════

/**
 * Validates a BIP39 mnemonic phrase (word count, words in list, checksum).
 * Returns false instead of throwing on invalid input.
 *
 * @param mnemonic - The mnemonic to validate.
 * @returns true if valid, false otherwise.
 */
export function validateMnemonic(mnemonic: string): bool {
  const wordArr = mnemonic.split(" ")
  const numWords = wordArr.length

  if (numWords % 3 != 0 || numWords < 12 || numWords > 24) return false

  const wordmap = getWordMap()

  const totalBits: i32 = numWords * 11
  const checksumBits: i32 = totalBits / 33
  const entropyBits: i32 = totalBits - checksumBits
  const entropyBytes: i32 = entropyBits >> 3

  const entropy = new Uint8Array(entropyBytes)
  let providedChecksumByte: u8 = 0
  let bitOffset: i32 = 0

  for (let w = 0; w < numWords; w++) {
    const word = unchecked(wordArr[w])
    if (!wordmap.has(word)) return false
    const index = wordmap.get(word)

    for (let bit: i32 = 10; bit >= 0; bit--) {
      if ((index >> bit) & 1) {
        const byteIdx = bitOffset >> 3
        const bitIdx: i32 = 7 - (bitOffset & 7)
        const bitMask: u8 = <u8>((<i32>1) << bitIdx)
        if (byteIdx < entropyBytes) {
          unchecked((entropy[byteIdx] = entropy[byteIdx] | bitMask))
        } else if (byteIdx == entropyBytes) {
          providedChecksumByte |= bitMask
        }
      }
      bitOffset++
    }
  }

  const hash = Sha256.hash(entropy)
  const expectedChecksumByte: u8 = unchecked(hash[0])

  const mask: u8 = <u8>((<i32>0xff) << (8 - checksumBits))
  return (providedChecksumByte & mask) == (expectedChecksumByte & mask)
}

// ═══════════════════════════════════════════════════════
// GENERATION
// ═══════════════════════════════════════════════════════

/**
 * Generates a random BIP39 mnemonic.
 * Uses Math.random() for entropy (CSPRNG should be seeded externally).
 *
 * @param wordCount - Number of words: 12, 15, 18, 21, or 24. Default: 12.
 * @returns A random mnemonic phrase.
 */
export function generateMnemonic(wordCount: i32 = 12): string {
  // entropyBytes = wordCount * 32 / 3 / 8 = wordCount * 4 / 3
  const entropyBytes: i32 = (wordCount * 4) / 3
  if (entropyBytes < 16 || entropyBytes > 32 || (entropyBytes & 3) != 0) {
    throw new Error("Invalid word count: must be 12, 15, 18, 21, or 24")
  }

  const entropy = new Uint8Array(entropyBytes)
  for (let i = 0; i < entropyBytes; i++) {
    entropy[i] = (<u8>(Math.random() * 256.0)) & 0xff
  }

  return entropyToMnemonic(entropy)
}
