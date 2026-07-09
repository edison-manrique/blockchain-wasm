import { entropyToMnemonic, mnemonicToSeed, validateMnemonic } from ".."
import { hexToBytes } from "../../utils"

export * from "./index.test"

/**
 * Benchmark: entropyToMnemonic (no PBKDF2, just bit manipulation + SHA-256)
 */
export function benchmark_bip39_entropy_to_mnemonic(count: i32): void {
  const entropy = hexToBytes("00000000000000000000000000000000")
  for (let i = 0; i < count; i++) {
    entropyToMnemonic(entropy)
  }
}

/**
 * Benchmark: mnemonicToSeed (full PBKDF2-HMAC-SHA512, 2048 iterations)
 */
export function benchmark_bip39_seed(count: i32): void {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  for (let i = 0; i < count; i++) {
    mnemonicToSeed(mnemonic, "TREZOR")
  }
}

/**
 * Benchmark: validation (word lookup + SHA-256 checksum)
 */
export function benchmark_bip39_validate(count: i32): void {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  for (let i = 0; i < count; i++) {
    validateMnemonic(mnemonic)
  }
}
