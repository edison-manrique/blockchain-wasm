/**
 * PBKDF2 WASM Test Suite
 */

import { pbkdf2_sha512 } from ".."
import { hexToBytes } from "../../utils"

function utf8ToBytes(s: string): Uint8Array {
  return Uint8Array.wrap(String.UTF8.encode(s))
}

/**
 * Simple 1-iteration test for basic PBKDF2-SHA512 correctness.
 * password="password", salt="salt", iterations=1, dkLen=64
 */
export function test_pbkdf2_simple(): bool {
  const password = utf8ToBytes("password")
  const salt = utf8ToBytes("salt")
  const expected = hexToBytes(
    "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
  )

  const derived = pbkdf2_sha512(password, salt, 1, 64)
  return memory.compare(derived.dataStart, expected.dataStart, 64) == 0
}

/**
 * 2-iteration test for PBKDF2-SHA512 XOR accumulation.
 * password="password", salt="salt", iterations=2, dkLen=64
 */
export function test_pbkdf2_2iter(): bool {
  const password = utf8ToBytes("password")
  const salt = utf8ToBytes("salt")
  const expected = hexToBytes(
    "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"
  )

  const derived = pbkdf2_sha512(password, salt, 2, 64)
  return memory.compare(derived.dataStart, expected.dataStart, 64) == 0
}

import { MemoryProfiler } from "../../utils/profiler"

/**
 * BIP39 test vector: "abandon abandon ... about" + passphrase "TREZOR"
 * 2048 iterations, 64 bytes output.
 */
export function test_pbkdf2_bip39(): bool {
  const handle = MemoryProfiler.watchScratch()

  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  const passphrase = "TREZOR"

  const password = utf8ToBytes(mnemonic)
  const salt = utf8ToBytes("mnemonic" + passphrase)

  const expected = hexToBytes(
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  )

  const derived = pbkdf2_sha512(password, salt, 2048, 64)
  const matches = memory.compare(derived.dataStart, expected.dataStart, 64) == 0

  const isHealthy = MemoryProfiler.verifyScratch(handle, "PBKDF2_BIP39")
  return matches && isHealthy
}
