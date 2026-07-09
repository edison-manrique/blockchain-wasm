import { HDKey, derivePrivateKey } from "../../bip32"
import { hexToBytes } from "../../utils"
export * from "./bip32.test"

const SEED_HEX =
  "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"

function getMaster(): HDKey {
  return HDKey.fromSeed(hexToBytes(SEED_HEX))
}

/**
 * Benchmark: Full BIP44 derivation (5 levels, m/44'/0'/0'/0/i)
 */
export function benchmark_bip44_derive(count: i32): void {
  const master = getMaster()
  for (let i = 0; i < count; i++) {
    derivePrivateKey(master, 44, 0, 0, 0, <u32>i)
  }
}

/**
 * Benchmark: Master key from seed
 */
export function benchmark_bip32_from_seed(count: i32): void {
  const seed = hexToBytes(SEED_HEX)
  for (let i = 0; i < count; i++) {
    HDKey.fromSeed(seed)
  }
}

/**
 * Benchmark: Public key generation from private
 */
export function benchmark_bip32_pubkey(count: i32): void {
  const master = getMaster()
  for (let i = 0; i < count; i++) {
    master.getPublicKey()
  }
}
