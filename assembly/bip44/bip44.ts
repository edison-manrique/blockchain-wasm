/**
 * ⚡ BIP44 — Multi-Account Hierarchy for Deterministic Wallets (WASM)
 *
 * Implements BIP44 key derivation:
 *   m / purpose' / coin_type' / account' / change / address_index
 *
 * IMPORTANT: This module derives KEYS, not addresses.
 * Address encoding is handled by the address module (assembly/crypto/address.ts).
 *
 * Integrates:
 *   - BIP39 (mnemonic → seed) via assembly/bip39
 *   - BIP32 (HD key derivation) via assembly/crypto/bip32
 *   - xpub serialization (Base58Check encoded 78-byte structure)
 */

import { HDKey, HARDENED_OFFSET } from "../bip32/bip32"
import { mnemonicToSeed, entropyToMnemonic, validateMnemonic } from "../bip39/bip39"
import { encodeCheck } from "../base58"

// ═══════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════

/** BIP32 xpub version bytes (mainnet: 0x0488B21E) */
const XPUB_VERSION_0: u8 = 0x04
const XPUB_VERSION_1: u8 = 0x88
const XPUB_VERSION_2: u8 = 0xb2
const XPUB_VERSION_3: u8 = 0x1e

/** BIP32 xprv version bytes (mainnet: 0x0488ADE4) */
const XPRV_VERSION_0: u8 = 0x04
const XPRV_VERSION_1: u8 = 0x88
const XPRV_VERSION_2: u8 = 0xad
const XPRV_VERSION_3: u8 = 0xe4

// ═══════════════════════════════════════════════════════
// XPUB / XPRV SERIALIZATION
// ═══════════════════════════════════════════════════════

/**
 * Serializes an HDKey to a 78-byte BIP32 extended public key structure,
 * then Base58Check encodes it (xpub format).
 *
 * Structure (78 bytes):
 *   [0-3]   version      (0x0488B21E for mainnet xpub)
 *   [4]     depth
 *   [5-8]   fingerprint  (first 4 bytes of HASH160 of parent pubkey)
 *   [9-12]  child index  (big-endian u32)
 *   [13-44] chain code   (32 bytes)
 *   [45-77] public key   (33 bytes compressed)
 */
function serializeXpub(key: HDKey): string {
  const pubKey = key.getPublicKey()
  const buf = new Uint8Array(78)

  // Version
  buf[0] = XPUB_VERSION_0
  buf[1] = XPUB_VERSION_1
  buf[2] = XPUB_VERSION_2
  buf[3] = XPUB_VERSION_3

  // Depth
  buf[4] = key.depth

  // Parent fingerprint (big-endian u32)
  buf[5] = <u8>((key.parentFingerprint >> 24) & 0xff)
  buf[6] = <u8>((key.parentFingerprint >> 16) & 0xff)
  buf[7] = <u8>((key.parentFingerprint >> 8) & 0xff)
  buf[8] = <u8>(key.parentFingerprint & 0xff)

  // Child index (big-endian u32)
  buf[9] = <u8>((key.childIndex >> 24) & 0xff)
  buf[10] = <u8>((key.childIndex >> 16) & 0xff)
  buf[11] = <u8>((key.childIndex >> 8) & 0xff)
  buf[12] = <u8>(key.childIndex & 0xff)

  // Chain code (32 bytes)
  memory.copy(buf.dataStart + 13, key.chainCode.dataStart, 32)

  // Public key (33 bytes compressed)
  memory.copy(buf.dataStart + 45, pubKey.dataStart, 33)

  return encodeCheck(buf)
}

/**
 * Serializes an HDKey to an xprv (extended private key) string.
 * Requires the key to be a private key (isPrivate == true).
 */
function serializeXprv(key: HDKey): string {
  if (!key.isPrivate) throw new Error("BIP44: serializeXprv requires a private key")

  const buf = new Uint8Array(78)

  // Version
  buf[0] = XPRV_VERSION_0
  buf[1] = XPRV_VERSION_1
  buf[2] = XPRV_VERSION_2
  buf[3] = XPRV_VERSION_3

  // Depth
  buf[4] = key.depth

  // Parent fingerprint (big-endian u32)
  buf[5] = <u8>((key.parentFingerprint >> 24) & 0xff)
  buf[6] = <u8>((key.parentFingerprint >> 16) & 0xff)
  buf[7] = <u8>((key.parentFingerprint >> 8) & 0xff)
  buf[8] = <u8>(key.parentFingerprint & 0xff)

  // Child index (big-endian u32)
  buf[9] = <u8>((key.childIndex >> 24) & 0xff)
  buf[10] = <u8>((key.childIndex >> 16) & 0xff)
  buf[11] = <u8>((key.childIndex >> 8) & 0xff)
  buf[12] = <u8>(key.childIndex & 0xff)

  // Chain code (32 bytes)
  memory.copy(buf.dataStart + 13, key.chainCode.dataStart, 32)

  // Private key: 0x00 prefix + 32 bytes
  buf[45] = 0x00
  memory.copy(buf.dataStart + 46, key.keyData.dataStart, 32)

  return encodeCheck(buf)
}

// ═══════════════════════════════════════════════════════
// BIP44 DERIVATION CORE
// ═══════════════════════════════════════════════════════

/**
 * Derives the account-level HDKey for a given BIP44 path:
 *   m / purpose' / coin_type' / account'
 *
 * All three levels use hardened derivation (+ HARDENED_OFFSET).
 */
function deriveAccountKey(master: HDKey, purpose: u32, coinType: u32, account: u32): HDKey {
  return master
    .derive(purpose + HARDENED_OFFSET)
    .derive(coinType + HARDENED_OFFSET)
    .derive(account + HARDENED_OFFSET)
}

// ═══════════════════════════════════════════════════════
// PUBLIC API — Key derivation (not addresses)
// ═══════════════════════════════════════════════════════

/**
 * Derives a full BIP44 leaf key node.
 *   m / purpose' / coin_type' / account' / change / address_index
 *
 * @param seed        64-byte BIP39 seed
 * @param purpose     BIP44 purpose (typically 44)
 * @param coinType    Coin type (BTC=0, ETH=60, TRX=195, etc.)
 * @param account     Account index (unhardened: 0, 1, 2…)
 * @param change      0 = external (receiving), 1 = internal (change)
 * @param addressIndex Address index (0, 1, 2…)
 * @returns 65-byte flat array: [privKey (32 bytes) | pubKey (33 bytes)]
 */
export function bip44DeriveLeafKeys(
  seed: Uint8Array,
  purpose: u32,
  coinType: u32,
  account: u32,
  change: u32,
  addressIndex: u32
): Uint8Array {
  const master = HDKey.fromSeed(seed)
  const child = deriveAccountKey(master, purpose, coinType, account).derive(change).derive(addressIndex)

  const result = new Uint8Array(65)
  // private key (32 bytes)
  memory.copy(result.dataStart, child.keyData.dataStart, 32)
  // compressed public key (33 bytes)
  const pubKey = child.getPublicKey()
  memory.copy(result.dataStart + 32, pubKey.dataStart, 33)
  return result
}

/**
 * Returns the xpub for the BIP44 account level:
 *   m / purpose' / coin_type' / account'
 *
 * The xpub can be used to derive all child public keys for that account
 * without exposing any private keys.
 *
 * @returns Base58Check-encoded xpub string (starts with "xpub")
 */
export function bip44AccountXpub(seed: Uint8Array, purpose: u32, coinType: u32, account: u32): string {
  const master = HDKey.fromSeed(seed)
  const accountKey = deriveAccountKey(master, purpose, coinType, account)
  return serializeXpub(accountKey)
}

/**
 * Returns the xprv for the BIP44 account level:
 *   m / purpose' / coin_type' / account'
 *
 * @returns Base58Check-encoded xprv string (starts with "xprv")
 */
export function bip44AccountXprv(seed: Uint8Array, purpose: u32, coinType: u32, account: u32): string {
  const master = HDKey.fromSeed(seed)
  const accountKey = deriveAccountKey(master, purpose, coinType, account)
  return serializeXprv(accountKey)
}

/**
 * Derives the private key only (32 bytes) for a BIP44 leaf node.
 */
export function bip44DerivePrivateKey(
  seed: Uint8Array,
  purpose: u32,
  coinType: u32,
  account: u32,
  change: u32,
  addressIndex: u32
): Uint8Array {
  const master = HDKey.fromSeed(seed)
  const child = deriveAccountKey(master, purpose, coinType, account).derive(change).derive(addressIndex)

  const result = new Uint8Array(32)
  memory.copy(result.dataStart, child.keyData.dataStart, 32)
  return result
}

/**
 * Derives the compressed public key (33 bytes) for a BIP44 leaf node.
 */
export function bip44DerivePublicKey(
  seed: Uint8Array,
  purpose: u32,
  coinType: u32,
  account: u32,
  change: u32,
  addressIndex: u32
): Uint8Array {
  const master = HDKey.fromSeed(seed)
  const child = deriveAccountKey(master, purpose, coinType, account).derive(change).derive(addressIndex)
  return child.getPublicKey()
}

// ═══════════════════════════════════════════════════════
// BIP39 INTEGRATION — Mnemonic entrypoints
// ═══════════════════════════════════════════════════════

/**
 * Converts a BIP39 mnemonic phrase to a 64-byte seed.
 * The seed can then be used in all bip44Derive* functions.
 *
 * @param mnemonic  The mnemonic phrase (12, 15, 18, 21, or 24 words)
 * @param passphrase  Optional BIP39 passphrase (salt)
 * @returns 64-byte seed
 */
export function bip44SeedFromMnemonic(mnemonic: string, passphrase: string = ""): Uint8Array {
  return mnemonicToSeed(mnemonic, passphrase)
}

/**
 * Validates a BIP39 mnemonic phrase.
 * @returns true if valid, false otherwise
 */
export function bip44ValidateMnemonic(mnemonic: string): bool {
  return validateMnemonic(mnemonic)
}

/**
 * Converts raw entropy bytes to a BIP39 mnemonic phrase.
 * @param entropy 16–32 bytes (multiple of 4)
 * @returns Space-separated mnemonic string
 */
export function bip44EntropyToMnemonic(entropy: Uint8Array): string {
  return entropyToMnemonic(entropy)
}

/**
 * Full pipeline: mnemonic → seed → BIP44 leaf key derivation.
 * Returns 65 bytes: [privKey (32) | pubKey (33)]
 */
export function bip44FromMnemonicDeriveKeys(
  mnemonic: string,
  passphrase: string,
  purpose: u32,
  coinType: u32,
  account: u32,
  change: u32,
  addressIndex: u32
): Uint8Array {
  const seed = mnemonicToSeed(mnemonic, passphrase)
  return bip44DeriveLeafKeys(seed, purpose, coinType, account, change, addressIndex)
}

/**
 * Full pipeline: mnemonic → seed → account xpub.
 * @returns Base58Check-encoded xpub string
 */
export function bip44FromMnemonicAccountXpub(
  mnemonic: string,
  passphrase: string,
  purpose: u32,
  coinType: u32,
  account: u32
): string {
  const seed = mnemonicToSeed(mnemonic, passphrase)
  return bip44AccountXpub(seed, purpose, coinType, account)
}
