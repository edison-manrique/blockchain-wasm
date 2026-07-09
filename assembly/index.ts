/**
 * Crypto WASM - Ultra-Optimized Cryptography Library
 *
 * Functional API for production use.
 * Exposes only plain functions (no classes) to ensure maximum compatibility in JS/WASM environments.
 */

import { Sha256, Sha512 } from "./sha2"
import { keccak256 as internalKeccak } from "./keccak256"
import { ECDH as internalECDH } from "./crypto/ecdh"
import { ECDSA, EcdsaSignature, SignatureFormat, getMessageHash as internalGetMessageHash } from "./crypto/ecdsa"
import { HDKey } from "./crypto/bip32"

// ── HASHING ──

export function sha256(data: Uint8Array): Uint8Array {
  return Sha256.hash(data)
}

export function hmac_sha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return Sha256.hmac(data, key)
}

export function hmac_sha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  return Sha512.hmac(data, key)
}

export function keccak(data: Uint8Array): Uint8Array {
  return internalKeccak(data)
}

// ── ECDSA (Functional) ──

export function get_message_hash(message: string, format: i32 = 0): Uint8Array {
  return internalGetMessageHash(message, <SignatureFormat>format)
}

/**
 * Returns a 65-byte signature: [R(32) | S(32) | V(1)]
 */
export function ecdsa_sign(hash: Uint8Array, privKey: Uint8Array): Uint8Array {
  const sig = ECDSA.sign(hash, privKey)
  const result = new Uint8Array(65)
  memory.copy(result.dataStart, sig.r.dataStart, 32)
  memory.copy(result.dataStart + 32, sig.s.dataStart, 32)
  result[64] = <u8>sig.v
  return result
}

/**
 * signature: 64 or 65 bytes: [R(32) | S(32) | Optional V(1)]
 */
export function ecdsa_verify(hash: Uint8Array, signature: Uint8Array, pubKey: Uint8Array): bool {
  if (signature.length < 64) return false
  const r = signature.slice(0, 32)
  const s = signature.slice(32, 64)
  const v = signature.length > 64 ? <i32>signature[64] : 0
  const sig = new EcdsaSignature(r, s, v)
  return ECDSA.verify(hash, sig, pubKey)
}

/**
 * Returns 65-byte signature [R|S|V]
 */
export function sign_text_message(message: string, privKey: Uint8Array, format: i32 = 0): Uint8Array {
  const hash = internalGetMessageHash(message, <SignatureFormat>format)
  return ecdsa_sign(hash, privKey)
}

export function verify_text_message(message: string, signature: Uint8Array, pubKey: Uint8Array, format: i32 = 0): bool {
  const hash = internalGetMessageHash(message, <SignatureFormat>format)
  return ecdsa_verify(hash, signature, pubKey)
}

// ── SCHNORR ──

export { signSchnorr, verifySchnorr, getSchnorrPublicKey } from "./crypto/schnorr"

// ── ECDH ──

export function shared_secret(privKey: Uint8Array, pubKey: Uint8Array): Uint8Array {
  return internalECDH.sharedSecret(privKey, pubKey)
}

// ── ADDRESSES ──

export {
  getBitcoinAddress,
  getBitcoinP2SHAddress,
  getBitcoinP2WPKHAddress,
  getBitcoinP2TRAddress,
  getEthereumAddress,
  getPublicKeyCompressed,
  getPublicKeyUncompressed,
  compressPublicKey,
  uncompressPublicKey
} from "./crypto/address"

// ── BIP32 (Functional) ──

export function bip32_derive_path(seed: Uint8Array, path: string): Uint8Array {
  const master = HDKey.fromSeed(seed)
  const key = master.derivePath(path)
  return key.keyData
}

export function bip32_get_pubkey(seed: Uint8Array, path: string): Uint8Array {
  const master = HDKey.fromSeed(seed)
  const key = master.derivePath(path)
  return key.getPublicKey()
}

// ── OTHERS ──

export { toWIF, fromWIF } from "./crypto/wif"
export { pbkdf2_sha512 } from "./pbkdf2"
export { bytesToHex, hexToBytes, bytesToBase64, base64ToBytes, isSameBytes, concatBytes } from "./utils"
