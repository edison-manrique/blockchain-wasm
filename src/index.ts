/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  index.ts — Punto de entrada público del wrapper blockchain-wasm
 * ═══════════════════════════════════════════════════════════════════════════
 */

// ── Singleton + allocator ─────────────────────────────────────────────────
export { BlockchainWasm } from "./blockchain-wasm"
export { WasmAllocator } from "./allocator"

// ── Fachadas de dominio (clases estáticas) ────────────────────────────────
export { Secp256k1 } from "./secp256k1"
export { Wif } from "./wif"
export { Address } from "./address"
export { Ecdsa, SignatureFormat } from "./ecdsa"
export { Schnorr } from "./schnorr"
export { Ecdh } from "./ecdh"
export { Pbkdf2 } from "./pbkdf2"
export { Bip32, HDKey } from "./bip32"
export { Bip39 } from "./bip39"
export { Bip44 } from "./bip44"

// ── Entropía host-side ────────────────────────────────────────────────────
export { EntropySource, getRandomBytes, fillRandom, fillRandomInto } from "./csprng"

// ── Errores (todos heredan de BlockchainWasmError) ────────────────────────
export {
  BlockchainWasmError,
  WasmError,
  NotInitializedError,
  MissingExportError,
  InvalidArgumentError,
  WasmBusyError,
  EntropyError,
  RuntimeCode,
  toBlockchainWasmError
} from "./errors"
export type { BlockchainWasmErrorCode, BlockchainWasmErrorOptions } from "./errors"

// ── Utilidades puras + constantes ─────────────────────────────────────────
export {
  bytesToHex,
  hexToBytes,
  toUint8Array,
  concatBytes,
  zeroize,
  getGlobalValue,
  isValidPrivateKey,
  MAX_PASSPHRASE_BYTES,
  PRIVKEY_BYTES,
  PUBKEY_COMPRESSED_BYTES,
  PUBKEY_UNCOMPRESSED_BYTES,
  XONLY_BYTES,
  XKEY_BYTES,
  SEED_BYTES,
  HASH_BYTES,
  SIG_BYTES,
  HALF_ZONE
} from "./types"

// ── Tipos (type-only) ─────────────────────────────────────────────────────
export type { AsmExports, MessageFormat, PrivateKey, PublicKey, Seed, Mnemonic } from "./types"
export type { WifKey } from "./wif"
export type { AddressType } from "./address"
export type { EcdsaSignature } from "./ecdsa"
export type { Bip44Leaf } from "./bip44"
export type { RandomBytesGenerator, EntropySourceOptions } from "./csprng"
