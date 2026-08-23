/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  index.ts — Punto de entrada público del wrapper blockchain-wasm
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * ✅ FIX v3.0: Añadida exportación de Musig2 y tipos relacionados.
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
export { Musig2 } from "./musig2" // ✅ FIX v3.0
export { Ecdh } from "./ecdh"
export { Pbkdf2 } from "./pbkdf2"
export { Bip32, HDKey } from "./bip32"
export { Bip39 } from "./bip39"
export { Bip44 } from "./bip44"

// ── Entropía host-side ────────────────────────────────────────────────────
export { EntropySource, getRandomBytes, fillRandom, fillRandomInto } from "./csprng"

// ── Errores ───────────────────────────────────────────────────────────────
export { WasmError, NotInitializedError, MissingExportError, InvalidArgumentError } from "./errors"

// ── Utilidades puras + constantes ─────────────────────────────────────────
export {
  bytesToHex,
  hexToBytes,
  toUint8Array,
  concatBytes,
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
  HALF_ZONE,
  // ✅ FIX v3.0: Constantes MuSig2
  MUSIG_PUBNONCE_BYTES,
  MUSIG_AGGNONCE_BYTES,
  MUSIG_SECNONCE_BYTES,
  MUSIG_SESSION_BYTES,
  MUSIG_SIG_BYTES,
  MUSIG_MAX_SIGNERS
} from "./types"

// ── Tipos (type-only) ─────────────────────────────────────────────────────
export type { AsmExports, MessageFormat, PrivateKey, PublicKey, Seed, Mnemonic } from "./types"
export type { WifKey } from "./wif"
export type { AddressType } from "./address"
export type { EcdsaSignature } from "./ecdsa"
export type { Bip44Leaf } from "./bip44"
export type { RandomBytesGenerator, EntropySourceOptions } from "./csprng"
// ✅ FIX v3.0: Tipos MuSig2
export type { Musig2KeyAggResult, Musig2NoncePair, Musig2Session } from "./types"
