/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  index.ts — Punto de entrada público del wrapper blockchain-wasm
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Expone SOLO las clases de dominio (fachadas estáticas + HDKey encadenable),
 * el singleton, utilidades puras y tipos. Re-exports selectivos para evitar
 * colisiones de nombres entre types.ts y los módulos de dominio.
 *
 *   import { BlockchainWasm, Bip39, Bip44, Address, Schnorr, bytesToHex } from "blockchain-wasm"
 *
 *   await BlockchainWasm.fromBuffer(wasmBytes)        // 1) cargar (una vez)
 *   const seed = Bip39.mnemonicToSeed(mnemonic)       // 2) usar las fachadas
 *   const { publicKey } = Bip44.deriveKeys(seed, 44, 0, 0, 0, 0)
 *   const addr = Address.p2wpkh(publicKey)
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
} from "./types"

// ── Tipos (type-only; cada uno desde su fuente canónica) ──────────────────
export type { AsmExports, MessageFormat, PrivateKey, PublicKey, Seed, Mnemonic } from "./types"
export type { WifKey } from "./wif"
export type { AddressType } from "./address"
export type { EcdsaSignature } from "./ecdsa"
export type { Bip44Leaf } from "./bip44"
export type { RandomBytesGenerator, EntropySourceOptions } from "./csprng"
