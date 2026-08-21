/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdsa.ts — class Ecdsa (fachada estática de dominio)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Firma/verificación ECDSA secp256k1 + firma/verificación de mensaje por
 * formato (Universal=SHA256, Bitcoin=doubleSHA256 con prefijo, Ethereum=Keccak).
 * `verify`/`verifyMessage` aceptan la firma como { r, s, v } o como 64 B (r‖s).
 * Valida la frontera y delega en BlockchainWasm.getInstance().
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"
import {
  PRIVKEY_BYTES,
  PUBKEY_COMPRESSED_BYTES,
  PUBKEY_UNCOMPRESSED_BYTES,
  HASH_BYTES,
  SIG_BYTES,
  HALF_ZONE,
  toUint8Array,
  isValidPrivateKey,
} from "./types"
import type { EcdsaSignature } from "./types"

export { type EcdsaSignature }

/** Formato de hash de mensaje. */
export const SignatureFormat = { Universal: 0, Bitcoin: 1, Ethereum: 2 } as const

/** Normaliza { r, s, v } | Uint8Array(64) → Uint8Array(64) = r‖s. */
function normalizeSig(sig: EcdsaSignature | Uint8Array): Uint8Array {
  if (sig instanceof Uint8Array) {
    if (sig.length !== SIG_BYTES) throw new InvalidArgumentError("signature debe ser 64 bytes", "ecdsa")
    return sig
  }
  if (sig.r.length !== 32) throw new InvalidArgumentError("signature.r debe ser 32 bytes", "ecdsa")
  if (sig.s.length !== 32) throw new InvalidArgumentError("signature.s debe ser 32 bytes", "ecdsa")
  const out = new Uint8Array(SIG_BYTES)
  out.set(sig.r, 0)
  out.set(sig.s, 32)
  return out
}

export class Ecdsa {
  private constructor() {}

  /** Firma un hash de 32 B → { r, s, v }. */
  static sign(hash: Uint8Array, privateKey: Uint8Array): EcdsaSignature {
    if (hash.length !== HASH_BYTES) throw new InvalidArgumentError("hash debe ser 32 bytes", "ecdsa")
    if (privateKey.length !== PRIVKEY_BYTES) throw new InvalidArgumentError("privateKey debe ser 32 bytes", "ecdsa")
    if (!isValidPrivateKey(privateKey)) {
      throw new InvalidArgumentError("privateKey fuera de rango (0 o ≥ N)", "<modulo>")
    }
    return BlockchainWasm.getInstance().ecdsaSign(hash, privateKey)
  }

  /** Verifica una firma sobre un hash de 32 B. */
  static verify(hash: Uint8Array, signature: EcdsaSignature | Uint8Array, publicKey: Uint8Array): boolean {
    if (hash.length !== HASH_BYTES) throw new InvalidArgumentError("hash debe ser 32 bytes", "ecdsa")
    if (publicKey.length !== PUBKEY_COMPRESSED_BYTES && publicKey.length !== PUBKEY_UNCOMPRESSED_BYTES) {
      throw new InvalidArgumentError("publicKey debe ser 33 o 65 bytes", "ecdsa")
    }
    return BlockchainWasm.getInstance().ecdsaVerify(hash, normalizeSig(signature), publicKey)
  }

  /** Hash de mensaje según formato (por defecto Universal = SHA-256). */
  static messageHash(message: Uint8Array, format: number = SignatureFormat.Universal): Uint8Array {
    if (message.length === 0 || message.length > HALF_ZONE) {
      throw new InvalidArgumentError(`message debe ser 1..${HALF_ZONE} bytes`, "ecdsa")
    }
    return BlockchainWasm.getInstance().ecdsaMessageHash(message, format)
  }

  /** Firma un mensaje (lo hashea según formato internamente) → { r, s, v }. */
  static signMessage(
    message: Uint8Array,
    privateKey: Uint8Array,
    format: number = SignatureFormat.Universal,
  ): EcdsaSignature {
    if (privateKey.length !== PRIVKEY_BYTES) throw new InvalidArgumentError("privateKey debe ser 32 bytes", "ecdsa")
    if (message.length === 0 || message.length > HALF_ZONE) {
      throw new InvalidArgumentError(`message debe ser 1..${HALF_ZONE} bytes`, "ecdsa")
    }
    if (!isValidPrivateKey(privateKey)) {
      throw new InvalidArgumentError("privateKey fuera de rango (0 o ≥ N)", "<modulo>")
    }
    return BlockchainWasm.getInstance().ecdsaSignMessage(message, privateKey, format)
  }

  /** Verifica una firma de mensaje. */
  static verifyMessage(
    message: Uint8Array,
    signature: EcdsaSignature | Uint8Array,
    publicKey: Uint8Array,
    format: number = SignatureFormat.Universal,
  ): boolean {
    if (publicKey.length !== PUBKEY_COMPRESSED_BYTES && publicKey.length !== PUBKEY_UNCOMPRESSED_BYTES) {
      throw new InvalidArgumentError("publicKey debe ser 33 o 65 bytes", "ecdsa")
    }
    if (message.length > HALF_ZONE) throw new InvalidArgumentError(`message debe ser <= ${HALF_ZONE} bytes`, "ecdsa")
    return BlockchainWasm.getInstance().ecdsaVerifyMessage(message, normalizeSig(signature), publicKey, format)
  }

  /** Firma un mensaje de texto (UTF‑8) según formato → { r, s, v }. */
  static signTextMessage(
    text: string,
    privateKey: Uint8Array,
    format: number = SignatureFormat.Universal,
  ): EcdsaSignature {
    return Ecdsa.signMessage(toUint8Array(text), privateKey, format)
  }

  /** Verifica una firma de mensaje de texto (UTF‑8) según formato. */
  static verifyTextMessage(
    text: string,
    signature: EcdsaSignature | Uint8Array,
    publicKey: Uint8Array,
    format: number = SignatureFormat.Universal,
  ): boolean {
    return Ecdsa.verifyMessage(toUint8Array(text), signature, publicKey, format)
  }
}
