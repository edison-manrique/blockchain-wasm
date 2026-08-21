/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  secp256k1.ts — class Secp256k1 (fachada estática de dominio)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Valida la frontera (longitudes) y delega en BlockchainWasm.getInstance().
 * El marshalling y la criptografía viven en el singleton/WASM.
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"
import { isValidPrivateKey, PRIVKEY_BYTES, PUBKEY_COMPRESSED_BYTES, PUBKEY_UNCOMPRESSED_BYTES } from "./types"

export class Secp256k1 {
  private constructor() {}

  /** Pubkey desde clave privada. compressed=true → 33 B; false → 65 B. */
  static getPublicKey(privateKey: Uint8Array, compressed = true): Uint8Array {
    if (privateKey.length !== PRIVKEY_BYTES) {
      throw new InvalidArgumentError("privateKey debe ser 32 bytes", "secp256k1")
    }
    if (!isValidPrivateKey(privateKey)) {
      throw new InvalidArgumentError("privateKey fuera de rango (0 o ≥ N)", "<modulo>")
    }
    return BlockchainWasm.getInstance().getPublicKey(privateKey, compressed)
  }

  /** Comprime (65→33) o re‑valida compressed (33→33). Lanza si inválido. */
  static compress(publicKey: Uint8Array): Uint8Array {
    if (publicKey.length !== PUBKEY_COMPRESSED_BYTES && publicKey.length !== PUBKEY_UNCOMPRESSED_BYTES) {
      throw new InvalidArgumentError("publicKey debe ser 33 o 65 bytes", "secp256k1")
    }
    return BlockchainWasm.getInstance().compress(publicKey)
  }

  /** Descomprime (33→65). Lanza si prefijo inválido o X fuera de la curva. */
  static uncompress(publicKey: Uint8Array): Uint8Array {
    if (publicKey.length !== PUBKEY_COMPRESSED_BYTES) {
      throw new InvalidArgumentError("uncompress requiere 33 bytes", "secp256k1")
    }
    return BlockchainWasm.getInstance().uncompress(publicKey)
  }

  /** Valida formato + pertenencia a la curva (sin lanzar). */
  static isValid(publicKey: Uint8Array): boolean {
    return BlockchainWasm.getInstance().isValidPoint(publicKey)
  }
}
