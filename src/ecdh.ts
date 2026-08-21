/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdh.ts — class Ecdh (fachada estática de dominio)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Secreto compartido = compressed(priv·pub) (33 B). Valida la frontera
 * (longitudes) y delega en BlockchainWasm.getInstance().ecdhSharedSecret.
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"
import { isValidPrivateKey, PRIVKEY_BYTES, PUBKEY_COMPRESSED_BYTES, PUBKEY_UNCOMPRESSED_BYTES } from "./types"

export class Ecdh {
  private constructor() {}

  /** Secreto compartido (33 B, compressed). Acepta pub compressed (33) o uncompressed (65). */
  static sharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    if (privateKey.length !== PRIVKEY_BYTES) {
      throw new InvalidArgumentError("privateKey debe ser 32 bytes", "ecdh")
    }
    if (publicKey.length !== PUBKEY_COMPRESSED_BYTES && publicKey.length !== PUBKEY_UNCOMPRESSED_BYTES) {
      throw new InvalidArgumentError("publicKey debe ser 33 o 65 bytes", "ecdh")
    }
    if (!isValidPrivateKey(privateKey)) {
      throw new InvalidArgumentError("privateKey fuera de rango (0 o ≥ N)", "<modulo>")
    }
    return BlockchainWasm.getInstance().ecdhSharedSecret(privateKey, publicKey)
  }
}
