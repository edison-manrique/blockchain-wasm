/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  pbkdf2.ts — class Pbkdf2 (KDF HMAC‑SHA512, fachada estática)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * PBKDF2‑HMAC‑SHA512 (RFC 8018). Lo usa BIP39 (mnemonic → seed) y cualquier
 * KDF de wallet. Valida la frontera (tamaños, iterations, dkLen) y delega en
 * BlockchainWasm.getInstance().pbkdf2Sha512.
 *
 * Límites (PARAM_IN = 4096 B, partido input|aux): password/salt ≤ 2048 B c/u;
 * dkLen ≤ 2048 B (salida en PARAM_OUT).
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"
import { toUint8Array } from "./types"

const MAX_PASS = 2048
const MAX_SALT = 2048
const MAX_DKLEN = 2048

export class Pbkdf2 {
  private constructor() {}

  /**
   * PBKDF2‑HMAC‑SHA512.
   * @param password   Contraseña (Uint8Array o string UTF‑8).
   * @param salt       Salt (Uint8Array o string UTF‑8).
   * @param iterations Número de iteraciones (> 0).
   * @param dkLen      Longitud derivada en bytes (1..2048).
   */
  static sha512(
    password: Uint8Array | string,
    salt: Uint8Array | string,
    iterations: number,
    dkLen: number
  ): Uint8Array {
    const pass = toUint8Array(password)
    const sal = toUint8Array(salt)
    if (pass.length > MAX_PASS) throw new InvalidArgumentError(`password > ${MAX_PASS} B`, "pbkdf2")
    if (sal.length > MAX_SALT) throw new InvalidArgumentError(`salt > ${MAX_SALT} B`, "pbkdf2")
    if (iterations <= 0) throw new InvalidArgumentError("iterations debe ser > 0", "pbkdf2")
    if (dkLen <= 0 || dkLen > MAX_DKLEN) throw new InvalidArgumentError(`dkLen debe ser 1..${MAX_DKLEN}`, "pbkdf2")
    return BlockchainWasm.getInstance().pbkdf2Sha512(pass, sal, iterations, dkLen)
  }
}
