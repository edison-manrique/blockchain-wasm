/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  wif.ts — class Wif (fachada estática de dominio, mainnet)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Mainnet únicamente: el prefijo 0x80 lo hardcodea el WASM. Valida la frontera
 * y delega en BlockchainWasm.getInstance().wifEncode/wifDecode.
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"
import { isValidPrivateKey, PRIVKEY_BYTES } from "./types"
export type { WifKey } from "./types"

const MAX_WIF_STR = 128

export class Wif {
  private constructor() {}

  /** Clave privada (32 B) → WIF. compressed=true por defecto (K…/L…). */
  static encode(privateKey: Uint8Array, compressed = true): string {
    if (privateKey.length !== PRIVKEY_BYTES) {
      throw new InvalidArgumentError("privateKey debe ser 32 bytes", "wif")
    }
    if (!isValidPrivateKey(privateKey)) {
      throw new InvalidArgumentError("privateKey fuera de rango (0 o ≥ N)", "<modulo>")
    }
    return BlockchainWasm.getInstance().wifEncode(privateKey, compressed)
  }

  /** WIF → { privateKey, compressed }. Lanza si carácter/checksum/prefijo inválido. */
  static decode(wif: string): import("./types").WifKey {
    if (wif.length > MAX_WIF_STR) {
      throw new InvalidArgumentError(`WIF demasiado largo (max ${MAX_WIF_STR} chars)`, "wif")
    }
    return BlockchainWasm.getInstance().wifDecode(wif)
  }
}
