/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip39.ts — class Bip39 (fachada estática de dominio)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Mnemónicos BIP39: generate (entropía segura del host vía getRng),
 * entropy↔mnemonic, mnemonic→seed (PBKDF2-HMAC-SHA512 en el WASM) y validate.
 * Valida la frontera y delega en BlockchainWasm.getInstance().
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"

const VALID_STRENGTHS = [128, 160, 192, 224, 256]
const VALID_ENTROPY_BYTES = [16, 20, 24, 28, 32]

export class Bip39 {
  private constructor() {}

  /** Genera un mnemónico aleatorio (12–24 palabras). strength en bits. */
  static generate(strength: number = 128): string {
    if (VALID_STRENGTHS.indexOf(strength) === -1) {
      throw new InvalidArgumentError("strength debe ser 128/160/192/224/256", "bip39")
    }
    return BlockchainWasm.getInstance().bip39Generate(strength)
  }

  /** Entropía (16/20/24/28/32 B) → mnemónico. */
  static entropyToMnemonic(entropy: Uint8Array): string {
    if (VALID_ENTROPY_BYTES.indexOf(entropy.length) === -1) {
      throw new InvalidArgumentError("entropy debe ser 16/20/24/28/32 bytes", "bip39")
    }
    return BlockchainWasm.getInstance().bip39EntropyToMnemonic(entropy)
  }

  /** Mnemónico → entropía. */
  static mnemonicToEntropy(mnemonic: string): Uint8Array {
    if (mnemonic.length === 0) throw new InvalidArgumentError("mnemonic no puede estar vacío", "bip39")
    return BlockchainWasm.getInstance().bip39MnemonicToEntropy(mnemonic)
  }

  /** Mnemónico → seed (64 B) vía PBKDF2-HMAC-SHA512. */
  static mnemonicToSeed(mnemonic: string, passphrase: string = ""): Uint8Array {
    if (mnemonic.length === 0) throw new InvalidArgumentError("mnemonic no puede estar vacío", "bip39")
    return BlockchainWasm.getInstance().bip39MnemonicToSeed(mnemonic, passphrase)
  }

  /** Valida palabras + checksum. */
  static validate(mnemonic: string): boolean {
    if (mnemonic.length === 0) throw new InvalidArgumentError("mnemonic no puede estar vacío", "bip39")
    return BlockchainWasm.getInstance().bip39Validate(mnemonic)
  }
}
