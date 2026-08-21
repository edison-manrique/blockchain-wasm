/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip44.ts — class Bip44 (fachada estática de dominio)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Derivación BIP44 m/purpose'/coinType'/account'/change/addressIndex desde
 * seed (64 B) o directamente desde mnemónico. Valida la frontera y delega en
 * BlockchainWasm.getInstance().
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"
import { MAX_PASSPHRASE_BYTES, SEED_BYTES, toUint8Array } from "./types"

export interface Bip44Leaf {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export class Bip44 {
  private constructor() {}

  /** Constantes de conveniencia. */
  static readonly PURPOSE = 44
  static readonly COIN_BTC = 0
  static readonly COIN_ETH = 60
  static readonly COIN_TRON = 195 // m/44'/195'/0'/0/0

  private static assertSeed(seed: Uint8Array): void {
    if (seed.length !== SEED_BYTES) throw new InvalidArgumentError("seed debe ser 64 bytes (BIP39)", "bip44")
  }
  private static assertMnemonic(mnemonic: string): void {
    if (mnemonic.length === 0) throw new InvalidArgumentError("mnemonic no puede estar vacío", "bip44")
  }
  private static assertPassphrase(passphrase: string): void {
    if (toUint8Array(passphrase).length > MAX_PASSPHRASE_BYTES) {
      throw new InvalidArgumentError(`passphrase > ${MAX_PASSPHRASE_BYTES} bytes UTF-8`, "bip44")
    }
  }

  static derivePrivateKey(
    seed: Uint8Array,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number,
  ): Uint8Array {
    Bip44.assertSeed(seed)
    return BlockchainWasm.getInstance().bip44DerivePrivkey(seed, purpose, coinType, account, change, addressIndex)
  }
  static derivePublicKey(
    seed: Uint8Array,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number,
  ): Uint8Array {
    Bip44.assertSeed(seed)
    return BlockchainWasm.getInstance().bip44DerivePubkey(seed, purpose, coinType, account, change, addressIndex)
  }
  static deriveKeys(
    seed: Uint8Array,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number,
  ): Bip44Leaf {
    Bip44.assertSeed(seed)
    return BlockchainWasm.getInstance().bip44DeriveLeaf(seed, purpose, coinType, account, change, addressIndex)
  }
  static accountXpub(seed: Uint8Array, purpose: number, coinType: number, account: number): string {
    Bip44.assertSeed(seed)
    return BlockchainWasm.getInstance().bip44AccountXpub(seed, purpose, coinType, account)
  }
  static accountXprv(seed: Uint8Array, purpose: number, coinType: number, account: number): string {
    Bip44.assertSeed(seed)
    return BlockchainWasm.getInstance().bip44AccountXprv(seed, purpose, coinType, account)
  }

  // ── Desde mnemónico (convierte a seed internamente) ─────────────────────
  static fromMnemonicDerive(
    mnemonic: string,
    passphrase: string,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number,
  ): Bip44Leaf {
    Bip44.assertMnemonic(mnemonic)
    Bip44.assertPassphrase(passphrase)
    return BlockchainWasm.getInstance().bip44FromMnemonicDerive(
      mnemonic,
      passphrase,
      purpose,
      coinType,
      account,
      change,
      addressIndex,
    )
  }
  static fromMnemonicXpub(
    mnemonic: string,
    passphrase: string,
    purpose: number,
    coinType: number,
    account: number,
  ): string {
    Bip44.assertMnemonic(mnemonic)
    Bip44.assertPassphrase(passphrase)
    return BlockchainWasm.getInstance().bip44FromMnemonicXpub(mnemonic, passphrase, purpose, coinType, account)
  }
  static fromMnemonicXprv(
    mnemonic: string,
    passphrase: string,
    purpose: number,
    coinType: number,
    account: number,
  ): string {
    Bip44.assertMnemonic(mnemonic)
    Bip44.assertPassphrase(passphrase)
    return BlockchainWasm.getInstance().bip44FromMnemonicXprv(mnemonic, passphrase, purpose, coinType, account)
  }
}
