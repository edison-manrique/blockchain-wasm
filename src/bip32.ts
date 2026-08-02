/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip32.ts — class Bip32 (fachada estática) + HDKey (encadenable)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * HDKey envuelve el xkey crudo (88 B) copiado del WASM. Los getters parsean el
 * raw en JS (layout de bip32/xkey.ts: depth@0, parentFP@1 LE, childIdx@5 LE,
 * isPrivate@9, chainCode@16..48, keyData@48..81). Los métodos encadenables
 * (derive/derivePath/neuter/…) delegan en BlockchainWasm y devuelven NUEVA HDKey.
 *
 * El usuario NO escribe `new HDKey(...)`: la construyen Bip32.fromSeed/derive/
 * fromXpub/… (constructor público solo para uso interno de Bip32).
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"
import { XKEY_BYTES } from "./types"

export class HDKey {
  readonly raw: Uint8Array // 88 B, inmutable

  constructor(raw: Uint8Array) {
    if (raw.length !== XKEY_BYTES) throw new InvalidArgumentError("xkey debe ser 88 bytes", "bip32")
    this.raw = raw
  }

  // ── Getters (delegan en los accessors del WASM; layout interno = detalle del WASM) ──
  get depth(): number {
    return BlockchainWasm.getInstance().bip32XkeyDepth(this.raw)
  }
  get parentFingerprint(): number {
    return BlockchainWasm.getInstance().bip32XkeyParentFp(this.raw)
  }
  get childIndex(): number {
    return BlockchainWasm.getInstance().bip32XkeyChildIndex(this.raw)
  }
  get isPrivate(): boolean {
    return BlockchainWasm.getInstance().bip32XkeyIsPrivate(this.raw)
  }
  get chainCode(): Uint8Array {
    return BlockchainWasm.getInstance().bip32XkeyChainCode(this.raw)
  }

  /** Clave privada (32 B). Lanza si es un xpub. */
  get privateKey(): Uint8Array {
    if (!this.isPrivate) throw new InvalidArgumentError("este HDKey es público (no tiene privateKey)", "bip32")
    return BlockchainWasm.getInstance().bip32XkeyKeyData(this.raw, 32)
  }

  /** Clave pública compressed (33 B). */
  get publicKey(): Uint8Array {
    if (this.isPrivate) return BlockchainWasm.getInstance().bip32GetPubkey(this.raw)
    return BlockchainWasm.getInstance().bip32XkeyKeyData(this.raw, 33)
  }

  // ── Métodos encadenables (sin cambios) ──────────────────────────────────
  derive(index: number): HDKey {
    return new HDKey(BlockchainWasm.getInstance().bip32Derive(this.raw, index))
  }
  derivePath(path: string): HDKey {
    return new HDKey(BlockchainWasm.getInstance().bip32DerivePath(this.raw, path))
  }
  deriveAccount(purpose: number, coinType: number, account: number): HDKey {
    return new HDKey(BlockchainWasm.getInstance().bip32DeriveAccount(this.raw, purpose, coinType, account))
  }
  neuter(): HDKey {
    return new HDKey(BlockchainWasm.getInstance().bip32Neuter(this.raw))
  }
  toXpub(): string {
    return BlockchainWasm.getInstance().bip32SerializeXpub(this.raw)
  }
  toXprv(): string {
    if (!this.isPrivate) throw new InvalidArgumentError("no se puede serializar xprv de un HDKey público", "bip32")
    return BlockchainWasm.getInstance().bip32SerializeXprv(this.raw)
  }
  getPublicKey(): Uint8Array {
    return BlockchainWasm.getInstance().bip32GetPubkey(this.raw)
  }
  fingerprint(): number {
    return BlockchainWasm.getInstance().bip32Fingerprint(this.raw)
  }
}

// ── Fachada estática ──────────────────────────────────────────────────────
export class Bip32 {
  private constructor() {}

  static fromSeed(seed: Uint8Array): HDKey {
    if (seed.length < 16 || seed.length > 64) throw new InvalidArgumentError("seed debe ser 16..64 bytes", "bip32")
    return new HDKey(BlockchainWasm.getInstance().bip32FromSeed(seed))
  }
  static derive(key: HDKey, index: number): HDKey {
    return key.derive(index)
  }
  static derivePath(key: HDKey, path: string): HDKey {
    return key.derivePath(path)
  }
  static deriveAccount(key: HDKey, purpose: number, coinType: number, account: number): HDKey {
    return key.deriveAccount(purpose, coinType, account)
  }
  static neuter(key: HDKey): HDKey {
    return key.neuter()
  }
  static toXpub(key: HDKey): string {
    return key.toXpub()
  }
  static toXprv(key: HDKey): string {
    return key.toXprv()
  }
  static fromXpub(xpub: string): HDKey {
    return new HDKey(BlockchainWasm.getInstance().bip32Deserialize(xpub))
  }
  static fromXprv(xprv: string): HDKey {
    return new HDKey(BlockchainWasm.getInstance().bip32Deserialize(xprv))
  }
  static getPublicKey(key: HDKey): Uint8Array {
    return key.getPublicKey()
  }
  static fingerprint(key: HDKey): number {
    return key.fingerprint()
  }
}
