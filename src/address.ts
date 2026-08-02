/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  address.ts — class Address (fachada estática de dominio, mainnet)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Direcciones Bitcoin (P2PKH / P2SH‑P2WPKH / P2WPKH / P2TR) y Ethereum.
 * Mainnet únicamente (prefijos hardcodeados en el WASM). Valida la frontera
 * (longitud de pubkey) y delega en BlockchainWasm.getInstance().
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"
import { PRIVKEY_BYTES, PUBKEY_COMPRESSED_BYTES, PUBKEY_UNCOMPRESSED_BYTES } from "./types"

export type AddressType = "p2pkh" | "p2sh-p2wpkh" | "p2wpkh" | "p2tr" | "eth"

function assertPubkey(publicKey: Uint8Array): void {
  if (publicKey.length !== PUBKEY_COMPRESSED_BYTES && publicKey.length !== PUBKEY_UNCOMPRESSED_BYTES) {
    throw new InvalidArgumentError("publicKey debe ser 33 o 65 bytes", "address")
  }
}

export class Address {
  private constructor() {}

  static p2pkh(publicKey: Uint8Array): string {
    assertPubkey(publicKey)
    return BlockchainWasm.getInstance().btcP2pkh(publicKey)
  }
  static p2shP2wpkh(publicKey: Uint8Array): string {
    assertPubkey(publicKey)
    return BlockchainWasm.getInstance().btcP2shP2wpkh(publicKey)
  }
  static p2wpkh(publicKey: Uint8Array): string {
    assertPubkey(publicKey)
    return BlockchainWasm.getInstance().btcP2wpkh(publicKey)
  }
  static p2tr(publicKey: Uint8Array): string {
    assertPubkey(publicKey)
    return BlockchainWasm.getInstance().btcP2tr(publicKey)
  }
  static eth(publicKey: Uint8Array): string {
    assertPubkey(publicKey)
    return BlockchainWasm.getInstance().ethAddress(publicKey)
  }

  /** Conveniencia: priv → pubkey → dirección del tipo pedido. */
  static fromPrivateKey(privateKey: Uint8Array, type: AddressType, compressed = true): string {
    if (privateKey.length !== PRIVKEY_BYTES) throw new InvalidArgumentError("privateKey debe ser 32 bytes", "address")
    const pub = BlockchainWasm.getInstance().getPublicKey(privateKey, compressed)
    switch (type) {
      case "p2pkh":
        return BlockchainWasm.getInstance().btcP2pkh(pub)
      case "p2sh-p2wpkh":
        return BlockchainWasm.getInstance().btcP2shP2wpkh(pub)
      case "p2wpkh":
        return BlockchainWasm.getInstance().btcP2wpkh(pub)
      case "p2tr":
        return BlockchainWasm.getInstance().btcP2tr(pub)
      case "eth":
        return BlockchainWasm.getInstance().ethAddress(pub)
    }
  }
}
