/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr.ts — class Schnorr (BIP-340, fachada estática de dominio)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Firma/verificación Schnorr, x-only pubkey y agregación naive. Si `sign` no
 * recibe `auxRand`, el singleton inyecta entropía segura del host (getRng),
 * como recomienda BIP-340. Valida la frontera y delega en BlockchainWasm.
 *
 * `message` es de longitud libre (el WASM lo procesa con tagged hash); para el
 * uso BIP-340 canónico pásale un hash de 32 bytes.
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"
import { PRIVKEY_BYTES, XONLY_BYTES, SIG_BYTES, HALF_ZONE, toUint8Array } from "./types"

const MAX_AGG = 128 // 128 * 32 = 4096 = PARAM_IN

function assertXonly(p: Uint8Array): void {
  if (p.length !== XONLY_BYTES) throw new InvalidArgumentError("x-only pubkey debe ser 32 bytes", "schnorr")
}

export class Schnorr {
  private constructor() {}

  /** x-only pubkey (32 B) desde clave privada. */
  static getPublicKey(privateKey: Uint8Array): Uint8Array {
    if (privateKey.length !== PRIVKEY_BYTES) throw new InvalidArgumentError("privateKey debe ser 32 bytes", "schnorr")
    return BlockchainWasm.getInstance().schnorrGetPubkey(privateKey)
  }

  /** Firma BIP-340 (64 B). Sin `auxRand` → entropía segura del host. */
  static sign(message: Uint8Array, privateKey: Uint8Array, auxRand?: Uint8Array): Uint8Array {
    if (privateKey.length !== PRIVKEY_BYTES) throw new InvalidArgumentError("privateKey debe ser 32 bytes", "schnorr")
    if (message.length === 0 || message.length > HALF_ZONE) {
      throw new InvalidArgumentError(`message debe ser 1..${HALF_ZONE} bytes`, "schnorr")
    }
    if (auxRand !== undefined && auxRand.length !== 32)
      throw new InvalidArgumentError("auxRand debe ser 32 bytes", "schnorr")
    return BlockchainWasm.getInstance().schnorrSign(message, privateKey, auxRand)
  }

  /** Verifica una firma BIP-340. pubkey x-only (32 B). */
  static verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
    if (signature.length !== SIG_BYTES) throw new InvalidArgumentError("signature debe ser 64 bytes", "schnorr")
    if (publicKey.length !== XONLY_BYTES)
      throw new InvalidArgumentError("publicKey (x-only) debe ser 32 bytes", "schnorr")
    if (message.length > HALF_ZONE) throw new InvalidArgumentError(`message debe ser <= ${HALF_ZONE} bytes`, "schnorr")
    return BlockchainWasm.getInstance().schnorrVerify(signature, message, publicKey)
  }

  /** Agregación naive de x-only pubkeys (sin coeficientes MuSig). */
  static aggregatePublicKeys(publicKeys: Uint8Array[]): Uint8Array {
    if (publicKeys.length === 0 || publicKeys.length > MAX_AGG) {
      throw new InvalidArgumentError(`publicKeys debe tener 1..${MAX_AGG} elementos`, "schnorr")
    }
    for (let i = 0; i < publicKeys.length; i++) assertXonly(publicKeys[i])
    return BlockchainWasm.getInstance().schnorrAggregatePubkeys(publicKeys)
  }

  /** Agregación naive de privkeys (consistente con aggregatePublicKeys). */
  static aggregatePrivateKeys(privateKeys: Uint8Array[]): Uint8Array {
    if (privateKeys.length === 0 || privateKeys.length > MAX_AGG) {
      throw new InvalidArgumentError(`privateKeys debe tener 1..${MAX_AGG} elementos`, "schnorr")
    }
    for (let i = 0; i < privateKeys.length; i++) {
      if (privateKeys[i].length !== PRIVKEY_BYTES)
        throw new InvalidArgumentError("cada privateKey debe ser 32 bytes", "schnorr")
    }
    return BlockchainWasm.getInstance().schnorrAggregatePrivkeys(privateKeys)
  }

  /** Firma un mensaje de texto: hashea según formato y firma el hash con BIP‑340. */
  static signTextMessage(text: string, privateKey: Uint8Array, format: number = 0, auxRand?: Uint8Array): Uint8Array {
    const hash = BlockchainWasm.getInstance().ecdsaMessageHash(toUint8Array(text), format)
    return Schnorr.sign(hash, privateKey, auxRand)
  }

  /** Verifica una firma Schnorr de mensaje de texto (mismo formato al hashear). */
  static verifyTextMessage(text: string, signature: Uint8Array, publicKey: Uint8Array, format: number = 0): boolean {
    const hash = BlockchainWasm.getInstance().ecdsaMessageHash(toUint8Array(text), format)
    return Schnorr.verify(signature, hash, publicKey)
  }
}
