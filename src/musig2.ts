/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  musig2.ts — class Musig2 (BIP-326, fachada estática de dominio)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * MuSig2: firmas multi-signatura Schnorr con agregación de claves.
 * Flujo típico (3 signers):
 *
 *   1. keyAgg(pubkeys) → { q, gacc }
 *   2. nonceGen(secrand, pk, sk, msg) × N → { secNonce, pubNonce }
 *   3. nonceAgg(pubNonces) → aggNonce
 *   4. sessionInit(aggNonce, q, msg) → session
 *   5. partialSign(session, gacc, secNonce, priv, coeff) × N → partials
 *   6. partialSigAgg(partials) → s
 *   7. signature = Rx ‖ s (64 bytes)
 *
 * O bien: signAll(privkeys, msg, secrands) → { signature, aggregatedPubkey }
 *
 * Valida la frontera (longitudes, rango de privkey) y delega en
 * BlockchainWasm.getInstance().
 */
import { BlockchainWasm } from "./blockchain-wasm"
import { InvalidArgumentError } from "./errors"
import {
  PRIVKEY_BYTES,
  XONLY_BYTES,
  HALF_ZONE,
  toUint8Array,
  isValidPrivateKey,
  negatePrivateKey,
  MUSIG_PUBNONCE_BYTES,
  MUSIG_SECNONCE_BYTES,
  MUSIG_SESSION_BYTES,
  MUSIG_MAX_SIGNERS,
  MUSIG_AGGNONCE_BYTES
} from "./types"
import type { Musig2KeyAggResult, Musig2NoncePair } from "./types"

function musigBytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function toCompressedPubkey(pk: Uint8Array, name: string): Uint8Array {
  if (pk.length === 33) return pk
  if (pk.length === XONLY_BYTES) {
    const c = new Uint8Array(33)
    c[0] = 0x02
    c.set(pk, 1)
    return c
  }
  throw new InvalidArgumentError(`${name} debe ser 32 bytes (x-only) o 33 bytes (compressed)`, "musig2")
}

export class Musig2 {
  private constructor() {}

  // ═══════════════════════════════════════════════════════════════════════
  // KEY AGGREGATION
  // ═══════════════════════════════════════════════════════════════════════

  /** Agrega pubkeys (32 B x-only o 33 B compressed) → clave pública agregada (32 B) + gacc. */
  static keyAgg(pubkeys: Uint8Array[]): Musig2KeyAggResult {
    if (pubkeys.length === 0 || pubkeys.length > MUSIG_MAX_SIGNERS) {
      throw new InvalidArgumentError(`se requieren 1..${MUSIG_MAX_SIGNERS} pubkeys`, "musig2")
    }
    const compressed = pubkeys.map((p, i) => toCompressedPubkey(p, `pubkey[${i}]`))
    const { q, gacc } = BlockchainWasm.getInstance().musig2KeyAgg(compressed)
    return { aggregatedPubkey: q, gacc }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // NONCE GENERATION & AGGREGATION
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Genera un par de nonces para un signer (BIP-327).
   * @param secrand  32 bytes de random seguro (del host).
   * @param pk       Pubkey del signer (32 B x-only o 33 B compressed).
   * @param sk       Privkey del signer (32 B, opcional — mejora seguridad).
   * @param msg      Mensaje a firmar (opcional — binding al mensaje).
   */
  static nonceGen(secrand: Uint8Array, pk: Uint8Array, sk?: Uint8Array, msg?: Uint8Array): Musig2NoncePair {
    if (secrand.length !== 32) {
      throw new InvalidArgumentError("secrand debe ser 32 bytes", "musig2")
    }
    const pk33 = toCompressedPubkey(pk, "pk")
    if (sk !== undefined && sk.length !== PRIVKEY_BYTES) {
      throw new InvalidArgumentError("sk debe ser 32 bytes", "musig2")
    }
    const { secNonce, pubNonce } = BlockchainWasm.getInstance().musig2NonceGen(secrand, pk33, sk, undefined, msg)
    return { secNonce, pubNonce }
  }

  /** Agrega los nonces públicos de todos los signers (66 B c/u). */
  static nonceAgg(pubNonces: Uint8Array[]): Uint8Array {
    if (pubNonces.length === 0 || pubNonces.length > MUSIG_MAX_SIGNERS) {
      throw new InvalidArgumentError(`se requieren 1..${MUSIG_MAX_SIGNERS} nonces`, "musig2")
    }
    for (let i = 0; i < pubNonces.length; i++) {
      if (pubNonces[i].length !== MUSIG_PUBNONCE_BYTES) {
        throw new InvalidArgumentError(`pubNonce[${i}] debe ser ${MUSIG_PUBNONCE_BYTES} bytes`, "musig2")
      }
    }
    return BlockchainWasm.getInstance().musig2NonceAgg(pubNonces)
  }

  // ═══════════════════════════════════════════════════════════════════════
  // SESSION
  // ═══════════════════════════════════════════════════════════════════════

  /** Inicializa la sesión de firma (todos los signers deben usar la misma). */
  static sessionInit(aggNonce: Uint8Array, q: Uint8Array, msg: Uint8Array): Uint8Array {
    if (aggNonce.length !== MUSIG_AGGNONCE_BYTES) {
      throw new InvalidArgumentError(`aggNonce debe ser ${MUSIG_AGGNONCE_BYTES} bytes`, "musig2")
    }
    if (q.length !== XONLY_BYTES) {
      throw new InvalidArgumentError("q debe ser 32 bytes (x-only)", "musig2")
    }
    if (msg.length === 0 || msg.length > HALF_ZONE - 104) {
      throw new InvalidArgumentError(`msg debe ser 1..${HALF_ZONE - 104} bytes`, "musig2")
    }
    return BlockchainWasm.getInstance().musig2SessionInit(aggNonce, q, msg)
  }

  // ═══════════════════════════════════════════════════════════════════════
  // PARTIAL SIGN / VERIFY
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Genera la firma parcial de un signer.
   * @param session   Sesión (97 B) de sessionInit.
   * @param gacc      Flag de signo (0 o 1) de keyAgg.
   * @param secNonce  Secret nonce del signer (97 B).
   * @param priv      Privkey del signer (32 B).
   * @param coeff     Coeficiente de agregación (32 B, limbs LE del WASM).
   */
  static partialSign(
    session: Uint8Array,
    gacc: number,
    secNonce: Uint8Array,
    priv: Uint8Array,
    coeff: Uint8Array
  ): Uint8Array {
    if (session.length !== MUSIG_SESSION_BYTES) {
      throw new InvalidArgumentError(`session debe ser ${MUSIG_SESSION_BYTES} bytes`, "musig2")
    }
    if (secNonce.length !== MUSIG_SECNONCE_BYTES) {
      throw new InvalidArgumentError(`secNonce debe ser ${MUSIG_SECNONCE_BYTES} bytes`, "musig2")
    }
    if (priv.length !== PRIVKEY_BYTES) {
      throw new InvalidArgumentError("priv debe ser 32 bytes", "musig2")
    }
    if (!isValidPrivateKey(priv)) {
      throw new InvalidArgumentError("priv fuera de rango (0 o ≥ N)", "musig2")
    }
    if (coeff.length !== 32) {
      throw new InvalidArgumentError("coeff debe ser 32 bytes", "musig2")
    }

    // Adaptación transparente para claves x-only (BIP-340):
    // Si secNonce guardó pk con prefijo 0x02 (típico de x-only), pero priv*G tiene Y impar (0x03),
    // la clave privada BIP-340 correspondiente al punto (P.x, par) es N - priv.
    let signingPriv = priv
    const pkPrefix = secNonce[64]
    if (pkPrefix === 0x02 || pkPrefix === 0x03) {
      const pub = BlockchainWasm.getInstance().getPublicKey(priv, true)
      if (pub[0] !== pkPrefix) {
        let xMatches = true
        for (let i = 0; i < 32; i++) {
          if (pub[1 + i] !== secNonce[65 + i]) {
            xMatches = false
            break
          }
        }
        if (xMatches) {
          signingPriv = negatePrivateKey(priv)
        }
      }
    }

    return BlockchainWasm.getInstance().musig2PartialSign(session, gacc, secNonce, signingPriv, coeff)
  }

  /** Verifica una firma parcial. Retorna true si es válida. */
  static partialVerify(
    s: Uint8Array,
    session: Uint8Array,
    gacc: number,
    pubNonce: Uint8Array,
    pk: Uint8Array,
    coeff: Uint8Array
  ): boolean {
    if (s.length !== 32) throw new InvalidArgumentError("s debe ser 32 bytes", "musig2")
    if (session.length !== MUSIG_SESSION_BYTES) {
      throw new InvalidArgumentError(`session debe ser ${MUSIG_SESSION_BYTES} bytes`, "musig2")
    }
    if (pubNonce.length !== MUSIG_PUBNONCE_BYTES) {
      throw new InvalidArgumentError(`pubNonce debe ser ${MUSIG_PUBNONCE_BYTES} bytes`, "musig2")
    }
    const pk33 = toCompressedPubkey(pk, "pk")
    if (coeff.length !== 32) throw new InvalidArgumentError("coeff debe ser 32 bytes", "musig2")
    return BlockchainWasm.getInstance().musig2PartialVerify(s, session, gacc, pubNonce, pk33, coeff)
  }

  // ═══════════════════════════════════════════════════════════════════════
  // SIGNATURE AGGREGATION
  // ═══════════════════════════════════════════════════════════════════════

  /** Agrega firmas parciales (32 B c/u) → s final (32 B). */
  static partialSigAgg(partials: Uint8Array[]): Uint8Array {
    if (partials.length === 0 || partials.length > MUSIG_MAX_SIGNERS) {
      throw new InvalidArgumentError(`se requieren 1..${MUSIG_MAX_SIGNERS} firmas parciales`, "musig2")
    }
    for (let i = 0; i < partials.length; i++) {
      if (partials[i].length !== 32) {
        throw new InvalidArgumentError(`partial[${i}] debe ser 32 bytes`, "musig2")
      }
    }
    return BlockchainWasm.getInstance().musig2PartialSigAgg(partials)
  }

  // ═══════════════════════════════════════════════════════════════════════
  // CONVENIENCIA: SIGN ALL (tests / uso interno)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Pipeline completo MuSig2: privkeys → firma agregada (64 B).
   * ⚠️ Solo para tests. En producción cada signer opera independientemente.
   *
   * @param privkeys  Array de privkeys (32 B c/u).
   * @param msg       Mensaje a firmar.
   * @param secrands  Array de random seeds (32 B c/u, uno por signer).
   * @returns         { signature: Uint8Array(64), aggregatedPubkey: Uint8Array(32) }
   */
  static signAll(
    privkeys: Uint8Array[],
    msg: Uint8Array,
    secrands: Uint8Array[]
  ): { signature: Uint8Array; aggregatedPubkey: Uint8Array } {
    const count = privkeys.length
    if (count === 0 || count > MUSIG_MAX_SIGNERS) {
      throw new InvalidArgumentError(`se requieren 1..${MUSIG_MAX_SIGNERS} signers`, "musig2")
    }
    if (secrands.length !== count) {
      throw new InvalidArgumentError("secrands.length debe ser == privkeys.length", "musig2")
    }
    for (let i = 0; i < count; i++) {
      if (privkeys[i].length !== PRIVKEY_BYTES) {
        throw new InvalidArgumentError(`privkey[${i}] debe ser 32 bytes`, "musig2")
      }
      if (!isValidPrivateKey(privkeys[i])) {
        throw new InvalidArgumentError(`privkey[${i}] fuera de rango (0 o ≥ N)`, "musig2")
      }
      if (secrands[i].length !== 32) {
        throw new InvalidArgumentError(`secrand[${i}] debe ser 32 bytes`, "musig2")
      }
    }
    if (msg.length === 0 || msg.length > HALF_ZONE - count * 32) {
      throw new InvalidArgumentError("msg demasiado largo para el buffer", "musig2")
    }
    return BlockchainWasm.getInstance().musig2SignAll(privkeys, msg, secrands)
  }

  /** Firma un mensaje de texto UTF-8 con MuSig2 (conveniencia). */
  static signAllText(
    text: string,
    privkeys: Uint8Array[],
    secrands: Uint8Array[]
  ): { signature: Uint8Array; aggregatedPubkey: Uint8Array } {
    return Musig2.signAll(privkeys, toUint8Array(text), secrands)
  }

  // ═══════════════════════════════════════════════════════════════════════
  // COEFICIENTES DE AGREGACIÓN (formato interno del WASM, limbs LE)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Calcula los coeficientes a_i listos para partialSign / partialVerify.
   * a_0 = 1 y a_{2ª distinta} = 1 (limbs LE); resto = H("KeyAgg coefficient", L‖pk) mod N.
   */
  static keyAggCoeffs(pubkeys: Uint8Array[]): Uint8Array[] {
    if (pubkeys.length === 0 || pubkeys.length > MUSIG_MAX_SIGNERS) {
      throw new InvalidArgumentError(`se requieren 1..${MUSIG_MAX_SIGNERS} pubkeys`, "musig2")
    }
    const compressed = pubkeys.map((p, i) => toCompressedPubkey(p, `pubkey[${i}]`))
    const wasm = BlockchainWasm.getInstance()
    const L = wasm.musig2KeyAggListHash(compressed)
    let secondIdx = -1
    for (let i = 1; i < compressed.length; i++) {
      if (!musigBytesEq(compressed[i], compressed[0])) {
        secondIdx = i
        break
      }
    }
    const ONE = new Uint8Array(32)
    ONE[0] = 1 // limbs LE de 1 (coincide con store<u64>(one, 1) del WASM)
    const out: Uint8Array[] = []
    for (let i = 0; i < compressed.length; i++) {
      const isSecond = secondIdx !== -1 && musigBytesEq(compressed[i], compressed[secondIdx])
      out.push(isSecond ? ONE.slice() : wasm.musig2KeyAggCoeff(L, compressed[i]))
    }
    return out
  }
}
