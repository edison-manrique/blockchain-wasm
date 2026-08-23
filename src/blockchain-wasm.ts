/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  blockchain-wasm.ts — Singleton global + API de bajo nivel
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Clase central (singleton, como AeadWasm) que:
 *  1. Carga/instancia el WASM (load / fromUrl / fromBuffer).
 *  2. Lee PARAM_IN/OUT y crea el WasmAllocator.
 *  3. Expone la API de bajo nivel por dominio: cada método encapsula el
 *     marshalling (writeInput → call WASM → readOutput). Las clases de dominio
 *     (Secp256k1, Wif, …) son fachadas delgadas que validan y delegan aquí.
 *
 * Rendimiento: calls directas tipadas (`this.exp.fn(...)`), sin lookup por
 * string ni spread; fail‑fast de `memory` en el constructor; validación de
 * frontera en las fachadas (no aquí).
 */
import {
  AsmExports,
  getGlobalValue,
  WifKey,
  HALF_ZONE,
  EcdsaSignature,
  MUSIG_PUBNONCE_BYTES,
  MUSIG_AGGNONCE_BYTES
} from "./types"
import { WasmAllocator } from "./allocator"
import { WasmError, NotInitializedError, MissingExportError } from "./errors"
import { EntropySource } from "./csprng"

const _enc = new TextEncoder()
const _dec = new TextDecoder()

export class BlockchainWasm {
  private exp: AsmExports
  private allocator: WasmAllocator
  private rng: EntropySource | null = null
  private static instance: BlockchainWasm | null = null

  private constructor(exp: AsmExports) {
    if (!(exp.memory instanceof WebAssembly.Memory)) throw new MissingExportError("memory")
    this.exp = exp
    const inPtr = getGlobalValue(exp.PARAM_IN_PTR, 0)
    const inSize = getGlobalValue(exp.PARAM_IN_SIZE, 4096)
    const outPtr = getGlobalValue(exp.PARAM_OUT_PTR, 4096)
    const outSize = getGlobalValue(exp.PARAM_OUT_SIZE, 4096)
    this.allocator = new WasmAllocator(exp.memory, inPtr, inSize, outPtr, outSize)
  }

  /** Singleton global. Lanza si aún no se ha cargado el WASM. */
  static getInstance(): BlockchainWasm {
    if (!BlockchainWasm.instance) throw new NotInitializedError()
    return BlockchainWasm.instance
  }

  getAllocator(): WasmAllocator {
    return this.allocator
  }
  getExports(): AsmExports {
    return this.exp
  }
  /** Fuente de entropía host (lazy). La usan Schnorr (aux_rand) y Bip39 (generate). */
  getRng(): EntropySource {
    if (!this.rng) this.rng = new EntropySource(this.exp.memory)
    return this.rng
  }

  // ── Carga del módulo ────────────────────────────────────────────────────

  static getDefaultWasmUrl(): string {
    const baseUrl = "./blockchain.wasm"
    try {
      return new URL(baseUrl, import.meta.url).href
    } catch {
      return baseUrl
    }
  }

  private static buildImports(imports: WebAssembly.Imports): WebAssembly.Imports {
    const defaultImports = {
      env: {
        abort(msg: number, file: number, line: number, col: number): never {
          throw new WasmError(`trap at ${file}:${line}:${col}`, "runtime", "TRAP")
        }
      }
    }
    return {
      ...defaultImports,
      ...imports,
      env: { ...defaultImports.env, ...((imports.env as Record<string, unknown>) || {}) }
    }
  }

  static async load(url?: string, imports: WebAssembly.Imports = {}): Promise<BlockchainWasm> {
    if (BlockchainWasm.instance) return BlockchainWasm.instance
    return BlockchainWasm.fromUrl(url || BlockchainWasm.getDefaultWasmUrl(), imports)
  }

  static async fromUrl(url: string, imports: WebAssembly.Imports = {}): Promise<BlockchainWasm> {
    const finalImports = BlockchainWasm.buildImports(imports)
    let instance: WebAssembly.Instance
    if (typeof WebAssembly.instantiateStreaming === "function") {
      instance = (await WebAssembly.instantiateStreaming(await fetch(url), finalImports)).instance
    } else {
      const buffer = await (await fetch(url)).arrayBuffer()
      instance = (await WebAssembly.instantiate(buffer, finalImports)).instance
    }
    BlockchainWasm.instance = new BlockchainWasm(instance.exports as unknown as AsmExports)
    return BlockchainWasm.instance
  }

  static async fromBuffer(
    buffer: ArrayBuffer | Uint8Array,
    imports: WebAssembly.Imports = {}
  ): Promise<BlockchainWasm> {
    const finalImports = BlockchainWasm.buildImports(imports)
    const buf = (
      buffer instanceof Uint8Array
        ? buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
        : buffer
    ) as ArrayBuffer
    const { instance } = await WebAssembly.instantiate(buf, finalImports)
    BlockchainWasm.instance = new BlockchainWasm(instance.exports as unknown as AsmExports)
    return BlockchainWasm.instance
  }

  // ── Secp256k1 (bajo nivel) ──────────────────────────────────────────────

  getPublicKey(privateKey: Uint8Array, compressed: boolean): Uint8Array {
    const a = this.allocator
    a.writeInput(privateKey, 0)
    if (compressed) {
      this.exp.pubkeyFromPrivkey(a.outPtr, a.inPtr)
      return a.readOutput(33)
    }
    this.exp.pubkeyUncompressedFromPrivkey(a.outPtr, a.inPtr)
    return a.readOutput(65)
  }

  compress(publicKey: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(publicKey, 0)
    const rc = this.exp.compressRaw(a.outPtr, a.inPtr, publicKey.length)
    if (rc < 0) throw new WasmError("publicKey inválida (prefijo)", "secp256k1", rc)
    return a.readOutput(33)
  }

  uncompress(publicKey: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(publicKey, 0)
    const rc = this.exp.uncompressRaw(a.outPtr, a.inPtr)
    if (rc < 0) throw new WasmError("publicKey inválida (prefijo o X fuera de curva)", "secp256k1", rc)
    return a.readOutput(65)
  }

  /** Valida formato + pertenencia a la curva (sin lanzar). */
  isValidPoint(publicKey: Uint8Array): boolean {
    const len = publicKey.length
    if (len !== 33 && len !== 65) return false
    const a = this.allocator
    const heap = a.getHeap()
    a.writeInput(publicKey, 0)

    if (len === 33) {
      return this.exp.uncompressRaw(a.outPtr, a.inPtr) >= 0
    }

    // uncompressed: prefijo 0x04 + (X,Y) en la curva
    if (heap[a.inPtr] !== 0x04) return false
    const aux = a.inPtr + HALF_ZONE
    heap[aux] = (heap[a.inPtr + 64] & 1) === 1 ? 0x03 : 0x02
    heap.copyWithin(aux + 1, a.inPtr + 1, a.inPtr + 33) // X → aux
    if (this.exp.uncompressRaw(a.outPtr, aux) < 0) return false
    for (let i = 0; i < 32; i++) {
      if (heap[a.outPtr + 33 + i] !== heap[a.inPtr + 33 + i]) return false // Y levantada ≠ Y dada
    }
    return true
  }

  // ── WIF (bajo nivel) ────────────────────────────────────────────────────

  wifEncode(privateKey: Uint8Array, compressed: boolean): string {
    const a = this.allocator
    a.writeInput(privateKey, 0)
    const len = this.exp.wif_encode_raw(a.outPtr, a.inPtr, compressed ? 1 : 0)
    this.exp.base58_indices_to_ascii(a.outPtr, len)
    return _dec.decode(a.readOutput(len))
  }

  wifDecode(wif: string): WifKey {
    const a = this.allocator
    const bytes = _enc.encode(wif)
    a.writeInput(bytes, 0)
    const rc = this.exp.base58_ascii_to_indices(a.inPtr, bytes.length)
    if (rc < 0) throw new WasmError("WIF inválido (carácter fuera de Base58)", "wif", rc)
    const flags = this.exp.wif_decode_raw(a.outPtr, a.inPtr, bytes.length)
    if (flags < 0) throw new WasmError("WIF inválido (checksum, prefijo o longitud)", "wif", flags)
    return { privateKey: a.readOutput(32), compressed: flags === 2 }
  }

  // ── Address (bajo nivel) ────────────────────────────────────────────────

  btcP2pkh(publicKey: Uint8Array): string {
    const a = this.allocator
    a.writeInput(publicKey, 0)
    const len = this.exp.btc_p2pkh(a.outPtr, a.inPtr, publicKey.length)
    if (len < 0) throw new WasmError("publicKey inválida para P2PKH", "address", len)
    return _dec.decode(a.readOutput(len))
  }

  btcP2shP2wpkh(publicKey: Uint8Array): string {
    const a = this.allocator
    a.writeInput(publicKey, 0)
    const len = this.exp.btc_p2sh_p2wpkh(a.outPtr, a.inPtr, publicKey.length)
    if (len < 0) throw new WasmError("publicKey inválida para P2SH-P2WPKH", "address", len)
    return _dec.decode(a.readOutput(len))
  }

  btcP2wpkh(publicKey: Uint8Array): string {
    const a = this.allocator
    a.writeInput(publicKey, 0)
    const len = this.exp.btc_p2wpkh(a.outPtr, a.inPtr, publicKey.length)
    if (len < 0) throw new WasmError("publicKey inválida para P2WPKH", "address", len)
    return _dec.decode(a.readOutput(len))
  }

  btcP2tr(publicKey: Uint8Array): string {
    const a = this.allocator
    a.writeInput(publicKey, 0)
    const len = this.exp.btc_p2tr(a.outPtr, a.inPtr, publicKey.length)
    if (len < 0) throw new WasmError("publicKey inválida para P2TR", "address", len)
    return _dec.decode(a.readOutput(len))
  }

  ethAddress(publicKey: Uint8Array): string {
    const a = this.allocator
    a.writeInput(publicKey, 0)
    const len = this.exp.eth_address(a.outPtr, a.inPtr, publicKey.length)
    if (len < 0) throw new WasmError("publicKey inválida para ETH", "address", len)
    return _dec.decode(a.readOutput(len))
  }

  btcP2pkhUncompressed(publicKey: Uint8Array): string {
    const a = this.allocator
    a.writeInput(publicKey, 0)
    const len = this.exp.btc_p2pkh_uncompressed(a.outPtr, a.inPtr, publicKey.length)
    if (len < 0)
      throw new WasmError("publicKey inválida para P2PKH uncompressed (debe ser 65 B con 0x04)", "address", len)
    return _dec.decode(a.readOutput(len))
  }

  tronAddress(publicKey: Uint8Array): string {
    const a = this.allocator
    a.writeInput(publicKey, 0)
    const len = this.exp.tron_address(a.outPtr, a.inPtr, publicKey.length)
    if (len < 0) throw new WasmError("publicKey inválida para Tron", "address", len)
    return _dec.decode(a.readOutput(len))
  }

  // ── PBKDF2 (bajo nivel) ─────────────────────────────────────────────────

  pbkdf2Sha512(password: Uint8Array, salt: Uint8Array, iterations: number, dkLen: number): Uint8Array {
    const a = this.allocator
    a.writeInput(password, 0)
    a.writeInput(salt, HALF_ZONE)
    this.exp.sha512_pbkdf2_raw(a.outPtr, a.inPtr, password.length, a.inPtr + HALF_ZONE, salt.length, iterations, dkLen)
    return a.readOutput(dkLen)
  }

  // ── ECDH (bajo nivel) ───────────────────────────────────────────────────
  ecdhSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(privateKey, 0)
    a.writeInput(publicKey, HALF_ZONE)
    const rc = this.exp.ecdh_shared_secret(a.outPtr, a.inPtr, a.inPtr + HALF_ZONE, publicKey.length)
    if (rc < 0) throw new WasmError("ECDH inválido (priv/pub malformada o punto al infinito)", "ecdh", rc)
    return a.readOutput(33)
  }

  // ── Schnorr BIP-340 (bajo nivel) ────────────────────────────────────────
  schnorrGetPubkey(privateKey: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(privateKey, 0)
    this.exp.schnorr_get_pubkey(a.outPtr, a.inPtr)
    return a.readOutput(32)
  }

  /** sign: msg@0 | priv@HALF_ZONE | aux@HALF_ZONE+32. Si !aux → entropía host vía getRng(). */
  schnorrSign(message: Uint8Array, privateKey: Uint8Array, auxRand?: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(message, 0)
    a.writeInput(privateKey, HALF_ZONE)
    const auxPtr = a.inPtr + HALF_ZONE + 32
    if (auxRand) a.writeInput(auxRand, HALF_ZONE + 32)
    else this.getRng().auxRandInto(auxPtr) // zero-copia sobre la memoria del WASM
    const rc = this.exp.schnorr_sign(a.outPtr, a.inPtr, message.length, a.inPtr + HALF_ZONE, auxPtr)
    if (rc < 0) throw new WasmError("firma Schnorr falló (nonce k=0 u otro)", "schnorr", rc)
    return a.readOutput(64)
  }

  /** verify: sig@0 | pub@64 | msg@HALF_ZONE. */
  schnorrVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
    const a = this.allocator
    a.writeInput(signature, 0)
    a.writeInput(publicKey, 64)
    a.writeInput(message, HALF_ZONE)
    return (
      this.exp.schnorr_verify(
        a.inPtr,
        signature.length,
        a.inPtr + HALF_ZONE,
        message.length,
        a.inPtr + 64,
        publicKey.length
      ) !== 0
    )
  }

  // ── MuSig2 BIP-326 (bajo nivel) ─────────────────────────────────────────

  // ── MuSig2 BIP-326 (bajo nivel) — ✅ FIX v3.0 ───────────────────────────

  /** L = H("KeyAgg list", pk1‖…‖pkn) → 32 B. pubkeys deben ser 33 B compressed. */
  musig2KeyAggListHash(pubkeys: Uint8Array[]): Uint8Array {
    const a = this.allocator
    let off = 0
    for (let i = 0; i < pubkeys.length; i++) {
      a.writeInput(pubkeys[i], off)
      off += 33 // ✅ 33 B compressed
    }
    const rc = this.exp.musig2_keyagg_list_hash(a.outPtr, a.inPtr, pubkeys.length)
    if (rc < 0) throw new WasmError("KeyAggListHash falló", "musig2", rc)
    return a.readOutput(32)
  }

  /** Coeficiente a_i en formato interno (limbs LE). Pasarlo TAL CUAL a partialSign/Verify. */
  musig2KeyAggCoeff(L: Uint8Array, pk: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(L, 0)
    a.writeInput(pk, 32)
    const rc = this.exp.musig2_keyagg_coeff(a.outPtr, a.inPtr, a.inPtr + 32)
    if (rc < 0) throw new WasmError("KeyAggCoeff falló", "musig2", rc)
    return a.readOutput(32)
  }

  /** KeyAgg: pubs@IN+0 (33 B each, compressed) → { q, gacc }. gacc = Q.y parity (0=even, 1=odd). */
  musig2KeyAgg(pubkeys: Uint8Array[]): { q: Uint8Array; gacc: number } {
    const a = this.allocator
    let off = 0
    for (let i = 0; i < pubkeys.length; i++) {
      a.writeInput(pubkeys[i], off)
      off += 33 // ✅ 33 B compressed (matching keyagg.ts which uses cpointToPoint)
    }
    const rc = this.exp.musig2_keyagg(a.outPtr, a.outPtr + 32, a.inPtr, pubkeys.length)
    if (rc < 0) throw new WasmError("KeyAgg falló", "musig2", rc)
    return { q: a.readOutput(32, 0), gacc: a.getHeap()[a.outPtr + 32] }
  }

  /**
   * NonceGen: secrand@0 | sk@32 | pk@64 | aggother@128 | msg@192.
   * ✅ v3.1: secNonce = 97 B (k1‖k2‖pk), pubNonce = 66 B (compressed).
   * Layout: OUT[0..96]=secNonce, OUT[97..162]=pubNonce.
   */
  musig2NonceGen(
    secrand: Uint8Array,
    pk: Uint8Array,
    sk?: Uint8Array,
    aggotherpk?: Uint8Array,
    msg?: Uint8Array
  ): { secNonce: Uint8Array; pubNonce: Uint8Array } {
    const a = this.allocator
    a.writeInput(secrand, 0)
    const skPtr = sk ? a.writeInput(sk, 32) : 0
    a.writeInput(pk, 64)  // pk33 always present
    const aggPtr = aggotherpk ? a.writeInput(aggotherpk, 128) : 0
    let msgPtr = 0
    let msgLen = 0
    if (msg && msg.length > 0) {
      msgPtr = a.writeInput(msg, 192)
      msgLen = msg.length
    }
    // 10 args: out_k97, out_r66, secrand, skPtr, pk33, aggPtr, msgPtr, msgLen, extPtr=0, extLen=0
    const rc = this.exp.musig2_nonce_gen(
      a.outPtr,       // out_k97: secNonce (97 B)
      a.outPtr + 97,  // out_r66: pubNonce (66 B)
      a.inPtr,        // secrand32
      skPtr,          // skPtr (0 if none)
      a.inPtr + 64,   // pk33
      aggPtr,         // aggotherpkPtr (0 if none)
      msgPtr,         // msgPtr (0 if none)
      msgLen,         // msgLen
      0,              // extPtr = 0
      0               // extLen = 0
    )
    if (rc < 0) throw new WasmError("NonceGen falló", "musig2", rc)
    return {
      secNonce: a.readOutput(97, 0),   // ✅ 97 bytes
      pubNonce: a.readOutput(66, 97)   // ✅ 66 bytes at offset 97
    }
  }

  /**
   * NonceAgg: nonces@IN+0 (stride 66).
   * ✅ v3.1: stride 66, salida 66 B, máx 62 nonces (4096/66).
   */
  musig2NonceAgg(pubNonces: Uint8Array[]): Uint8Array {
    if (pubNonces.length * MUSIG_PUBNONCE_BYTES > 2 * HALF_ZONE) {
      throw new WasmError("NonceAgg: demasiados nonces para PARAM_IN (máx 62)", "musig2", -1)
    }
    const a = this.allocator
    let off = 0
    for (let i = 0; i < pubNonces.length; i++) {
      a.writeInput(pubNonces[i], off)
      off += MUSIG_PUBNONCE_BYTES // ✅ FIX: 64 → 66
    }
    const rc = this.exp.musig2_nonce_agg(a.outPtr, a.inPtr, pubNonces.length)
    if (rc < 0) throw new WasmError("NonceAgg falló", "musig2", rc)
    return a.readOutput(MUSIG_AGGNONCE_BYTES) // ✅ FIX: 64 → 66
  }

  /**
   * SessionInit: aggNonce@0 (66 B) | q@72 | msg@104 → session(97 B).
   * ✅ v3.1 FIX CRÍTICO: antes q@64 pisaba aggnonce[64..65] y msg@96 solapaba.
   */
  musig2SessionInit(aggNonce: Uint8Array, q: Uint8Array, msg: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(aggNonce, 0) // 0..65
    a.writeInput(q, 72) // ✅ 72..103 (alineado, sin solape)
    a.writeInput(msg, 104) // ✅ 104..
    const rc = this.exp.musig2_session_init(a.outPtr, a.inPtr, a.inPtr + 72, a.inPtr + 104, msg.length)
    if (rc < 0) throw new WasmError("SessionInit falló", "musig2", rc)
    return a.readOutput(97)
  }

  /**
   * PartialVerify: s@0 (32 B) | session@32 (97 B) | pubnonce@160 (66 B) | pk@232 (33 B) | coeff@272 (32 B).
   */
  musig2PartialVerify(
    s: Uint8Array,
    session: Uint8Array,
    gacc: number,
    pubNonce: Uint8Array,
    pk: Uint8Array,
    coeff: Uint8Array
  ): boolean {
    const a = this.allocator
    a.writeInput(s, 0)          // 0..31
    a.writeInput(session, 32)   // 32..128 (97 B)
    a.writeInput(pubNonce, 160) // 160..225 (66 B)
    a.writeInput(pk, 232)       // 232..264 (33 B)
    a.writeInput(coeff, 272)    // 272..303 (32 B)
    return (
      this.exp.musig2_partial_verify(a.inPtr, a.inPtr + 32, gacc, a.inPtr + 160, a.inPtr + 232, a.inPtr + 272) !== 0
    )
  }

  /** PartialSign: session@0 (97 B) | secnonce@128 (97 B) | priv@232 (32 B) | coeff@264 (32 B) → s(32 B). */
  musig2PartialSign(
    session: Uint8Array,
    gacc: number,
    secNonce: Uint8Array,
    priv: Uint8Array,
    coeff: Uint8Array
  ): Uint8Array {
    const a = this.allocator
    a.writeInput(session, 0)     // 0..96
    a.writeInput(secNonce, 128)  // 128..224 (97 B)
    a.writeInput(priv, 232)      // 232..263 (32 B)
    a.writeInput(coeff, 264)     // 264..295 (32 B)
    const rc = this.exp.musig2_partial_sign(a.outPtr, a.inPtr, gacc, a.inPtr + 128, a.inPtr + 232, a.inPtr + 264)
    if (rc < 0) throw new WasmError("PartialSign falló", "musig2", rc)
    return a.readOutput(32)
  }

  /** PartialSigAgg: partials@IN+0 (count × 32) → s(32 B). */
  musig2PartialSigAgg(partials: Uint8Array[]): Uint8Array {
    const a = this.allocator
    let off = 0
    for (let i = 0; i < partials.length; i++) {
      a.writeInput(partials[i], off)
      off += 32
    }
    const rc = this.exp.musig2_partial_sig_agg(a.outPtr, a.inPtr, partials.length)
    if (rc < 0) throw new WasmError("PartialSigAgg falló", "musig2", rc)
    return a.readOutput(32)
  }

  /**
   * SignAll (tests): privs@IN+0 | msg@IN+count*32 | secrands@IN+HALF_ZONE.
   * Layout exige count*32 + msgLen ≤ HALF_ZONE y count*32 ≤ HALF_ZONE (≤ 64 signers).
   */
  musig2SignAll(
    privkeys: Uint8Array[],
    msg: Uint8Array,
    secrands: Uint8Array[]
  ): { signature: Uint8Array; aggregatedPubkey: Uint8Array } {
    const count = privkeys.length
    if (count * 32 + msg.length > HALF_ZONE || count * 32 > HALF_ZONE) {
      throw new WasmError("SignAll: demasiados signers/msg para PARAM_IN (máx ~64)", "musig2", -1)
    }
    const a = this.allocator
    let off = 0
    for (let i = 0; i < count; i++) {
      a.writeInput(privkeys[i], off)
      off += 32
    }
    a.writeInput(msg, off)
    let rOff = 0
    for (let i = 0; i < count; i++) {
      a.writeInput(secrands[i], HALF_ZONE + rOff)
      rOff += 32
    }
    const rc = this.exp.musig2_sign_all(
      a.outPtr,
      a.outPtr + 64,
      a.inPtr,
      count,
      a.inPtr + off,
      msg.length,
      a.inPtr + HALF_ZONE
    )
    if (rc < 0) throw new WasmError("SignAll falló", "musig2", rc)
    return { signature: a.readOutput(64, 0), aggregatedPubkey: a.readOutput(32, 64) }
  }

  // ── ECDSA (bajo nivel) ──────────────────────────────────────────────────
  /** sign: hash@0 | priv@32 → out65 = r‖s‖v. */
  ecdsaSign(hash: Uint8Array, privateKey: Uint8Array): EcdsaSignature {
    const a = this.allocator
    a.writeInput(hash, 0)
    a.writeInput(privateKey, 32)
    const rc = this.exp.ecdsa_sign(a.outPtr, a.inPtr, a.inPtr + 32)
    if (rc < 0) throw new WasmError("firma ECDSA falló (r=0 o s=0)", "ecdsa", rc)
    const heap = a.getHeap()
    return {
      r: heap.slice(a.outPtr, a.outPtr + 32),
      s: heap.slice(a.outPtr + 32, a.outPtr + 64),
      v: heap[a.outPtr + 64]
    }
  }

  /** verify: sig@0 | pub@64 | hash@HALF_ZONE. */
  ecdsaVerify(hash: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    const a = this.allocator
    a.writeInput(signature, 0)
    a.writeInput(publicKey, 64)
    a.writeInput(hash, HALF_ZONE)
    return this.exp.ecdsa_verify(a.inPtr + HALF_ZONE, a.inPtr, a.inPtr + 64, publicKey.length) !== 0
  }

  ecdsaMessageHash(message: Uint8Array, format: number): Uint8Array {
    const a = this.allocator
    a.writeInput(message, 0)
    const rc = this.exp.ecdsa_message_hash(a.outPtr, a.inPtr, message.length, format)
    if (rc < 0) throw new WasmError("messageHash ECDSA falló", "ecdsa", rc)
    return a.readOutput(32)
  }

  /** signMessage: msg@0 | priv@HALF_ZONE → out65 = r‖s‖v. */
  ecdsaSignMessage(message: Uint8Array, privateKey: Uint8Array, format: number): EcdsaSignature {
    const a = this.allocator
    a.writeInput(message, 0)
    a.writeInput(privateKey, HALF_ZONE)
    const rc = this.exp.ecdsa_sign_message(a.outPtr, a.inPtr, message.length, a.inPtr + HALF_ZONE, format)
    if (rc < 0) throw new WasmError("signMessage ECDSA falló", "ecdsa", rc)
    const heap = a.getHeap()
    return {
      r: heap.slice(a.outPtr, a.outPtr + 32),
      s: heap.slice(a.outPtr + 32, a.outPtr + 64),
      v: heap[a.outPtr + 64]
    }
  }

  /** verifyMessage: sig@0 | pub@64 | msg@HALF_ZONE. */
  ecdsaVerifyMessage(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array, format: number): boolean {
    const a = this.allocator
    a.writeInput(signature, 0)
    a.writeInput(publicKey, 64)
    a.writeInput(message, HALF_ZONE)
    return (
      this.exp.ecdsa_verify_message(
        a.inPtr + HALF_ZONE,
        message.length,
        a.inPtr,
        a.inPtr + 64,
        publicKey.length,
        format
      ) !== 0
    )
  }

  // ── BIP39 (bajo nivel) ──────────────────────────────────────────────────
  /** generate: entropía del host (getRng) → mnemónico. strength en bits. */
  bip39Generate(strength: number): string {
    const a = this.allocator
    const entBytes = strength >> 3
    this.getRng().entropyInto(a.inPtr, entBytes) // zero-copia sobre la memoria del WASM
    const rc = this.exp.bip39_entropy_to_mnemonic(a.outPtr, a.inPtr, entBytes)
    if (rc < 0) throw new WasmError("generación BIP39 falló", "bip39", rc)
    return _dec.decode(a.readOutput(rc))
  }

  bip39EntropyToMnemonic(entropy: Uint8Array): string {
    const a = this.allocator
    a.writeInput(entropy, 0)
    const rc = this.exp.bip39_entropy_to_mnemonic(a.outPtr, a.inPtr, entropy.length)
    if (rc < 0) throw new WasmError("entropy inválida para BIP39", "bip39", rc)
    return _dec.decode(a.readOutput(rc))
  }

  bip39MnemonicToEntropy(mnemonic: string): Uint8Array {
    const a = this.allocator
    const mnBytes = _enc.encode(mnemonic)
    a.writeInput(mnBytes, 0)
    const rc = this.exp.bip39_mnemonic_to_entropy(a.outPtr, a.inPtr, mnBytes.length)
    if (rc < 0) throw new WasmError("mnemónico BIP39 inválido", "bip39", rc)
    return a.readOutput(rc)
  }

  /** mnemonic@0 | passphrase@HALF_ZONE → seed (64 B). */
  bip39MnemonicToSeed(mnemonic: string, passphrase: string): Uint8Array {
    const a = this.allocator
    const mnBytes = _enc.encode(mnemonic)
    a.writeInput(mnBytes, 0)
    const passBytes = _enc.encode(passphrase)
    a.writeInput(passBytes, HALF_ZONE)
    this.exp.bip39_mnemonic_to_seed(a.outPtr, a.inPtr, mnBytes.length, a.inPtr + HALF_ZONE, passBytes.length)
    return a.readOutput(64)
  }

  bip39Validate(mnemonic: string): boolean {
    const a = this.allocator
    const mnBytes = _enc.encode(mnemonic)
    a.writeInput(mnBytes, 0)
    return this.exp.bip39_validate_mnemonic(a.inPtr, mnBytes.length) !== 0
  }

  // ── BIP32 (bajo nivel) — retornan el xkey crudo (88 B) ─────────────────
  bip32FromSeed(seed: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(seed, 0)
    const rc = this.exp.bip32_from_seed(a.outPtr, a.inPtr, seed.length)
    if (rc < 0) throw new WasmError("BIP32 fromSeed falló", "bip32", rc)
    return a.readOutput(88)
  }
  bip32Derive(parentRaw: Uint8Array, index: number): Uint8Array {
    const a = this.allocator
    a.writeInput(parentRaw, 0)
    const rc = this.exp.bip32_derive(a.outPtr, a.inPtr, index)
    if (rc < 0) throw new WasmError("BIP32 derive falló", "bip32", rc)
    return a.readOutput(88)
  }
  /** parentRaw@0 | path@88. */
  /** parentRaw@0 | path@88. */
  bip32DerivePath(parentRaw: Uint8Array, path: string): Uint8Array {
    const a = this.allocator
    a.writeInput(parentRaw, 0)
    const pathBytes = _enc.encode(path)
    a.writeInput(pathBytes, 88)
    // ✅ 4 args: child, parent, pathPtr, pathLen
    const rc = this.exp.bip32_derive_path(a.outPtr, a.inPtr, a.inPtr + 88, pathBytes.length)
    if (rc < 0) throw new WasmError("BIP32 derivePath falló", "bip32", rc)
    return a.readOutput(88)
  }
  bip32DeriveAccount(parentRaw: Uint8Array, purpose: number, coinType: number, account: number): Uint8Array {
    const a = this.allocator
    a.writeInput(parentRaw, 0)
    const rc = this.exp.bip32_derive_account(a.outPtr, a.inPtr, purpose, coinType, account)
    if (rc < 0) throw new WasmError("BIP32 deriveAccount falló", "bip32", rc)
    return a.readOutput(88)
  }
  bip32SerializeXpub(raw: Uint8Array): string {
    const a = this.allocator
    a.writeInput(raw, 0)
    const rc = this.exp.bip32_serialize_xpub(a.outPtr, a.inPtr)
    if (rc < 0) throw new WasmError("BIP32 serializeXpub falló", "bip32", rc)
    return _dec.decode(a.readOutput(rc))
  }
  bip32SerializeXprv(raw: Uint8Array): string {
    const a = this.allocator
    a.writeInput(raw, 0)
    const rc = this.exp.bip32_serialize_xprv(a.outPtr, a.inPtr)
    if (rc < 0) throw new WasmError("BIP32 serializeXprv falló", "bip32", rc)
    return _dec.decode(a.readOutput(rc))
  }
  bip32Deserialize(str: string): Uint8Array {
    const a = this.allocator
    const strBytes = _enc.encode(str)
    a.writeInput(strBytes, 0)
    const rc = this.exp.bip32_deserialize(a.outPtr, a.inPtr, strBytes.length)
    if (rc < 0) throw new WasmError("BIP32 deserialize falló (xpub/xprv inválido)", "bip32", rc)
    return a.readOutput(88)
  }
  bip32Neuter(raw: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(raw, 0)
    const rc = this.exp.bip32_neuter(a.outPtr, a.inPtr)
    if (rc < 0) throw new WasmError("BIP32 neuter falló", "bip32", rc)
    return a.readOutput(88)
  }
  bip32GetPubkey(raw: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(raw, 0)
    this.exp.bip32_get_pubkey(a.outPtr, a.inPtr)
    return a.readOutput(33)
  }
  // ── Accessors del xkey (el WASM conoce el layout; el wrapper NO) ────────
  private _xkeyWrite(raw: Uint8Array): number {
    const a = this.allocator
    a.writeInput(raw, 0)
    return a.inPtr
  }
  bip32XkeyDepth(raw: Uint8Array): number {
    return this.exp.bip32_xkey_depth(this._xkeyWrite(raw))
  }
  bip32XkeyParentFp(raw: Uint8Array): number {
    return this.exp.bip32_xkey_parent_fp(this._xkeyWrite(raw)) >>> 0
  }
  bip32XkeyChildIndex(raw: Uint8Array): number {
    return this.exp.bip32_xkey_child_index(this._xkeyWrite(raw)) >>> 0
  }
  bip32XkeyIsPrivate(raw: Uint8Array): boolean {
    return this.exp.bip32_xkey_is_private(this._xkeyWrite(raw)) !== 0
  }
  bip32XkeyChainCode(raw: Uint8Array): Uint8Array {
    const a = this.allocator
    a.writeInput(raw, 0)
    const ptr = this.exp.bip32_xkey_chaincode_ptr(a.inPtr)
    return a.readBytes(ptr, 32)
  }
  /** keyData crudo: 32 B si es priv, 33 B si es pub (lo decide el caller). */
  bip32XkeyKeyData(raw: Uint8Array, len: number): Uint8Array {
    const a = this.allocator
    a.writeInput(raw, 0)
    const ptr = this.exp.bip32_xkey_keydata_ptr(a.inPtr)
    return a.readBytes(ptr, len)
  }
  /** Fingerprint (u32). Rellena el cache de pubkey con get_pubkey antes. */
  bip32Fingerprint(raw: Uint8Array): number {
    const a = this.allocator
    a.writeInput(raw, 0)
    this.exp.bip32_get_pubkey(a.outPtr, a.inPtr) // rellena cache interno
    return this.exp.bip32_fingerprint(a.outPtr) >>> 0 // <-- CAMBIO: a.outPtr
  }

  // ── BIP44 (bajo nivel) ──────────────────────────────────────────────────
  bip44DerivePrivkey(
    seed: Uint8Array,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number
  ): Uint8Array {
    const a = this.allocator
    a.writeInput(seed, 0)
    const rc = this.exp.bip44_derive_privkey(
      a.outPtr,
      a.inPtr,
      seed.length,
      purpose,
      coinType,
      account,
      change,
      addressIndex
    )
    if (rc < 0) throw new WasmError("BIP44 derivePrivkey falló", "bip44", rc)
    return a.readOutput(32)
  }
  bip44DerivePubkey(
    seed: Uint8Array,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number
  ): Uint8Array {
    const a = this.allocator
    a.writeInput(seed, 0)
    const rc = this.exp.bip44_derive_pubkey(
      a.outPtr,
      a.inPtr,
      seed.length,
      purpose,
      coinType,
      account,
      change,
      addressIndex
    )
    if (rc < 0) throw new WasmError("BIP44 derivePubkey falló", "bip44", rc)
    return a.readOutput(33)
  }
  /** priv@outPtr | pub@outPtr+32. */
  bip44DeriveLeaf(
    seed: Uint8Array,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number
  ): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const a = this.allocator
    a.writeInput(seed, 0)
    const rc = this.exp.bip44_derive_leaf(
      a.outPtr,
      a.outPtr + 32,
      a.inPtr,
      seed.length,
      purpose,
      coinType,
      account,
      change,
      addressIndex
    )
    if (rc < 0) throw new WasmError("BIP44 deriveLeaf falló", "bip44", rc)
    return { privateKey: a.readOutput(32, 0), publicKey: a.readOutput(33, 32) }
  }
  bip44AccountXpub(seed: Uint8Array, purpose: number, coinType: number, account: number): string {
    const a = this.allocator
    a.writeInput(seed, 0)
    const rc = this.exp.bip44_account_xpub(a.outPtr, a.inPtr, seed.length, purpose, coinType, account)
    if (rc < 0) throw new WasmError("BIP44 accountXpub falló", "bip44", rc)
    return _dec.decode(a.readOutput(rc))
  }
  bip44AccountXprv(seed: Uint8Array, purpose: number, coinType: number, account: number): string {
    const a = this.allocator
    a.writeInput(seed, 0)
    const rc = this.exp.bip44_account_xprv(a.outPtr, a.inPtr, seed.length, purpose, coinType, account)
    if (rc < 0) throw new WasmError("BIP44 accountXprv falló", "bip44", rc)
    return _dec.decode(a.readOutput(rc))
  }
  /** mnemonic@0 | passphrase@HALF_ZONE; priv@outPtr | pub@outPtr+32. */
  bip44FromMnemonicDerive(
    mnemonic: string,
    passphrase: string,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number
  ): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const a = this.allocator
    const mnBytes = _enc.encode(mnemonic)
    a.writeInput(mnBytes, 0)
    const passBytes = _enc.encode(passphrase)
    a.writeInput(passBytes, HALF_ZONE)
    const rc = this.exp.bip44_from_mnemonic_derive(
      a.outPtr,
      a.outPtr + 32,
      a.inPtr,
      mnBytes.length,
      a.inPtr + HALF_ZONE,
      passBytes.length,
      purpose,
      coinType,
      account,
      change,
      addressIndex
    )
    if (rc < 0) throw new WasmError("BIP44 fromMnemonicDerive falló", "bip44", rc)
    return { privateKey: a.readOutput(32, 0), publicKey: a.readOutput(33, 32) }
  }
  bip44FromMnemonicXpub(
    mnemonic: string,
    passphrase: string,
    purpose: number,
    coinType: number,
    account: number
  ): string {
    const a = this.allocator
    const mnBytes = _enc.encode(mnemonic)
    a.writeInput(mnBytes, 0)
    const passBytes = _enc.encode(passphrase)
    a.writeInput(passBytes, HALF_ZONE)
    const rc = this.exp.bip44_from_mnemonic_xpub(
      a.outPtr,
      a.inPtr,
      mnBytes.length,
      a.inPtr + HALF_ZONE,
      passBytes.length,
      purpose,
      coinType,
      account
    )
    if (rc < 0) throw new WasmError("BIP44 fromMnemonicXpub falló", "bip44", rc)
    return _dec.decode(a.readOutput(rc))
  }
  bip44FromMnemonicXprv(
    mnemonic: string,
    passphrase: string,
    purpose: number,
    coinType: number,
    account: number
  ): string {
    const a = this.allocator
    const mnBytes = _enc.encode(mnemonic)
    a.writeInput(mnBytes, 0)
    const passBytes = _enc.encode(passphrase)
    a.writeInput(passBytes, HALF_ZONE)
    const rc = this.exp.bip44_from_mnemonic_xprv(
      a.outPtr,
      a.inPtr,
      mnBytes.length,
      a.inPtr + HALF_ZONE,
      passBytes.length,
      purpose,
      coinType,
      account
    )
    if (rc < 0) throw new WasmError("BIP44 fromMnemonicXprv falló", "bip44", rc)
    return _dec.decode(a.readOutput(rc))
  }
}
