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
import { AsmExports, getGlobalValue, WifKey, HALF_ZONE, EcdsaSignature } from "./types"
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
    const defaultImports = { env: { abort() {} } }
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
      if (heap[a.outPtr + 32 + i] !== heap[a.inPtr + 32 + i]) return false // Y levantada ≠ Y dada
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

  /** Escribe las x-only contiguas directo en el heap (sin concat/alloc intermedia). */
  schnorrAggregatePubkeys(publicKeys: Uint8Array[]): Uint8Array {
    const a = this.allocator
    const heap = a.getHeap()
    for (let i = 0; i < publicKeys.length; i++) heap.set(publicKeys[i], a.inPtr + i * 32)
    const rc = this.exp.schnorr_aggregate_pubkeys(a.outPtr, a.inPtr, publicKeys.length)
    if (rc < 0) throw new WasmError("agregación de pubkeys Schnorr falló", "schnorr", rc)
    return a.readOutput(32)
  }

  schnorrAggregatePrivkeys(privateKeys: Uint8Array[]): Uint8Array {
    const a = this.allocator
    const heap = a.getHeap()
    for (let i = 0; i < privateKeys.length; i++) heap.set(privateKeys[i], a.inPtr + i * 32)
    const rc = this.exp.schnorr_aggregate_privkeys(a.outPtr, a.inPtr, privateKeys.length)
    if (rc < 0) throw new WasmError("agregación de privkeys Schnorr falló", "schnorr", rc)
    return a.readOutput(32)
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
    return this.exp.bip32_fingerprint(a.inPtr) >>> 0
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
