/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  types.ts — Contrato WASM (AsmExports) + tipos de dominio + utilidades puras
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Módulo fundacional del wrapper (sin dependencias internas). En la frontera
 * WASM↔JS, punteros (usize) y bool viajan como `number`; los retornos bool del
 * WASM se tipan `number` (0/1) y el wrapper convierte con `!== 0`.
 *
 * El contrato lista TODOS los dominios para no modificar este archivo en cada
 * entrega; las firmas marcadas ⚠ se validan con tests al usarlas.
 */

// ── Contrato de exports del módulo WASM ───────────────────────────────────
export interface AsmExports {
  memory: WebAssembly.Memory

  // Globals de I/O (Global | number)
  PARAM_IN_PTR?: WebAssembly.Global | number
  PARAM_IN_SIZE?: WebAssembly.Global | number
  PARAM_OUT_PTR?: WebAssembly.Global | number
  PARAM_OUT_SIZE?: WebAssembly.Global | number

  // ── secp256k1 ──
  pubkeyFromPrivkey: (out33: number, privPtr32: number) => void
  pubkeyUncompressedFromPrivkey: (out65: number, privPtr32: number) => void
  compressRaw: (out33: number, pubPtr: number, pubLen: number) => number
  uncompressRaw: (out65: number, pub33Ptr: number) => number

  // ── wif ──
  wif_encode_raw: (outIdxPtr: number, privPtr: number, compressed: number) => number
  wif_decode_raw: (outPrivPtr: number, srcIdxPtr: number, srcLen: number) => number
  base58_indices_to_ascii: (idxPtr: number, len: number) => void
  base58_ascii_to_indices: (srcPtr: number, len: number) => number

  // ── address ──
  btc_p2pkh: (outPtr: number, pubPtr: number, pubLen: number) => number
  btc_p2sh_p2wpkh: (outPtr: number, pubPtr: number, pubLen: number) => number
  btc_p2wpkh: (outPtr: number, pubPtr: number, pubLen: number) => number
  btc_p2tr: (outPtr: number, pubPtr: number, pubLen: number) => number
  eth_address: (outPtr: number, pubPtr: number, pubLen: number) => number
  btc_p2pkh_uncompressed: (outPtr: number, pubPtr: number, pubLen: number) => number
  tron_address: (outPtr: number, pubPtr: number, pubLen: number) => number

  // ── ecdsa ──
  ecdsa_sign: (out65: number, hashPtr32: number, privPtr32: number) => number
  ecdsa_verify: (hashPtr32: number, sigPtr64: number, pubPtr: number, pubLen: number) => number
  ecdsa_message_hash: (out32: number, msgPtr: number, msgLen: number, format: number) => number
  ecdsa_sign_message: (out65: number, msgPtr: number, msgLen: number, privPtr32: number, format: number) => number
  ecdsa_verify_message: (
    msgPtr: number,
    msgLen: number,
    sigPtr64: number,
    pubPtr: number,
    pubLen: number,
    format: number
  ) => number

  // ── schnorr ──
  schnorr_get_pubkey: (out32: number, privPtr32: number) => number
  schnorr_sign: (out64: number, msgPtr: number, msgLen: number, privPtr32: number, auxPtr32: number) => number
  schnorr_verify: (
    sigPtr64: number,
    sigLen: number,
    msgPtr: number,
    msgLen: number,
    pubPtr32: number,
    pubLen: number
  ) => number

  musigTagHashesPtr: () => number

  // ── musig2 (BIP-327) ─────────────────────────────────────────────────────
  musig2_keyagg_list_hash: (out32: number, pubsPtr: number, count: number) => number
  musig2_keyagg_coeff: (out32: number, L32: number, pkBE33: number) => number
  musig2_keyagg: (out_q32: number, out_gacc8: number, pubsPtr: number, count: number) => number
  musig2_nonce_gen: (
    out_k97: number,
    out_r66: number,
    secrand32: number,
    skPtr: number,
    pk33: number,
    aggotherpkPtr: number,
    msgPtr: number,
    msgLen: number,
    extPtr: number,
    extLen: number
  ) => number
  musig2_nonce_agg: (out_r66: number, noncesPtr: number, count: number) => number
  musig2_session_init: (out97: number, aggNonce66: number, q32: number, msgPtr: number, msgLen: number) => number
  musig2_partial_sign: (
    out_s32: number,
    session97: number,
    gacc8: number,
    secnonce97: number,
    priv32: number,
    coeff32: number
  ) => number
  musig2_partial_verify: (
    s32: number,
    session97: number,
    gacc8: number,
    pubnonce66: number,
    pk33: number,
    coeff32: number
  ) => number
  musig2_partial_sig_agg: (out_s32: number, partialsPtr: number, count: number) => number
  musig2_sign_all: (
    out64: number,
    out_q32: number,
    privsPtr: number,
    count: number,
    msgPtr: number,
    msgLen: number,
    secrandPtr: number
  ) => number

  // ── ecdh ──
  ecdh_shared_secret: (out33: number, privPtr32: number, pubPtr: number, pubLen: number) => number

  // ── pbkdf2 ──
  sha512_pbkdf2_raw: (
    outPtr: number,
    passPtr: number,
    passLen: number,
    saltPtr: number,
    saltLen: number,
    iterations: number,
    dkLen: number
  ) => void

  // ── bip32 ──
  bip32_from_seed: (xkeyPtr: number, seedPtr: number, seedLen: number) => number
  bip32_derive: (childPtr: number, parentPtr: number, index: number) => number
  bip32_derive_path: (childPtr: number, parentPtr: number, pathPtr: number, pathLen: number) => number
  bip32_derive_account: (
    childPtr: number,
    parentPtr: number,
    purpose: number,
    coinType: number,
    account: number
  ) => number
  bip32_serialize_xpub: (outPtr: number, xkeyPtr: number) => number
  bip32_serialize_xprv: (outPtr: number, xkeyPtr: number) => number
  bip32_deserialize: (xkeyPtr: number, srcPtr: number, srcLen: number) => number
  bip32_neuter: (pubXkeyPtr: number, privXkeyPtr: number) => number
  bip32_get_pubkey: (out33: number, xkeyPtr: number) => number
  bip32_fingerprint: (pub33Ptr: number) => number
  bip32_xkey_depth: (xkeyPtr: number) => number
  bip32_xkey_parent_fp: (xkeyPtr: number) => number
  bip32_xkey_child_index: (xkeyPtr: number) => number
  bip32_xkey_is_private: (xkeyPtr: number) => number
  bip32_xkey_chaincode_ptr: (xkeyPtr: number) => number
  bip32_xkey_keydata_ptr: (xkeyPtr: number) => number

  // ── bip39 ──
  bip39_mnemonic_to_seed: (outPtr: number, mnPtr: number, mnLen: number, passPtr: number, passLen: number) => number
  bip39_validate_mnemonic: (mnPtr: number, mnLen: number) => number
  bip39_entropy_to_mnemonic: (outPtr: number, entPtr: number, entLen: number) => number
  bip39_mnemonic_to_entropy: (outPtr: number, mnPtr: number, mnLen: number) => number

  // ── bip44 (⚠ verificar firmas al usarlas) ──
  bip44_derive_privkey: (
    out32: number,
    seedPtr: number,
    seedLen: number,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number
  ) => number
  bip44_derive_pubkey: (
    out33: number,
    seedPtr: number,
    seedLen: number,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number
  ) => number
  bip44_derive_leaf: (
    outPriv32: number,
    outPub33: number,
    seedPtr: number,
    seedLen: number,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number
  ) => number
  bip44_account_xpub: (
    outPtr: number,
    seedPtr: number,
    seedLen: number,
    purpose: number,
    coinType: number,
    account: number
  ) => number
  bip44_account_xprv: (
    outPtr: number,
    seedPtr: number,
    seedLen: number,
    purpose: number,
    coinType: number,
    account: number
  ) => number
  bip44_from_mnemonic_derive: (
    outPriv32: number,
    outPub33: number,
    mnPtr: number,
    mnLen: number,
    passPtr: number,
    passLen: number,
    purpose: number,
    coinType: number,
    account: number,
    change: number,
    addressIndex: number
  ) => number
  bip44_from_mnemonic_xpub: (
    outPtr: number,
    mnPtr: number,
    mnLen: number,
    passPtr: number,
    passLen: number,
    purpose: number,
    coinType: number,
    account: number
  ) => number
  bip44_from_mnemonic_xprv: (
    outPtr: number,
    mnPtr: number,
    mnLen: number,
    passPtr: number,
    passLen: number,
    purpose: number,
    coinType: number,
    account: number
  ) => number

  // ── hash (uso interno / canary de tests) ──
  sha256_hash_raw: (outPtr: number, mPtr: number, len: number) => void

  /** Requerido por AssemblyScript con parámetros opcionales. */
  __setArgumentsLength?: (n: number) => void
}

// ── Constantes de longitud ────────────────────────────────────────────────
export const PRIVKEY_BYTES = 32
export const PUBKEY_COMPRESSED_BYTES = 33
export const PUBKEY_UNCOMPRESSED_BYTES = 65
export const XONLY_BYTES = 32
export const XKEY_BYTES = 88
export const SEED_BYTES = 64
export const HASH_BYTES = 32
export const SIG_BYTES = 64
export const HALF_ZONE = 2048 // mitad de PARAM_IN/OUT (4096): input | aux

// ✅ v3.1: BIP-327 estricto (compressed 33+33)
export const MUSIG_PUBNONCE_BYTES = 66 // cbytes(R1) ‖ cbytes(R2)
export const MUSIG_AGGNONCE_BYTES = 66 // cbytes_ext(R1) ‖ cbytes_ext(R2)
export const MUSIG_SECNONCE_BYTES = 97 // k1 ‖ k2 ‖ pk = 32+32+33 (BIP-327 rc.2+)
export const MUSIG_SESSION_BYTES = 97  // b ‖ e ‖ Rx ‖ g_R = 32+32+32+1
export const MUSIG_SIG_BYTES = 64
export const MUSIG_MAX_SIGNERS = 128

// ── Tipos de dominio ──────────────────────────────────────────────────────
export interface WifKey {
  privateKey: Uint8Array
  compressed: boolean
}
export interface EcdsaSignature {
  r: Uint8Array
  s: Uint8Array
  v: number
}
/** ✅ FIX v3.0: Resultado de Musig2.keyAgg */
export interface Musig2KeyAggResult {
  aggregatedPubkey: Uint8Array // Q.x (32 B, x-only)
  gacc: number // 0 = Y par, 1 = Y impar
}

/** ✅ FIX v3.0: Par de nonces de Musig2.nonceGen */
export interface Musig2NoncePair {
  secNonce: Uint8Array // k1‖k2 (64 B — NUNCA compartir)
  pubNonce: Uint8Array // R1.x‖R2.x (64 B — público)
}

/** ✅ FIX v3.0: Sesión MuSig2 */
export interface Musig2Session {
  data: Uint8Array // 97 B opacos (b‖e‖Rx‖g)
  aggNonce: Uint8Array
  aggregatedPubkey: Uint8Array
}
export type MessageFormat = 0 | 1 | 2 // Universal | Bitcoin | Ethereum
export type PrivateKey = Uint8Array
export type PublicKey = Uint8Array
export type Seed = Uint8Array
export type Mnemonic = string

// ── Utilidades: lectura de globals ────────────────────────────────────────
/** Normaliza un global del WASM a `number` (Global o number plano); fallback si no existe. */
export function getGlobalValue(val: WebAssembly.Global | number | undefined, fallback: number): number {
  if (typeof val === "number") return val
  if (val && typeof val === "object" && "value" in val) return Number(val.value)
  return fallback
}

// ── Utilidades: hex ↔ bytes ───────────────────────────────────────────────
const HEX_LUT: string[] = []
for (let i = 0; i < 256; i++) HEX_LUT.push(i.toString(16).padStart(2, "0"))

export function bytesToHex(bytes: Uint8Array): string {
  let hex = ""
  for (let i = 0; i < bytes.length; i++) hex += HEX_LUT[bytes[i]]
  return hex
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 0 ? hex : "0" + hex
  const out = new Uint8Array(clean.length >> 1)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16)
  return out
}

/** String (UTF‑8) → Uint8Array; si ya es Uint8Array, la devuelve tal cual. */
export function toUint8Array(data: string | Uint8Array): Uint8Array {
  return typeof data === "string" ? new TextEncoder().encode(data) : data
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (let i = 0; i < parts.length; i++) total += parts[i].length
  const out = new Uint8Array(total)
  let offset = 0
  for (let i = 0; i < parts.length; i++) {
    out.set(parts[i], offset)
    offset += parts[i].length
  }
  return out
}

// ── Validación de escalares en la frontera (E6) ────────────────────────────
/** N (orden del grupo secp256k1) en bytes big-endian. */
// prettier-ignore
const N_BE: ReadonlyArray<number> = [
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
  0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
  0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
]

/** true si privkey (32 B BE) es un escalar válido: 0 < k < N. */
export function isValidPrivateKey(privateKey: Uint8Array): boolean {
  if (privateKey.length !== PRIVKEY_BYTES) return false
  let nonZero = false
  for (let i = 0; i < PRIVKEY_BYTES; i++) {
    if (privateKey[i] !== 0) {
      nonZero = true
      break
    }
  }
  if (!nonZero) return false // k == 0
  for (let i = 0; i < PRIVKEY_BYTES; i++) {
    if (privateKey[i] < N_BE[i]) return true // k < N
    if (privateKey[i] > N_BE[i]) return false // k > N
  }
  return false // k == N
}

/** Calcula (N - k) mod N para un escalar válido 0 < k < N (bytes big-endian). */
export function negatePrivateKey(privateKey: Uint8Array): Uint8Array {
  const out = new Uint8Array(32)
  let borrow = 0
  for (let i = 31; i >= 0; i--) {
    let diff = N_BE[i] - privateKey[i] - borrow
    if (diff < 0) {
      diff += 256
      borrow = 1
    } else {
      borrow = 0
    }
    out[i] = diff
  }
  return out
}

// ── Límite de passphrase BIP39 (E5) ────────────────────────────────────────
/** Máx. bytes UTF-8 de la passphrase: HASH_WORK 4096 − SALT_OFF 2200 − 8 = 1888. */
export const MAX_PASSPHRASE_BYTES = 1888

