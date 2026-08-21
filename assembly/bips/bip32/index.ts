/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip32/index.ts — API pública de BIP32 (barrel + funciones de conveniencia)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Superficie pública WASM (todo con prefijo bip32_):
 *
 *   bip32_from_seed(xkeyPtr, seedPtr, seedLen) → i32
 *   bip32_derive(childPtr, parentPtr, index) → i32
 *   bip32_derive_path(childPtr, parentPtr, pathPtr, pathLen) → i32
 *   bip32_derive_account(childPtr, parentPtr, purpose, coin, account) → i32
 *   bip32_derive_address(childPtr, parentPtr, purpose, coin, account, change, idx) → i32
 *   bip32_get_pubkey(out33Ptr, xkeyPtr) → i32
 *   bip32_neuter(pubXkeyPtr, privXkeyPtr) → i32
 *   bip32_fingerprint(pub33Ptr) → u32
 *
 *   Accessors xkey:
 *   bip32_xkey_depth(ptr) → u32
 *   bip32_xkey_parent_fp(ptr) → u32
 *   bip32_xkey_child_index(ptr) → u32
 *   bip32_xkey_is_private(ptr) → bool
 *   bip32_xkey_chaincode_ptr(ptr) → usize
 *   bip32_xkey_keydata_ptr(ptr) → usize
 */
import { BIP32_WORK_PTR, align8, PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/memory"
import { PUBKEY_LEN, BW_PUBKEY_TMP, BIP32_OK, BIP32_ERR_NOT_PRIVATE } from "./constants"
import { isPrivate, keyDataPtr, chainCodePtr, neuterRaw } from "./xkey"
import { getDepth, getParentFingerprint, getChildIndex } from "./xkey"
import { pubkeyFromPrivkey } from "./crypto"
import { fingerprint } from "./hash"

// ── Punteros de I/O ────────────────────────────────────────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR, BIP32_WORK_PTR }

// ── Constantes ─────────────────────────────────────────────────────────────
export {
  HARDENED_OFFSET,
  XKEY_SIZE,
  BIP44_PURPOSE,
  BIP49_PURPOSE,
  BIP84_PURPOSE,
  BIP86_PURPOSE,
  COIN_BTC,
  COIN_BTC_TESTNET,
  COIN_ETH,
  BIP32_OK,
  BIP32_ERR_SEED_LEN,
  BIP32_ERR_INVALID_KEY,
  BIP32_ERR_HARDENED_FROM_PUB,
  BIP32_ERR_INVALID_PATH,
  BIP32_ERR_CHILD_INVALID,
  BIP32_ERR_NOT_PRIVATE,
} from "./constants"

// ── Serialización xpub/xprv ───────────────────────────────────────────────
export { bip32_serialize_xpub, bip32_serialize_xprv, bip32_deserialize } from "./serialize"

// ── Core (re-exports con prefijo) ──────────────────────────────────────────
export { bip32_from_seed, bip32_derive, bip32_ckd_priv, bip32_ckd_pub } from "./ckd"
export { bip32_derive_path, bip32_derive_account, bip32_derive_address } from "./path"

// ── Accessors xkey (re-exports con prefijo) ────────────────────────────────
export {
  bip32_xkey_depth,
  bip32_xkey_parent_fp,
  bip32_xkey_child_index,
  bip32_xkey_is_private,
  bip32_xkey_chaincode_ptr,
  bip32_xkey_keydata_ptr,
} from "./xkey"

// ── Fingerprint (re-export con prefijo) ────────────────────────────────────
export { fingerprint as bip32_fingerprint } from "./hash"

// ═══════════════════════════════════════════════════════════════════════════
// FUNCIONES DE CONVENIENCIA (definidas aquí)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Obtiene la pubkey comprimida (33 B) de un xkey.
 * Si es privado: calcula k·G. Si es público: copia keyData.
 */
export function bip32_get_pubkey(out33Ptr: usize, xkeyPtr: usize): i32 {
  if (isPrivate(xkeyPtr)) {
    pubkeyFromPrivkey(out33Ptr, keyDataPtr(xkeyPtr))
  } else {
    memory.copy(out33Ptr, keyDataPtr(xkeyPtr), PUBKEY_LEN)
  }
  return BIP32_OK
}

/**
 * Neuter: convierte un xprv en xpub (misma metadata + chainCode,
 * keyData reemplazada por la pubkey comprimida, isPrivate = false).
 */
export function bip32_neuter(pubXkeyPtr: usize, privXkeyPtr: usize): i32 {
  if (!isPrivate(privXkeyPtr)) return BIP32_ERR_NOT_PRIVATE
  const work = align8(BIP32_WORK_PTR)
  pubkeyFromPrivkey(work + BW_PUBKEY_TMP, keyDataPtr(privXkeyPtr))
  neuterRaw(pubXkeyPtr, privXkeyPtr, work + BW_PUBKEY_TMP)
  return BIP32_OK
}
