/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  musig2/index.ts — Barrel MuSig2 (BIP-327) zero-alloc
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  Superficie pública (contratos detallados en musig2/*.ts):
 *
 *   musig2_keyagg_list_hash(out32, pksPtr, count) → 32 | <0
 *   musig2_keyagg_coeff(out32, L32, pk32) → 32
 *   musig2_keyagg(out_q32, out_gacc8, pksPtr, count) → 0 | <0
 *   musig2_nonce_gen(out_k64, out_r66, secrand32, skPtr|0, pk32,
 *                    otherPkPtr|0, msgPtr|0, msgLen) → 0 | <0
 *   musig2_nonce_agg(out_r66, noncesPtr, count) → 0 | <0
 *   musig2_session_init(out97, aggNonce66, q32, msgPtr, msgLen) → 0 | <0
 *   musig2_partial_sign(out_s32, session97, gacc8, secnonce64, priv32, coeff32) → 0 | <0
 *   musig2_partial_verify(s32, session97, gacc8, pubnonce66, pk32, coeff32) → 1 | 0
 *   musig2_partial_sig_agg(out_s32, partialsPtr, count) → 0 | <0
 *   musig2_sign_all(out64, out_q32, privsPtr, count, msgPtr, msgLen,
 *                   secrandPtr) → 64 | <0
 *
 *  Layout (ver constants.ts):
 *    v3.0: pubnonce/aggnonce = 64 B (x-only 32+32)
 *    v3.1: pubnonce/aggnonce = 66 B (compressed 33+33, BIP-327 estricto)
 *
 *  Zero-alloc: todo vive en CRYPTO_WORK (Memory.save/restore, LIFO).
 */

// ── Punteros de I/O de la arena ───────────────────────────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../../utils/memory"

// ── KeyAgg ────────────────────────────────────────────────────────────────
export { musig2_keyagg_list_hash, musig2_keyagg_coeff, musig2_keyagg } from "./keyagg"

// ── Nonces ────────────────────────────────────────────────────────────────
export { musig2_nonce_gen, musig2_nonce_agg } from "./nonce"

// ── Signing & Verification ────────────────────────────────────────────────
export {
  musig2_session_init,
  musig2_partial_sign,
  musig2_partial_verify,
  musig2_partial_sig_agg,
  musig2_sign_all
} from "./sign"

// ── Tags, errores y tamaños de layout (críticos para el host TS) ──────────
export {
  // Tags
  TAG_KEYAGG_LIST,
  TAG_KEYAGG_COEFF,
  TAG_MUSIG_AUX,
  TAG_MUSIG_NONCE,
  TAG_MUSIG_NONCECOEF,
  // Errores
  MUSIG_OK,
  MUSIG_ERR_COUNT,
  MUSIG_ERR_PUBKEY,
  MUSIG_ERR_INFINITY,
  MUSIG_ERR_NONCE,
  MUSIG_ERR_SIG,
  MUSIG_ERR_PRIVKEY,
  // Tamaños
  MUSIG_PUBNONCE_SIZE,
  MUSIG_AGGNONCE_SIZE,
  MUSIG_SECNONCE_SIZE,
  MUSIG_SESSION_SIZE,
  MUSIG_MAX_SIGNERS
} from "../constants"
