/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr/index.ts — API pública BIP-340 Schnorr + MuSig2 (barrel zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  BIP-340:
 *   schnorr_get_pubkey(out32, privPtr32) → 32
 *   schnorr_sign(out64, msgPtr, msgLen, privPtr32, auxPtr32) → 64 | <0
 *   schnorr_verify(sigPtr, sigLen, msgPtr, msgLen, pubPtr, pubLen) → 1 | 0
 *   schnorr_aggregate_pubkeys(out32, pubsPtr, count)  → 32 | <0  (naive, legacy)
 *   schnorr_aggregate_privkeys(out32, privsPtr, count) → 32 | <0 (naive, legacy)
 *
 *  MuSig2 (BIP-326) — contratos detallados en musig2/*.ts:
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
 *   musig2_sign_all(out_sig64, out_q32, privsPtr, count, msgPtr, msgLen,
 *                   secrandPtr) → 64 | <0
 *
 * El wrapper TS convierte punteros ↔ Uint8Array/hex (única alloc).
 */
// ── Punteros de I/O ───────────────────────────────────────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/memory"
// ── Códigos de error (para el wrapper) ────────────────────────────────────
export {
  SCHNORR_OK,
  SCHNORR_ERR_K_ZERO,
  SCHNORR_ERR_PUBKEY,
  SCHNORR_ERR_INFINITY,
  SCHNORR_ERR_SIG_LEN,
  SCHNORR_ERR_PUB_LEN,
  MUSIG_OK,
  MUSIG_ERR_COUNT,
  MUSIG_ERR_PUBKEY,
  MUSIG_ERR_INFINITY,
  MUSIG_ERR_NONCE,
  MUSIG_ERR_SIG,
  // Tags
  TAG_KEYAGG_LIST,
  TAG_KEYAGG_COEFF,
  TAG_MUSIG_AUX,
  TAG_MUSIG_NONCE,
  TAG_MUSIG_NONCECOEF,
  // Errores
  MUSIG_ERR_PRIVKEY,
  // Tamaños de layout (Críticos para el Host)
  MUSIG_PUBNONCE_SIZE,
  MUSIG_AGGNONCE_SIZE,
  MUSIG_SECNONCE_SIZE,
  MUSIG_SESSION_SIZE,
  MUSIG_MAX_SIGNERS
} from "./constants"
// ── Firma / pubkey ────────────────────────────────────────────────────────
export { schnorr_get_pubkey, schnorr_sign } from "./sign"
// ── Verificación ──────────────────────────────────────────────────────────
export { schnorr_verify } from "./verify"
// ── MuSig2 (BIP-326) — M4: wiring al barrel ────────────────────────────────
export {
  musig2_keyagg_list_hash,
  musig2_keyagg_coeff,
  musig2_keyagg,
  // ── Nonces ──
  musig2_nonce_gen,
  musig2_nonce_agg,
  // ── Signing & Verification ──
  musig2_session_init,
  musig2_partial_sign,
  musig2_partial_verify,
  musig2_partial_sig_agg,
  musig2_sign_all
} from "./musig2"
