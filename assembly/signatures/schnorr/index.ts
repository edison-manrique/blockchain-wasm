/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr/index.ts — API pública BIP-340 Schnorr (barrel zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   schnorr_get_pubkey(out32, privPtr32) → 32
 *   schnorr_sign(out64, msgPtr, msgLen, privPtr32, auxPtr32) → 64 | <0
 *   schnorr_verify(sigPtr, sigLen, msgPtr, msgLen, pubPtr, pubLen) → 1 | 0
 *
 * El wrapper TS convierte punteros ↔ Uint8Array/hex (única alloc).
 */
// ── Punteros de I/O ───────────────────────────────────────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/arena"
// ── Códigos de error (para el wrapper) ────────────────────────────────────
export {
  SCHNORR_OK,
  SCHNORR_ERR_K_ZERO,
  SCHNORR_ERR_PUBKEY,
  SCHNORR_ERR_INFINITY,
  SCHNORR_ERR_SIG_LEN,
  SCHNORR_ERR_PUB_LEN
} from "./constants"
// ── Firma / pubkey ────────────────────────────────────────────────────────
export { schnorr_get_pubkey, schnorr_sign } from "./sign"
// ── Verificación ──────────────────────────────────────────────────────────
export { schnorr_verify } from "./verify"
