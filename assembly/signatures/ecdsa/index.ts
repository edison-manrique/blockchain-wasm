/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdsa/index.ts — API pública ECDSA secp256k1 (barrel zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   ecdsa_sign(out65, hashPtr32, privPtr32) → 65 | <0            // r‖s‖v
 *   ecdsa_verify(hashPtr32, sigPtr64, pubPtr, pubLen) → 1 | 0
 *   ecdsa_message_hash(out32, msgPtr, msgLen, format) → 32
 *   ecdsa_sign_message(out65, msgPtr, msgLen, privPtr32, format) → 65 | <0
 *   ecdsa_verify_message(msgPtr, msgLen, sigPtr64, pubPtr, pubLen, format) → 1 | 0
 *
 * format: 0 = Universal (SHA-256), 1 = Bitcoin (double SHA-256), 2 = Ethereum (Keccak-256).
 *
 * Re-exporta pubkeyFromPrivkey / pubkeyUncompressedFromPrivkey (de ../pubkey)
 * para que el wrapper/test derive pubkeys ancladas a G sin otro módulo.
 */

// ── Punteros de I/O ───────────────────────────────────────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/memory"

// ── Códigos de error ──────────────────────────────────────────────────────
export {
  ECDSA_OK,
  ECDSA_ERR_INPUT_LEN,
  ECDSA_ERR_R_ZERO,
  ECDSA_ERR_S_ZERO,
  ECDSA_ERR_K_INF,
  ECDSA_ERR_PUBKEY
} from "./constants"

// ── Firma / verificación sobre hash ───────────────────────────────────────
export { ecdsa_sign } from "./sign"
export { ecdsa_verify } from "./verify"

// ── Hash de mensaje + sign/verify de mensaje ──────────────────────────────
export { ecdsa_message_hash, ecdsa_sign_message, ecdsa_verify_message } from "./message"

// ── Derivación de pubkey (ancla a G para tests / wrapper) ─────────────────
export { pubkeyFromPrivkey, pubkeyUncompressedFromPrivkey } from "../../utils/pubkey"
