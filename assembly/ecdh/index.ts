/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdh/index.ts — API pública ECDH secp256k1 (barrel zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   ecdh_shared_secret(out33, privPtr32, pubPtr, pubLen) → 33 | <0
 *       pubLen = 33 (compressed) | 65 (uncompressed).
 *
 * Re-exporta pubkeyFromPrivkey / pubkeyUncompressedFromPrivkey (de ../pubkey)
 * para que el wrapper/test derive pubkeys ancladas a G sin otro módulo.
 */

// ── Punteros de I/O ───────────────────────────────────────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../utils/memory"

// ── ECDH + códigos de error ───────────────────────────────────────────────
export { ecdh_shared_secret, ECDH_OK, ECDH_ERR_PRIV_LEN, ECDH_ERR_PUB_FORMAT, ECDH_ERR_INFINITY } from "./ecdh"

// ── Derivación de pubkey (ancla a G para tests / wrapper) ─────────────────
export { pubkeyFromPrivkey, pubkeyUncompressedFromPrivkey } from "../utils/pubkey"
