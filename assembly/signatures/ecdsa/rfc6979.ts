/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdsa/rfc6979.ts — Nonce determinístico RFC 6979 (HMAC-DRBG SHA-256)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   generateK(k_out, hashPtr, privPtr)
 *       Nonce k ∈ [1, N−1] determinístico (HMAC-DRBG con SHA-256), réplica
 *       exacta del código original: el setup usa el hash crudo (que para
 *       hash < N —el caso práctico— coincide bit a bit con RFC 6979 estricto).
 *
 *   reduceScalar(a)
 *       a ← a mod N (while a ≥ N: a −= N). Helper compartido por sign/verify.
 *
 * Zero-alloc: K/V/blobs en CRYPTO_WORK (Arena.save/restore); HMAC usa
 * HASH_WORK internamente. El aliasing out==key y out==msg de sha256_hmac_raw
 * es el mismo que ejercía el original (Sha256.hmac_ptr), así que es seguro.
 */
import { Arena } from "../../utils/arena"
import { fromBytesPtr } from "../../secp256k1/field"
import { isZero, isGreaterOrEqualN, subN } from "../../secp256k1/scalar"
import { sha256_hmac_raw } from "../../hash/sha2"

// ═══════════════════════════════════════════════════════════════════════════
// REDUCE mod N (helper compartido)
// ═══════════════════════════════════════════════════════════════════════════

/** a ← a mod N, in-place (limbs LE). */
export function reduceScalar(a: usize): void {
  while (isGreaterOrEqualN(a)) {
    subN(a, a)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// RFC 6979 — HMAC-DRBG (SHA-256)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Genera el nonce determinístico k ∈ [1, N−1] (limbs LE en k_out).
 * hashPtr / privPtr apuntan a 32 bytes big-endian cada uno.
 */
export function generateK(k_out: usize, hashPtr: usize, privPtr: usize): void {
  const ctx = Arena.save()
  const K = Arena.alloc(32)
  const V = Arena.alloc(32)
  const blob = Arena.alloc(97) // V(32) ‖ byte(1) ‖ priv(32) ‖ hash(32)
  const blob2 = Arena.alloc(33) // V(32) ‖ byte(1)

  // V = 0x01×32, K = 0x00×32
  memory.fill(V, 0x01, 32)
  memory.fill(K, 0x00, 32)

  // K = HMAC(K, V ‖ 0x00 ‖ priv ‖ hash);  V = HMAC(K, V)
  memory.copy(blob, V, 32)
  store<u8>(blob + 32, 0x00)
  memory.copy(blob + 33, privPtr, 32)
  memory.copy(blob + 65, hashPtr, 32)
  sha256_hmac_raw(K, K, 32, blob, 97)
  sha256_hmac_raw(V, K, 32, V, 32)

  // K = HMAC(K, V ‖ 0x01 ‖ priv ‖ hash);  V = HMAC(K, V)
  memory.copy(blob, V, 32)
  store<u8>(blob + 32, 0x01) // priv y hash ya están en blob+33..97
  sha256_hmac_raw(K, K, 32, blob, 97)
  sha256_hmac_raw(V, K, 32, V, 32)

  // Bucle hasta obtener k ∈ [1, N−1]
  while (true) {
    sha256_hmac_raw(V, K, 32, V, 32) // V = HMAC(K, V)
    fromBytesPtr(k_out, V) // V (BE) → k_out (limbs LE)
    if (!isZero(k_out) && !isGreaterOrEqualN(k_out)) {
      Arena.restore(ctx)
      return
    }
    // K = HMAC(K, V ‖ 0x00);  V = HMAC(K, V)
    memory.copy(blob2, V, 32)
    store<u8>(blob2 + 32, 0x00)
    sha256_hmac_raw(K, K, 32, blob2, 33)
    sha256_hmac_raw(V, K, 32, V, 32)
  }
}
