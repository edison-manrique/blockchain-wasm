/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  sha2/index.ts — Punto de entrada AssemblyScript de SHA-2
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Superficie pública (funciones de bajo nivel compiladas a WASM):
 *   • Hash one-shot:     SHA-256 y SHA-512.
 *   • HMAC one-shot:     HMAC-SHA256 y HMAC-SHA512 (+ verify constant-time).
 *   • Streaming:         contextos SHA-256 (112 B) y SHA-512 (208 B) con
 *                        create / update / final (el contexto lo pone el caller).
 *   • KDF:               PBKDF2-HMAC-SHA256 y PBKDF2-HMAC-SHA512 (RFC 8018).
 *
 * Esta es la base criptográfica de BIP39 (PBKDF2-HMAC-SHA512 + wordlist) y
 * BIP32 (HMAC-SHA512). Todo zero-alloc: SHA2 usa la zona HASH_WORK (layout
 * fijo) y secp256k1 la arena CRYPTO_WORK; al ser disjuntas, pueden anidarse.
 *
 * También re-exporta los punteros de I/O (PARAM_IN_PTR / PARAM_OUT_PTR) para
 * que el wrapper TypeScript localice las zonas de entrada/salida, y los
 * punteros de las zonas de trabajo por transparencia/diagnóstico.
 */
import { PARAM_IN_PTR, PARAM_OUT_PTR, CRYPTO_WORK_PTR, HASH_WORK_PTR, align8 } from "../../utils/arena"
import { Sha256, Sha256Context } from "./sha256"
import { Sha512, Sha512Context } from "./sha512"
import { Pbkdf2 } from "./pbkdf2"

// ── Punteros de memoria (para el wrapper TS) ───────────────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR, CRYPTO_WORK_PTR, HASH_WORK_PTR }

// ── Tamaños de contexto (para que el caller reserve en streaming) ──────────
export const SHA256_CTX_SIZE: usize = Sha256Context.SIZE // 112
export const SHA512_CTX_SIZE: usize = Sha512Context.SIZE // 208

// ── Hash one-shot SHA-256 ──────────────────────────────────────────────────

/** SHA-256 de n bytes en mPtr → 32 bytes en outPtr (one-shot, zero-alloc). */
export function sha256_hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
  Sha256.hash_raw(outPtr, mPtr, n)
}

/** HMAC-SHA256 de kPtr[0..kLen) sobre mPtr[0..mLen) → 32 bytes en outPtr. */
export function sha256_hmac_raw(outPtr: usize, kPtr: usize, kLen: isize, mPtr: usize, mLen: isize): void {
  Sha256.hmac_raw(outPtr, kPtr, kLen, mPtr, mLen)
}

/**
 * Verifica HMAC-SHA256 en tiempo constante (sin early-exit). Retorna true si
 * el HMAC de (k, m) coincide con macPtr[0..macLen). macLen debe ser 32.
 */
export function sha256_hmac_verify_raw(
  kPtr: usize,
  kLen: isize,
  mPtr: usize,
  mLen: isize,
  macPtr: usize,
  macLen: isize
): bool {
  return Sha256.hmac_verify_raw(kPtr, kLen, mPtr, mLen, macPtr, macLen)
}

// ── Hash one-shot SHA-512 ──────────────────────────────────────────────────

/** SHA-512 de n bytes en mPtr → 64 bytes en outPtr (one-shot, zero-alloc). */
export function sha512_hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
  Sha512.hash_raw(outPtr, mPtr, n)
}

/** HMAC-SHA512 de kPtr[0..kLen) sobre mPtr[0..mLen) → 64 bytes en outPtr. */
export function sha512_hmac_raw(outPtr: usize, kPtr: usize, kLen: isize, mPtr: usize, mLen: isize): void {
  Sha512.hmac_raw(outPtr, kPtr, kLen, mPtr, mLen)
}

/**
 * Verifica HMAC-SHA512 en tiempo constante (sin early-exit). Retorna true si
 * el HMAC de (k, m) coincide con macPtr[0..macLen). macLen debe ser 64.
 */
export function sha512_hmac_verify_raw(
  kPtr: usize,
  kLen: isize,
  mPtr: usize,
  mLen: isize,
  macPtr: usize,
  macLen: isize
): bool {
  return Sha512.hmac_verify_raw(kPtr, kLen, mPtr, mLen, macPtr, macLen)
}

// ── Streaming SHA-256 (contexto ≥ 112 B lo pone el caller) ─────────────────

/** Inicializa un contexto SHA-256 en ctxPtr (≥ 112 B). Llamar una vez. */
export function sha256_create_ctx(ctxPtr: usize): void {
  const ctx = changetype<Sha256Context>(ctxPtr)
  ctx.init()
}

/** Alimenta n bytes de mPtr al contexto SHA-256 en ctxPtr (muchas veces). */
export function sha256_update_raw(ctxPtr: usize, mPtr: usize, n: isize): void {
  const ctx = changetype<Sha256Context>(ctxPtr)
  Sha256.update(ctx, mPtr, n)
}

/**
 * Finaliza SHA-256: padding + 32 bytes en outPtr. paddedPtr ≥ 128 B
 * (buffer temporal de padding; lo pone el caller, p.ej. tras el contexto).
 */
export function sha256_final_raw(ctxPtr: usize, paddedPtr: usize, outPtr: usize): void {
  const ctx = changetype<Sha256Context>(ctxPtr)
  Sha256.final(ctx, paddedPtr, outPtr)
}

// ── Streaming SHA-512 (contexto ≥ 208 B lo pone el caller) ─────────────────

/** Inicializa un contexto SHA-512 en ctxPtr (≥ 208 B). Llamar una vez. */
export function sha512_create_ctx(ctxPtr: usize): void {
  const ctx = changetype<Sha512Context>(ctxPtr)
  ctx.init()
}

/** Alimenta n bytes de mPtr al contexto SHA-512 en ctxPtr (muchas veces). */
export function sha512_update_raw(ctxPtr: usize, mPtr: usize, n: isize): void {
  const ctx = changetype<Sha512Context>(ctxPtr)
  Sha512.update(ctx, mPtr, n)
}

/**
 * Finaliza SHA-512: padding + 64 bytes en outPtr. paddedPtr ≥ 256 B
 * (buffer temporal de padding; lo pone el caller, p.ej. tras el contexto).
 */
export function sha512_final_raw(ctxPtr: usize, paddedPtr: usize, outPtr: usize): void {
  const ctx = changetype<Sha512Context>(ctxPtr)
  Sha512.final(ctx, paddedPtr, outPtr)
}

// ── PBKDF2 (RFC 8018) ──────────────────────────────────────────────────────

/** PBKDF2-HMAC-SHA256. Escribe dkLen bytes en outPtr. */
export function sha256_pbkdf2_raw(
  outPtr: usize,
  passwordPtr: usize,
  passwordLen: i32,
  saltPtr: usize,
  saltLen: i32,
  iterations: i32,
  dkLen: i32
): void {
  Pbkdf2.sha256_raw(outPtr, passwordPtr, passwordLen, saltPtr, saltLen, iterations, dkLen)
}

/** PBKDF2-HMAC-SHA512. Escribe dkLen bytes en outPtr. (Base de BIP39.) */
export function sha512_pbkdf2_raw(
  outPtr: usize,
  passwordPtr: usize,
  passwordLen: i32,
  saltPtr: usize,
  saltLen: i32,
  iterations: i32,
  dkLen: i32
): void {
  Pbkdf2.sha512_raw(outPtr, passwordPtr, passwordLen, saltPtr, saltLen, iterations, dkLen)
}
