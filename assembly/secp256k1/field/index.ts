/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  field/index.ts — API pública de la aritmética de campo (mod P)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Re-exporta todas las operaciones del campo primo de secp256k1 como funciones
 * directas (sin clase fachada). Uso:
 *
 *   import { mulMod, sqrMod, add, sub, modInverse } from "../field"
 *   mulMod(res, a, b)   // res = a·b mod P
 *
 * Esto reemplaza al antiguo `BigInt256.mulMod(...)`; en Fases 3–5 (point, glv,
 * generator) migraremos los usos a estos imports directos y eliminaremos
 * bigint256.ts.
 *
 * Convención: todas las funciones operan sobre punteros a 32 bytes (4 limbs u64
 * little-endian), salvo mul/sqr (64 B de salida, 512 bits) y modInverse (arena).
 */

// ── Constantes del campo ────────────────────────────────────────────────────
export { P0, P1, P2, P3, C_FIELD } from "../constants"

// ── Punteros de I/O de la arena (para tests y wrapper; el layout vive en memory.ts) ──
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/memory"

// ── Aritmética "cruda" (sin módulo) — compartida con scalar ─────────────────
export { addRaw, subRaw, cmp, isZero, shr1Raw, select64 } from "./raw"

// ── Suma / resta modular (mod P, constant-time) ─────────────────────────────
export { add, sub, subP, isGreaterOrEqualP, addP_shr1 } from "./addsub"

// ── Multiplicación / squaring (256×256 → 512 bits, a memoria) ───────────────
export { mul, sqr } from "./mul"

// ── Multiplicación / squaring FUSED mod P (en registros, lo más caliente) ───
export { mulMod, sqrMod } from "./mulmod"

// ── Reducción 512 → 256 bits (mod P) ────────────────────────────────────────
export { reduce } from "./reduce"

// ── Conversión bytes ↔ limbs (zero-alloc) ───────────────────────────────────
export { fromBytesPtr, toBytesPtr } from "./convert"

// ── Inversa modular (BEEA; ver nota de seguridad en inverse.ts) ─────────────
export { modInverse } from "./inverse"
