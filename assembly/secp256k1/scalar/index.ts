/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  scalar/index.ts — API pública de la aritmética de escalares (mod N)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Funciones directas (sin clase), mismas convenciones que field/: punteros a
 * 32 bytes (4 limbs u64 little-endian); mul/sqr producen 64 bytes (512 bits).
 *
 *   import { mulMod, modInverse } from "../scalar"
 *   mulMod(res, a, b)   // res = a·b mod N
 */

// ── Constantes del orden ──────────────────────────────────────────────────
export { N0, N1, N2, N3, CN0, CN1, CN2, CN3, NH0, NH1, NH2, NH3 } from "../constants"

// ── Punteros de I/O de la arena (para tests/wrapper) ──────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/arena"

// ── Aritmética cruda compartida con field (sin módulo) ────────────────────
export { addRaw, subRaw, cmp, isZero, shr1Raw, select64 } from "../field/raw"

// ── Producto 256×256 → 512 bits (reusado de field) ────────────────────────
export { mul, sqr } from "../field/mul"

// ── Suma / resta modular (mod N, constant-time) ───────────────────────────
export { add, sub, subN, isGreaterOrEqualN, addN_shr1 } from "./addsub"

// ── Reducción 512 → 256 bits (mod N) ──────────────────────────────────────
export { reduce } from "./reduce"

// ── Multiplicación / squaring mod N ───────────────────────────────────────
export { mulMod, sqrMod } from "./mulmod"

// ── Inversa modular (BEEA mod N) ──────────────────────────────────────────
export { modInverse } from "./inverse"
