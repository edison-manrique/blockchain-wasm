/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  constants.ts — Constantes de secp256k1 (UNIFICADO)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Todas las constantes del dominio secp256k1 en un solo lugar:
 *  • P     — primo del campo (field prime),        2^256 − 2^32 − 977
 *  • C_FIELD — constante de reducción del campo,   P = 2^256 − C_FIELD
 *  • N     — orden del grupo (group order)
 *  • CN    — complemento de N,                     2^256 − N  (reducción scalar)
 *  • NH    — (N − 1) / 2  (umbral de signo GLV / reducción balanceada)
 *  • NM2   — N − 2  (exponente de Fermat, si se usara)
 *  • G     — punto generador (coordenadas afines X, Y)
 *  • BETA_  — endomorfismo GLV, BETA_^3 ≡ 1 (mod P)
 *  • A1/B1/A2 — vectores cortos de la retícula de λ (descomposición GLV)
 *
 * Representación: little-endian en 4 limbs u64 (limb0 = menos significativo).
 *
 * ⚠️ IMPORTANTE: cada `const` es un GLOBAL independiente en el data segment;
 *    NO forman arrays contiguos. Para cargar un escalar de 256 bits en un
 *    buffer hay que hacer 4× store<u64> (limb a limb), NUNCA memory.copy de
 *    un rango de constantes. Los limbs marcados como 0 existen explícitamente
 *    para que el código los referencie por nombre (A1_2, B1_3, …).
 *
 * Solo datos (sin lógica) — no depende de ningún otro módulo.
 */

// ── P — primo del campo ────────────────────────────────────────────────────
// FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
export const P0: u64 = 0xfffffffefffffc2f
export const P1: u64 = 0xffffffffffffffff
export const P2: u64 = 0xffffffffffffffff
export const P3: u64 = 0xffffffffffffffff

// ── C_FIELD — constante de reducción del campo: P = 2^256 − C, C = 2^32 + 977
export const C_FIELD: u64 = 0x1000003d1

// ── N — orden del grupo ────────────────────────────────────────────────────
// FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
export const N0: u64 = 0xbfd25e8cd0364141
export const N1: u64 = 0xbaaedce6af48a03b
export const N2: u64 = 0xfffffffffffffffe
export const N3: u64 = 0xffffffffffffffff

// ── CN — complemento de N: 2^256 − N (reducción pseudo-Mersenne de scalar) ─
export const CN0: u64 = 0x402da1732fc9bebf
export const CN1: u64 = 0x4551231950b75fc4
export const CN2: u64 = 0x0000000000000001
export const CN3: u64 = 0x0000000000000000

// ── NH — (N − 1) / 2 (umbral de signo en GLV / reducción balanceada) ───────
export const NH0: u64 = 0xdfe92f46681b20a0
export const NH1: u64 = 0x5d576e7357a4501d
export const NH2: u64 = 0xffffffffffffffff
export const NH3: u64 = 0x7fffffffffffffff

// ── NM2 — N − 2 (exponente de Fermat a^(N−2), opcional) ────────────────────
export const NM2_0: u64 = 0xbfd25e8cd036413f
export const NM2_1: u64 = 0xbaaedce6af48a03b
export const NM2_2: u64 = 0xfffffffffffffffe
export const NM2_3: u64 = 0xffffffffffffffff

// ── G — punto generador (afín) ─────────────────────────────────────────────
export const GX_0: u64 = 0x59f2815b16f81798
export const GX_1: u64 = 0x029bfcdb2dce28d9
export const GX_2: u64 = 0x55a06295ce870b07
export const GX_3: u64 = 0x79be667ef9dcbbac
export const GY_0: u64 = 0x9c47d08ffb10d4b8
export const GY_1: u64 = 0xfd17b448a6855419
export const GY_2: u64 = 0x5da4fbfc0e1108a8
export const GY_3: u64 = 0x483ada7726a3c465

// ── BETA — endomorfismo GLV: φ(x, y) = (BETA·x, y),  BETA_^3 ≡ 1 (mod P) ───
export const BETA_0: u64 = 0xc1396c28719501ee
export const BETA_1: u64 = 0x9cf0497512f58995
export const BETA_2: u64 = 0x6e64479eac3434e9
export const BETA_3: u64 = 0x7ae96a2b657c0710

// ── GLV — vectores cortos de la retícula de λ (k → k1 + k2·λ) ──────────────
// (b2 = −a1, no se almacena.) Los limbs = 0 están explícitos por completitud.
export const A1_0: u64 = 0xe86c90e49284eb15
export const A1_1: u64 = 0x3086d221a7d46bcd
export const A1_2: u64 = 0x0000000000000000
export const A1_3: u64 = 0x0000000000000000

export const B1_0: u64 = 0x6f547fa90abfe4c3
export const B1_1: u64 = 0xe4437ed6010e8828
export const B1_2: u64 = 0x0000000000000000
export const B1_3: u64 = 0x0000000000000000

export const A2_0: u64 = 0x57c1108d9d44cfd8
export const A2_1: u64 = 0x14ca50f7a8e2f3f6
export const A2_2: u64 = 0x0000000000000001
export const A2_3: u64 = 0x0000000000000000
