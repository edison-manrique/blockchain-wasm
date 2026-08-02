/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  secp256k1/index.ts — API pública de la curva (zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Superficie pública de alto nivel. Field y Scalar son módulos "internos":
 * se importan directo cuando hacen falta (evitamos colisión de nombres como
 * field.mulMod vs scalar.mulMod).
 *
 *   import { multiplyG, glvMul, double, toAffine } from "assembly/secp256k1"
 *   import { mulMod, modInverse } from "assembly/secp256k1/field"
 *   import { mulMod as scalarMulMod } from "assembly/secp256k1/scalar"
 */

// ── I/O de la arena ────────────────────────────────────────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../utils/memory"

// ── Punto (coordenadas Jacobianas) ────────────────────────────────────────
export {
  double,
  addPoint,
  addMixed,
  negate,
  toAffine,
  generator,
  infinity,
  isInfinity,
  eqJacobian,
  setGenerator,
  setInfinity
} from "./point/index"

// ── GLV (k·P con endomorfismo, P arbitrario) ──────────────────────────────
export { decompose, mul as glvMul } from "./glv/index"

// ── Generator (k·G con tabla fija precomputada) ───────────────────────────
export { multiplyG, init as generatorInit } from "./generator/index"

// ── wNAF ───────────────────────────────────────────────────────────────────
export { compute as wnafCompute } from "./wnaf/index"

// ── Constantes (selectivo; el resto vía import directo de "./constants") ──
export { P0, P1, P2, P3, N0, N1, N2, N3, GX_0, GX_1, GX_2, GX_3, GY_0, GY_1, GY_2, GY_3 } from "./constants"
