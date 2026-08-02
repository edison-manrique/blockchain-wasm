/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  point/index.ts — API pública de la aritmética de curva secp256k1
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Funciones directas (sin clase). Convenciones:
 *   • Jacobiano: 96 B  [ X | Y | Z ]   (Z==0 ⇒ infinito)
 *   • Afín:      64 B  [ X | Y ]
 *
 *   import { double, addPoint, addMixed, toAffine } from "../point"
 */

// ── Constantes de curva (re-export) ───────────────────────────────────────
export { GX_0, GX_1, GX_2, GX_3, GY_0, GY_1, GY_2, GY_3 } from "../constants"

// ── Punteros de I/O de la arena (para tests/wrapper) ──────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/memory"

// ── Aritmética de punto ───────────────────────────────────────────────────
export {
  infinity,
  generator,
  setGenerator,
  setInfinity,
  isInfinity,
  double,
  addPoint,
  addMixed,
  negate,
  toAffine,
  eqJacobian
} from "./point"
