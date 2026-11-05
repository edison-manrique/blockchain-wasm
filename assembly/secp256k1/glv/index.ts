/**
 * glv/index.ts — API pública del endomorfismo GLV.
 * Re-exporta también las operaciones de punto que usan los tests/consumidores.
 */
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/arena"

export { decompose, precomputeTable, initGTable, mul } from "./glv"

// Re-export de point (sin PARAM_*, que ya vienen de memory arriba)
export {
  double,
  addPoint,
  addMixed,
  negate,
  toAffine,
  setInfinity,
  isInfinity,
  generator,
  infinity,
  eqJacobian
} from "../point"
