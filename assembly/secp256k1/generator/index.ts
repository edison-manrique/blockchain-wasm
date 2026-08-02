/**
 * generator/index.ts — API pública de la multiplicación fija k·G.
 * Re-exporta utilidades de punto y glv.mul (como oráculo para tests).
 */
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/memory"

export { init, multiplyG } from "./generator"

// Re-exports para tests / consumidores de nivel superior
export { mul as mulGLV } from "../glv"
export { toAffine, generator, setInfinity, isInfinity } from "../point"
