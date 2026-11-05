/**
 * wnaf/index.ts — API pública del wNAF.
 */
// Punteros de I/O (necesarios para tests/wrapper; wnaf en sí es puro)
export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/arena"

export { compute } from "./wnaf"
