/**
 * assembly/bip39/index.ts — Entry point (barrel) del módulo BIP39.
 * Re-exporta la implementación zero-alloc de ./bip39 para que el test
 * (que compila este archivo) vea todos los exports en el WASM resultante.
 */
export {
  bip39_init,
  bip39_entropy_to_mnemonic,
  bip39_mnemonic_to_entropy,
  bip39_mnemonic_to_seed,
  bip39_validate_mnemonic
} from "./bip39"

export { PARAM_IN_PTR, PARAM_OUT_PTR } from "../../utils/arena"
