/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  address/index.ts — API pública de direcciones (BTC + ETH) y claves públicas
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Barrel zero-alloc. Re-exporta las direcciones de btc.ts / eth.ts y las
 * utilidades de clave pública de ../pubkey (compartidas con bip32).
 *
 * Direcciones (escriben string ASCII en outPtr, retornan longitud | <0 error):
 *   btc_p2pkh(out, pub, len)         P2PKH        Base58Check  "1…"
 *   btc_p2sh_p2wpkh(out, pub, len)   P2SH-P2WPKH  Base58Check  "3…"
 *   btc_p2wpkh(out, pub, len)        P2WPKH       Bech32       "bc1q…"
 *   btc_p2tr(out, pub, len)          P2TR/Taproot Bech32m      "bc1p…"
 *   eth_address(out, pub, len)       Ethereum     hex EIP-55   "0x…" (42)
 *
 * Claves públicas:
 *   pubkeyFromPrivkey(out33, priv32)               priv → compressed
 *   pubkeyUncompressedFromPrivkey(out65, priv32)   priv → uncompressed
 *   compressRaw(out33, pub, len) → 33 | -1
 *   uncompressRaw(out65, pub33)  → 65 | -1
 *
 * El wrapper TS convierte outPtr → string con TextDecoder (única alloc).
 */

// ── Punteros de I/O ───────────────────────────────────────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR, ADDRESS_WORK_PTR } from "../utils/memory"

// ── Códigos de error / versiones (para el wrapper) ────────────────────────
export { ADDR_OK, ADDR_ERR_PUBKEY, ADDR_ERR_CONVERT, VER_P2PKH, VER_P2SH } from "./constants"

// ── Direcciones Bitcoin ───────────────────────────────────────────────────
export { btc_p2pkh, btc_p2sh_p2wpkh, btc_p2wpkh, btc_p2tr } from "./btc"

// ── Dirección Ethereum ────────────────────────────────────────────────────
export { eth_address } from "./eth"

// ── Utilidades de clave pública (re-export desde el módulo compartido) ────
export { pubkeyFromPrivkey, pubkeyUncompressedFromPrivkey, compressRaw, uncompressRaw } from "../utils/pubkey"
