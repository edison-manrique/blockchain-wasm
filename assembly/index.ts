/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  assembly/index.ts — Barrel global de la librería criptográfica zero-alloc
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Expone la API pública de ALTO NIVEL. Reglas anti-colisión:
 *   • memory y pubkey se re-exportan UNA vez (fuente canónica).
 *   • Los módulos de alto nivel usan nombres prefijados únicos (bip32_, ecdsa_, …).
 *   • hashing/encoding (sha2/keccak/ripemd/base58/bech32/wif) van con export *.
 *   • secp256k1 de bajo nivel (field/scalar/point/glv/…) NO se re-exporta aquí:
 *       import { ... } from "assembly/secp256k1"   // si lo necesitas
 *
 * Los códigos de error (ECDSA_ERR_*, SCHNORR_ERR_*, BIP32_ERR_*, …) y los
 * accessors finos (bip32_xkey_*) se importan directo del módulo correspondiente
 * para mantener este barrel enxuto.
 */

// ═══════════════════════════════════════════════════════════════════════════
// 1) MEMORIA — fuente canónica de punteros / arena (NO re-exportar de otros)
// ═══════════════════════════════════════════════════════════════════════════
export {
  PARAM_IN_PTR,
  PARAM_OUT_PTR,
  PARAM_IN_SIZE,
  PARAM_OUT_SIZE,
  WORK_SIZE,
  HASH_WORK_SIZE,
  BIP32_WORK_SIZE,
  ADDRESS_WORK_SIZE,
  SCRATCH_SIZE,
  CRYPTO_WORK_PTR,
  HASH_WORK_PTR,
  BIP32_WORK_PTR,
  ADDRESS_WORK_PTR,
  align8,
} from "./utils/memory"

// ═══════════════════════════════════════════════════════════════════════════
// 2) CLAVES PÚBLICAS — fuente canónica (NO re-exportar de address/ecdsa/ecdh)
// ═══════════════════════════════════════════════════════════════════════════
export {
  sqrtModP,
  decompressXY,
  decompressToPoint,
  pubkeyFromPrivkey,
  pubkeyUncompressedFromPrivkey,
  compressRaw,
  uncompressRaw,
} from "./utils/pubkey"

// ═══════════════════════════════════════════════════════════════════════════
// 3) HASHING — prefijos propios (sha256_/sha512_/keccak256_/ripemd160_)
// ═══════════════════════════════════════════════════════════════════════════
export * from "./hash/sha2"
export * from "./hash/keccak256"
export * from "./hash/ripemd160"

// ═══════════════════════════════════════════════════════════════════════════
// 4) ENCODING — prefijos propios (base58_/bech32_/toWIF/fromWIF)
// ═══════════════════════════════════════════════════════════════════════════
export * from "./utils/base58"
export * from "./utils/bech32"
// ✅ selectivo: wif re-exporta helpers de base58 que ya vienen arriba → evitar TS2308
export { wif_encode_raw, wif_decode_raw } from "./utils/wif"

// ═══════════════════════════════════════════════════════════════════════════
// 5) BIPs
// ═══════════════════════════════════════════════════════════════════════════
export {
  bip32_from_seed,
  bip32_derive,
  bip32_derive_path,
  bip32_derive_account,
  bip32_derive_address,
  bip32_get_pubkey,
  bip32_neuter,
  bip32_fingerprint,
  bip32_serialize_xpub,
  bip32_serialize_xprv,
  bip32_deserialize,
  bip32_xkey_depth,
  bip32_xkey_parent_fp,
  bip32_xkey_child_index,
  bip32_xkey_is_private,
  bip32_xkey_chaincode_ptr,
  bip32_xkey_keydata_ptr,
  HARDENED_OFFSET,
} from "./bips/bip32"

export {
  bip39_mnemonic_to_seed,
  bip39_validate_mnemonic,
  bip39_entropy_to_mnemonic,
  bip39_mnemonic_to_entropy,
} from "./bips/bip39"

export {
  bip44_derive_leaf,
  bip44_derive_privkey,
  bip44_derive_pubkey,
  bip44_account_xpub,
  bip44_account_xprv,
  bip44_from_mnemonic_derive,
  bip44_from_mnemonic_xpub,
  bip44_from_mnemonic_xprv,
} from "./bips/bip44"

// ═══════════════════════════════════════════════════════════════════════════
// 6) FIRMAS
// ═══════════════════════════════════════════════════════════════════════════
export {
  ecdsa_sign,
  ecdsa_verify,
  ecdsa_message_hash,
  ecdsa_sign_message,
  ecdsa_verify_message,
} from "./signatures/ecdsa"

export {
  schnorr_get_pubkey,
  schnorr_sign,
  schnorr_verify,
  schnorr_aggregate_pubkeys,
  schnorr_aggregate_privkeys,
} from "./signatures/schnorr"

// ═══════════════════════════════════════════════════════════════════════════
// 7) ECDH
// ═══════════════════════════════════════════════════════════════════════════
export { ecdh_shared_secret } from "./ecdh"

// ═══════════════════════════════════════════════════════════════════════════
// 8) DIRECCIONES (Bitcoin + Ethereum)
// ═══════════════════════════════════════════════════════════════════════════
export {
  btc_p2pkh,
  btc_p2sh_p2wpkh,
  btc_p2wpkh,
  btc_p2tr,
  btc_p2pkh_uncompressed,
  eth_address,
  tron_address,
} from "./address"
