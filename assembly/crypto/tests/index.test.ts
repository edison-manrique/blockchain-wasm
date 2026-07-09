/**
 * Crypto WASM - Tests target
 */

// ── CORE ──
export {
  test_bigint_add,
  test_bigint_mul,
  test_bigint_sqr,
  test_scalar_add,
  test_scalar_mul,
  test_scalar_mod_inverse,
  test_point_infinity,
  test_point_generator,
  test_point_double,
  test_point_add,
  test_point_negate,
  test_point_scalar_mul,
  test_ecdsa_sign_verify,
  test_ecdh,
  test_scalar_mod_inverse_fuzz,
  test_point_scalar_mul_fuzz,
  test_wif,
  test_sign_message_hola,
  test_verify_universal_der,
  test_schnorr_vector,
  test_vector_universal,
  test_vector_bitcoin,
  test_vector_ethereum,
  test_schnorr_multisig
} from "./core.test"

// ── BIP32 ──
export {
  test_bip32_master_privkey,
  test_bip32_master_pubkey,
  test_bip32_master_chaincode,
  test_bip44_btc_addr0_privkey,
  test_bip44_btc_addr0_pubkey,
  test_bip44_btc_addr1_privkey,
  test_bip44_btc_addr2_privkey,
  test_bip44_eth_addr0_privkey,
  test_bip44_eth_addr0_pubkey,
  test_bip44_eth_addr1_privkey,
  test_bip44_trx_addr0_privkey,
  test_bip84_btc_addr0_privkey,
  test_bip84_btc_addr0_pubkey,
  test_bip86_btc_addr0_privkey,
  test_bip86_btc_addr0_pubkey,
  test_bip44_seed2_master_privkey,
  test_bip44_seed2_btc_addr0,
  test_bip44_seed2_eth_addr0,
  test_bip44_seed3_master_privkey,
  test_bip44_seed3_btc_addr0,
  test_bip44_seed3_eth_addr0,
  test_bip32_derivepath_vs_manual,
  test_bip32_neuter,
  test_bip44_unique_addresses
} from "./bip32.test"

// ── UTILS ──
export {
  test_hex_encode_empty,
  test_hex_encode_single,
  test_hex_encode_zeros,
  test_hex_encode_ff,
  test_hex_encode_mixed,
  test_hex_encode_all_nibbles,
  test_hex_encode_sha256,
  test_hex_decode_empty,
  test_hex_decode_single,
  test_hex_decode_deadbeef,
  test_hex_decode_uppercase,
  test_hex_decode_0x_prefix,
  test_hex_roundtrip,
  test_hex_roundtrip_32,
  test_b64_encode_empty,
  test_b64_encode_hello,
  test_b64_encode_2bytes,
  test_b64_encode_1byte,
  test_b64_encode_3bytes,
  test_b64_encode_zeros,
  test_b64_encode_ffs,
  test_b64_decode_empty,
  test_b64_decode_hello,
  test_b64_decode_1byte,
  test_b64_decode_no_padding,
  test_b64_roundtrip,
  test_b64_roundtrip_64,
  test_same_equal,
  test_same_different,
  test_same_different_length,
  test_concat
} from "../../../../assembly/lib/tests/index.test"
