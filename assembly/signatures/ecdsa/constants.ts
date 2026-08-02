/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdsa/constants.ts — Formatos, prefijos de mensaje, N/2, códigos de error
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Prefijos verificados con hashlib:
 *   BITCOIN_PREFIX  = "\x18Bitcoin Signed Message:\n"   (25 B)
 *   ETHEREUM_PREFIX = "\x19Ethereum Signed Message:\n"  (26 B)
 * N_HALF = floor(N/2) para canonical S (BIP-62).
 */

// ── Formato de firma / hash de mensaje ────────────────────────────────────
export enum SignatureFormat {
  Universal = 0, // SHA-256(msg)
  Bitcoin = 1,   // double SHA-256( prefix ‖ varint(len) ‖ msg )
  Ethereum = 2   // Keccak-256( prefix ‖ decimal(len) ‖ msg )
}

// ── Prefijo Bitcoin Signed Message (25 B) ─────────────────────────────────
export const BITCOIN_PREFIX: StaticArray<u8> = [
  0x18, 0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e,
  0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20,
  0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3a,
  0x0a
]
export const BITCOIN_PREFIX_LEN: usize = 25

// ── Prefijo Ethereum Signed Message (26 B) ────────────────────────────────
export const ETHEREUM_PREFIX: StaticArray<u8> = [
  0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75,
  0x6d, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64,
  0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
  0x3a, 0x0a
]
export const ETHEREUM_PREFIX_LEN: usize = 26

// ── N_HALF = floor(N/2) — canonical S (BIP-62) ────────────────────────────
// 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
export const N_HALF_0: u64 = 0xdfe92f46681b20a0
export const N_HALF_1: u64 = 0x5d576e7357a4501d
export const N_HALF_2: u64 = 0xffffffffffffffff
export const N_HALF_3: u64 = 0x7fffffffffffffff

// ── Códigos de error (retorno i32; 0 = OK) ────────────────────────────────
export const ECDSA_OK: i32 = 0
export const ECDSA_ERR_INPUT_LEN: i32 = -1 // hash o privkey ≠ 32 B
export const ECDSA_ERR_R_ZERO: i32 = -2    // r resultó 0
export const ECDSA_ERR_S_ZERO: i32 = -3    // s resultó 0
export const ECDSA_ERR_K_INF: i32 = -4     // k·G en el infinito
export const ECDSA_ERR_PUBKEY: i32 = -5    // pubkey malformada / fuera de curva