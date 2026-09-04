/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr/constants.ts — Tags BIP-340 + MuSig2 (BIP-327) + códigos de error
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * v3.1: Cumplimiento estricto BIP-327
 *   • pubnonce  = cbytes(R1) ‖ cbytes(R2)     = 66 bytes (33+33 compressed)
 *   • aggnonce  = cbytes_ext(R1) ‖ cbytes_ext(R2) = 66 bytes (permite ∞)
 *   • secnonce  = 64 bytes (k1‖k2, sin pk; simplificación segura)
 */
// ── Índices de tag BIP-340 ────────────────────────────────────────────────
export const TAG_AUX: i32 = 0
export const TAG_NONCE: i32 = 1
export const TAG_CHALLENGE: i32 = 2

// ── Tag hashes BIP-340 (96 bytes: aux ‖ nonce ‖ challenge) ───────────────
// prettier-ignore
export const TAG_HASHES: StaticArray<u8> = [
  // aux = SHA256("BIP0340/aux")
  0xf1, 0xef, 0x4e, 0x5e, 0xc0, 0x63, 0xca, 0xda,
  0x6d, 0x94, 0xca, 0xfa, 0x9d, 0x98, 0x7e, 0xa0,
  0x69, 0x26, 0x58, 0x39, 0xec, 0xc1, 0x1f, 0x97,
  0x2d, 0x77, 0xa5, 0x2e, 0xd8, 0xc1, 0xcc, 0x90,
  // nonce = SHA256("BIP0340/nonce")
  0x07, 0x49, 0x77, 0x34, 0xa7, 0x9b, 0xcb, 0x35,
  0x5b, 0x9b, 0x8c, 0x7d, 0x03, 0x4f, 0x12, 0x1c,
  0xf4, 0x34, 0xd7, 0x3e, 0xf7, 0x2d, 0xda, 0x19,
  0x87, 0x00, 0x61, 0xfb, 0x52, 0xbf, 0xeb, 0x2f,
  // challenge = SHA256("BIP0340/challenge")
  0x7b, 0xb5, 0x2d, 0x7a, 0x9f, 0xef, 0x58, 0x32,
  0x3e, 0xb1, 0xbf, 0x7a, 0x40, 0x7d, 0xb3, 0x82,
  0xd2, 0xf3, 0xf2, 0xd8, 0x1b, 0xb1, 0x22, 0x4f,
  0x49, 0xfe, 0x51, 0x8f, 0x6d, 0x48, 0xd3, 0x7c
]

// ═══════════════════════════════════════════════════════════════════════════
// MuSig2 (BIP-327) — índices de tag (posición en el buffer de 160 B)
// ═══════════════════════════════════════════════════════════════════════════
export const TAG_KEYAGG_LIST: i32 = 0
export const TAG_KEYAGG_COEFF: i32 = 1
export const TAG_MUSIG_AUX: i32 = 2
export const TAG_MUSIG_NONCE: i32 = 3
export const TAG_MUSIG_NONCECOEF: i32 = 4

// ── Cadenas ASCII de los tags MuSig2 (para musigInit) ─────────────────────
// prettier-ignore
export const MUSIG_TAG_KEYAGG_LIST: StaticArray<u8> = [
  0x4b, 0x65, 0x79, 0x41, 0x67, 0x67, 0x20, 0x6c, 0x69, 0x73, 0x74
]
export const MUSIG_TAG_KEYAGG_LIST_LEN: usize = 11

// prettier-ignore
export const MUSIG_TAG_KEYAGG_COEFF: StaticArray<u8> = [
  0x4b, 0x65, 0x79, 0x41, 0x67, 0x67, 0x20, 0x63,
  0x6f, 0x65, 0x66, 0x66, 0x69, 0x63, 0x69, 0x65,
  0x6e, 0x74
]
export const MUSIG_TAG_KEYAGG_COEFF_LEN: usize = 18

// prettier-ignore
export const MUSIG_TAG_AUX: StaticArray<u8> = [
  0x4d, 0x75, 0x53, 0x69, 0x67, 0x2f, 0x61, 0x75, 0x78
]
export const MUSIG_TAG_AUX_LEN: usize = 9

// prettier-ignore
export const MUSIG_TAG_NONCE: StaticArray<u8> = [
  0x4d, 0x75, 0x53, 0x69, 0x67, 0x2f, 0x6e, 0x6f, 0x6e, 0x63, 0x65
]
export const MUSIG_TAG_NONCE_LEN: usize = 11

// prettier-ignore
export const MUSIG_TAG_NONCECOEF: StaticArray<u8> = [
  0x4d, 0x75, 0x53, 0x69, 0x67, 0x2f, 0x6e, 0x6f,
  0x6e, 0x63, 0x65, 0x63, 0x6f, 0x65, 0x66
]
export const MUSIG_TAG_NONCECOEF_LEN: usize = 15

// ═══════════════════════════════════════════════════════════════════════════
// CÓDIGOS DE ERROR
// ═══════════════════════════════════════════════════════════════════════════
export const SCHNORR_OK: i32 = 0
export const SCHNORR_ERR_K_ZERO: i32 = -1
export const SCHNORR_ERR_PUBKEY: i32 = -2
export const SCHNORR_ERR_INFINITY: i32 = -3
export const SCHNORR_ERR_SIG_LEN: i32 = -4
export const SCHNORR_ERR_PUB_LEN: i32 = -5

export const MUSIG_OK: i32 = 0
export const MUSIG_ERR_COUNT: i32 = -7
export const MUSIG_ERR_PUBKEY: i32 = -8
export const MUSIG_ERR_INFINITY: i32 = -9
export const MUSIG_ERR_NONCE: i32 = -10
export const MUSIG_ERR_SIG: i32 = -11
export const MUSIG_ERR_PRIVKEY: i32 = -12

// ═══════════════════════════════════════════════════════════════════════════
// ✅ v3.2: TAMAÑOS DE LAYOUT (BIP-327 v1.0.4 estricto)
// ═══════════════════════════════════════════════════════════════════════════
/** pubnonce = cbytes(R1) ‖ cbytes(R2) = 33 + 33 = 66 bytes */
export const MUSIG_PUBNONCE_SIZE: usize = 66
/** aggnonce = cbytes_ext(R1) ‖ cbytes_ext(R2) = 33 + 33 = 66 bytes */
export const MUSIG_AGGNONCE_SIZE: usize = 66
/** secnonce = k1 ‖ k2 ‖ pk = 32 + 32 + 33 = 97 bytes (Obligatorio BIP-327 v1.0.0-rc.2+) */
export const MUSIG_SECNONCE_SIZE: usize = 97
/** session = b(32) ‖ e(32) ‖ Rx(32) ‖ g_R(1) = 97 bytes. gacc pasado por parámetro */
export const MUSIG_SESSION_SIZE: usize = 97
export const MUSIG_MAX_SIGNERS: u32 = 128
/** Tamaño de clave pública individual comprimida (plain) */
export const MUSIG_PUBKEY_SIZE: usize = 33
