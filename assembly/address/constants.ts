/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  address/constants.ts — Constantes y layout de ADDRESS_WORK
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Offsets RELATIVOS a ADDRESS_WORK_PTR (ver memory.ts). Los buffers se usan
 * de forma secuencial/disjunta dentro de cada función de address/.
 *
 * Version bytes (BIP32 / Bitcoin):
 *   P2PKH mainnet payload prefix = 0x00
 *   P2SH  mainnet payload prefix = 0x05
 *
 * tagHash = SHA256("TapTweak") (BIP-341), como StaticArray (data segment).
 */

// ── Version bytes ─────────────────────────────────────────────────────────
export const VER_P2PKH: u8 = 0x00
export const VER_P2SH: u8 = 0x05

// ── tagHash = SHA256("TapTweak") ──────────────────────────────────────────
export const TAP_TWEAK_TAG_HASH: StaticArray<u8> = [
  0xe8, 0x0f, 0xe1, 0x63, 0x9c, 0x9c, 0xa0, 0x50,
  0xe3, 0xaf, 0x1b, 0x39, 0xc1, 0x43, 0xc6, 0x3e,
  0x42, 0x9c, 0xbc, 0xeb, 0x15, 0xd9, 0x40, 0xfb,
  0xb5, 0xc5, 0xa1, 0xf4, 0xaf, 0x57, 0xc5, 0xe9
]

// ── Layout de ADDRESS_WORK (offsets relativos) ────────────────────────────
export const AW_SHA256_TMP: usize = 0     // 32 B  (intermedio hash160)
export const AW_RIPEMD_TMP: usize = 32    // 20 B  (hash160)
export const AW_PAYLOAD: usize = 64       // 32 B  (redeemScript 22 / payload 21)
export const AW_BECH32_DATA: usize = 128  // 64 B  (grupos 5-bit + witness)
export const AW_XBUF: usize = 192         // 33 B  (x-only con prefijo / hrp "bc")
export const AW_TAPROOT_MSG: usize = 256  // 96 B  (tagHash‖tagHash‖xOnly)
export const AW_TWEAK: usize = 352        // 32 B  (tweak = SHA256(msg))
export const AW_P: usize = 384            // 96 B  (punto P Jacobiano)
export const AW_T: usize = 480            // 96 B  (punto T = t·G)
export const AW_Q: usize = 576            // 96 B  (Q = P + T)
export const AW_ETH_HEX: usize = 672      // 40 B  (hex lowercase de 20 B)
export const AW_ETH_UNCOMP: usize = 720   // 65 B  (uncompressed para ETH)

// ── Códigos de error ──────────────────────────────────────────────────────
export const ADDR_OK: i32 = 0
export const ADDR_ERR_PUBKEY: i32 = -1   // pubkey malformada
export const ADDR_ERR_CONVERT: i32 = -2  // convertBits falló