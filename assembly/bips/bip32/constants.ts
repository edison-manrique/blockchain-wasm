/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip32/constants.ts — Constantes, offsets y códigos de error de BIP32
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Todo es compile-time (StaticArray / const). Sin heap, sin ejecución en
 * _start. Los offsets del xkey y de BIP32_WORK son relativos a la base que
 * el caller (o memory.ts) provea.
 */

// ═══════════════════════════════════════════════════════════════════════════
// BIP32 FUNDAMENTALS
// ═══════════════════════════════════════════════════════════════════════════

/** Offset que marca derivación hardened (BIP32). */
export const HARDENED_OFFSET: u32 = 0x80000000

/** "Bitcoin seed" — clave HMAC para generar el master key desde la seed. */
export const BITCOIN_SEED: StaticArray<u8> = [0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64] // B  i  t  c  o  i  n  (sp) s  e  e  d
export const BITCOIN_SEED_LEN: u32 = 12

// ═══════════════════════════════════════════════════════════════════════════
// EXPONENTE (P+1)/4 — para sqrt mod P (P ≡ 3 mod 4)
// P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
// (P+1)/4 en 4 limbs u64 little-endian:
// ═══════════════════════════════════════════════════════════════════════════

export const EXP_P14_0: u64 = 0xffffffffbfffff0c
export const EXP_P14_1: u64 = 0xffffffffffffffff
export const EXP_P14_2: u64 = 0xffffffffffffffff
export const EXP_P14_3: u64 = 0x3fffffffffffffff

// ═══════════════════════════════════════════════════════════════════════════
// LAYOUT DEL XKEY (extended key sobre puntero, 88 bytes alineados a 8)
// ═══════════════════════════════════════════════════════════════════════════
//
//  offset  tamaño  campo
//  [0]     1       depth (u8)
//  [4]     4       parentFingerprint (u32, LE interno)
//  [8]     4       childIndex (u32)
//  [12]    1       isPrivate (u8: 1=priv, 0=pub)
//  [16]    32      chainCode
//  [48]    33      keyData (priv: 32 B; pub: 33 B compressed)
//  → total 81 → pad a 88
// ═══════════════════════════════════════════════════════════════════════════

export const XKEY_SIZE: usize = 88

export const OFF_DEPTH: usize = 0
export const OFF_PARENT_FP: usize = 4
export const OFF_CHILD_IDX: usize = 8
export const OFF_IS_PRIVATE: usize = 12
export const OFF_CHAIN_CODE: usize = 16
export const OFF_KEY_DATA: usize = 48

export const CHAIN_CODE_LEN: usize = 32
export const PRIVKEY_LEN: usize = 32
export const PUBKEY_LEN: usize = 33 // compressed (0x02/0x03 + 32 B)

// ═══════════════════════════════════════════════════════════════════════════
// LAYOUT INTERNO DE BIP32_WORK (512 B, offsets relativos a BIP32_WORK_PTR)
// ═══════════════════════════════════════════════════════════════════════════
//
//  [0   .. 88)   xkeyA       ← path-walking (alterna con xkeyB)
//  [88  .. 176)  xkeyB       ← path-walking
//  [176 .. 240)  hmacResult  ← 64 B: IL=[176..208), IR=[208..240)
//  [240 .. 280)  hmacData    ← 37 B (0x00||privkey||index  o  pubkey||index)
//  [280 .. 320)  pubkeyTmp   ← 33 B compressed pubkey
//  [320 .. 352)  sha256Tmp   ← 32 B (intermedio hash160)
//  [352 .. 376)  hash160Tmp  ← 20 B (fingerprint)
//  [376 .. 512)  libre
// ═══════════════════════════════════════════════════════════════════════════

export const BIP32_WORK_SIZE: usize = 512

export const BW_XKEY_A: usize = 0
export const BW_XKEY_B: usize = 88
export const BW_HMAC_RESULT: usize = 176
export const BW_IL: usize = 176 // alias: IL = hmacResult[0..32)
export const BW_IR: usize = 208 // alias: IR = hmacResult[32..64)
export const BW_HMAC_DATA: usize = 240
export const BW_PUBKEY_TMP: usize = 280
export const BW_SHA256_TMP: usize = 320
export const BW_HASH160_TMP: usize = 352

/** Longitud del buffer HMAC: max(1+32+4, 33+4) = 37. */
export const HMAC_DATA_LEN: usize = 37
/** Buffer de serialización xpub/xprv (78 bytes). Zona libre tras BW_HASH160_TMP. */
export const BW_SERIALIZE_BUF: usize = 376

// ═══════════════════════════════════════════════════════════════════════════
// CÓDIGOS DE ERROR (retorno i32; 0 = OK)
// ═══════════════════════════════════════════════════════════════════════════

export const BIP32_OK: i32 = 0
export const BIP32_ERR_SEED_LEN: i32 = -1 // seed ≠ 64 bytes
export const BIP32_ERR_INVALID_KEY: i32 = -2 // IL es 0 o ≥ N
export const BIP32_ERR_HARDENED_FROM_PUB: i32 = -3 // hardened desde xpub
export const BIP32_ERR_INVALID_PATH: i32 = -4 // path malformado
export const BIP32_ERR_CHILD_INVALID: i32 = -5 // child key resulta 0 o ≥ N
export const BIP32_ERR_NOT_PRIVATE: i32 = -6 // operación requiere xprv
export const BIP32_ERR_PUBKEY_INVALID: i32 = -7 // ✅ NUEVO: pubkey fuera de la curva (CKDpub)

// ═══════════════════════════════════════════════════════════════════════════
// BIP44 / BIP84 / BIP86 — propósitos y coin types frecuentes
// ═══════════════════════════════════════════════════════════════════════════

export const BIP44_PURPOSE: u32 = 44 // m/44'  (legacy P2PKH)
export const BIP49_PURPOSE: u32 = 49 // m/49'  (P2WPKH-nested-in-P2SH)
export const BIP84_PURPOSE: u32 = 84 // m/84'  (native SegWit P2WPKH)
export const BIP86_PURPOSE: u32 = 86 // m/86'  (Taproot P2TR)

export const COIN_BTC: u32 = 0 // Bitcoin mainnet
export const COIN_BTC_TESTNET: u32 = 1 // Bitcoin testnet
export const COIN_ETH: u32 = 60 // Ethereum
