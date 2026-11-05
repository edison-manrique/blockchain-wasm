/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip44/index.ts — BIP44 Multi-Account Hierarchy (wrapper zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * BIP44: m / purpose' / coin_type' / account' / change / address_index
 *
 * Este módulo es un wrapper fino que compone BIP32 + BIP39 + serialize.
 * NO tiene lógica criptográfica propia.
 *
 * ── API ───────────────────────────────────────────────────────────────────
 *   bip44_derive_leaf(outPriv, outPub, seedPtr, seedLen, p, c, a, ch, idx) → i32
 *   bip44_derive_privkey(out32, seedPtr, seedLen, p, c, a, ch, idx) → i32
 *   bip44_derive_pubkey(out33, seedPtr, seedLen, p, c, a, ch, idx) → i32
 *   bip44_account_xpub(outPtr, seedPtr, seedLen, p, c, a) → outLen | -1
 *   bip44_account_xprv(outPtr, seedPtr, seedLen, p, c, a) → outLen | -1
 *   bip44_from_mnemonic_derive(outPriv, outPub, mnPtr, mnLen, passPtr, passLen, p, c, a, ch, idx) → i32
 *   bip44_from_mnemonic_xpub(outPtr, mnPtr, mnLen, passPtr, passLen, p, c, a) → outLen | -1
 *   bip44_from_mnemonic_xprv(outPtr, mnPtr, mnLen, passPtr, passLen, p, c, a) → outLen | -1
 */
import { BIP32_WORK_PTR, align8, PARAM_IN_PTR, PARAM_OUT_PTR } from "../utils/arena"
import {
  bip32_from_seed,
  bip32_derive_account,
  bip32_derive_address,
  bip32_get_pubkey,
  bip32_serialize_xpub,
  bip32_serialize_xprv,
} from "./bip32"
import { bip39_mnemonic_to_seed } from "./bip39"
import {
  BW_XKEY_A,
  BW_XKEY_B,
  BW_SERIALIZE_BUF,
  OFF_KEY_DATA,
  HARDENED_OFFSET,
  PRIVKEY_LEN,
  PUBKEY_LEN,
  BIP44_PURPOSE,
  BIP49_PURPOSE,
  BIP84_PURPOSE,
  BIP86_PURPOSE,
  COIN_BTC,
  COIN_BTC_TESTNET,
  COIN_ETH,
  BIP32_OK,
} from "./bip32/constants"

// ── Re-exports (constantes y utilidades) ──────────────────────────────────
export { PARAM_IN_PTR, PARAM_OUT_PTR }
export {
  HARDENED_OFFSET,
  BIP44_PURPOSE,
  BIP49_PURPOSE,
  BIP84_PURPOSE,
  BIP86_PURPOSE,
  COIN_BTC,
  COIN_BTC_TESTNET,
  COIN_ETH,
}

// ── Re-exports BIP39 (para conveniencia del wrapper TS) ───────────────────
export { bip39_mnemonic_to_seed, bip39_validate_mnemonic, bip39_entropy_to_mnemonic } from "./bip39"

// ═══════════════════════════════════════════════════════════════════════════
// DERIVACIÓN DESDE SEED
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Deriva privkey (32 B) + pubkey (33 B) para un leaf BIP44.
 * outPriv y outPub pueden ser cualquier puntero (PARAM_OUT, etc.).
 */
export function bip44_derive_leaf(
  outPriv32: usize,
  outPub33: usize,
  seedPtr: usize,
  seedLen: u32,
  purpose: u32,
  coinType: u32,
  account: u32,
  change: u32,
  addressIndex: u32,
): i32 {
  const work = align8(BIP32_WORK_PTR)
  const master = work + BW_XKEY_A
  const childXkey = work + BW_XKEY_B // BW_XKEY_B (88 B)
  const rc1 = bip32_from_seed(master, seedPtr, seedLen)
  if (rc1 != BIP32_OK) return rc1
  const rc2 = bip32_derive_address(childXkey, master, purpose, coinType, account, change, addressIndex)
  if (rc2 != BIP32_OK) return rc2
  bip32_get_pubkey(outPub33, childXkey)
  memory.copy(outPriv32, childXkey + OFF_KEY_DATA, PRIVKEY_LEN)
  return BIP32_OK
}

/** Deriva solo la privkey (32 B) para un leaf BIP44. */
export function bip44_derive_privkey(
  out32: usize,
  seedPtr: usize,
  seedLen: u32,
  purpose: u32,
  coinType: u32,
  account: u32,
  change: u32,
  addressIndex: u32,
): i32 {
  const work = align8(BIP32_WORK_PTR)
  const master = work + BW_XKEY_A
  const childXkey = work + 88 // BW_XKEY_B

  const rc1 = bip32_from_seed(master, seedPtr, seedLen)
  if (rc1 != BIP32_OK) return rc1

  const rc2 = bip32_derive_address(childXkey, master, purpose, coinType, account, change, addressIndex)
  if (rc2 != BIP32_OK) return rc2

  memory.copy(out32, childXkey + OFF_KEY_DATA, PRIVKEY_LEN)
  return BIP32_OK
}

/** Deriva solo la pubkey (33 B) para un leaf BIP44. */
export function bip44_derive_pubkey(
  out33: usize,
  seedPtr: usize,
  seedLen: u32,
  purpose: u32,
  coinType: u32,
  account: u32,
  change: u32,
  addressIndex: u32,
): i32 {
  const work = align8(BIP32_WORK_PTR)
  const master = work + BW_XKEY_A
  const childXkey = work + 88 // BW_XKEY_B

  const rc1 = bip32_from_seed(master, seedPtr, seedLen)
  if (rc1 != BIP32_OK) return rc1

  const rc2 = bip32_derive_address(childXkey, master, purpose, coinType, account, change, addressIndex)
  if (rc2 != BIP32_OK) return rc2

  return bip32_get_pubkey(out33, childXkey)
}

// ═══════════════════════════════════════════════════════════════════════════
// ACCOUNT-LEVEL XPUB / XPRV
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Serializa el xpub de la cuenta BIP44: m/purpose'/coinType'/account'.
 * Escribe ASCII en outPtr. Retorna longitud o -1.
 */
export function bip44_account_xpub(
  outPtr: usize,
  seedPtr: usize,
  seedLen: u32,
  purpose: u32,
  coinType: u32,
  account: u32,
): i32 {
  const work = align8(BIP32_WORK_PTR)
  const master = work + BW_XKEY_A
  const childXkey = work + 88

  const rc1 = bip32_from_seed(master, seedPtr, seedLen)
  if (rc1 != BIP32_OK) return rc1

  const rc2 = bip32_derive_account(childXkey, master, purpose, coinType, account)
  if (rc2 != BIP32_OK) return rc2

  return bip32_serialize_xpub(outPtr, childXkey)
}

/**
 * Serializa el xprv de la cuenta BIP44: m/purpose'/coinType'/account'.
 * Escribe ASCII en outPtr. Retorna longitud o -1.
 */
export function bip44_account_xprv(
  outPtr: usize,
  seedPtr: usize,
  seedLen: u32,
  purpose: u32,
  coinType: u32,
  account: u32,
): i32 {
  const work = align8(BIP32_WORK_PTR)
  const master = work + BW_XKEY_A
  const childXkey = work + 88

  const rc1 = bip32_from_seed(master, seedPtr, seedLen)
  if (rc1 != BIP32_OK) return rc1

  const rc2 = bip32_derive_account(childXkey, master, purpose, coinType, account)
  if (rc2 != BIP32_OK) return rc2

  return bip32_serialize_xprv(outPtr, childXkey)
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPOSICIÓN: MNEMONIC → SEED → DERIVE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Pipeline completo: mnemonic → seed → leaf keys (priv + pub).
 * La seed (64 B) se almacena temporalmente en BIP32_WORK[BW_SERIALIZE_BUF].
 */
export function bip44_from_mnemonic_derive(
  outPriv32: usize,
  outPub33: usize,
  mnPtr: usize,
  mnLen: u32,
  passPtr: usize,
  passLen: u32,
  purpose: u32,
  coinType: u32,
  account: u32,
  change: u32,
  addressIndex: u32,
): i32 {
  const work = align8(BIP32_WORK_PTR)
  const seedBuf = work + BW_SERIALIZE_BUF // 64 B de seed (caben en 78 B)

  bip39_mnemonic_to_seed(seedBuf, mnPtr, mnLen, passPtr, passLen)

  return bip44_derive_leaf(outPriv32, outPub33, seedBuf, 64, purpose, coinType, account, change, addressIndex)
}

/** Pipeline: mnemonic → seed → account xpub. */
export function bip44_from_mnemonic_xpub(
  outPtr: usize,
  mnPtr: usize,
  mnLen: u32,
  passPtr: usize,
  passLen: u32,
  purpose: u32,
  coinType: u32,
  account: u32,
): i32 {
  const work = align8(BIP32_WORK_PTR)
  const seedBuf = work + BW_SERIALIZE_BUF

  bip39_mnemonic_to_seed(seedBuf, mnPtr, mnLen, passPtr, passLen)

  return bip44_account_xpub(outPtr, seedBuf, 64, purpose, coinType, account)
}

/** Pipeline: mnemonic → seed → account xprv. */
export function bip44_from_mnemonic_xprv(
  outPtr: usize,
  mnPtr: usize,
  mnLen: u32,
  passPtr: usize,
  passLen: u32,
  purpose: u32,
  coinType: u32,
  account: u32,
): i32 {
  const work = align8(BIP32_WORK_PTR)
  const seedBuf = work + BW_SERIALIZE_BUF

  bip39_mnemonic_to_seed(seedBuf, mnPtr, mnLen, passPtr, passLen)

  return bip44_account_xprv(outPtr, seedBuf, 64, purpose, coinType, account)
}
