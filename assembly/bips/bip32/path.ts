/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip32/path.ts — Derivación por path (BIP32/BIP44)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   bip32_derivePath(childPtr, parentPtr, pathPtr, pathLen) → i32
 *   bip32_deriveAccount(childPtr, parentPtr, purpose, coinType, account) → i32
 *   bip32_deriveAddress(childPtr, parentPtr, purpose, coinType, account, change, idx) → i32
 *
 * El path se parsea byte a byte desde UTF-8 (sin split, sin parseInt, sin
 * alloc). Formato: "m/44'/0'/0'/0/0" (hardened con ', h, o H).
 *
 * Path-walking: alterna entre xkeyA y xkeyB (BIP32_WORK[0..176)) como
 * current/next. bip32_derive() usa BIP32_WORK[176+] internamente → sin solape.
 */
import { BIP32_WORK_PTR, align8 } from "../../utils/arena"
import { HARDENED_OFFSET, BW_XKEY_A, BW_XKEY_B, BIP32_OK, BIP32_ERR_INVALID_PATH } from "./constants"
import { copyXkey } from "./xkey"
import { bip32_derive } from "./ckd"

// ═══════════════════════════════════════════════════════════════════════════
// DERIVE PATH (string UTF-8 → derivación secuencial)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Deriva un xkey siguiendo un path BIP32 en bytes UTF-8.
 * Acepta: "m/44'/0'/0'/0/0", "M/44h/0h/0h", "44'/0'", "m", "".
 *
 * @param childPtr   Destino (≥ 88 B). No debe estar en BIP32_WORK.
 * @param parentPtr  Xkey padre (≥ 88 B).
 * @param pathPtr    Path como bytes UTF-8 (sin null terminator).
 * @param pathLen    Longitud del path en bytes.
 * @returns BIP32_OK o código de error.
 */
function bip32_derivePath(childPtr: usize, parentPtr: usize, pathPtr: usize, pathLen: u32): i32 {
  const work = align8(BIP32_WORK_PTR)
  let cur: usize = work + BW_XKEY_A
  let next: usize = work + BW_XKEY_B

  copyXkey(cur, parentPtr)

  let pos: u32 = 0

  // Skip "m/" o "M/"
  if (pathLen > 0) {
    const c0 = load<u8>(pathPtr)
    if (c0 == 0x6d || c0 == 0x4d) {
      // 'm' o 'M'
      pos = 1
      if (pos < pathLen && load<u8>(pathPtr + pos) == 0x2f) pos++ // skip '/'
    }
  }

  // Parsear segmentos
  while (pos < pathLen) {
    // Skip '/'
    if (load<u8>(pathPtr + pos) == 0x2f) {
      pos++
      continue
    }

    // Parsear un segmento: dígitos + sufijo hardened opcional
    let idx: u32 = 0
    let hardened: bool = false
    let hasDigit: bool = false

    while (pos < pathLen) {
      const c = load<u8>(pathPtr + pos)
      if (c >= 0x30 && c <= 0x39) {
        // Dígito '0'-'9'
        idx = idx * 10 + <u32>(c - 0x30)
        hasDigit = true
        pos++
      } else if (c == 0x27 || c == 0x68 || c == 0x48) {
        // Hardened: ' (apóstrofo), h, H
        hardened = true
        pos++
      } else if (c == 0x2f) {
        // Separador '/'
        pos++
        break
      } else {
        // Carácter inválido
        return BIP32_ERR_INVALID_PATH
      }
    }

    if (!hasDigit) continue // segmento vacío (ej: "m//0"), skip

    const finalIndex: u32 = hardened ? idx + HARDENED_OFFSET : idx
    const rc: i32 = bip32_derive(next, cur, finalIndex)
    if (rc != BIP32_OK) return rc

    // Swap cur ↔ next
    const tmp: usize = cur
    cur = next
    next = tmp
  }

  copyXkey(childPtr, cur)
  return BIP32_OK
}

// ═══════════════════════════════════════════════════════════════════════════
// BIP44 HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Deriva m/purpose'/coinType'/account' (3 niveles hardened).
 */
function bip32_deriveAccount(childPtr: usize, parentPtr: usize, purpose: u32, coinType: u32, account: u32): i32 {
  const work = align8(BIP32_WORK_PTR)
  let cur: usize = work + BW_XKEY_A
  let next: usize = work + BW_XKEY_B
  copyXkey(cur, parentPtr)

  let rc: i32
  let tmp: usize

  rc = bip32_derive(next, cur, purpose + HARDENED_OFFSET)
  if (rc != BIP32_OK) return rc
  tmp = cur
  cur = next
  next = tmp

  rc = bip32_derive(next, cur, coinType + HARDENED_OFFSET)
  if (rc != BIP32_OK) return rc
  tmp = cur
  cur = next
  next = tmp

  rc = bip32_derive(next, cur, account + HARDENED_OFFSET)
  if (rc != BIP32_OK) return rc
  tmp = cur
  cur = next
  next = tmp

  copyXkey(childPtr, cur)
  return BIP32_OK
}

/**
 * Deriva m/purpose'/coinType'/account'/change/addressIndex (5 niveles).
 */
function bip32_deriveAddress(
  childPtr: usize,
  parentPtr: usize,
  purpose: u32,
  coinType: u32,
  account: u32,
  change: u32,
  addressIndex: u32
): i32 {
  const work = align8(BIP32_WORK_PTR)
  let cur: usize = work + BW_XKEY_A
  let next: usize = work + BW_XKEY_B
  copyXkey(cur, parentPtr)

  let rc: i32
  let tmp: usize

  rc = bip32_derive(next, cur, purpose + HARDENED_OFFSET)
  if (rc != BIP32_OK) return rc
  tmp = cur
  cur = next
  next = tmp

  rc = bip32_derive(next, cur, coinType + HARDENED_OFFSET)
  if (rc != BIP32_OK) return rc
  tmp = cur
  cur = next
  next = tmp

  rc = bip32_derive(next, cur, account + HARDENED_OFFSET)
  if (rc != BIP32_OK) return rc
  tmp = cur
  cur = next
  next = tmp

  rc = bip32_derive(next, cur, change)
  if (rc != BIP32_OK) return rc
  tmp = cur
  cur = next
  next = tmp

  rc = bip32_derive(next, cur, addressIndex)
  if (rc != BIP32_OK) return rc
  tmp = cur
  cur = next
  next = tmp

  copyXkey(childPtr, cur)
  return BIP32_OK
}

export { bip32_derivePath as bip32_derive_path }
export { bip32_deriveAccount as bip32_derive_account }
export { bip32_deriveAddress as bip32_derive_address }
