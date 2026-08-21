/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip32/ckd.ts — Child Key Derivation (BIP32 CKDpriv / CKDpub)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   fromSeed(xkeyPtr, seedPtr, seedLen) → i32
 *   ckdPriv(childPtr, parentPtr, index) → i32
 *   ckdPub(childPtr, parentPtr, index)  → i32
 *   derive(childPtr, parentPtr, index)  → i32   (dispatch por isPrivate)
 *
 * Zero-alloc: todos los temporales en BIP32_WORK (offsets fijos) o en
 * CRYPTO_WORK / HASH_WORK (vía las funciones de crypto.ts / hash.ts).
 */
import { BIP32_WORK_PTR, align8 } from "../../utils/memory"
import {
  HARDENED_OFFSET, BITCOIN_SEED, BITCOIN_SEED_LEN,
  BW_HMAC_RESULT, BW_IL, BW_IR, BW_HMAC_DATA, BW_PUBKEY_TMP,
  PRIVKEY_LEN, PUBKEY_LEN,
  BIP32_OK, BIP32_ERR_SEED_LEN, BIP32_ERR_INVALID_KEY,
  BIP32_ERR_HARDENED_FROM_PUB, BIP32_ERR_CHILD_INVALID
} from "./constants"
import { getDepth, isPrivate, chainCodePtr, keyDataPtr, initXkey } from "./xkey"
import { hmacSha512, fingerprint } from "./hash"
import { pubkeyFromPrivkey, pointAddPubkeys, scalarAddModN, isScalarInvalid } from "./crypto"

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/** Escribe un u32 en big-endian (4 bytes) en ptr. */
// @ts-ignore
@inline
function writeU32BE(ptr: usize, val: u32): void {
  store<u8>(ptr,     <u8>(val >> 24))
  store<u8>(ptr + 1, <u8>(val >> 16))
  store<u8>(ptr + 2, <u8>(val >> 8))
  store<u8>(ptr + 3, <u8>(val))
}

// ═══════════════════════════════════════════════════════════════════════════
// FROM SEED (master key)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Genera el master xkey desde una seed BIP39 de 64 bytes.
 * HMAC-SHA512(key="Bitcoin seed", data=seed) → IL (privkey) + IR (chainCode).
 */
 function fromSeed(xkeyPtr: usize, seedPtr: usize, seedLen: u32): i32 {
  if (seedLen < 16 || seedLen > 64) return BIP32_ERR_SEED_LEN

  const work = align8(BIP32_WORK_PTR)

  // Copiar "Bitcoin seed" a hmacData como key (evita .dataStart con stub)
  for (let i: u32 = 0; i < BITCOIN_SEED_LEN; i++) {
    store<u8>(work + BW_HMAC_DATA + i, unchecked(BITCOIN_SEED[<i32>i]))
  }

  // HMAC-SHA512 → IL ‖ IR en BW_HMAC_RESULT
  hmacSha512(work + BW_HMAC_RESULT, work + BW_HMAC_DATA, BITCOIN_SEED_LEN, seedPtr, seedLen)

  // Validar IL (no debe ser 0 ni ≥ N)
  if (isScalarInvalid(work + BW_IL)) return BIP32_ERR_INVALID_KEY

  // depth=0, fp=0, childIdx=0, isPrivate=true, chainCode=IR, keyData=IL
  initXkey(xkeyPtr, 0, 0, 0, true, work + BW_IR, work + BW_IL, PRIVKEY_LEN)
  return BIP32_OK
}

// ═══════════════════════════════════════════════════════════════════════════
// CKDpriv (derivación privada)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * CKDpriv: deriva un hijo privado desde un padre privado.
 *   hardened:     HMAC(chainCode, 0x00 ‖ privkey ‖ index)
 *   non-hardened: HMAC(chainCode, pubkey ‖ index)
 * childKey = (IL + parentKey) mod N
 */
 function ckdPriv(childPtr: usize, parentPtr: usize, index: u32): i32 {
  const work = align8(BIP32_WORK_PTR)
  const isHardened: bool = index >= HARDENED_OFFSET

  // 1. Pubkey del padre (para fingerprint y para hmacData non-hardened)
  pubkeyFromPrivkey(work + BW_PUBKEY_TMP, keyDataPtr(parentPtr))

  // 2. Fingerprint del padre
  const fp: u32 = fingerprint(work + BW_PUBKEY_TMP)

  // 3. Construir hmacData (37 bytes)
  if (isHardened) {
    // 0x00 ‖ privkey(32) ‖ index_BE(4)
    store<u8>(work + BW_HMAC_DATA, 0x00)
    memory.copy(work + BW_HMAC_DATA + 1, keyDataPtr(parentPtr), PRIVKEY_LEN)
    writeU32BE(work + BW_HMAC_DATA + 33, index)
  } else {
    // pubkey(33) ‖ index_BE(4)
    memory.copy(work + BW_HMAC_DATA, work + BW_PUBKEY_TMP, PUBKEY_LEN)
    writeU32BE(work + BW_HMAC_DATA + 33, index)
  }

  // 4. HMAC-SHA512(chainCode, hmacData) → IL ‖ IR
  hmacSha512(work + BW_HMAC_RESULT, chainCodePtr(parentPtr), 32, work + BW_HMAC_DATA, 37)

  // 5. Validar IL
  if (isScalarInvalid(work + BW_IL)) return BIP32_ERR_INVALID_KEY

  // 6. childKey = (IL + parentKey) mod N  (aliasing-safe: IL se copia antes de escribir)
  scalarAddModN(work + BW_IL, work + BW_IL, keyDataPtr(parentPtr))

  // 7. Validar childKey
  if (isScalarInvalid(work + BW_IL)) return BIP32_ERR_CHILD_INVALID

  // 8. Construir child xkey
  initXkey(
    childPtr,
    getDepth(parentPtr) + 1,
    fp,
    index,
    true,
    work + BW_IR,
    work + BW_IL,
    PRIVKEY_LEN
  )
  return BIP32_OK
}

// ═══════════════════════════════════════════════════════════════════════════
// CKDpub (derivación pública)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * CKDpub: deriva un hijo público desde un padre público (solo non-hardened).
 * childPub = point(IL) + parentPub
 */
function ckdPub(childPtr: usize, parentPtr: usize, index: u32): i32 {
  if (index >= HARDENED_OFFSET) return BIP32_ERR_HARDENED_FROM_PUB
  const work = align8(BIP32_WORK_PTR)

  // 1. hmacData = pubkey(33) ‖ index_BE(4)
  memory.copy(work + BW_HMAC_DATA, keyDataPtr(parentPtr), PUBKEY_LEN)
  writeU32BE(work + BW_HMAC_DATA + 33, index)

  // 2. HMAC-SHA512(chainCode, hmacData) → IL ‖ IR
  hmacSha512(work + BW_HMAC_RESULT, chainCodePtr(parentPtr), 32, work + BW_HMAC_DATA, 37)

  // 3. Validar IL
  if (isScalarInvalid(work + BW_IL)) return BIP32_ERR_INVALID_KEY

  // 4. childPub = point(IL) + parentPub → compressed (33 B)
  // ✅ FIX (BLOQUE 3): propagar error si la pubkey del padre está fuera de la curva
  const rcAdd: i32 = pointAddPubkeys(work + BW_PUBKEY_TMP, keyDataPtr(parentPtr), work + BW_IL)
  if (rcAdd != BIP32_OK) return rcAdd

  // 5. Fingerprint del padre
  const fp: u32 = fingerprint(keyDataPtr(parentPtr))

  // 6. Construir child xkey (público)
  initXkey(
    childPtr,
    getDepth(parentPtr) + 1,
    fp,
    index,
    false,
    work + BW_IR,
    work + BW_PUBKEY_TMP,
    PUBKEY_LEN
  )
  return BIP32_OK
}

// ═══════════════════════════════════════════════════════════════════════════
// DISPATCH
// ═══════════════════════════════════════════════════════════════════════════

/** Deriva un hijo (dispatch automático: CKDpriv si el padre es privado, CKDpub si es público). */
 function derive(childPtr: usize, parentPtr: usize, index: u32): i32 {
  if (isPrivate(parentPtr)) {
    return ckdPriv(childPtr, parentPtr, index)
  }
  return ckdPub(childPtr, parentPtr, index)
}

export { fromSeed as bip32_from_seed }
export { derive as bip32_derive }
export { ckdPriv as bip32_ckd_priv }
export { ckdPub as bip32_ckd_pub }