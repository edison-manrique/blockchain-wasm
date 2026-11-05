/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip32/serialize.ts — Serialización xpub/xprv (BIP32, 78 bytes + Base58Check)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Estructura BIP32 serializada (78 bytes):
 *   [0..4]    version       (xpub: 0488B21E, xprv: 0488ADE4)
 *   [4]       depth         (1 byte)
 *   [5..9]    parentFP      (4 bytes big-endian)
 *   [9..13]   childIndex    (4 bytes big-endian)
 *   [13..45]  chainCode     (32 bytes)
 *   [45..78]  keyData       (xpub: pubkey 33 B; xprv: 0x00 + privkey 32 B)
 *
 * Zero-alloc: el buffer de 78 bytes va en BIP32_WORK[BW_SERIALIZE_BUF].
 * Base58Check usa HASH_WORK internamente. Pubkey usa CRYPTO_WORK.
 * Todo disjunto.
 *
 *   bip32_serialize_xpub(outPtr, xkeyPtr) → outLen | -1
 *   bip32_serialize_xprv(outPtr, xkeyPtr) → outLen | -1
 *   bip32_deserialize(xkeyPtr, srcPtr, srcLen) → i32
 */
import { BIP32_WORK_PTR, align8 } from "../../utils/arena"
import {
  OFF_DEPTH, OFF_PARENT_FP, OFF_CHILD_IDX, OFF_IS_PRIVATE,
  OFF_CHAIN_CODE, OFF_KEY_DATA,
  BW_SERIALIZE_BUF, BW_PUBKEY_TMP,
  BIP32_OK, BIP32_ERR_NOT_PRIVATE
} from "./constants"
import { isPrivate, chainCodePtr, keyDataPtr, initXkey } from "./xkey"
import { pubkeyFromPrivkey } from "./crypto"
import {
  base58check_encode_raw, base58check_decode_raw,
  base58_indices_to_ascii, base58_ascii_to_indices
} from "../../utils/base58"

// ═══════════════════════════════════════════════════════════════════════════
// VERSIONES
// ═══════════════════════════════════════════════════════════════════════════

// xpub: 0x0488B21E
const VER_XPUB_0: u8 = 0x04
const VER_XPUB_1: u8 = 0x88
const VER_XPUB_2: u8 = 0xb2
const VER_XPUB_3: u8 = 0x1e

// xprv: 0x0488ADE4
const VER_XPRV_0: u8 = 0x04
const VER_XPRV_1: u8 = 0x88
const VER_XPRV_2: u8 = 0xad
const VER_XPRV_3: u8 = 0xe4

const SER_LEN: usize = 78

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

// @ts-ignore
@inline
function writeU32BE(ptr: usize, val: u32): void {
  store<u8>(ptr,     <u8>(val >> 24))
  store<u8>(ptr + 1, <u8>(val >> 16))
  store<u8>(ptr + 2, <u8>(val >> 8))
  store<u8>(ptr + 3, <u8>(val))
}

// @ts-ignore
@inline
function readU32BE(ptr: usize): u32 {
  return (
    (<u32>load<u8>(ptr)     << 24) |
    (<u32>load<u8>(ptr + 1) << 16) |
    (<u32>load<u8>(ptr + 2) << 8)  |
    (<u32>load<u8>(ptr + 3))
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// SERIALIZE (xkey → 78 bytes → Base58Check → ASCII en outPtr)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Serializa un xkey a Base58Check (xpub o xprv).
 * Escribe el string ASCII en outPtr. Retorna la longitud, o -1 si error.
 *
 * @param outPtr   Buffer de salida (≥ 120 B). Típicamente PARAM_OUT.
 * @param xkeyPtr  Xkey a serializar (≥ 88 B).
 * @param wantXpub true = xpub, false = xprv.
 */
function serializeRaw(outPtr: usize, xkeyPtr: usize, wantXpub: bool): i32 {
  const work = align8(BIP32_WORK_PTR)
  const buf = work + BW_SERIALIZE_BUF // 78 bytes
  const priv: bool = isPrivate(xkeyPtr)

  // xprv desde clave pública → error
  if (!wantXpub && !priv) return BIP32_ERR_NOT_PRIVATE

  // ── Version (4 bytes) ──
  if (wantXpub) {
    store<u8>(buf + 0, VER_XPUB_0)
    store<u8>(buf + 1, VER_XPUB_1)
    store<u8>(buf + 2, VER_XPUB_2)
    store<u8>(buf + 3, VER_XPUB_3)
  } else {
    store<u8>(buf + 0, VER_XPRV_0)
    store<u8>(buf + 1, VER_XPRV_1)
    store<u8>(buf + 2, VER_XPRV_2)
    store<u8>(buf + 3, VER_XPRV_3)
  }

  // ── Depth (1 byte) ──
  store<u8>(buf + 4, load<u8>(xkeyPtr + OFF_DEPTH))

  // ── Parent fingerprint (4 bytes BE) ──
  writeU32BE(buf + 5, load<u32>(xkeyPtr + OFF_PARENT_FP))

  // ── Child index (4 bytes BE) ──
  writeU32BE(buf + 9, load<u32>(xkeyPtr + OFF_CHILD_IDX))

  // ── Chain code (32 bytes) ──
  memory.copy(buf + 13, chainCodePtr(xkeyPtr), 32)

  // ── Key data (33 bytes) ──
  if (wantXpub) {
    if (priv) {
      // Calcular pubkey desde la clave privada
      pubkeyFromPrivkey(work + BW_PUBKEY_TMP, keyDataPtr(xkeyPtr))
      memory.copy(buf + 45, work + BW_PUBKEY_TMP, 33)
    } else {
      // Ya es pública: copiar keyData (33 B)
      memory.copy(buf + 45, keyDataPtr(xkeyPtr), 33)
    }
  } else {
    // xprv: 0x00 + privkey(32)
    store<u8>(buf + 45, 0x00)
    memory.copy(buf + 46, keyDataPtr(xkeyPtr), 32)
  }

  // ── Base58Check encode → índices en outPtr ──
  const idxLen: u32 = base58check_encode_raw(outPtr, buf, <u32>SER_LEN)
  if (idxLen == 0) return -1

  // ── Índices → ASCII (in-place en outPtr) ──
  base58_indices_to_ascii(outPtr, idxLen)

  return <i32>idxLen
}

/** Serializa un xkey como xpub (Base58Check). Retorna longitud ASCII o -1. */
export function bip32_serialize_xpub(outPtr: usize, xkeyPtr: usize): i32 {
  return serializeRaw(outPtr, xkeyPtr, true)
}

/** Serializa un xkey como xprv (Base58Check). Retorna longitud ASCII o -1. */
export function bip32_serialize_xprv(outPtr: usize, xkeyPtr: usize): i32 {
  return serializeRaw(outPtr, xkeyPtr, false)
}

// ═══════════════════════════════════════════════════════════════════════════
// DESERIALIZE (ASCII → Base58Check decode → 78 bytes → xkey)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Deserializa un string xpub/xprv (ASCII) a un xkey.
 *
 * @param xkeyPtr  Destino (≥ 88 B).
 * @param srcPtr   String ASCII en memoria (se modifica in-place: ASCII → índices).
 * @param srcLen   Longitud del string.
 * @returns BIP32_OK, o código de error.
 */
export function bip32_deserialize(xkeyPtr: usize, srcPtr: usize, srcLen: u32): i32 {
  const work = align8(BIP32_WORK_PTR)
  const buf = work + BW_SERIALIZE_BUF

  // ASCII → índices (in-place en srcPtr)
  const rc: i32 = base58_ascii_to_indices(srcPtr, srcLen)
  if (rc != 0) return -1

  // Base58Check decode → 78 bytes en buf
  const payloadLen: i32 = base58check_decode_raw(buf, srcPtr, srcLen)
  if (payloadLen != <i32>SER_LEN) return -1 // debe ser exactamente 78

  // ── Parsear version ──
  const v2: u8 = load<u8>(buf + 2)
  let isXpub: bool
  if (v2 == VER_XPUB_2) {
    isXpub = true
  } else if (v2 == VER_XPRV_2) {
    isXpub = false
  } else {
    return -1 // versión desconocida
  }

  // ── Parsear campos ──
  const depth: u32 = <u32>load<u8>(buf + 4)
  const parentFP: u32 = readU32BE(buf + 5)
  const childIdx: u32 = readU32BE(buf + 9)
  const chainPtr: usize = buf + 13

  if (isXpub) {
    // keyData = pubkey (33 bytes en buf+45)
    initXkey(xkeyPtr, depth, parentFP, childIdx, false, chainPtr, buf + 45, 33)
  } else {
    // keyData = 0x00 + privkey (32 bytes en buf+46)
    if (load<u8>(buf + 45) != 0x00) return -1 // prefijo inválido
    initXkey(xkeyPtr, depth, parentFP, childIdx, true, chainPtr, buf + 46, 32)
  }

  return BIP32_OK
}