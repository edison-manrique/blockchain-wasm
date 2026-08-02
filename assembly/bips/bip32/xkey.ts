/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip32/xkey.ts — Extended key como struct sobre puntero (zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Un "xkey" es un bloque de XKEY_SIZE (88) bytes en memoria lineal.
 * Todas las funciones son loads/stores directos — sin heap, sin objetos,
 * sin alloc. El caller posee el buffer (PARAM_IN/OUT, BIP32_WORK, o donde
 * el wrapper TS lo reserve).
 *
 * Layout (ver constants.ts):
 *   [0]  depth | [4] parentFP | [8] childIdx | [12] isPrivate
 *   [16] chainCode(32) | [48] keyData(33)
 */
import {
  XKEY_SIZE,
  OFF_DEPTH,
  OFF_PARENT_FP,
  OFF_CHILD_IDX,
  OFF_IS_PRIVATE,
  OFF_CHAIN_CODE,
  OFF_KEY_DATA,
  CHAIN_CODE_LEN,
  PUBKEY_LEN,
} from "./constants"

// ═══════════════════════════════════════════════════════════════════════════
// GETTERS (lectura de campos)
// ═══════════════════════════════════════════════════════════════════════════

// @ts-ignore
@inline
export function getDepth(ptr: usize): u32 {
  return <u32>load<u8>(ptr + OFF_DEPTH)
}

// @ts-ignore
@inline
export function getParentFingerprint(ptr: usize): u32 {
  return load<u32>(ptr + OFF_PARENT_FP)
}

// @ts-ignore
@inline
export function getChildIndex(ptr: usize): u32 {
  return load<u32>(ptr + OFF_CHILD_IDX)
}

// @ts-ignore
@inline
export function isPrivate(ptr: usize): bool {
  return load<u8>(ptr + OFF_IS_PRIVATE) != 0
}

/** Puntero al chainCode (32 B) dentro del xkey. */
// @ts-ignore
@inline
export function chainCodePtr(ptr: usize): usize {
  return ptr + OFF_CHAIN_CODE
}

/** Puntero al keyData (32 B priv / 33 B pub) dentro del xkey. */
// @ts-ignore
@inline
export function keyDataPtr(ptr: usize): usize {
  return ptr + OFF_KEY_DATA
}

// ═══════════════════════════════════════════════════════════════════════════
// SETTERS (escritura de campos)
// ═══════════════════════════════════════════════════════════════════════════

// @ts-ignore
@inline
export function setDepth(ptr: usize, val: u32): void {
  store<u8>(ptr + OFF_DEPTH, <u8>val)
}

// @ts-ignore
@inline
export function setParentFingerprint(ptr: usize, val: u32): void {
  store<u32>(ptr + OFF_PARENT_FP, val)
}

// @ts-ignore
@inline
export function setChildIndex(ptr: usize, val: u32): void {
  store<u32>(ptr + OFF_CHILD_IDX, val)
}

// @ts-ignore
@inline
export function setPrivate(ptr: usize, priv: bool): void {
  store<u8>(ptr + OFF_IS_PRIVATE, priv ? 1 : 0)
}

// ═══════════════════════════════════════════════════════════════════════════
// OPERACIONES ESTRUCTURALES
// ═══════════════════════════════════════════════════════════════════════════

/** Copia completa de un xkey (88 B). */
// @ts-ignore
@inline
export function copyXkey(dst: usize, src: usize): void {
  memory.copy(dst, src, XKEY_SIZE)
}

/**
 * Inicializa un xkey con todos sus campos.
 *
 * @param ptr       Destino (≥ 88 B).
 * @param depth     Profundidad (0 = master).
 * @param fp        Parent fingerprint (0 = master).
 * @param childIdx  Child index (0 = master).
 * @param priv      true = clave privada.
 * @param chainPtr  Puntero a 32 B de chain code.
 * @param keyPtr    Puntero a keyData (32 B si priv, 33 B si pub).
 * @param keyLen    32 (priv) o 33 (pub).
 */
export function initXkey(
  ptr: usize,
  depth: u32,
  fp: u32,
  childIdx: u32,
  priv: bool,
  chainPtr: usize,
  keyPtr: usize,
  keyLen: usize
): void {
  // Zero-fill para limpiar padding y bytes no usados
  memory.fill(ptr, 0, XKEY_SIZE)

  store<u8>(ptr + OFF_DEPTH, <u8>depth)
  store<u32>(ptr + OFF_PARENT_FP, fp)
  store<u32>(ptr + OFF_CHILD_IDX, childIdx)
  store<u8>(ptr + OFF_IS_PRIVATE, priv ? 1 : 0)
  memory.copy(ptr + OFF_CHAIN_CODE, chainPtr, CHAIN_CODE_LEN)
  memory.copy(ptr + OFF_KEY_DATA, keyPtr, keyLen)
}

/**
 * Neuter estructural: copia el xkey privado a `dst`, marca isPrivate=0 y
 * reemplaza keyData con la clave pública comprimida (33 B) que el caller
 * ya computó (usando crypto.pubkeyFromPrivkey).
 *
 * @param dst         Xkey destino (≥ 88 B).
 * @param src         Xkey privado fuente.
 * @param pubkey33Ptr Puntero a 33 B de pubkey comprimida (ya calculada).
 */
export function neuterRaw(dst: usize, src: usize, pubkey33Ptr: usize): void {
  // Copiar metadata (depth, fp, childIdx) + chainCode
  memory.copy(dst, src, OFF_CHAIN_CODE + CHAIN_CODE_LEN) // [0..48)
  // Marcar como público
  store<u8>(dst + OFF_IS_PRIVATE, 0)
  // Limpiar keyData y escribir pubkey
  memory.fill(dst + OFF_KEY_DATA, 0, 33)
  memory.copy(dst + OFF_KEY_DATA, pubkey33Ptr, PUBKEY_LEN)
}

/**
 * Escribe el chainCode desde un puntero externo (ej: IR del HMAC).
 */
// @ts-ignore
@inline
export function setChainCode(ptr: usize, src32: usize): void {
  memory.copy(ptr + OFF_CHAIN_CODE, src32, CHAIN_CODE_LEN)
}

/**
 * Escribe el keyData desde un puntero externo.
 * @param keyLen 32 (priv) o 33 (pub).
 */
// @ts-ignore
@inline
export function setKeyData(ptr: usize, srcPtr: usize, keyLen: usize): void {
  memory.copy(ptr + OFF_KEY_DATA, srcPtr, keyLen)
}

/**
 * Incrementa depth (para derivación de hijos).
 */
// @ts-ignore
@inline
export function incrementDepth(ptr: usize): void {
  store<u8>(ptr + OFF_DEPTH, <u8>(<u32>load<u8>(ptr + OFF_DEPTH) + 1))
}

export {
  getDepth as bip32_xkey_depth,
  getParentFingerprint as bip32_xkey_parent_fp,
  getChildIndex as bip32_xkey_child_index,
  isPrivate as bip32_xkey_is_private,
  chainCodePtr as bip32_xkey_chaincode_ptr,
  keyDataPtr as bip32_xkey_keydata_ptr
}