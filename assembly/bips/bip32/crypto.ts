/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip32/crypto.ts — Operaciones EC específicas de BIP32 (zero-alloc)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * pubkeyFromPrivkey / decompressToPoint viven ahora en ../pubkey (compartido
 * con address/). Aquí se re-exportan para no romper a ckd.ts / index.ts.
 * Este archivo conserva lo específico de BIP32: pointAddPubkeys (CKDpub),
 * scalarAddModN e isScalarInvalid.
 */
import { Memory } from "../../utils/memory"
import { fromBytesPtr, toBytesPtr, isZero } from "../../secp256k1/field"
import { add as scalarAdd, isGreaterOrEqualN } from "../../secp256k1/scalar"
import { multiplyG } from "../../secp256k1/generator"
import { addPoint, toAffine } from "../../secp256k1/point"

// ── Re-export desde el módulo compartido (transparencia para ckd/index) ───
import { pubkeyFromPrivkey, decompressToPoint } from "../../utils/pubkey"
export { pubkeyFromPrivkey, decompressToPoint }

// ═══════════════════════════════════════════════════════════════════════════
// SUMA DE PUNTOS (CKDpub): childPub = point(IL) + parentPub → compressed
// ═══════════════════════════════════════════════════════════════════════════

export function pointAddPubkeys(out33: usize, parentPub33: usize, scalarIL32: usize): void {
  const ctx = Memory.save()
  const ilScalar = Memory.alloc(32)
  const ilPoint = Memory.alloc(96)
  const parentPoint = Memory.alloc(96)
  const resultPoint = Memory.alloc(96)
  const affine = Memory.alloc(64)

  fromBytesPtr(ilScalar, scalarIL32)
  multiplyG(ilPoint, ilScalar)
  decompressToPoint(parentPoint, parentPub33)
  addPoint(resultPoint, ilPoint, parentPoint)

  toAffine(affine, resultPoint)
  const yIsOdd: bool = (load<u64>(affine + 32) & 1) != 0
  store<u8>(out33, yIsOdd ? 0x03 : 0x02)
  toBytesPtr(affine, out33 + 1)

  Memory.restore(ctx)
}

// ═══════════════════════════════════════════════════════════════════════════
// ARITMÉTICA DE ESCALARES
// ═══════════════════════════════════════════════════════════════════════════

/** out32 = (a + b) mod N. Entradas/salida en bytes BE (32 B). */
export function scalarAddModN(out32: usize, a32: usize, b32: usize): void {
  const ctx = Memory.save()
  const aLimbs = Memory.alloc(32)
  const bLimbs = Memory.alloc(32)
  const resLimbs = Memory.alloc(32)

  fromBytesPtr(aLimbs, a32)
  fromBytesPtr(bLimbs, b32)
  scalarAdd(resLimbs, aLimbs, bLimbs)
  toBytesPtr(resLimbs, out32)

  Memory.restore(ctx)
}

/** ¿Escalar inválido para BIP32? (k == 0 || k >= N). Entrada BE (32 B). */
export function isScalarInvalid(k32: usize): bool {
  const ctx = Memory.save()
  const kLimbs = Memory.alloc(32)
  fromBytesPtr(kLimbs, k32)
  const invalid: bool = isZero(kLimbs) || isGreaterOrEqualN(kLimbs)
  Memory.restore(ctx)
  return invalid
}
