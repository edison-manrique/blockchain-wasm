/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  musig2/sign.ts — Session, partial sign/verify, aggregation (BIP-327)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * v3.1:
 *   • session_init lee compressed points del aggnonce; si R=∞ → usar G
 *     (BIP-327 §"Dealing with Infinity in Nonce Aggregation").
 *   • Hash `b` usa el aggnonce COMPLETO (66 B), no solo X₁‖X₂.
 *   • partial_sign niega k₁, k₂ según paridad del nonce FINAL R (no individual).
 *   • partial_verify lee compressed points del pubnonce (33 B c/u).
 *
 * Zero-alloc: CRYPTO_WORK (Memory.save/restore, LIFO).
 */
import { Memory } from "../../../utils/memory"
import { N0, N1, N2, N3 } from "../../../secp256k1/constants"
import { fromBytesPtr, toBytesPtr, isZero } from "../../../secp256k1/field"
import { mulMod as scalarMul, add as scalarAdd, sub as scalarSub, isGreaterOrEqualN } from "../../../secp256k1/scalar"
import { multiplyG } from "../../../secp256k1/generator"
import { addPoint, toAffine, isInfinity, negate, eqJacobian, setGenerator } from "../../../secp256k1/point"
import { mul as glvMul } from "../../../secp256k1/glv"
import { liftX, taggedHash, taggedHashMulti, pushChunk, musigTagPtr, scalarFromPtrModN, cpointToPoint, writeCbytesExt } from "../core"
import {
  TAG_CHALLENGE,
  TAG_MUSIG_NONCECOEF,
  TAG_KEYAGG_LIST,
  TAG_KEYAGG_COEFF,
  MUSIG_OK,
  MUSIG_ERR_COUNT,
  MUSIG_ERR_PUBKEY,
  MUSIG_ERR_NONCE,
  MUSIG_ERR_SIG,
  MUSIG_ERR_PRIVKEY,
  MUSIG_PUBNONCE_SIZE,
  MUSIG_AGGNONCE_SIZE,
  MUSIG_SESSION_SIZE,
  MUSIG_MAX_SIGNERS
} from "../constants"
import { musig2_keyagg } from "./keyagg"
import { musig2_nonce_gen, musig2_nonce_agg } from "./nonce"

// ═══════════════════════════════════════════════════════════════════════════
// LAYOUT DE SESIÓN (97 bytes): b(32) ‖ e(32) ‖ Rx(32) ‖ g_R(1)
// gacc se pasa directamente a partial_sign/partial_verify desde keyagg
// ═══════════════════════════════════════════════════════════════════════════
const SES_OFF_B: usize = 0
const SES_OFF_E: usize = 32
const SES_OFF_RX: usize = 64
const SES_OFF_G_R: usize = 96 // Paridad de R (1 byte)

// @ts-ignore
@inline
function storeN(res: usize): void {
  store<u64>(res, N0)
  store<u64>(res, N1, 8)
  store<u64>(res, N2, 16)
  store<u64>(res, N3, 24)
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION INIT (BIP-327 §GetSessionValues)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * @param out97      sesión (97 B: b‖e‖Rx‖g_R).
 * @param aggNonce66 aggnonce (66 B compressed, permite ∞).
 * @param q32        clave pública agregada (x-only, 32 B).
 * @param msgPtr     puntero al mensaje.
 * @param msgLen     longitud del mensaje.
 *
 * Test call: musig2_session_init(OUT, IN, IN+128, IN+256, msg.length)
 */
export function musig2_session_init(
  out97: usize,
  aggNonce66: usize,
  q32: usize,
  msgPtr: usize,
  msgLen: isize
): i32 {
  const ctx = Memory.save()
  const chunks = Memory.alloc(64)
  const bHash = Memory.alloc(32)
  const b = Memory.alloc(32)
  const eHash = Memory.alloc(32)
  const e = Memory.alloc(32)
  const R1 = Memory.alloc(96)
  const R2 = Memory.alloc(96)
  const t = Memory.alloc(96)
  const R = Memory.alloc(96)
  const affine = Memory.alloc(64)

  pushChunk(chunks, 0, aggNonce66, 66)
  pushChunk(chunks, 1, q32, 32)
  pushChunk(chunks, 2, msgPtr, <u32>msgLen)
  taggedHashMulti(bHash, musigTagPtr(TAG_MUSIG_NONCECOEF), chunks, 3)
  scalarFromPtrModN(b, bHash)

  if (!cpointToPoint(R1, aggNonce66)) {
    Memory.restore(ctx)
    return MUSIG_ERR_NONCE
  }
  if (!cpointToPoint(R2, aggNonce66 + 33)) {
    Memory.restore(ctx)
    return MUSIG_ERR_NONCE
  }

  glvMul(t, R2, b)
  addPoint(R, R1, t)

  if (isInfinity(R)) setGenerator(R)

  toAffine(affine, R)
  toBytesPtr(affine, out97 + SES_OFF_RX)
  const yParity: u8 = (load<u64>(affine + 32) & 1) != 0 ? 1 : 0

  store<u8>(out97 + SES_OFF_G_R, yParity)

  taggedHash(eHash, TAG_CHALLENGE, out97 + SES_OFF_RX, 32, q32, 32, msgPtr, msgLen)
  scalarFromPtrModN(e, eHash)

  toBytesPtr(b, out97 + SES_OFF_B)
  toBytesPtr(e, out97 + SES_OFF_E)
  Memory.restore(ctx)
  return MUSIG_OK
}

// ═══════════════════════════════════════════════════════════════════════════
// PARTIAL SIGN (BIP-327 §4.4)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * s_i = k₁ + b·k₂ + e·aᵢ·gacc·dᵢ  (mod N)
 *
 * Negaciones BIP-327:
 *   • d  se niega si gacc != 0 (Q.y es impar según keyagg)
 *   • k₁, k₂ se niegan si R_final.y es impar (g flag de sesión)
 *
 * Test call: musig2_partial_sign(OUT, IN, gacc, IN+128, IN+256, IN+320)
 */
export function musig2_partial_sign(
  out_s32: usize,
  session97: usize,
  gacc: u8,
  secnonce97: usize,
  priv32: usize,
  coeff32: usize
): i32 {
  const ctx = Memory.save()
  const N = Memory.alloc(32)
  storeN(N)
  const d = Memory.alloc(32)
  const P = Memory.alloc(96)
  const k1 = Memory.alloc(32)
  const k2 = Memory.alloc(32)
  const b = Memory.alloc(32)
  const e = Memory.alloc(32)
  const a = Memory.alloc(32)
  const t = Memory.alloc(32)
  const s = Memory.alloc(32)
  const pk_sec = Memory.alloc(33)
  const pk_calc = Memory.alloc(33)

  fromBytesPtr(b, session97 + SES_OFF_B)
  fromBytesPtr(e, session97 + SES_OFF_E)
  memory.copy(a, coeff32, 32)
  fromBytesPtr(k1, secnonce97)
  fromBytesPtr(k2, secnonce97 + 32)
  memory.copy(pk_sec, secnonce97 + 64, 33)

  fromBytesPtr(d, priv32)
  if (isZero(d) || isGreaterOrEqualN(d)) {
    Memory.restore(ctx)
    return MUSIG_ERR_PRIVKEY
  }
  if (isZero(k1) || isZero(k2)) {
    Memory.restore(ctx)
    return MUSIG_ERR_NONCE
  }

  // ✅ BIP-327 v1.0.0-rc.2: Verificar pk
  multiplyG(P, d)
  writeCbytesExt(pk_calc, P)
  if (memory.compare(pk_sec, pk_calc, 33) != 0) {
    Memory.restore(ctx)
    return MUSIG_ERR_PRIVKEY
  }

  // Negar k₁, k₂ si R_final.y es impar
  if (load<u8>(session97 + SES_OFF_G_R) != 0) {
    scalarSub(k1, N, k1)
    scalarSub(k2, N, k2)
  }

  // ✅ Negación correcta BIP-327: negar d si gacc=1 (Q.y es impar)
  if (gacc != 0) scalarSub(d, N, d)

  scalarMul(t, b, k2)
  scalarAdd(s, k1, t)
  scalarMul(t, e, a)
  scalarMul(t, t, d)
  scalarAdd(s, s, t)

  toBytesPtr(s, out_s32)
  Memory.restore(ctx)
  return MUSIG_OK
}

// ═══════════════════════════════════════════════════════════════════════════
// PARTIAL VERIFY (BIP-327 §4.5)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * Check: s·G == Re* + e·a·gacc·P,  donde
 *   Re* = R₁ + b·R₂  (con R₁, R₂ leídos como compressed points),
 *   Re* se niega si R_final.y es impar.
 *
 * Test call: musig2_partial_verify(s, session, gacc, pubnonce66, pk33, coeff)
 */
export function musig2_partial_verify(
  s32: usize,
  session97: usize,
  gacc: u8,
  pubnonce66: usize,
  pk33: usize, // ✅ 33 bytes
  coeff32: usize
): i32 {
  const ctx = Memory.save()
  const N = Memory.alloc(32)
  storeN(N)
  const sL = Memory.alloc(32)
  const b = Memory.alloc(32)
  const e = Memory.alloc(32)
  const a = Memory.alloc(32)
  const R1 = Memory.alloc(96)
  const R2 = Memory.alloc(96)
  const tP = Memory.alloc(96)
  const sum = Memory.alloc(96)
  const P = Memory.alloc(96)
  const lhs = Memory.alloc(96)

  fromBytesPtr(sL, s32)
  fromBytesPtr(b, session97 + SES_OFF_B)
  fromBytesPtr(e, session97 + SES_OFF_E)
  memory.copy(a, coeff32, 32)

  multiplyG(lhs, sL)

  if (!cpointToPoint(R1, pubnonce66)) {
    Memory.restore(ctx)
    return 0
  }
  if (!cpointToPoint(R2, pubnonce66 + 33)) {
    Memory.restore(ctx)
    return 0
  }

  glvMul(tP, R2, b)
  addPoint(sum, R1, tP)

  if (load<u8>(session97 + SES_OFF_G_R) != 0) negate(sum, sum)

  scalarMul(a, e, a)

  // ✅ Negación BIP-327: negar e·a si gacc=1 (Q.y es impar)
  if (gacc != 0) scalarSub(a, N, a)

  if (!cpointToPoint(P, pk33)) {
    Memory.restore(ctx)
    return 0
  }

  glvMul(tP, P, a)
  addPoint(sum, sum, tP)

  const ok: i32 = eqJacobian(lhs, sum) ? 1 : 0
  Memory.restore(ctx)
  return ok
}

// ═══════════════════════════════════════════════════════════════════════════
// PARTIAL SIG AGG (BIP-327 §4.6)
// ═══════════════════════════════════════════════════════════════════════════
export function musig2_partial_sig_agg(out_s32: usize, partialsPtr: usize, count: u32): i32 {
  if (count == 0 || count > MUSIG_MAX_SIGNERS) return MUSIG_ERR_COUNT
  const ctx = Memory.save()
  const acc = Memory.alloc(32)
  const t = Memory.alloc(32)
  fromBytesPtr(acc, partialsPtr)
  if (isGreaterOrEqualN(acc)) {
    Memory.restore(ctx)
    return MUSIG_ERR_SIG
  }
  for (let i: u32 = 1; i < count; i++) {
    fromBytesPtr(t, partialsPtr + <usize>(i << 5))
    if (isGreaterOrEqualN(t)) {
      Memory.restore(ctx)
      return MUSIG_ERR_SIG
    }
    scalarAdd(acc, acc, t)
  }
  toBytesPtr(acc, out_s32)
  Memory.restore(ctx)
  return MUSIG_OK
}

// ═══════════════════════════════════════════════════════════════════════════
// SIGN ALL (orquestador completo para tests / uso interno)
// ═══════════════════════════════════════════════════════════════════════════
export function musig2_sign_all(
  out64: usize,
  out_q32: usize,
  privsPtr: usize,
  count: u32,
  msgPtr: usize,
  msgLen: isize,
  secrandPtr: usize
): i32 {
  if (count == 0 || count > MUSIG_MAX_SIGNERS) return MUSIG_ERR_COUNT
  const ctx = Memory.save()

  const pubs = Memory.alloc(<usize>count * 33)         // count × 33 (compressed pubkeys)
  const coeffs = Memory.alloc((<usize>count) << 5)     // count × 32
  const secnonces = Memory.alloc(<usize>count * 97)    // count × 97 (secnonce = k1‖k2‖pk)
  const pubnonces = Memory.alloc(<usize>count * MUSIG_PUBNONCE_SIZE) // ✅ stride 66
  const partials = Memory.alloc((<usize>count) << 5)   // count × 32
  const desc = Memory.alloc((<usize>count) << 4)
  const L = Memory.alloc(32)
  const gaccBuf = Memory.alloc(8)
  const aggNonce = Memory.alloc(MUSIG_AGGNONCE_SIZE)   // ✅ 66 bytes
  const session = Memory.alloc(MUSIG_SESSION_SIZE)
  const d = Memory.alloc(32)
  const P = Memory.alloc(96)

  // 1. Derivar pubkeys comprimidas (33 B) desde privkeys
  for (let i: u32 = 0; i < count; i++) {
    fromBytesPtr(d, privsPtr + <usize>(i << 5))
    multiplyG(P, d)
    writeCbytesExt(pubs + <usize>(i * 33), P)
  }

  // 2. L (hash sobre las pubkeys comprimidas de 33 B)
  for (let i: u32 = 0; i < count; i++) {
    pushChunk(desc, <i32>i, pubs + <usize>(i * 33), 33)
  }
  taggedHashMulti(L, musigTagPtr(TAG_KEYAGG_LIST), desc, <i32>count)

  // 3. Índice de la 2ª clave distinta
  let secondIdx: i32 = -1
  for (let i: u32 = 1; i < count; i++) {
    if (memory.compare(pubs, pubs + <usize>(i * 33), 33) != 0) {
      secondIdx = <i32>i
      break
    }
  }

  // 4. Coeficientes
  const one = Memory.alloc(32)
  store<u64>(one, 1)
  store<u64>(one, 0, 8)
  store<u64>(one, 0, 16)
  store<u64>(one, 0, 24)
  for (let i: u32 = 0; i < count; i++) {
    const isSecond: bool = secondIdx != -1 && memory.compare(pubs + <usize>(i * 33), pubs + <usize>(secondIdx * 33), 33) == 0
    if (isSecond) {
      memory.copy(coeffs + <usize>(i << 5), one, 32)
    } else {
      const cctx = Memory.save()
      const cdesc = Memory.alloc(32)
      pushChunk(cdesc, 0, L, 32)
      pushChunk(cdesc, 1, pubs + <usize>(i * 33), 33)
      const ch = Memory.alloc(32)
      taggedHashMulti(ch, musigTagPtr(TAG_KEYAGG_COEFF), cdesc, 2)
      scalarFromPtrModN(coeffs + <usize>(i << 5), ch)
      Memory.restore(cctx)
    }
  }

  // 5. KeyAgg (4 args: out_q32, out_gacc8, pubsPtr, count)
  const rcK = musig2_keyagg(out_q32, gaccBuf, pubs, count)
  if (rcK != MUSIG_OK) {
    Memory.restore(ctx)
    return rcK
  }
  const gacc: u8 = load<u8>(gaccBuf)

  // 6. Generar nonces (stride 66 en pubnonces, secnonce stride 97)
  for (let i: u32 = 0; i < count; i++) {
    const rc = musig2_nonce_gen(
      secnonces + <usize>(i * 97),
      pubnonces + <usize>(i * <u32>MUSIG_PUBNONCE_SIZE),
      secrandPtr + <usize>(i << 5),
      privsPtr + <usize>(i << 5),
      pubs + <usize>(i * 33),
      0,
      msgPtr,
      <i32>msgLen,
      0,
      0
    )
    if (rc != MUSIG_OK) {
      Memory.restore(ctx)
      return rc
    }
  }

  // 7. Agregar nonces
  const rcN = musig2_nonce_agg(aggNonce, pubnonces, count)
  if (rcN != MUSIG_OK) {
    Memory.restore(ctx)
    return rcN
  }

  // 8. Inicializar sesión (5 args: out97, aggNonce, q32, msgPtr, msgLen)
  const rcS = musig2_session_init(session, aggNonce, out_q32, msgPtr, msgLen)
  if (rcS != MUSIG_OK) {
    Memory.restore(ctx)
    return rcS
  }

  // 9. Firmas parciales (6 args: out, session, gacc, secnonce, priv, coeff)
  for (let i: u32 = 0; i < count; i++) {
    const rc = musig2_partial_sign(
      partials + <usize>(i << 5),
      session,
      gacc,
      secnonces + <usize>(i * 97),
      privsPtr + <usize>(i << 5),
      coeffs + <usize>(i << 5)
    )
    if (rc != MUSIG_OK) {
      Memory.restore(ctx)
      return rc
    }
  }

  // 10. Agregar firmas parciales
  const s = Memory.alloc(32)
  musig2_partial_sig_agg(s, partials, count)

  // 11. Firma final: Rx ‖ s
  memory.copy(out64, session + SES_OFF_RX, 32)
  memory.copy(out64 + 32, s, 32)
  Memory.restore(ctx)
  return 64
}
