/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ripemd160/index.ts — RIPEMD-160 (FIPS-compatible, 160-bit hash)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Implementación zero-alloc de RIPEMD-160 (Dobbertin et al., 1996).
 * Uso en blockchain: RIPEMD160(SHA256(pubkey)) → hash160 (Bitcoin addresses).
 *
 * ── ARQUITECTURA (alineada con SHA-2) ─────────────────────────────────────
 * • Contexto @unmanaged de 96 bytes sobre HASH_WORK_PTR (layout fijo).
 * • Buffer de padding de 128 bytes contiguo al contexto.
 * • CERO Memory.alloc / Memory.save / Memory.restore.
 * • CERO heap, CERO memory.grow.
 * • Comparte HASH_WORK con SHA-2 (seguro: nunca se anidan entre sí;
 *   hash160 = SHA256 primero, RIPEMD160 después, secuencial).
 *
 * ── ENDIANNESS ────────────────────────────────────────────────────────────
 * RIPEMD-160 es LITTLE-ENDIAN nativo (a diferencia de SHA-2 que es BE).
 * WASM es LE → load<u32>/store<u32> directos, SIN bswap.
 *
 * ── API ───────────────────────────────────────────────────────────────────
 *   One-shot:  ripemd160_hash_raw(outPtr, mPtr, len)
 *   Streaming: ripemd160_create_ctx(ctxPtr)
 *              ripemd160_update_raw(ctxPtr, mPtr, len)
 *              ripemd160_final_raw(ctxPtr, paddedPtr, outPtr)
 */

import { HASH_WORK_PTR, align8, PARAM_IN_PTR, PARAM_OUT_PTR } from "../utils/memory"
export { PARAM_IN_PTR, PARAM_OUT_PTR }

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTES
// ═══════════════════════════════════════════════════════════════════════════

export const RIPEMD160_BLOCK: usize = 64
export const RIPEMD160_HASH: usize = 20

// ═══════════════════════════════════════════════════════════════════════════
// FUNCIONES BOOLEANAS
// ═══════════════════════════════════════════════════════════════════════════

// @ts-ignore
@inline function f1(x: u32, y: u32, z: u32): u32 { return x ^ y ^ z }
// @ts-ignore
@inline function f2(x: u32, y: u32, z: u32): u32 { return (x & y) | (~x & z) }
// @ts-ignore
@inline function f3(x: u32, y: u32, z: u32): u32 { return (x | ~y) ^ z }
// @ts-ignore
@inline function f4(x: u32, y: u32, z: u32): u32 { return (x & z) | (y & ~z) }
// @ts-ignore
@inline function f5(x: u32, y: u32, z: u32): u32 { return x ^ (y | ~z) }

// ═══════════════════════════════════════════════════════════════════════════
// CONTEXTO (96 bytes, @unmanaged)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Layout: [0..19] state (5×u32) | [20..23] bufferLen (u32) |
 *         [24..31] totalLen (u64) | [32..95] buffer (64 B)
 */
@unmanaged
class Ripemd160Context {
  static readonly SIZE: usize = 96

  @inline get statePtr(): usize { return changetype<usize>(this) }
  @inline get bufferPtr(): usize { return changetype<usize>(this) + 32 }

  @inline getTotalLen(): u64 { return load<u64>(changetype<usize>(this) + 24) }
  @inline setTotalLen(v: u64): void { store<u64>(changetype<usize>(this) + 24, v) }
  @inline getBufferLen(): u32 { return load<u32>(changetype<usize>(this) + 20) }
  @inline setBufferLen(v: u32): void { store<u32>(changetype<usize>(this) + 20, v) }

  @inline
  init(): void {
    const st = this.statePtr
    store<u32>(st + 0, 0x67452301)
    store<u32>(st + 4, 0xefcdab89)
    store<u32>(st + 8, 0x98badcfe)
    store<u32>(st + 12, 0x10325476)
    store<u32>(st + 16, 0xc3d2e1f0)
    this.setTotalLen(0)
    this.setBufferLen(0)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// NÚCLEO DE COMPRESIÓN
// ═══════════════════════════════════════════════════════════════════════════

function compress(stPtr: usize, mPtr: usize, n: usize): void {
  let h0 = load<u32>(stPtr + 0)
  let h1 = load<u32>(stPtr + 4)
  let h2 = load<u32>(stPtr + 8)
  let h3 = load<u32>(stPtr + 12)
  let h4 = load<u32>(stPtr + 16)

  let pos: usize = 0

  while (n >= 64) {
    let A = h0, B = h1, C = h2, D = h3, E = h4
    let Ap = h0, Bp = h1, Cp = h2, Dp = h3, Ep = h4

    // RIPEMD-160 es little-endian nativo → load<u32> directo (SIN bswap)
    let X0  = load<u32>(mPtr + pos + 0)
    let X1  = load<u32>(mPtr + pos + 4)
    let X2  = load<u32>(mPtr + pos + 8)
    let X3  = load<u32>(mPtr + pos + 12)
    let X4  = load<u32>(mPtr + pos + 16)
    let X5  = load<u32>(mPtr + pos + 20)
    let X6  = load<u32>(mPtr + pos + 24)
    let X7  = load<u32>(mPtr + pos + 28)
    let X8  = load<u32>(mPtr + pos + 32)
    let X9  = load<u32>(mPtr + pos + 36)
    let X10 = load<u32>(mPtr + pos + 40)
    let X11 = load<u32>(mPtr + pos + 44)
    let X12 = load<u32>(mPtr + pos + 48)
    let X13 = load<u32>(mPtr + pos + 52)
    let X14 = load<u32>(mPtr + pos + 56)
    let X15 = load<u32>(mPtr + pos + 60)

    // ── Round 1 (left: f1, K=0) / (right: f5, K=0x50a28be6) ──
    A += f1(B, C, D) + X0;  A = rotl<u32>(A, 11) + E; C = rotl<u32>(C, 10)
    Ap += f5(Bp, Cp, Dp) + X5 + 0x50a28be6;  Ap = rotl<u32>(Ap, 8) + Ep;  Cp = rotl<u32>(Cp, 10)
    E += f1(A, B, C) + X1;  E = rotl<u32>(E, 14) + D; B = rotl<u32>(B, 10)
    Ep += f5(Ap, Bp, Cp) + X14 + 0x50a28be6; Ep = rotl<u32>(Ep, 9) + Dp;  Bp = rotl<u32>(Bp, 10)
    D += f1(E, A, B) + X2;  D = rotl<u32>(D, 15) + C; A = rotl<u32>(A, 10)
    Dp += f5(Ep, Ap, Bp) + X7 + 0x50a28be6;  Dp = rotl<u32>(Dp, 9) + Cp;  Ap = rotl<u32>(Ap, 10)
    C += f1(D, E, A) + X3;  C = rotl<u32>(C, 12) + B; E = rotl<u32>(E, 10)
    Cp += f5(Dp, Ep, Ap) + X0 + 0x50a28be6;  Cp = rotl<u32>(Cp, 11) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f1(C, D, E) + X4;  B = rotl<u32>(B, 5) + A;  D = rotl<u32>(D, 10)
    Bp += f5(Cp, Dp, Ep) + X9 + 0x50a28be6;  Bp = rotl<u32>(Bp, 13) + Ap; Dp = rotl<u32>(Dp, 10)
    A += f1(B, C, D) + X5;  A = rotl<u32>(A, 8) + E;  C = rotl<u32>(C, 10)
    Ap += f5(Bp, Cp, Dp) + X2 + 0x50a28be6;  Ap = rotl<u32>(Ap, 15) + Ep; Cp = rotl<u32>(Cp, 10)
    E += f1(A, B, C) + X6;  E = rotl<u32>(E, 7) + D;  B = rotl<u32>(B, 10)
    Ep += f5(Ap, Bp, Cp) + X11 + 0x50a28be6; Ep = rotl<u32>(Ep, 15) + Dp; Bp = rotl<u32>(Bp, 10)
    D += f1(E, A, B) + X7;  D = rotl<u32>(D, 9) + C;  A = rotl<u32>(A, 10)
    Dp += f5(Ep, Ap, Bp) + X4 + 0x50a28be6;  Dp = rotl<u32>(Dp, 5) + Cp;  Ap = rotl<u32>(Ap, 10)
    C += f1(D, E, A) + X8;  C = rotl<u32>(C, 11) + B; E = rotl<u32>(E, 10)
    Cp += f5(Dp, Ep, Ap) + X13 + 0x50a28be6; Cp = rotl<u32>(Cp, 7) + Bp;  Ep = rotl<u32>(Ep, 10)
    B += f1(C, D, E) + X9;  B = rotl<u32>(B, 13) + A; D = rotl<u32>(D, 10)
    Bp += f5(Cp, Dp, Ep) + X6 + 0x50a28be6;  Bp = rotl<u32>(Bp, 7) + Ap;  Dp = rotl<u32>(Dp, 10)
    A += f1(B, C, D) + X10; A = rotl<u32>(A, 14) + E; C = rotl<u32>(C, 10)
    Ap += f5(Bp, Cp, Dp) + X15 + 0x50a28be6; Ap = rotl<u32>(Ap, 8) + Ep;  Cp = rotl<u32>(Cp, 10)
    E += f1(A, B, C) + X11; E = rotl<u32>(E, 15) + D; B = rotl<u32>(B, 10)
    Ep += f5(Ap, Bp, Cp) + X8 + 0x50a28be6;  Ep = rotl<u32>(Ep, 11) + Dp; Bp = rotl<u32>(Bp, 10)
    D += f1(E, A, B) + X12; D = rotl<u32>(D, 6) + C;  A = rotl<u32>(A, 10)
    Dp += f5(Ep, Ap, Bp) + X1 + 0x50a28be6;  Dp = rotl<u32>(Dp, 14) + Cp; Ap = rotl<u32>(Ap, 10)
    C += f1(D, E, A) + X13; C = rotl<u32>(C, 7) + B;  E = rotl<u32>(E, 10)
    Cp += f5(Dp, Ep, Ap) + X10 + 0x50a28be6; Cp = rotl<u32>(Cp, 14) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f1(C, D, E) + X14; B = rotl<u32>(B, 9) + A;  D = rotl<u32>(D, 10)
    Bp += f5(Cp, Dp, Ep) + X3 + 0x50a28be6;  Bp = rotl<u32>(Bp, 12) + Ap; Dp = rotl<u32>(Dp, 10)
    A += f1(B, C, D) + X15; A = rotl<u32>(A, 8) + E;  C = rotl<u32>(C, 10)
    Ap += f5(Bp, Cp, Dp) + X12 + 0x50a28be6; Ap = rotl<u32>(Ap, 6) + Ep;  Cp = rotl<u32>(Cp, 10)

    // ── Round 2 (left: f2, K=0x5a827999) / (right: f4, K=0x5c4dd124) ──
    E += f2(A, B, C) + X7 + 0x5a827999;  E = rotl<u32>(E, 7) + D;  B = rotl<u32>(B, 10)
    Ep += f4(Ap, Bp, Cp) + X6 + 0x5c4dd124;  Ep = rotl<u32>(Ep, 9) + Dp;  Bp = rotl<u32>(Bp, 10)
    D += f2(E, A, B) + X4 + 0x5a827999;  D = rotl<u32>(D, 6) + C;  A = rotl<u32>(A, 10)
    Dp += f4(Ep, Ap, Bp) + X11 + 0x5c4dd124; Dp = rotl<u32>(Dp, 13) + Cp; Ap = rotl<u32>(Ap, 10)
    C += f2(D, E, A) + X13 + 0x5a827999; C = rotl<u32>(C, 8) + B;  E = rotl<u32>(E, 10)
    Cp += f4(Dp, Ep, Ap) + X3 + 0x5c4dd124;  Cp = rotl<u32>(Cp, 15) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f2(C, D, E) + X1 + 0x5a827999;  B = rotl<u32>(B, 13) + A; D = rotl<u32>(D, 10)
    Bp += f4(Cp, Dp, Ep) + X7 + 0x5c4dd124;  Bp = rotl<u32>(Bp, 7) + Ap;  Dp = rotl<u32>(Dp, 10)
    A += f2(B, C, D) + X10 + 0x5a827999; A = rotl<u32>(A, 11) + E; C = rotl<u32>(C, 10)
    Ap += f4(Bp, Cp, Dp) + X0 + 0x5c4dd124;  Ap = rotl<u32>(Ap, 12) + Ep; Cp = rotl<u32>(Cp, 10)
    E += f2(A, B, C) + X6 + 0x5a827999;  E = rotl<u32>(E, 9) + D;  B = rotl<u32>(B, 10)
    Ep += f4(Ap, Bp, Cp) + X13 + 0x5c4dd124; Ep = rotl<u32>(Ep, 8) + Dp;  Bp = rotl<u32>(Bp, 10)
    D += f2(E, A, B) + X15 + 0x5a827999; D = rotl<u32>(D, 7) + C;  A = rotl<u32>(A, 10)
    Dp += f4(Ep, Ap, Bp) + X5 + 0x5c4dd124;  Dp = rotl<u32>(Dp, 9) + Cp;  Ap = rotl<u32>(Ap, 10)
    C += f2(D, E, A) + X3 + 0x5a827999;  C = rotl<u32>(C, 15) + B; E = rotl<u32>(E, 10)
    Cp += f4(Dp, Ep, Ap) + X10 + 0x5c4dd124; Cp = rotl<u32>(Cp, 11) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f2(C, D, E) + X12 + 0x5a827999; B = rotl<u32>(B, 7) + A;  D = rotl<u32>(D, 10)
    Bp += f4(Cp, Dp, Ep) + X14 + 0x5c4dd124; Bp = rotl<u32>(Bp, 7) + Ap;  Dp = rotl<u32>(Dp, 10)
    A += f2(B, C, D) + X0 + 0x5a827999;  A = rotl<u32>(A, 12) + E; C = rotl<u32>(C, 10)
    Ap += f4(Bp, Cp, Dp) + X15 + 0x5c4dd124; Ap = rotl<u32>(Ap, 7) + Ep;  Cp = rotl<u32>(Cp, 10)
    E += f2(A, B, C) + X9 + 0x5a827999;  E = rotl<u32>(E, 15) + D; B = rotl<u32>(B, 10)
    Ep += f4(Ap, Bp, Cp) + X8 + 0x5c4dd124;  Ep = rotl<u32>(Ep, 12) + Dp; Bp = rotl<u32>(Bp, 10)
    D += f2(E, A, B) + X5 + 0x5a827999;  D = rotl<u32>(D, 9) + C;  A = rotl<u32>(A, 10)
    Dp += f4(Ep, Ap, Bp) + X12 + 0x5c4dd124; Dp = rotl<u32>(Dp, 7) + Cp;  Ap = rotl<u32>(Ap, 10)
    C += f2(D, E, A) + X2 + 0x5a827999;  C = rotl<u32>(C, 11) + B; E = rotl<u32>(E, 10)
    Cp += f4(Dp, Ep, Ap) + X4 + 0x5c4dd124;  Cp = rotl<u32>(Cp, 6) + Bp;  Ep = rotl<u32>(Ep, 10)
    B += f2(C, D, E) + X14 + 0x5a827999; B = rotl<u32>(B, 7) + A;  D = rotl<u32>(D, 10)
    Bp += f4(Cp, Dp, Ep) + X9 + 0x5c4dd124;  Bp = rotl<u32>(Bp, 15) + Ap; Dp = rotl<u32>(Dp, 10)
    A += f2(B, C, D) + X11 + 0x5a827999; A = rotl<u32>(A, 13) + E; C = rotl<u32>(C, 10)
    Ap += f4(Bp, Cp, Dp) + X1 + 0x5c4dd124;  Ap = rotl<u32>(Ap, 13) + Ep; Cp = rotl<u32>(Cp, 10)
    E += f2(A, B, C) + X8 + 0x5a827999;  E = rotl<u32>(E, 12) + D; B = rotl<u32>(B, 10)
    Ep += f4(Ap, Bp, Cp) + X2 + 0x5c4dd124;  Ep = rotl<u32>(Ep, 11) + Dp; Bp = rotl<u32>(Bp, 10)

    // ── Round 3 (left: f3, K=0x6ed9eba1) / (right: f3, K=0x6d703ef3) ──
    D += f3(E, A, B) + X3 + 0x6ed9eba1;  D = rotl<u32>(D, 11) + C; A = rotl<u32>(A, 10)
    Dp += f3(Ep, Ap, Bp) + X15 + 0x6d703ef3; Dp = rotl<u32>(Dp, 9) + Cp;  Ap = rotl<u32>(Ap, 10)
    C += f3(D, E, A) + X10 + 0x6ed9eba1; C = rotl<u32>(C, 13) + B; E = rotl<u32>(E, 10)
    Cp += f3(Dp, Ep, Ap) + X5 + 0x6d703ef3;  Cp = rotl<u32>(Cp, 7) + Bp;  Ep = rotl<u32>(Ep, 10)
    B += f3(C, D, E) + X14 + 0x6ed9eba1; B = rotl<u32>(B, 6) + A;  D = rotl<u32>(D, 10)
    Bp += f3(Cp, Dp, Ep) + X1 + 0x6d703ef3;  Bp = rotl<u32>(Bp, 15) + Ap; Dp = rotl<u32>(Dp, 10)
    A += f3(B, C, D) + X4 + 0x6ed9eba1;  A = rotl<u32>(A, 7) + E;  C = rotl<u32>(C, 10)
    Ap += f3(Bp, Cp, Dp) + X3 + 0x6d703ef3;  Ap = rotl<u32>(Ap, 11) + Ep; Cp = rotl<u32>(Cp, 10)
    E += f3(A, B, C) + X9 + 0x6ed9eba1;  E = rotl<u32>(E, 14) + D; B = rotl<u32>(B, 10)
    Ep += f3(Ap, Bp, Cp) + X7 + 0x6d703ef3;  Ep = rotl<u32>(Ep, 8) + Dp;  Bp = rotl<u32>(Bp, 10)
    D += f3(E, A, B) + X15 + 0x6ed9eba1; D = rotl<u32>(D, 9) + C;  A = rotl<u32>(A, 10)
    Dp += f3(Ep, Ap, Bp) + X14 + 0x6d703ef3; Dp = rotl<u32>(Dp, 6) + Cp;  Ap = rotl<u32>(Ap, 10)
    C += f3(D, E, A) + X8 + 0x6ed9eba1;  C = rotl<u32>(C, 13) + B; E = rotl<u32>(E, 10)
    Cp += f3(Dp, Ep, Ap) + X6 + 0x6d703ef3;  Cp = rotl<u32>(Cp, 6) + Bp;  Ep = rotl<u32>(Ep, 10)
    B += f3(C, D, E) + X1 + 0x6ed9eba1;  B = rotl<u32>(B, 15) + A; D = rotl<u32>(D, 10)
    Bp += f3(Cp, Dp, Ep) + X9 + 0x6d703ef3;  Bp = rotl<u32>(Bp, 14) + Ap; Dp = rotl<u32>(Dp, 10)
    A += f3(B, C, D) + X2 + 0x6ed9eba1;  A = rotl<u32>(A, 14) + E; C = rotl<u32>(C, 10)
    Ap += f3(Bp, Cp, Dp) + X11 + 0x6d703ef3; Ap = rotl<u32>(Ap, 12) + Ep; Cp = rotl<u32>(Cp, 10)
    E += f3(A, B, C) + X7 + 0x6ed9eba1;  E = rotl<u32>(E, 8) + D;  B = rotl<u32>(B, 10)
    Ep += f3(Ap, Bp, Cp) + X8 + 0x6d703ef3;  Ep = rotl<u32>(Ep, 13) + Dp; Bp = rotl<u32>(Bp, 10)
    D += f3(E, A, B) + X0 + 0x6ed9eba1;  D = rotl<u32>(D, 13) + C; A = rotl<u32>(A, 10)
    Dp += f3(Ep, Ap, Bp) + X12 + 0x6d703ef3; Dp = rotl<u32>(Dp, 5) + Cp;  Ap = rotl<u32>(Ap, 10)
    C += f3(D, E, A) + X6 + 0x6ed9eba1;  C = rotl<u32>(C, 6) + B;  E = rotl<u32>(E, 10)
    Cp += f3(Dp, Ep, Ap) + X2 + 0x6d703ef3;  Cp = rotl<u32>(Cp, 14) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f3(C, D, E) + X13 + 0x6ed9eba1; B = rotl<u32>(B, 5) + A;  D = rotl<u32>(D, 10)
    Bp += f3(Cp, Dp, Ep) + X10 + 0x6d703ef3; Bp = rotl<u32>(Bp, 13) + Ap; Dp = rotl<u32>(Dp, 10)
    A += f3(B, C, D) + X11 + 0x6ed9eba1; A = rotl<u32>(A, 12) + E; C = rotl<u32>(C, 10)
    Ap += f3(Bp, Cp, Dp) + X0 + 0x6d703ef3;  Ap = rotl<u32>(Ap, 13) + Ep; Cp = rotl<u32>(Cp, 10)
    E += f3(A, B, C) + X5 + 0x6ed9eba1;  E = rotl<u32>(E, 7) + D;  B = rotl<u32>(B, 10)
    Ep += f3(Ap, Bp, Cp) + X4 + 0x6d703ef3;  Ep = rotl<u32>(Ep, 7) + Dp;  Bp = rotl<u32>(Bp, 10)
    D += f3(E, A, B) + X12 + 0x6ed9eba1; D = rotl<u32>(D, 5) + C;  A = rotl<u32>(A, 10)
    Dp += f3(Ep, Ap, Bp) + X13 + 0x6d703ef3; Dp = rotl<u32>(Dp, 5) + Cp;  Ap = rotl<u32>(Ap, 10)

    // ── Round 4 (left: f4, K=0x8f1bbcdc) / (right: f2, K=0x7a6d76e9) ──
    C += f4(D, E, A) + X1 + 0x8f1bbcdc;  C = rotl<u32>(C, 11) + B; E = rotl<u32>(E, 10)
    Cp += f2(Dp, Ep, Ap) + X8 + 0x7a6d76e9;  Cp = rotl<u32>(Cp, 15) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f4(C, D, E) + X9 + 0x8f1bbcdc;  B = rotl<u32>(B, 12) + A; D = rotl<u32>(D, 10)
    Bp += f2(Cp, Dp, Ep) + X6 + 0x7a6d76e9;  Bp = rotl<u32>(Bp, 5) + Ap;  Dp = rotl<u32>(Dp, 10)
    A += f4(B, C, D) + X11 + 0x8f1bbcdc; A = rotl<u32>(A, 14) + E; C = rotl<u32>(C, 10)
    Ap += f2(Bp, Cp, Dp) + X4 + 0x7a6d76e9;  Ap = rotl<u32>(Ap, 8) + Ep;  Cp = rotl<u32>(Cp, 10)
    E += f4(A, B, C) + X10 + 0x8f1bbcdc; E = rotl<u32>(E, 15) + D; B = rotl<u32>(B, 10)
    Ep += f2(Ap, Bp, Cp) + X1 + 0x7a6d76e9;  Ep = rotl<u32>(Ep, 11) + Dp; Bp = rotl<u32>(Bp, 10)
    D += f4(E, A, B) + X0 + 0x8f1bbcdc;  D = rotl<u32>(D, 14) + C; A = rotl<u32>(A, 10)
    Dp += f2(Ep, Ap, Bp) + X3 + 0x7a6d76e9;  Dp = rotl<u32>(Dp, 14) + Cp; Ap = rotl<u32>(Ap, 10)
    C += f4(D, E, A) + X8 + 0x8f1bbcdc;  C = rotl<u32>(C, 15) + B; E = rotl<u32>(E, 10)
    Cp += f2(Dp, Ep, Ap) + X11 + 0x7a6d76e9; Cp = rotl<u32>(Cp, 14) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f4(C, D, E) + X12 + 0x8f1bbcdc; B = rotl<u32>(B, 9) + A;  D = rotl<u32>(D, 10)
    Bp += f2(Cp, Dp, Ep) + X15 + 0x7a6d76e9; Bp = rotl<u32>(Bp, 6) + Ap;  Dp = rotl<u32>(Dp, 10)
    A += f4(B, C, D) + X4 + 0x8f1bbcdc;  A = rotl<u32>(A, 8) + E;  C = rotl<u32>(C, 10)
    Ap += f2(Bp, Cp, Dp) + X0 + 0x7a6d76e9;  Ap = rotl<u32>(Ap, 14) + Ep; Cp = rotl<u32>(Cp, 10)
    E += f4(A, B, C) + X13 + 0x8f1bbcdc; E = rotl<u32>(E, 9) + D;  B = rotl<u32>(B, 10)
    Ep += f2(Ap, Bp, Cp) + X5 + 0x7a6d76e9;  Ep = rotl<u32>(Ep, 6) + Dp;  Bp = rotl<u32>(Bp, 10)
    D += f4(E, A, B) + X3 + 0x8f1bbcdc;  D = rotl<u32>(D, 14) + C; A = rotl<u32>(A, 10)
    Dp += f2(Ep, Ap, Bp) + X12 + 0x7a6d76e9; Dp = rotl<u32>(Dp, 9) + Cp;  Ap = rotl<u32>(Ap, 10)
    C += f4(D, E, A) + X7 + 0x8f1bbcdc;  C = rotl<u32>(C, 5) + B;  E = rotl<u32>(E, 10)
    Cp += f2(Dp, Ep, Ap) + X2 + 0x7a6d76e9;  Cp = rotl<u32>(Cp, 12) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f4(C, D, E) + X15 + 0x8f1bbcdc; B = rotl<u32>(B, 6) + A;  D = rotl<u32>(D, 10)
    Bp += f2(Cp, Dp, Ep) + X13 + 0x7a6d76e9; Bp = rotl<u32>(Bp, 9) + Ap;  Dp = rotl<u32>(Dp, 10)
    A += f4(B, C, D) + X14 + 0x8f1bbcdc; A = rotl<u32>(A, 8) + E;  C = rotl<u32>(C, 10)
    Ap += f2(Bp, Cp, Dp) + X9 + 0x7a6d76e9;  Ap = rotl<u32>(Ap, 12) + Ep; Cp = rotl<u32>(Cp, 10)
    E += f4(A, B, C) + X5 + 0x8f1bbcdc;  E = rotl<u32>(E, 6) + D;  B = rotl<u32>(B, 10)
    Ep += f2(Ap, Bp, Cp) + X7 + 0x7a6d76e9;  Ep = rotl<u32>(Ep, 5) + Dp;  Bp = rotl<u32>(Bp, 10)
    D += f4(E, A, B) + X6 + 0x8f1bbcdc;  D = rotl<u32>(D, 5) + C;  A = rotl<u32>(A, 10)
    Dp += f2(Ep, Ap, Bp) + X10 + 0x7a6d76e9; Dp = rotl<u32>(Dp, 15) + Cp; Ap = rotl<u32>(Ap, 10)
    C += f4(D, E, A) + X2 + 0x8f1bbcdc;  C = rotl<u32>(C, 12) + B; E = rotl<u32>(E, 10)
    Cp += f2(Dp, Ep, Ap) + X14 + 0x7a6d76e9; Cp = rotl<u32>(Cp, 8) + Bp;  Ep = rotl<u32>(Ep, 10)

    // ── Round 5 (left: f5, K=0xa953fd4e) / (right: f1, K=0) ──
    B += f5(C, D, E) + X4 + 0xa953fd4e;  B = rotl<u32>(B, 9) + A;  D = rotl<u32>(D, 10)
    Bp += f1(Cp, Dp, Ep) + X12; Bp = rotl<u32>(Bp, 8) + Ap;  Dp = rotl<u32>(Dp, 10)
    A += f5(B, C, D) + X0 + 0xa953fd4e;  A = rotl<u32>(A, 15) + E; C = rotl<u32>(C, 10)
    Ap += f1(Bp, Cp, Dp) + X15; Ap = rotl<u32>(Ap, 5) + Ep;  Cp = rotl<u32>(Cp, 10)
    E += f5(A, B, C) + X5 + 0xa953fd4e;  E = rotl<u32>(E, 5) + D;  B = rotl<u32>(B, 10)
    Ep += f1(Ap, Bp, Cp) + X10; Ep = rotl<u32>(Ep, 12) + Dp; Bp = rotl<u32>(Bp, 10)
    D += f5(E, A, B) + X9 + 0xa953fd4e;  D = rotl<u32>(D, 11) + C; A = rotl<u32>(A, 10)
    Dp += f1(Ep, Ap, Bp) + X4;  Dp = rotl<u32>(Dp, 9) + Cp;  Ap = rotl<u32>(Ap, 10)
    C += f5(D, E, A) + X7 + 0xa953fd4e;  C = rotl<u32>(C, 6) + B;  E = rotl<u32>(E, 10)
    Cp += f1(Dp, Ep, Ap) + X1;  Cp = rotl<u32>(Cp, 12) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f5(C, D, E) + X12 + 0xa953fd4e; B = rotl<u32>(B, 8) + A;  D = rotl<u32>(D, 10)
    Bp += f1(Cp, Dp, Ep) + X5;  Bp = rotl<u32>(Bp, 5) + Ap;  Dp = rotl<u32>(Dp, 10)
    A += f5(B, C, D) + X2 + 0xa953fd4e;  A = rotl<u32>(A, 13) + E; C = rotl<u32>(C, 10)
    Ap += f1(Bp, Cp, Dp) + X8;  Ap = rotl<u32>(Ap, 14) + Ep; Cp = rotl<u32>(Cp, 10)
    E += f5(A, B, C) + X10 + 0xa953fd4e; E = rotl<u32>(E, 12) + D; B = rotl<u32>(B, 10)
    Ep += f1(Ap, Bp, Cp) + X7;  Ep = rotl<u32>(Ep, 6) + Dp;  Bp = rotl<u32>(Bp, 10)
    D += f5(E, A, B) + X14 + 0xa953fd4e; D = rotl<u32>(D, 5) + C;  A = rotl<u32>(A, 10)
    Dp += f1(Ep, Ap, Bp) + X6;  Dp = rotl<u32>(Dp, 8) + Cp;  Ap = rotl<u32>(Ap, 10)
    C += f5(D, E, A) + X1 + 0xa953fd4e;  C = rotl<u32>(C, 12) + B; E = rotl<u32>(E, 10)
    Cp += f1(Dp, Ep, Ap) + X2;  Cp = rotl<u32>(Cp, 13) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f5(C, D, E) + X3 + 0xa953fd4e;  B = rotl<u32>(B, 13) + A; D = rotl<u32>(D, 10)
    Bp += f1(Cp, Dp, Ep) + X13; Bp = rotl<u32>(Bp, 6) + Ap;  Dp = rotl<u32>(Dp, 10)
    A += f5(B, C, D) + X8 + 0xa953fd4e;  A = rotl<u32>(A, 14) + E; C = rotl<u32>(C, 10)
    Ap += f1(Bp, Cp, Dp) + X14; Ap = rotl<u32>(Ap, 5) + Ep;  Cp = rotl<u32>(Cp, 10)
    E += f5(A, B, C) + X11 + 0xa953fd4e; E = rotl<u32>(E, 11) + D; B = rotl<u32>(B, 10)
    Ep += f1(Ap, Bp, Cp) + X0;  Ep = rotl<u32>(Ep, 15) + Dp; Bp = rotl<u32>(Bp, 10)
    D += f5(E, A, B) + X6 + 0xa953fd4e;  D = rotl<u32>(D, 8) + C;  A = rotl<u32>(A, 10)
    Dp += f1(Ep, Ap, Bp) + X3;  Dp = rotl<u32>(Dp, 13) + Cp; Ap = rotl<u32>(Ap, 10)
    C += f5(D, E, A) + X15 + 0xa953fd4e; C = rotl<u32>(C, 5) + B;  E = rotl<u32>(E, 10)
    Cp += f1(Dp, Ep, Ap) + X9;  Cp = rotl<u32>(Cp, 11) + Bp; Ep = rotl<u32>(Ep, 10)
    B += f5(C, D, E) + X13 + 0xa953fd4e; B = rotl<u32>(B, 6) + A;  D = rotl<u32>(D, 10)
    Bp += f1(Cp, Dp, Ep) + X11; Bp = rotl<u32>(Bp, 11) + Ap; Dp = rotl<u32>(Dp, 10)

    // ── Combinar líneas izquierda/derecha ──
    const T = h1 + C + Dp
    h1 = h2 + D + Ep
    h2 = h3 + E + Ap
    h3 = h4 + A + Bp
    h4 = h0 + B + Cp
    h0 = T

    pos += 64
    n -= 64
  }

  store<u32>(stPtr + 0, h0)
  store<u32>(stPtr + 4, h1)
  store<u32>(stPtr + 8, h2)
  store<u32>(stPtr + 12, h3)
  store<u32>(stPtr + 16, h4)
}

// ═══════════════════════════════════════════════════════════════════════════
// CLASE PÚBLICA
// ═══════════════════════════════════════════════════════════════════════════

@final
class Ripemd160 {
  /** Streaming: alimenta n bytes al contexto. */
  static update(ctx: Ripemd160Context, mPtr: usize, n: isize): void {
    if (n <= 0) return
    ctx.setTotalLen(ctx.getTotalLen() + <u64>n)
    let r = ctx.getBufferLen()
    let pos: isize = 0
    const stPtr = ctx.statePtr
    const bufPtr = ctx.bufferPtr

    if (r > 0) {
      let copiable = min(n, 64 - <isize>r)
      memory.copy(bufPtr + r, mPtr, copiable)
      r += <u32>copiable
      n -= copiable
      pos += copiable
      if (r === 64) {
        compress(stPtr, bufPtr, 64)
        r = 0
      }
    }
    if (n >= 64) {
      const blocksLen = n & ~63
      compress(stPtr, mPtr + pos, blocksLen)
      pos += blocksLen
      n -= blocksLen
    }
    if (n > 0) {
      memory.copy(bufPtr, mPtr + pos, n)
      r = <u32>n
    }
    ctx.setBufferLen(r)
  }

  /** Finaliza: padding LE + digest de 20 bytes en outPtr. paddedPtr ≥ 128 B. */
  static final(ctx: Ripemd160Context, paddedPtr: usize, outPtr: usize): void {
    const r = ctx.getBufferLen()
    const t = ctx.getTotalLen()
    const stPtr = ctx.statePtr
    const bufPtr = ctx.bufferPtr
    const bitLen = t << 3

    memory.copy(paddedPtr, bufPtr, r)
    store<u8>(paddedPtr + r, 0x80)

    if (r < 56) {
      memory.fill(paddedPtr + r + 1, 0, 64 - r - 1)
      // Length en LITTLE-ENDIAN (RIPEMD-160 es LE nativo)
      store<u32>(paddedPtr + 56, <u32>(bitLen & 0xffffffff))
      store<u32>(paddedPtr + 60, <u32>(bitLen >> 32))
      compress(stPtr, paddedPtr, 64)
    } else {
      memory.fill(paddedPtr + r + 1, 0, 128 - r - 1)
      store<u32>(paddedPtr + 120, <u32>(bitLen & 0xffffffff))
      store<u32>(paddedPtr + 124, <u32>(bitLen >> 32))
      compress(stPtr, paddedPtr, 128)
    }

    // Output little-endian (nativo WASM, sin bswap)
    store<u32>(outPtr + 0, load<u32>(stPtr + 0))
    store<u32>(outPtr + 4, load<u32>(stPtr + 4))
    store<u32>(outPtr + 8, load<u32>(stPtr + 8))
    store<u32>(outPtr + 12, load<u32>(stPtr + 12))
    store<u32>(outPtr + 16, load<u32>(stPtr + 16))
  }

  /** One-shot: RIPEMD-160 de n bytes → 20 bytes en outPtr. Zero-alloc. */
  static hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
    const scratch = align8(HASH_WORK_PTR)
    const ctx = changetype<Ripemd160Context>(scratch)
    const padded = align8(scratch + Ripemd160Context.SIZE)
    ctx.init()
    Ripemd160.update(ctx, mPtr, n)
    Ripemd160.final(ctx, padded, outPtr)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS (snake_case, solo punteros)
// ═══════════════════════════════════════════════════════════════════════════

export const RIPEMD160_CTX_SIZE: usize = Ripemd160Context.SIZE // 96

/** One-shot: RIPEMD-160(mPtr[0..len)) → outPtr (20 B). */
export function ripemd160_hash_raw(outPtr: usize, mPtr: usize, len: isize): void {
  Ripemd160.hash_raw(outPtr, mPtr, len)
}

/** Streaming: inicializa contexto en ctxPtr (≥ 96 B). */
export function ripemd160_create_ctx(ctxPtr: usize): void {
  changetype<Ripemd160Context>(ctxPtr).init()
}

/** Streaming: alimenta len bytes de mPtr al contexto. */
export function ripemd160_update_raw(ctxPtr: usize, mPtr: usize, len: isize): void {
  Ripemd160.update(changetype<Ripemd160Context>(ctxPtr), mPtr, len)
}

/** Streaming: finaliza → 20 B en outPtr. paddedPtr ≥ 128 B. */
export function ripemd160_final_raw(ctxPtr: usize, paddedPtr: usize, outPtr: usize): void {
  Ripemd160.final(changetype<Ripemd160Context>(ctxPtr), paddedPtr, outPtr)
}