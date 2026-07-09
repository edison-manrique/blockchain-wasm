/**
 * RIPEMD-160 implementation - Optimized for AssemblyScript
 * Following the Poly1305 formatting pattern.
 */

// ═══════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════

const RIPEMD160_IV: StaticArray<u32> = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
export const RIPEMD160_BLOCK_BYTES: i32 = 64
export const RIPEMD160_HASH_BYTES: i32 = 20

@final
export class Internal {
  @inline
  static F1(x: u32, y: u32, z: u32): u32 {
    return x ^ y ^ z
  }
  @inline
  static F2(x: u32, y: u32, z: u32): u32 {
    return (x & y) | (~x & z)
  }
  @inline
  static F3(x: u32, y: u32, z: u32): u32 {
    return (x | ~y) ^ z
  }
  @inline
  static F4(x: u32, y: u32, z: u32): u32 {
    return (x & z) | (y & ~z)
  }
  @inline
  static F5(x: u32, y: u32, z: u32): u32 {
    return x ^ (y | ~z)
  }

  static _hashblocks(stPtr: usize, mPtr: usize, n: isize): isize {
    let h0 = load<u32>(stPtr + 0)
    let h1 = load<u32>(stPtr + 4)
    let h2 = load<u32>(stPtr + 8)
    let h3 = load<u32>(stPtr + 12)
    let h4 = load<u32>(stPtr + 16)

    let pos: usize = 0

    while (n >= 64) {
      let A = h0,
        B = h1,
        C = h2,
        D = h3,
        E = h4
      let Ap = h0,
        Bp = h1,
        Cp = h2,
        Dp = h3,
        Ep = h4

      let X0 = load<u32>(mPtr + pos + 0)
      let X1 = load<u32>(mPtr + pos + 4)
      let X2 = load<u32>(mPtr + pos + 8)
      let X3 = load<u32>(mPtr + pos + 12)
      let X4 = load<u32>(mPtr + pos + 16)
      let X5 = load<u32>(mPtr + pos + 20)
      let X6 = load<u32>(mPtr + pos + 24)
      let X7 = load<u32>(mPtr + pos + 28)
      let X8 = load<u32>(mPtr + pos + 32)
      let X9 = load<u32>(mPtr + pos + 36)
      let X10 = load<u32>(mPtr + pos + 40)
      let X11 = load<u32>(mPtr + pos + 44)
      let X12 = load<u32>(mPtr + pos + 48)
      let X13 = load<u32>(mPtr + pos + 52)
      let X14 = load<u32>(mPtr + pos + 56)
      let X15 = load<u32>(mPtr + pos + 60)

      // Round 1
      A += Internal.F1(B, C, D) + X0 + 0x00000000
      A = rotl(A, 11) + E
      C = rotl(C, 10)
      Ap += Internal.F5(Bp, Cp, Dp) + X5 + 0x50a28be6
      Ap = rotl(Ap, 8) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F1(A, B, C) + X1 + 0x00000000
      E = rotl(E, 14) + D
      B = rotl(B, 10)
      Ep += Internal.F5(Ap, Bp, Cp) + X14 + 0x50a28be6
      Ep = rotl(Ep, 9) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F1(E, A, B) + X2 + 0x00000000
      D = rotl(D, 15) + C
      A = rotl(A, 10)
      Dp += Internal.F5(Ep, Ap, Bp) + X7 + 0x50a28be6
      Dp = rotl(Dp, 9) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F1(D, E, A) + X3 + 0x00000000
      C = rotl(C, 12) + B
      E = rotl(E, 10)
      Cp += Internal.F5(Dp, Ep, Ap) + X0 + 0x50a28be6
      Cp = rotl(Cp, 11) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F1(C, D, E) + X4 + 0x00000000
      B = rotl(B, 5) + A
      D = rotl(D, 10)
      Bp += Internal.F5(Cp, Dp, Ep) + X9 + 0x50a28be6
      Bp = rotl(Bp, 13) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F1(B, C, D) + X5 + 0x00000000
      A = rotl(A, 8) + E
      C = rotl(C, 10)
      Ap += Internal.F5(Bp, Cp, Dp) + X2 + 0x50a28be6
      Ap = rotl(Ap, 15) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F1(A, B, C) + X6 + 0x00000000
      E = rotl(E, 7) + D
      B = rotl(B, 10)
      Ep += Internal.F5(Ap, Bp, Cp) + X11 + 0x50a28be6
      Ep = rotl(Ep, 15) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F1(E, A, B) + X7 + 0x00000000
      D = rotl(D, 9) + C
      A = rotl(A, 10)
      Dp += Internal.F5(Ep, Ap, Bp) + X4 + 0x50a28be6
      Dp = rotl(Dp, 5) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F1(D, E, A) + X8 + 0x00000000
      C = rotl(C, 11) + B
      E = rotl(E, 10)
      Cp += Internal.F5(Dp, Ep, Ap) + X13 + 0x50a28be6
      Cp = rotl(Cp, 7) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F1(C, D, E) + X9 + 0x00000000
      B = rotl(B, 13) + A
      D = rotl(D, 10)
      Bp += Internal.F5(Cp, Dp, Ep) + X6 + 0x50a28be6
      Bp = rotl(Bp, 7) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F1(B, C, D) + X10 + 0x00000000
      A = rotl(A, 14) + E
      C = rotl(C, 10)
      Ap += Internal.F5(Bp, Cp, Dp) + X15 + 0x50a28be6
      Ap = rotl(Ap, 8) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F1(A, B, C) + X11 + 0x00000000
      E = rotl(E, 15) + D
      B = rotl(B, 10)
      Ep += Internal.F5(Ap, Bp, Cp) + X8 + 0x50a28be6
      Ep = rotl(Ep, 11) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F1(E, A, B) + X12 + 0x00000000
      D = rotl(D, 6) + C
      A = rotl(A, 10)
      Dp += Internal.F5(Ep, Ap, Bp) + X1 + 0x50a28be6
      Dp = rotl(Dp, 14) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F1(D, E, A) + X13 + 0x00000000
      C = rotl(C, 7) + B
      E = rotl(E, 10)
      Cp += Internal.F5(Dp, Ep, Ap) + X10 + 0x50a28be6
      Cp = rotl(Cp, 14) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F1(C, D, E) + X14 + 0x00000000
      B = rotl(B, 9) + A
      D = rotl(D, 10)
      Bp += Internal.F5(Cp, Dp, Ep) + X3 + 0x50a28be6
      Bp = rotl(Bp, 12) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F1(B, C, D) + X15 + 0x00000000
      A = rotl(A, 8) + E
      C = rotl(C, 10)
      Ap += Internal.F5(Bp, Cp, Dp) + X12 + 0x50a28be6
      Ap = rotl(Ap, 6) + Ep
      Cp = rotl(Cp, 10)

      // Round 2
      E += Internal.F2(A, B, C) + X7 + 0x5a827999
      E = rotl(E, 7) + D
      B = rotl(B, 10)
      Ep += Internal.F4(Ap, Bp, Cp) + X6 + 0x5c4dd124
      Ep = rotl(Ep, 9) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F2(E, A, B) + X4 + 0x5a827999
      D = rotl(D, 6) + C
      A = rotl(A, 10)
      Dp += Internal.F4(Ep, Ap, Bp) + X11 + 0x5c4dd124
      Dp = rotl(Dp, 13) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F2(D, E, A) + X13 + 0x5a827999
      C = rotl(C, 8) + B
      E = rotl(E, 10)
      Cp += Internal.F4(Dp, Ep, Ap) + X3 + 0x5c4dd124
      Cp = rotl(Cp, 15) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F2(C, D, E) + X1 + 0x5a827999
      B = rotl(B, 13) + A
      D = rotl(D, 10)
      Bp += Internal.F4(Cp, Dp, Ep) + X7 + 0x5c4dd124
      Bp = rotl(Bp, 7) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F2(B, C, D) + X10 + 0x5a827999
      A = rotl(A, 11) + E
      C = rotl(C, 10)
      Ap += Internal.F4(Bp, Cp, Dp) + X0 + 0x5c4dd124
      Ap = rotl(Ap, 12) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F2(A, B, C) + X6 + 0x5a827999
      E = rotl(E, 9) + D
      B = rotl(B, 10)
      Ep += Internal.F4(Ap, Bp, Cp) + X13 + 0x5c4dd124
      Ep = rotl(Ep, 8) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F2(E, A, B) + X15 + 0x5a827999
      D = rotl(D, 7) + C
      A = rotl(A, 10)
      Dp += Internal.F4(Ep, Ap, Bp) + X5 + 0x5c4dd124
      Dp = rotl(Dp, 9) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F2(D, E, A) + X3 + 0x5a827999
      C = rotl(C, 15) + B
      E = rotl(E, 10)
      Cp += Internal.F4(Dp, Ep, Ap) + X10 + 0x5c4dd124
      Cp = rotl(Cp, 11) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F2(C, D, E) + X12 + 0x5a827999
      B = rotl(B, 7) + A
      D = rotl(D, 10)
      Bp += Internal.F4(Cp, Dp, Ep) + X14 + 0x5c4dd124
      Bp = rotl(Bp, 7) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F2(B, C, D) + X0 + 0x5a827999
      A = rotl(A, 12) + E
      C = rotl(C, 10)
      Ap += Internal.F4(Bp, Cp, Dp) + X15 + 0x5c4dd124
      Ap = rotl(Ap, 7) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F2(A, B, C) + X9 + 0x5a827999
      E = rotl(E, 15) + D
      B = rotl(B, 10)
      Ep += Internal.F4(Ap, Bp, Cp) + X8 + 0x5c4dd124
      Ep = rotl(Ep, 12) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F2(E, A, B) + X5 + 0x5a827999
      D = rotl(D, 9) + C
      A = rotl(A, 10)
      Dp += Internal.F4(Ep, Ap, Bp) + X12 + 0x5c4dd124
      Dp = rotl(Dp, 7) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F2(D, E, A) + X2 + 0x5a827999
      C = rotl(C, 11) + B
      E = rotl(E, 10)
      Cp += Internal.F4(Dp, Ep, Ap) + X4 + 0x5c4dd124
      Cp = rotl(Cp, 6) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F2(C, D, E) + X14 + 0x5a827999
      B = rotl(B, 7) + A
      D = rotl(D, 10)
      Bp += Internal.F4(Cp, Dp, Ep) + X9 + 0x5c4dd124
      Bp = rotl(Bp, 15) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F2(B, C, D) + X11 + 0x5a827999
      A = rotl(A, 13) + E
      C = rotl(C, 10)
      Ap += Internal.F4(Bp, Cp, Dp) + X1 + 0x5c4dd124
      Ap = rotl(Ap, 13) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F2(A, B, C) + X8 + 0x5a827999
      E = rotl(E, 12) + D
      B = rotl(B, 10)
      Ep += Internal.F4(Ap, Bp, Cp) + X2 + 0x5c4dd124
      Ep = rotl(Ep, 11) + Dp
      Bp = rotl(Bp, 10)

      // Round 3
      D += Internal.F3(E, A, B) + X3 + 0x6ed9eba1
      D = rotl(D, 11) + C
      A = rotl(A, 10)
      Dp += Internal.F3(Ep, Ap, Bp) + X15 + 0x6d703ef3
      Dp = rotl(Dp, 9) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F3(D, E, A) + X10 + 0x6ed9eba1
      C = rotl(C, 13) + B
      E = rotl(E, 10)
      Cp += Internal.F3(Dp, Ep, Ap) + X5 + 0x6d703ef3
      Cp = rotl(Cp, 7) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F3(C, D, E) + X14 + 0x6ed9eba1
      B = rotl(B, 6) + A
      D = rotl(D, 10)
      Bp += Internal.F3(Cp, Dp, Ep) + X1 + 0x6d703ef3
      Bp = rotl(Bp, 15) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F3(B, C, D) + X4 + 0x6ed9eba1
      A = rotl(A, 7) + E
      C = rotl(C, 10)
      Ap += Internal.F3(Bp, Cp, Dp) + X3 + 0x6d703ef3
      Ap = rotl(Ap, 11) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F3(A, B, C) + X9 + 0x6ed9eba1
      E = rotl(E, 14) + D
      B = rotl(B, 10)
      Ep += Internal.F3(Ap, Bp, Cp) + X7 + 0x6d703ef3
      Ep = rotl(Ep, 8) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F3(E, A, B) + X15 + 0x6ed9eba1
      D = rotl(D, 9) + C
      A = rotl(A, 10)
      Dp += Internal.F3(Ep, Ap, Bp) + X14 + 0x6d703ef3
      Dp = rotl(Dp, 6) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F3(D, E, A) + X8 + 0x6ed9eba1
      C = rotl(C, 13) + B
      E = rotl(E, 10)
      Cp += Internal.F3(Dp, Ep, Ap) + X6 + 0x6d703ef3
      Cp = rotl(Cp, 6) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F3(C, D, E) + X1 + 0x6ed9eba1
      B = rotl(B, 15) + A
      D = rotl(D, 10)
      Bp += Internal.F3(Cp, Dp, Ep) + X9 + 0x6d703ef3
      Bp = rotl(Bp, 14) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F3(B, C, D) + X2 + 0x6ed9eba1
      A = rotl(A, 14) + E
      C = rotl(C, 10)
      Ap += Internal.F3(Bp, Cp, Dp) + X11 + 0x6d703ef3
      Ap = rotl(Ap, 12) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F3(A, B, C) + X7 + 0x6ed9eba1
      E = rotl(E, 8) + D
      B = rotl(B, 10)
      Ep += Internal.F3(Ap, Bp, Cp) + X8 + 0x6d703ef3
      Ep = rotl(Ep, 13) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F3(E, A, B) + X0 + 0x6ed9eba1
      D = rotl(D, 13) + C
      A = rotl(A, 10)
      Dp += Internal.F3(Ep, Ap, Bp) + X12 + 0x6d703ef3
      Dp = rotl(Dp, 5) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F3(D, E, A) + X6 + 0x6ed9eba1
      C = rotl(C, 6) + B
      E = rotl(E, 10)
      Cp += Internal.F3(Dp, Ep, Ap) + X2 + 0x6d703ef3
      Cp = rotl(Cp, 14) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F3(C, D, E) + X13 + 0x6ed9eba1
      B = rotl(B, 5) + A
      D = rotl(D, 10)
      Bp += Internal.F3(Cp, Dp, Ep) + X10 + 0x6d703ef3
      Bp = rotl(Bp, 13) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F3(B, C, D) + X11 + 0x6ed9eba1
      A = rotl(A, 12) + E
      C = rotl(C, 10)
      Ap += Internal.F3(Bp, Cp, Dp) + X0 + 0x6d703ef3
      Ap = rotl(Ap, 13) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F3(A, B, C) + X5 + 0x6ed9eba1
      E = rotl(E, 7) + D
      B = rotl(B, 10)
      Ep += Internal.F3(Ap, Bp, Cp) + X4 + 0x6d703ef3
      Ep = rotl(Ep, 7) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F3(E, A, B) + X12 + 0x6ed9eba1
      D = rotl(D, 5) + C
      A = rotl(A, 10)
      Dp += Internal.F3(Ep, Ap, Bp) + X13 + 0x6d703ef3
      Dp = rotl(Dp, 5) + Cp
      Ap = rotl(Ap, 10)

      // Round 4
      C += Internal.F4(D, E, A) + X1 + 0x8f1bbcdc
      C = rotl(C, 11) + B
      E = rotl(E, 10)
      Cp += Internal.F2(Dp, Ep, Ap) + X8 + 0x7a6d76e9
      Cp = rotl(Cp, 15) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F4(C, D, E) + X9 + 0x8f1bbcdc
      B = rotl(B, 12) + A
      D = rotl(D, 10)
      Bp += Internal.F2(Cp, Dp, Ep) + X6 + 0x7a6d76e9
      Bp = rotl(Bp, 5) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F4(B, C, D) + X11 + 0x8f1bbcdc
      A = rotl(A, 14) + E
      C = rotl(C, 10)
      Ap += Internal.F2(Bp, Cp, Dp) + X4 + 0x7a6d76e9
      Ap = rotl(Ap, 8) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F4(A, B, C) + X10 + 0x8f1bbcdc
      E = rotl(E, 15) + D
      B = rotl(B, 10)
      Ep += Internal.F2(Ap, Bp, Cp) + X1 + 0x7a6d76e9
      Ep = rotl(Ep, 11) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F4(E, A, B) + X0 + 0x8f1bbcdc
      D = rotl(D, 14) + C
      A = rotl(A, 10)
      Dp += Internal.F2(Ep, Ap, Bp) + X3 + 0x7a6d76e9
      Dp = rotl(Dp, 14) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F4(D, E, A) + X8 + 0x8f1bbcdc
      C = rotl(C, 15) + B
      E = rotl(E, 10)
      Cp += Internal.F2(Dp, Ep, Ap) + X11 + 0x7a6d76e9
      Cp = rotl(Cp, 14) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F4(C, D, E) + X12 + 0x8f1bbcdc
      B = rotl(B, 9) + A
      D = rotl(D, 10)
      Bp += Internal.F2(Cp, Dp, Ep) + X15 + 0x7a6d76e9
      Bp = rotl(Bp, 6) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F4(B, C, D) + X4 + 0x8f1bbcdc
      A = rotl(A, 8) + E
      C = rotl(C, 10)
      Ap += Internal.F2(Bp, Cp, Dp) + X0 + 0x7a6d76e9
      Ap = rotl(Ap, 14) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F4(A, B, C) + X13 + 0x8f1bbcdc
      E = rotl(E, 9) + D
      B = rotl(B, 10)
      Ep += Internal.F2(Ap, Bp, Cp) + X5 + 0x7a6d76e9
      Ep = rotl(Ep, 6) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F4(E, A, B) + X3 + 0x8f1bbcdc
      D = rotl(D, 14) + C
      A = rotl(A, 10)
      Dp += Internal.F2(Ep, Ap, Bp) + X12 + 0x7a6d76e9
      Dp = rotl(Dp, 9) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F4(D, E, A) + X7 + 0x8f1bbcdc
      C = rotl(C, 5) + B
      E = rotl(E, 10)
      Cp += Internal.F2(Dp, Ep, Ap) + X2 + 0x7a6d76e9
      Cp = rotl(Cp, 12) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F4(C, D, E) + X15 + 0x8f1bbcdc
      B = rotl(B, 6) + A
      D = rotl(D, 10)
      Bp += Internal.F2(Cp, Dp, Ep) + X13 + 0x7a6d76e9
      Bp = rotl(Bp, 9) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F4(B, C, D) + X14 + 0x8f1bbcdc
      A = rotl(A, 8) + E
      C = rotl(C, 10)
      Ap += Internal.F2(Bp, Cp, Dp) + X9 + 0x7a6d76e9
      Ap = rotl(Ap, 12) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F4(A, B, C) + X5 + 0x8f1bbcdc
      E = rotl(E, 6) + D
      B = rotl(B, 10)
      Ep += Internal.F2(Ap, Bp, Cp) + X7 + 0x7a6d76e9
      Ep = rotl(Ep, 5) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F4(E, A, B) + X6 + 0x8f1bbcdc
      D = rotl(D, 5) + C
      A = rotl(A, 10)
      Dp += Internal.F2(Ep, Ap, Bp) + X10 + 0x7a6d76e9
      Dp = rotl(Dp, 15) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F4(D, E, A) + X2 + 0x8f1bbcdc
      C = rotl(C, 12) + B
      E = rotl(E, 10)
      Cp += Internal.F2(Dp, Ep, Ap) + X14 + 0x7a6d76e9
      Cp = rotl(Cp, 8) + Bp
      Ep = rotl(Ep, 10)

      // Round 5
      B += Internal.F5(C, D, E) + X4 + 0xa953fd4e
      B = rotl(B, 9) + A
      D = rotl(D, 10)
      Bp += Internal.F1(Cp, Dp, Ep) + X12 + 0x00000000
      Bp = rotl(Bp, 8) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F5(B, C, D) + X0 + 0xa953fd4e
      A = rotl(A, 15) + E
      C = rotl(C, 10)
      Ap += Internal.F1(Bp, Cp, Dp) + X15 + 0x00000000
      Ap = rotl(Ap, 5) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F5(A, B, C) + X5 + 0xa953fd4e
      E = rotl(E, 5) + D
      B = rotl(B, 10)
      Ep += Internal.F1(Ap, Bp, Cp) + X10 + 0x00000000
      Ep = rotl(Ep, 12) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F5(E, A, B) + X9 + 0xa953fd4e
      D = rotl(D, 11) + C
      A = rotl(A, 10)
      Dp += Internal.F1(Ep, Ap, Bp) + X4 + 0x00000000
      Dp = rotl(Dp, 9) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F5(D, E, A) + X7 + 0xa953fd4e
      C = rotl(C, 6) + B
      E = rotl(E, 10)
      Cp += Internal.F1(Dp, Ep, Ap) + X1 + 0x00000000
      Cp = rotl(Cp, 12) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F5(C, D, E) + X12 + 0xa953fd4e
      B = rotl(B, 8) + A
      D = rotl(D, 10)
      Bp += Internal.F1(Cp, Dp, Ep) + X5 + 0x00000000
      Bp = rotl(Bp, 5) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F5(B, C, D) + X2 + 0xa953fd4e
      A = rotl(A, 13) + E
      C = rotl(C, 10)
      Ap += Internal.F1(Bp, Cp, Dp) + X8 + 0x00000000
      Ap = rotl(Ap, 14) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F5(A, B, C) + X10 + 0xa953fd4e
      E = rotl(E, 12) + D
      B = rotl(B, 10)
      Ep += Internal.F1(Ap, Bp, Cp) + X7 + 0x00000000
      Ep = rotl(Ep, 6) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F5(E, A, B) + X14 + 0xa953fd4e
      D = rotl(D, 5) + C
      A = rotl(A, 10)
      Dp += Internal.F1(Ep, Ap, Bp) + X6 + 0x00000000
      Dp = rotl(Dp, 8) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F5(D, E, A) + X1 + 0xa953fd4e
      C = rotl(C, 12) + B
      E = rotl(E, 10)
      Cp += Internal.F1(Dp, Ep, Ap) + X2 + 0x00000000
      Cp = rotl(Cp, 13) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F5(C, D, E) + X3 + 0xa953fd4e
      B = rotl(B, 13) + A
      D = rotl(D, 10)
      Bp += Internal.F1(Cp, Dp, Ep) + X13 + 0x00000000
      Bp = rotl(Bp, 6) + Ap
      Dp = rotl(Dp, 10)
      A += Internal.F5(B, C, D) + X8 + 0xa953fd4e
      A = rotl(A, 14) + E
      C = rotl(C, 10)
      Ap += Internal.F1(Bp, Cp, Dp) + X14 + 0x00000000
      Ap = rotl(Ap, 5) + Ep
      Cp = rotl(Cp, 10)
      E += Internal.F5(A, B, C) + X11 + 0xa953fd4e
      E = rotl(E, 11) + D
      B = rotl(B, 10)
      Ep += Internal.F1(Ap, Bp, Cp) + X0 + 0x00000000
      Ep = rotl(Ep, 15) + Dp
      Bp = rotl(Bp, 10)
      D += Internal.F5(E, A, B) + X6 + 0xa953fd4e
      D = rotl(D, 8) + C
      A = rotl(A, 10)
      Dp += Internal.F1(Ep, Ap, Bp) + X3 + 0x00000000
      Dp = rotl(Dp, 13) + Cp
      Ap = rotl(Ap, 10)
      C += Internal.F5(D, E, A) + X15 + 0xa953fd4e
      C = rotl(C, 5) + B
      E = rotl(E, 10)
      Cp += Internal.F1(Dp, Ep, Ap) + X9 + 0x00000000
      Cp = rotl(Cp, 11) + Bp
      Ep = rotl(Ep, 10)
      B += Internal.F5(C, D, E) + X13 + 0xa953fd4e
      B = rotl(B, 6) + A
      D = rotl(D, 10)
      Bp += Internal.F1(Cp, Dp, Ep) + X11 + 0x00000000
      Bp = rotl(Bp, 11) + Ap
      Dp = rotl(Dp, 10)

      let tempC = h1 + C + Dp
      h1 = h2 + D + Ep
      h2 = h3 + E + Ap
      h3 = h4 + A + Bp
      h4 = h0 + B + Cp
      h0 = tempC

      pos += 64
      n -= 64
    }

    store<u32>(stPtr + 0, h0)
    store<u32>(stPtr + 4, h1)
    store<u32>(stPtr + 8, h2)
    store<u32>(stPtr + 12, h3)
    store<u32>(stPtr + 16, h4)

    return n
  }

  static _hashInit(): Uint8Array {
    let st = new Uint8Array(20 + 64)
    let stPtr = st.dataStart
    store<u32>(stPtr + 0, RIPEMD160_IV[0])
    store<u32>(stPtr + 4, RIPEMD160_IV[1])
    store<u32>(stPtr + 8, RIPEMD160_IV[2])
    store<u32>(stPtr + 12, RIPEMD160_IV[3])
    store<u32>(stPtr + 16, RIPEMD160_IV[4])
    return st
  }

  static _hashUpdate(st: Uint8Array, m: Uint8Array, n: isize, r: isize): isize {
    let pos: isize = 0
    let stPtr = st.dataStart
    let mPtr = m.dataStart

    if (r > 0) {
      let copiable = <isize>Math.min(<f64>n, <f64>(64 - r))
      memory.copy(stPtr + 20 + r, mPtr, copiable)
      r += copiable
      n -= copiable
      pos += copiable
      if (r === 64) {
        Internal._hashblocks(stPtr, stPtr + 20, 64)
        r = 0
      }
    }
    if (n >= 64) {
      let blocks_len = n & ~63
      Internal._hashblocks(stPtr, mPtr + pos, blocks_len)
      pos += blocks_len
      n -= blocks_len
    }
    if (n > 0) {
      memory.copy(stPtr + 20, mPtr + pos, n)
      r = n
    }
    return r
  }

  static _hashFinal(st: Uint8Array, out: Uint8Array, t: u64, r: isize): void {
    let padded = new Uint8Array(128)
    let paddedPtr = padded.dataStart
    let stPtr = st.dataStart

    memory.copy(paddedPtr, stPtr + 20, r)
    padded[<i32>r] = 0x80
    let bitLen = t << 3
    if (r < 56) {
      store<u32>(paddedPtr + 56, <u32>(bitLen & 0xffffffff))
      store<u32>(paddedPtr + 60, <u32>(bitLen >>> 32))
      Internal._hashblocks(stPtr, paddedPtr, 64)
    } else {
      store<u32>(paddedPtr + 120, <u32>(bitLen & 0xffffffff))
      store<u32>(paddedPtr + 124, <u32>(bitLen >>> 32))
      Internal._hashblocks(stPtr, paddedPtr, 128)
    }

    store<u32>(out.dataStart + 0, load<u32>(stPtr + 0))
    store<u32>(out.dataStart + 4, load<u32>(stPtr + 4))
    store<u32>(out.dataStart + 8, load<u32>(stPtr + 8))
    store<u32>(out.dataStart + 12, load<u32>(stPtr + 12))
    store<u32>(out.dataStart + 16, load<u32>(stPtr + 16))
  }

  static _hash(out: Uint8Array, m: Uint8Array, n: isize): void {
    let st = Internal._hashInit()
    let r = Internal._hashUpdate(st, m, n, 0)
    Internal._hashFinal(st, out, <u64>n, r)
  }

  static _hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
    let st = Internal._hashInit()
    let r = Internal._hashUpdate_raw(st, mPtr, n, 0)
    Internal._hashFinal_raw(st, outPtr, <u64>n, r)
  }

  static _hashUpdate_raw(st: Uint8Array, mPtr: usize, n: isize, r: isize): isize {
    let pos: isize = 0
    let stPtr = st.dataStart
    if (r > 0) {
      let copiable = <isize>Math.min(<f64>n, <f64>(64 - r))
      memory.copy(stPtr + 20 + r, mPtr, copiable)
      r += copiable
      n -= copiable
      pos += copiable
      if (r === 64) {
        Internal._hashblocks(stPtr, stPtr + 20, 64)
        r = 0
      }
    }
    if (n >= 64) {
      let blocks_len = n & ~63
      Internal._hashblocks(stPtr, mPtr + pos, blocks_len)
      pos += blocks_len
      n -= blocks_len
    }
    if (n > 0) {
      memory.copy(stPtr + 20, mPtr + pos, n)
      r = n
    }
    return r
  }

  static _hashFinal_raw(st: Uint8Array, outPtr: usize, t: u64, r: isize): void {
    let padded = new Uint8Array(128)
    let paddedPtr = padded.dataStart
    let stPtr = st.dataStart
    memory.copy(paddedPtr, stPtr + 20, r)
    padded[<i32>r] = 0x80
    let bitLen = t << 3
    if (r < 56) {
      store<u32>(paddedPtr + 56, <u32>(bitLen & 0xffffffff))
      store<u32>(paddedPtr + 60, <u32>(bitLen >>> 32))
      Internal._hashblocks(stPtr, paddedPtr, 64)
    } else {
      store<u32>(paddedPtr + 120, <u32>(bitLen & 0xffffffff))
      store<u32>(paddedPtr + 124, <u32>(bitLen >>> 32))
      Internal._hashblocks(stPtr, paddedPtr, 128)
    }
    store<u32>(outPtr + 0, load<u32>(stPtr + 0))
    store<u32>(outPtr + 4, load<u32>(stPtr + 4))
    store<u32>(outPtr + 8, load<u32>(stPtr + 8))
    store<u32>(outPtr + 12, load<u32>(stPtr + 12))
    store<u32>(outPtr + 16, load<u32>(stPtr + 16))
  }
}

@final
export class Ripemd160 {
  r: isize = 0
  t: u64 = 0
  st: Uint8Array

  constructor() {
    this.st = Internal._hashInit()
  }

  update(m: Uint8Array): void {
    let n = m.length
    this.t += n
    this.r = Internal._hashUpdate(this.st, m, n, this.r)
  }

  final(): Uint8Array {
    let h = new Uint8Array(RIPEMD160_HASH_BYTES)
    Internal._hashFinal(this.st, h, this.t, this.r)
    return h
  }

  static hash(m: Uint8Array): Uint8Array {
    let h = new Uint8Array(RIPEMD160_HASH_BYTES)
    Internal._hash(h, m, m.length)
    return h
  }
}

export function hash(m: Uint8Array): Uint8Array {
  return Ripemd160.hash(m)
}

export function ripemd160(data: Uint8Array): Uint8Array {
  return Ripemd160.hash(data)
}
