import { BigInt256 } from "./bigint256"
import { Memory } from "../../utils/Memory"
import { GeneratorTable } from "./generator_table"
import { GLV } from "./glv"

@final
export class Scalar256 {
  // secp256k1 Order N
  static readonly N0: u64 = 0xbfd25e8cd0364141
  static readonly N1: u64 = 0xbaaedce6af48a03b
  static readonly N2: u64 = 0xfffffffffffffffe
  static readonly N3: u64 = 0xffffffffffffffff

  // Complement C = 2^256 - N
  static readonly C0: u64 = 0x402da1732fc9bebf
  static readonly C1: u64 = 0x4551231950b75fc4
  static readonly C2: u64 = 0x0000000000000001
  static readonly C3: u64 = 0x0000000000000000

  // N - 2
  static readonly N_MINUS_2_L0: u64 = 0xbfd25e8cd036413f
  static readonly N_MINUS_2_L1: u64 = 0xbaaedce6af48a03b
  static readonly N_MINUS_2_L2: u64 = 0xfffffffffffffffe
  static readonly N_MINUS_2_L3: u64 = 0xffffffffffffffff

  // Static Scratchpad
  static readonly SCRATCH_SIZE: usize = 1024
  static readonly SCRATCH: usize = heap.alloc(Scalar256.SCRATCH_SIZE)

  // Temporal "Registers" (128-byte spacing for safety)
  static readonly t0: usize = Scalar256.SCRATCH + 0
  static readonly t1: usize = Scalar256.SCRATCH + 128
  static readonly t2: usize = Scalar256.SCRATCH + 256
  static readonly t3: usize = Scalar256.SCRATCH + 384
  static readonly t4: usize = Scalar256.SCRATCH + 512
  static readonly t5: usize = Scalar256.SCRATCH + 640

  @inline
  static mul_hi(a: u64, b: u64): u64 {
    const a_lo = a & 0xffffffff
    const a_hi = a >>> 32
    const b_lo = b & 0xffffffff
    const b_hi = b >>> 32
    const p0 = a_lo * b_lo
    const p1 = a_lo * b_hi
    const p2 = a_hi * b_lo
    const p3 = a_hi * b_hi
    const cy = (p0 >>> 32) + (p1 & 0xffffffff) + (p2 & 0xffffffff)
    return p3 + (p1 >>> 32) + (p2 >>> 32) + (cy >>> 32)
  }

  @inline
  static select_u64(a: u64, b: u64, mask: u64): u64 {
    return (a & ~mask) | (b & mask)
  }

  @inline
  static add(res: usize, a: usize, b: usize): void {
    let a0 = load<u64>(a, 0),
      a1 = load<u64>(a, 8),
      a2 = load<u64>(a, 16),
      a3 = load<u64>(a, 24)
    let b0 = load<u64>(b, 0),
      b1 = load<u64>(b, 8),
      b2 = load<u64>(b, 16),
      b3 = load<u64>(b, 24)

    let s0 = a0 + b0
    let c = u64(s0 < a0)
    let s1 = a1 + b1 + c
    c = u64(s1 < a1) | (u64(s1 == a1) & c)
    let s2 = a2 + b2 + c
    c = u64(s2 < a2) | (u64(s2 == a2) & c)
    let s3 = a3 + b3 + c
    c = u64(s3 < a3) | (u64(s3 == a3) & c)

    let d0 = s0 - Scalar256.N0
    let bor = u64(d0 > s0)
    let d1 = s1 - Scalar256.N1 - bor
    bor = u64(d1 > s1) | (u64(d1 == s1) & bor)
    let d2 = s2 - Scalar256.N2 - bor
    bor = u64(d2 > s2) | (u64(d2 == s2) & bor)
    let d3 = s3 - Scalar256.N3 - bor
    bor = u64(d3 > s3) | (u64(d3 == s3) & bor)

    let mask = 0 - (c | (1 - bor))
    store<u64>(res, (s0 & ~mask) | (d0 & mask), 0)
    store<u64>(res, (s1 & ~mask) | (d1 & mask), 8)
    store<u64>(res, (s2 & ~mask) | (d2 & mask), 16)
    store<u64>(res, (s3 & ~mask) | (d3 & mask), 24)
  }

  @inline
  static sub(res: usize, a: usize, b: usize): void {
    let a0 = load<u64>(a, 0),
      a1 = load<u64>(a, 8),
      a2 = load<u64>(a, 16),
      a3 = load<u64>(a, 24)
    let b0 = load<u64>(b, 0),
      b1 = load<u64>(b, 8),
      b2 = load<u64>(b, 16),
      b3 = load<u64>(b, 24)

    let d0 = a0 - b0
    let bor = u64(d0 > a0)
    let d1 = a1 - b1 - bor
    bor = u64(d1 > a1) | (u64(d1 == a1) & bor)
    let d2 = a2 - b2 - bor
    bor = u64(d2 > a2) | (u64(d2 == a2) & bor)
    let d3 = a3 - b3 - bor
    bor = u64(d3 > a3) | (u64(d3 == a3) & bor)

    let p0 = d0 + Scalar256.N0
    let c = u64(p0 < d0)
    let p1 = d1 + Scalar256.N1 + c
    c = u64(p1 < d1) | (u64(p1 == d1) & c)
    let p2 = d2 + Scalar256.N2 + c
    c = u64(p2 < d2) | (u64(p2 == d2) & c)
    let p3 = d3 + Scalar256.N3 + c

    let mask = 0 - bor
    store<u64>(res, (d0 & ~mask) | (p0 & mask), 0)
    store<u64>(res, (d1 & ~mask) | (p1 & mask), 8)
    store<u64>(res, (d2 & ~mask) | (p2 & mask), 16)
    store<u64>(res, (d3 & ~mask) | (p3 & mask), 24)
  }

  @inline
  static mul(res: usize, a: usize, b: usize): void {
    const wide = Scalar256.t2
    BigInt256.mul(wide, a, b)
    Scalar256.reduce(res, wide)
  }

  @inline
  static sqr(res: usize, a: usize): void {
    const wide = Scalar256.t2
    BigInt256.sqr(wide, a)
    Scalar256.reduce(res, wide)
  }

  @inline
  static mulWide(res: usize, a: usize, b: usize): void {
    BigInt256.mul(res, a, b)
  }

  /**
   * Safe Iterative Pseudo-Mersenne Reduction
   */
  static reduce(res: usize, a: usize): void {
    const hc_wide = Scalar256.t4 // Separate register
    const h_temp = Scalar256.t5
    store<u64>(h_temp, load<u64>(a, 32), 0)
    store<u64>(h_temp, load<u64>(a, 40), 8)
    store<u64>(h_temp, load<u64>(a, 48), 16)
    store<u64>(h_temp, load<u64>(a, 56), 24)

    // Copy L to res
    store<u64>(res, load<u64>(a, 0), 0)
    store<u64>(res, load<u64>(a, 8), 8)
    store<u64>(res, load<u64>(a, 16), 16)
    store<u64>(res, load<u64>(a, 24), 24)

    const c_ptr = Scalar256.t0
    store<u64>(c_ptr, Scalar256.C0, 0)
    store<u64>(c_ptr, Scalar256.C1, 8)
    store<u64>(c_ptr, 1, 16)
    store<u64>(c_ptr, 0, 24)

    for (let i = 0; i < 3; i++) {
      if (Scalar256.isZero(h_temp)) break
      BigInt256.mul(hc_wide, h_temp, c_ptr)
      let carry = Scalar256.addRaw(res, res, hc_wide)
      let hh0 = load<u64>(hc_wide, 32),
        hh1 = load<u64>(hc_wide, 40),
        hh2 = load<u64>(hc_wide, 48),
        hh3 = load<u64>(hc_wide, 56)
      if (carry > 0) {
        hh0 += 1
        if (hh0 == 0) {
          hh1 += 1
          if (hh1 == 0) {
            hh2 += 1
            if (hh2 == 0) hh3 += 1
          }
        }
      }
      store<u64>(h_temp, hh0, 0)
      store<u64>(h_temp, hh1, 8)
      store<u64>(h_temp, hh2, 16)
      store<u64>(h_temp, hh3, 24)
    }
    while (Scalar256.isGreaterOrEqualN(res)) Scalar256.subN(res, res)
  }

  static addRaw(res: usize, a: usize, b: usize): u32 {
    let a0 = load<u64>(a, 0),
      b0 = load<u64>(b, 0)
    let s0 = a0 + b0
    let c = u64(s0 < a0)
    store<u64>(res, s0, 0)
    let a1 = load<u64>(a, 8),
      b1 = load<u64>(b, 8)
    let s1 = a1 + b1 + c
    c = u64(s1 < a1) | (u64(s1 == a1) & c)
    store<u64>(res, s1, 8)
    let a2 = load<u64>(a, 16),
      b2 = load<u64>(b, 16)
    let s2 = a2 + b2 + c
    c = u64(s2 < a2) | (u64(s2 == a2) & c)
    store<u64>(res, s2, 16)
    let a3 = load<u64>(a, 24),
      b3 = load<u64>(b, 24)
    let s3 = a3 + b3 + c
    c = u64(s3 < a3) | (u64(s3 == a3) & c)
    store<u64>(res, s3, 24)
    return <u32>c
  }

  static subRaw(res: usize, a: usize, b: usize): u32 {
    let a0 = load<u64>(a, 0),
      b0 = load<u64>(b, 0)
    let d0 = a0 - b0
    let bor = u64(d0 > a0)
    store<u64>(res, d0, 0)
    let a1 = load<u64>(a, 8),
      b1 = load<u64>(b, 8)
    let d1 = a1 - b1 - bor
    bor = u64(d1 > a1) | (u64(d1 == a1) & bor)
    store<u64>(res, d1, 8)
    let a2 = load<u64>(a, 16),
      b2 = load<u64>(b, 16)
    let d2 = a2 - b2 - bor
    bor = u64(d2 > a2) | (u64(d2 == a2) & bor)
    store<u64>(res, d2, 16)
    let a3 = load<u64>(a, 24),
      b3 = load<u64>(b, 24)
    let d3 = a3 - b3 - bor
    bor = u64(d3 > a3) | (u64(d3 == a3) & bor)
    store<u64>(res, d3, 24)
    return <u32>bor
  }

  static subN(res: usize, a: usize): void {
    const n = Scalar256.t3
    store<u64>(n, Scalar256.N0, 0)
    store<u64>(n, Scalar256.N1, 8)
    store<u64>(n, Scalar256.N2, 16)
    store<u64>(n, Scalar256.N3, 24)
    Scalar256.subRaw(res, a, n)
  }

  static addN(res: usize, a: usize): void {
    const n = Scalar256.t3
    store<u64>(n, Scalar256.N0, 0)
    store<u64>(n, Scalar256.N1, 8)
    store<u64>(n, Scalar256.N2, 16)
    store<u64>(n, Scalar256.N3, 24)
    Scalar256.addRaw(res, a, n)
  }

  static isGreaterOrEqualN(a: usize): bool {
    const a3 = load<u64>(a, 24)
    if (a3 > Scalar256.N3) return true
    if (a3 < Scalar256.N3) return false
    const a2 = load<u64>(a, 16)
    if (a2 > Scalar256.N2) return true
    if (a2 < Scalar256.N2) return false
    const a1 = load<u64>(a, 8)
    if (a1 > Scalar256.N1) return true
    if (a1 < Scalar256.N1) return false
    return load<u64>(a, 0) >= Scalar256.N0
  }

  @inline
  static isZero(a: usize): bool {
    return load<u64>(a, 0) == 0 && load<u64>(a, 8) == 0 && load<u64>(a, 16) == 0 && load<u64>(a, 24) == 0
  }

  @inline
  static isOdd(a: usize): bool {
    return (load<u64>(a, 0) & 1) != 0
  }

  static addU64(res: usize, a: usize, val: u64): void {
    const b = Scalar256.t3
    store<u64>(b, val, 0)
    store<u64>(b, 0, 8)
    store<u64>(b, 0, 16)
    store<u64>(b, 0, 24)
    Scalar256.addRaw(res, a, b)
  }

  static subU64(res: usize, a: usize, val: u64): void {
    const b = Scalar256.t3
    store<u64>(b, val, 0)
    store<u64>(b, 0, 8)
    store<u64>(b, 0, 16)
    store<u64>(b, 0, 24)
    Scalar256.subRaw(res, a, b)
  }

  static shiftRight(res: usize, a: usize, n: i32): void {
    if (n == 0) {
      memory.copy(res, a, 32)
      return
    }
    const s = <u64>n,
      inv = 64 - <u64>n
    const r0 = load<u64>(a, 0),
      r1 = load<u64>(a, 8),
      r2 = load<u64>(a, 16),
      r3 = load<u64>(a, 24)
    store<u64>(res, (r0 >> s) | (r1 << inv), 0)
    store<u64>(res, (r1 >> s) | (r2 << inv), 8)
    store<u64>(res, (r2 >> s) | (r3 << inv), 16)
    store<u64>(res, r3 >> s, 24)
  }

  @inline
  static bitwiseAndU32(a: usize, mask: u32): u32 {
    return load<u32>(a, 0) & mask
  }

  static mulByC(res: usize, a: usize): void {
    store<u64>(Scalar256.t0, Scalar256.C0, 0)
    store<u64>(Scalar256.t0, Scalar256.C1, 8)
    store<u64>(Scalar256.t0, Scalar256.C2, 16)
    store<u64>(Scalar256.t0, Scalar256.C3, 24)
    BigInt256.mul(res, a, Scalar256.t0)
  }

  static modInverse(res: usize, a: usize): void {
    if (Scalar256.isZero(a)) {
      store<u64>(res, 0, 0)
      store<u64>(res, 0, 8)
      store<u64>(res, 0, 16)
      store<u64>(res, 0, 24)
      return
    }

    const ctx = Memory.save()
    const u = Memory.alloc(32)
    const v = Memory.alloc(32)
    const x1 = Memory.alloc(32)
    const x2 = Memory.alloc(32)

    memory.copy(u, a, 32)
    store<u64>(v, Scalar256.N0, 0)
    store<u64>(v, Scalar256.N1, 8)
    store<u64>(v, Scalar256.N2, 16)
    store<u64>(v, Scalar256.N3, 24)

    store<u64>(x1, 1, 0)
    store<u64>(x1, 0, 8)
    store<u64>(x1, 0, 16)
    store<u64>(x1, 0, 24)

    store<u64>(x2, 0, 0)
    store<u64>(x2, 0, 8)
    store<u64>(x2, 0, 16)
    store<u64>(x2, 0, 24)

    while (!Scalar256.isZero(u)) {
      while ((load<u64>(u, 0) & 1) == 0) {
        BigInt256.shr1_raw(u)
        if ((load<u64>(x1, 0) & 1) == 0) {
          BigInt256.shr1_raw(x1)
        } else {
          Scalar256.addN_and_shr1(x1)
        }
      }
      while ((load<u64>(v, 0) & 1) == 0) {
        BigInt256.shr1_raw(v)
        if ((load<u64>(x2, 0) & 1) == 0) {
          BigInt256.shr1_raw(x2)
        } else {
          Scalar256.addN_and_shr1(x2)
        }
      }

      if (BigInt256.cmp_raw(u, v) >= 0) {
        BigInt256.sub_raw256(u, u, v)
        Scalar256.sub(x1, x1, x2)
      } else {
        BigInt256.sub_raw256(v, v, u)
        Scalar256.sub(x2, x2, x1)
      }
    }

    memory.copy(res, x2, 32)
    Memory.restore(ctx)
  }

  @inline
  static addN_and_shr1(a: usize): void {
    let a0 = load<u64>(a, 0),
      a1 = load<u64>(a, 8)
    let a2 = load<u64>(a, 16),
      a3 = load<u64>(a, 24)
    let s0 = a0 + Scalar256.N0
    let c = u64(s0 < a0)
    let s1 = a1 + Scalar256.N1 + c
    c = u64(s1 < a1) | (u64(s1 == a1) & c)
    let s2 = a2 + Scalar256.N2 + c
    c = u64(s2 < a2) | (u64(s2 == a2) & c)
    let s3 = a3 + Scalar256.N3 + c
    c = u64(s3 < a3) | (u64(s3 == a3) & c)
    store<u64>(a, (s0 >>> 1) | (s1 << 63), 0)
    store<u64>(a, (s1 >>> 1) | (s2 << 63), 8)
    store<u64>(a, (s2 >>> 1) | (s3 << 63), 16)
    store<u64>(a, (s3 >>> 1) | (c << 63), 24)
  }

  static isGreaterOrEqual(a: usize, b: usize): bool {
    const a3 = load<u64>(a, 24),
      b3 = load<u64>(b, 24)
    if (a3 > b3) return true
    if (a3 < b3) return false
    const a2 = load<u64>(a, 16),
      b2 = load<u64>(b, 16)
    if (a2 > b2) return true
    if (a2 < b2) return false
    const a1 = load<u64>(a, 8),
      b1 = load<u64>(b, 8)
    if (a1 > b1) return true
    if (a1 < b1) return false
    return load<u64>(a, 0) >= load<u64>(b, 0)
  }

  /**
   * Multiplicación escalar: res = k * P
   * Usa endomorfismo GLV para mayor eficiencia.
   */
  @inline
  static multiplyGLV(res: usize, p: usize, k: usize): void {
    GLV.mul(res, p, k)
  }

  /**
   * Multiplicación escalar por el generador: res = k * G
   * Usa una tabla precomputada (super rápido).
   */
  @inline
  static multiplyG(res: usize, k: usize): void {
    GeneratorTable.multiply(res, k)
  }
}
