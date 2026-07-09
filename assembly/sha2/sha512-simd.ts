import { SHA512_K, SHA512_IV } from "./constants"
import {
  load64_be,
  store64_be,
  store64_be_arr,
  sigma0_512,
  sigma1_512,
  Sigma0_512,
  Sigma1_512,
  Ch64,
  Maj64
} from "./common"

type aisize = i32

@final
export class InternalSIMD512 {
  @inline
  static sigma0_512_simd(v: v128): v128 {
    // rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
    let r1 = v128.or(i64x2.shr_u(v, 1), i64x2.shl(v, 63))
    let r8 = v128.or(i64x2.shr_u(v, 8), i64x2.shl(v, 56))
    let s7 = i64x2.shr_u(v, 7)
    return v128.xor(v128.xor(r1, r8), s7)
  }

  @inline
  static sigma1_512_simd(v: v128): v128 {
    // rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)
    let r19 = v128.or(i64x2.shr_u(v, 19), i64x2.shl(v, 45))
    let r61 = v128.or(i64x2.shr_u(v, 61), i64x2.shl(v, 3))
    let s6 = i64x2.shr_u(v, 6)
    return v128.xor(v128.xor(r19, r61), s6)
  }

  static _hashblocks(stPtr: usize, mPtr: usize, n: isize): isize {
    let h0 = load<u64>(stPtr + 0),
      h1 = load<u64>(stPtr + 8),
      h2 = load<u64>(stPtr + 16),
      h3 = load<u64>(stPtr + 24)
    let h4 = load<u64>(stPtr + 32),
      h5 = load<u64>(stPtr + 40),
      h6 = load<u64>(stPtr + 48),
      h7 = load<u64>(stPtr + 56)

    let pos: usize = 0

    while (n >= 128) {
      let a = h0,
        b = h1,
        c = h2,
        d = h3,
        e = h4,
        f = h5,
        g = h6,
        h = h7

      // Load 16 words using SIMD and bswap
      let v0 = i8x16.shuffle(
        v128.load(mPtr + pos + 0),
        v128.load(mPtr + pos + 0),
        7,
        6,
        5,
        4,
        3,
        2,
        1,
        0,
        15,
        14,
        13,
        12,
        11,
        10,
        9,
        8
      )
      let v1 = i8x16.shuffle(
        v128.load(mPtr + pos + 16),
        v128.load(mPtr + pos + 16),
        7,
        6,
        5,
        4,
        3,
        2,
        1,
        0,
        15,
        14,
        13,
        12,
        11,
        10,
        9,
        8
      )
      let v2 = i8x16.shuffle(
        v128.load(mPtr + pos + 32),
        v128.load(mPtr + pos + 32),
        7,
        6,
        5,
        4,
        3,
        2,
        1,
        0,
        15,
        14,
        13,
        12,
        11,
        10,
        9,
        8
      )
      let v3 = i8x16.shuffle(
        v128.load(mPtr + pos + 48),
        v128.load(mPtr + pos + 48),
        7,
        6,
        5,
        4,
        3,
        2,
        1,
        0,
        15,
        14,
        13,
        12,
        11,
        10,
        9,
        8
      )
      let v4 = i8x16.shuffle(
        v128.load(mPtr + pos + 64),
        v128.load(mPtr + pos + 64),
        7,
        6,
        5,
        4,
        3,
        2,
        1,
        0,
        15,
        14,
        13,
        12,
        11,
        10,
        9,
        8
      )
      let v5 = i8x16.shuffle(
        v128.load(mPtr + pos + 80),
        v128.load(mPtr + pos + 80),
        7,
        6,
        5,
        4,
        3,
        2,
        1,
        0,
        15,
        14,
        13,
        12,
        11,
        10,
        9,
        8
      )
      let v6 = i8x16.shuffle(
        v128.load(mPtr + pos + 96),
        v128.load(mPtr + pos + 96),
        7,
        6,
        5,
        4,
        3,
        2,
        1,
        0,
        15,
        14,
        13,
        12,
        11,
        10,
        9,
        8
      )
      let v7 = i8x16.shuffle(
        v128.load(mPtr + pos + 112),
        v128.load(mPtr + pos + 112),
        7,
        6,
        5,
        4,
        3,
        2,
        1,
        0,
        15,
        14,
        13,
        12,
        11,
        10,
        9,
        8
      )

      let w0 = i64x2.extract_lane(v0, 0),
        w1 = i64x2.extract_lane(v0, 1)
      let w2 = i64x2.extract_lane(v1, 0),
        w3 = i64x2.extract_lane(v1, 1)
      let w4 = i64x2.extract_lane(v2, 0),
        w5 = i64x2.extract_lane(v2, 1)
      let w6 = i64x2.extract_lane(v3, 0),
        w7 = i64x2.extract_lane(v3, 1)
      let w8 = i64x2.extract_lane(v4, 0),
        w9 = i64x2.extract_lane(v4, 1)
      let w10 = i64x2.extract_lane(v5, 0),
        w11 = i64x2.extract_lane(v5, 1)
      let w12 = i64x2.extract_lane(v6, 0),
        w13 = i64x2.extract_lane(v6, 1)
      let w14 = i64x2.extract_lane(v7, 0),
        w15 = i64x2.extract_lane(v7, 1)

      // Rounds 0-15
      h += Sigma1_512(e) + Ch64(e, f, g) + 0x428a2f98d728ae22 + w0
      d += h
      h += Sigma0_512(a) + Maj64(a, b, c)
      g += Sigma1_512(d) + Ch64(d, e, f) + 0x7137449123ef65cd + w1
      c += g
      g += Sigma0_512(h) + Maj64(h, a, b)
      f += Sigma1_512(c) + Ch64(c, d, e) + 0xb5c0fbcfec4d3b2f + w2
      b += f
      f += Sigma0_512(g) + Maj64(g, h, a)
      e += Sigma1_512(b) + Ch64(b, c, d) + 0xe9b5dba58189dbbc + w3
      a += e
      e += Sigma0_512(f) + Maj64(f, g, h)
      d += Sigma1_512(a) + Ch64(a, b, c) + 0x3956c25bf348b538 + w4
      h += d
      d += Sigma0_512(e) + Maj64(e, f, g)
      c += Sigma1_512(h) + Ch64(h, a, b) + 0x59f111f1b605d019 + w5
      g += c
      c += Sigma0_512(d) + Maj64(d, e, f)
      b += Sigma1_512(g) + Ch64(g, h, a) + 0x923f82a4af194f9b + w6
      f += b
      b += Sigma0_512(c) + Maj64(c, d, e)
      a += Sigma1_512(f) + Ch64(f, g, h) + 0xab1c5ed5da6d8118 + w7
      e += a
      a += Sigma0_512(b) + Maj64(b, c, d)
      h += Sigma1_512(e) + Ch64(e, f, g) + 0xd807aa98a3030242 + w8
      d += h
      h += Sigma0_512(a) + Maj64(a, b, c)
      g += Sigma1_512(d) + Ch64(d, e, f) + 0x12835b0145706fbe + w9
      c += g
      g += Sigma0_512(h) + Maj64(h, a, b)
      f += Sigma1_512(c) + Ch64(c, d, e) + 0x243185be4ee4b28c + w10
      b += f
      f += Sigma0_512(g) + Maj64(g, h, a)
      e += Sigma1_512(b) + Ch64(b, c, d) + 0x550c7dc3d5ffb4e2 + w11
      a += e
      e += Sigma0_512(f) + Maj64(f, g, h)
      d += Sigma1_512(a) + Ch64(a, b, c) + 0x72be5d74f27b896f + w12
      h += d
      d += Sigma0_512(e) + Maj64(e, f, g)
      c += Sigma1_512(h) + Ch64(h, a, b) + 0x80deb1fe3b1696b1 + w13
      g += c
      c += Sigma0_512(d) + Maj64(d, e, f)
      b += Sigma1_512(g) + Ch64(g, h, a) + 0x9bdc06a725c71235 + w14
      f += b
      b += Sigma0_512(c) + Maj64(c, d, e)
      a += Sigma1_512(f) + Ch64(f, g, h) + 0xc19bf174cf692694 + w15
      e += a
      a += Sigma0_512(b) + Maj64(b, c, d)

      // Rounds 16-79
      for (let i = 16; i < 80; i += 16) {
        let kPtr = changetype<usize>(SHA512_K) + (i << 3)

        // SIMD Message Schedule
        let v_i_15_14 = i8x16.shuffle(v0, v1, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        let v_i_7_6 = i8x16.shuffle(v4, v5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        v0 = i64x2.add(
          i64x2.add(v0, InternalSIMD512.sigma0_512_simd(v_i_15_14)),
          i64x2.add(v_i_7_6, InternalSIMD512.sigma1_512_simd(v7))
        )
        w0 = i64x2.extract_lane(v0, 0)
        h += Sigma1_512(e) + Ch64(e, f, g) + load<u64>(kPtr + 0) + w0
        d += h
        h += Sigma0_512(a) + Maj64(a, b, c)
        w1 = i64x2.extract_lane(v0, 1)
        g += Sigma1_512(d) + Ch64(d, e, f) + load<u64>(kPtr + 8) + w1
        c += g
        g += Sigma0_512(h) + Maj64(h, a, b)

        let v_i_15_14_b = i8x16.shuffle(v1, v2, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        let v_i_7_6_b = i8x16.shuffle(v5, v6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        v1 = i64x2.add(
          i64x2.add(v1, InternalSIMD512.sigma0_512_simd(v_i_15_14_b)),
          i64x2.add(v_i_7_6_b, InternalSIMD512.sigma1_512_simd(v0))
        )
        w2 = i64x2.extract_lane(v1, 0)
        f += Sigma1_512(c) + Ch64(c, d, e) + load<u64>(kPtr + 16) + w2
        b += f
        f += Sigma0_512(g) + Maj64(g, h, a)
        w3 = i64x2.extract_lane(v1, 1)
        e += Sigma1_512(b) + Ch64(b, c, d) + load<u64>(kPtr + 24) + w3
        a += e
        e += Sigma0_512(f) + Maj64(f, g, h)

        let v_i_15_14_c = i8x16.shuffle(v2, v3, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        let v_i_7_6_c = i8x16.shuffle(v6, v7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        v2 = i64x2.add(
          i64x2.add(v2, InternalSIMD512.sigma0_512_simd(v_i_15_14_c)),
          i64x2.add(v_i_7_6_c, InternalSIMD512.sigma1_512_simd(v1))
        )
        w4 = i64x2.extract_lane(v2, 0)
        d += Sigma1_512(a) + Ch64(a, b, c) + load<u64>(kPtr + 32) + w4
        h += d
        d += Sigma0_512(e) + Maj64(e, f, g)
        w5 = i64x2.extract_lane(v2, 1)
        c += Sigma1_512(h) + Ch64(h, a, b) + load<u64>(kPtr + 40) + w5
        g += c
        c += Sigma0_512(d) + Maj64(d, e, f)

        let v_i_15_14_d = i8x16.shuffle(v3, v4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        let v_i_7_6_d = i8x16.shuffle(v7, v0, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        v3 = i64x2.add(
          i64x2.add(v3, InternalSIMD512.sigma0_512_simd(v_i_15_14_d)),
          i64x2.add(v_i_7_6_d, InternalSIMD512.sigma1_512_simd(v2))
        )
        w6 = i64x2.extract_lane(v3, 0)
        b += Sigma1_512(g) + Ch64(g, h, a) + load<u64>(kPtr + 48) + w6
        f += b
        b += Sigma0_512(c) + Maj64(c, d, e)
        w7 = i64x2.extract_lane(v3, 1)
        a += Sigma1_512(f) + Ch64(f, g, h) + load<u64>(kPtr + 56) + w7
        e += a
        a += Sigma0_512(b) + Maj64(b, c, d)

        let v_i_15_14_e = i8x16.shuffle(v4, v5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        let v_i_7_6_e = i8x16.shuffle(v0, v1, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        v4 = i64x2.add(
          i64x2.add(v4, InternalSIMD512.sigma0_512_simd(v_i_15_14_e)),
          i64x2.add(v_i_7_6_e, InternalSIMD512.sigma1_512_simd(v3))
        )
        w8 = i64x2.extract_lane(v4, 0)
        h += Sigma1_512(e) + Ch64(e, f, g) + load<u64>(kPtr + 64) + w8
        d += h
        h += Sigma0_512(a) + Maj64(a, b, c)
        w9 = i64x2.extract_lane(v4, 1)
        g += Sigma1_512(d) + Ch64(d, e, f) + load<u64>(kPtr + 72) + w9
        c += g
        g += Sigma0_512(h) + Maj64(h, a, b)

        let v_i_15_14_f = i8x16.shuffle(v5, v6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        let v_i_7_6_f = i8x16.shuffle(v1, v2, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        v5 = i64x2.add(
          i64x2.add(v5, InternalSIMD512.sigma0_512_simd(v_i_15_14_f)),
          i64x2.add(v_i_7_6_f, InternalSIMD512.sigma1_512_simd(v4))
        )
        w10 = i64x2.extract_lane(v5, 0)
        f += Sigma1_512(c) + Ch64(c, d, e) + load<u64>(kPtr + 80) + w10
        b += f
        f += Sigma0_512(g) + Maj64(g, h, a)
        w11 = i64x2.extract_lane(v5, 1)
        e += Sigma1_512(b) + Ch64(b, c, d) + load<u64>(kPtr + 88) + w11
        a += e
        e += Sigma0_512(f) + Maj64(f, g, h)

        let v_i_15_14_g = i8x16.shuffle(v6, v7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        let v_i_7_6_g = i8x16.shuffle(v2, v3, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        v6 = i64x2.add(
          i64x2.add(v6, InternalSIMD512.sigma0_512_simd(v_i_15_14_g)),
          i64x2.add(v_i_7_6_g, InternalSIMD512.sigma1_512_simd(v5))
        )
        w12 = i64x2.extract_lane(v6, 0)
        d += Sigma1_512(a) + Ch64(a, b, c) + load<u64>(kPtr + 96) + w12
        h += d
        d += Sigma0_512(e) + Maj64(e, f, g)
        w13 = i64x2.extract_lane(v6, 1)
        c += Sigma1_512(h) + Ch64(h, a, b) + load<u64>(kPtr + 104) + w13
        g += c
        c += Sigma0_512(d) + Maj64(d, e, f)

        let v_i_15_14_h = i8x16.shuffle(v7, v0, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        let v_i_7_6_h = i8x16.shuffle(v3, v4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
        v7 = i64x2.add(
          i64x2.add(v7, InternalSIMD512.sigma0_512_simd(v_i_15_14_h)),
          i64x2.add(v_i_7_6_h, InternalSIMD512.sigma1_512_simd(v6))
        )
        w14 = i64x2.extract_lane(v7, 0)
        b += Sigma1_512(g) + Ch64(g, h, a) + load<u64>(kPtr + 112) + w14
        f += b
        b += Sigma0_512(c) + Maj64(c, d, e)
        w15 = i64x2.extract_lane(v7, 1)
        a += Sigma1_512(f) + Ch64(f, g, h) + load<u64>(kPtr + 120) + w15
        e += a
        a += Sigma0_512(b) + Maj64(b, c, d)
      }

      h0 += a
      h1 += b
      h2 += c
      h3 += d
      h4 += e
      h5 += f
      h6 += g
      h7 += h
      pos += 128
      n -= 128
    }

    store<u64>(stPtr + 0, h0)
    store<u64>(stPtr + 8, h1)
    store<u64>(stPtr + 16, h2)
    store<u64>(stPtr + 24, h3)
    store<u64>(stPtr + 32, h4)
    store<u64>(stPtr + 40, h5)
    store<u64>(stPtr + 48, h6)
    store<u64>(stPtr + 56, h7)

    return n
  }

  static _hashInit(): Uint8Array {
    let st = new Uint8Array(64 + 128)
    let stPtr = st.dataStart
    store<u64>(stPtr + 0, unchecked(SHA512_IV[0]))
    store<u64>(stPtr + 8, unchecked(SHA512_IV[1]))
    store<u64>(stPtr + 16, unchecked(SHA512_IV[2]))
    store<u64>(stPtr + 24, unchecked(SHA512_IV[3]))
    store<u64>(stPtr + 32, unchecked(SHA512_IV[4]))
    store<u64>(stPtr + 40, unchecked(SHA512_IV[5]))
    store<u64>(stPtr + 48, unchecked(SHA512_IV[6]))
    store<u64>(stPtr + 56, unchecked(SHA512_IV[7]))
    return st
  }

  static _hashUpdate_raw(st: Uint8Array, mPtr: usize, n: isize, r: isize): isize {
    let pos: isize = 0
    let stPtr = st.dataStart

    if (r > 0) {
      let copiable = min(n, 128 - r)
      memory.copy(stPtr + 64 + r, mPtr, copiable)
      r += copiable
      n -= copiable
      pos += copiable
      if (r === 128) {
        InternalSIMD512._hashblocks(stPtr, stPtr + 64, 128)
        r = 0
      }
    }
    if (n >= 128) {
      let blocks_len = n & ~127
      InternalSIMD512._hashblocks(stPtr, mPtr + pos, blocks_len)
      pos += blocks_len
      n -= blocks_len
    }
    if (n > 0) {
      memory.copy(stPtr + 64, mPtr + pos, n)
      r = n
    }
    return r
  }

  static _hashFinal_raw(st: Uint8Array, outPtr: usize, t: isize, r: isize): void {
    let padded = new Uint8Array(256)
    let paddedPtr = padded.dataStart
    let stPtr = st.dataStart

    memory.copy(paddedPtr, stPtr + 64, r)
    padded[<aisize>r] = 0x80
    if (r < 112) {
      store64_be_arr(padded, 128 - 8, (<u64>t) << 3)
      InternalSIMD512._hashblocks(stPtr, paddedPtr, 128)
    } else {
      store64_be_arr(padded, 256 - 8, (<u64>t) << 3)
      InternalSIMD512._hashblocks(stPtr, paddedPtr, 256)
    }

    store64_be(outPtr + 0, load<u64>(stPtr + 0))
    store64_be(outPtr + 8, load<u64>(stPtr + 8))
    store64_be(outPtr + 16, load<u64>(stPtr + 16))
    store64_be(outPtr + 24, load<u64>(stPtr + 24))
    store64_be(outPtr + 32, load<u64>(stPtr + 32))
    store64_be(outPtr + 40, load<u64>(stPtr + 40))
    store64_be(outPtr + 48, load<u64>(stPtr + 48))
    store64_be(outPtr + 56, load<u64>(stPtr + 56))
  }

  static _hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
    let st = InternalSIMD512._hashInit()
    let r = InternalSIMD512._hashUpdate_raw(st, mPtr, n, 0)
    InternalSIMD512._hashFinal_raw(st, outPtr, n, r)
  }
}

@final
export class Sha512SIMD {
  static hash(m: Uint8Array): Uint8Array {
    let h = new Uint8Array(64)
    InternalSIMD512._hash_raw(h.dataStart, m.dataStart, m.length)
    return h
  }
}
