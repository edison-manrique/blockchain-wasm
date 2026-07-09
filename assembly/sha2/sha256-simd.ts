import { SHA256_K, SHA256_IV } from "./constants"
import {
  load32_be,
  store32_be,
  store64_be_arr,
  sigma0_256,
  sigma1_256,
  Sigma0_256,
  Sigma1_256,
  Ch32,
  Maj32
} from "./common"

type aisize = i32

@final
export class InternalSIMD {
  @inline
  static sigma0_256_simd(v: v128): v128 {
    let r7 = v128.or(i32x4.shr_u(v, 7), i32x4.shl(v, 25))
    let r18 = v128.or(i32x4.shr_u(v, 18), i32x4.shl(v, 14))
    let s3 = i32x4.shr_u(v, 3)
    return v128.xor(v128.xor(r7, r18), s3)
  }

  static _hashblocks(stPtr: usize, mPtr: usize, n: isize): isize {
    let h0 = load<u32>(stPtr + 0),
      h1 = load<u32>(stPtr + 4),
      h2 = load<u32>(stPtr + 8),
      h3 = load<u32>(stPtr + 12)
    let h4 = load<u32>(stPtr + 16),
      h5 = load<u32>(stPtr + 20),
      h6 = load<u32>(stPtr + 24),
      h7 = load<u32>(stPtr + 28)

    let pos: usize = 0

    while (n >= 64) {
      let a = h0,
        b = h1,
        c = h2,
        d = h3,
        e = h4,
        f = h5,
        g = h6,
        h = h7

      let v0 = i8x16.shuffle(
        v128.load(mPtr + pos + 0),
        v128.load(mPtr + pos + 0),
        3,
        2,
        1,
        0,
        7,
        6,
        5,
        4,
        11,
        10,
        9,
        8,
        15,
        14,
        13,
        12
      )
      let v1 = i8x16.shuffle(
        v128.load(mPtr + pos + 16),
        v128.load(mPtr + pos + 16),
        3,
        2,
        1,
        0,
        7,
        6,
        5,
        4,
        11,
        10,
        9,
        8,
        15,
        14,
        13,
        12
      )
      let v2 = i8x16.shuffle(
        v128.load(mPtr + pos + 32),
        v128.load(mPtr + pos + 32),
        3,
        2,
        1,
        0,
        7,
        6,
        5,
        4,
        11,
        10,
        9,
        8,
        15,
        14,
        13,
        12
      )
      let v3 = i8x16.shuffle(
        v128.load(mPtr + pos + 48),
        v128.load(mPtr + pos + 48),
        3,
        2,
        1,
        0,
        7,
        6,
        5,
        4,
        11,
        10,
        9,
        8,
        15,
        14,
        13,
        12
      )

      let w0 = i32x4.extract_lane(v0, 0),
        w1 = i32x4.extract_lane(v0, 1),
        w2 = i32x4.extract_lane(v0, 2),
        w3 = i32x4.extract_lane(v0, 3)
      let w4 = i32x4.extract_lane(v1, 0),
        w5 = i32x4.extract_lane(v1, 1),
        w6 = i32x4.extract_lane(v1, 2),
        w7 = i32x4.extract_lane(v1, 3)
      let w8 = i32x4.extract_lane(v2, 0),
        w9 = i32x4.extract_lane(v2, 1),
        w10 = i32x4.extract_lane(v2, 2),
        w11 = i32x4.extract_lane(v2, 3)
      let w12 = i32x4.extract_lane(v3, 0),
        w13 = i32x4.extract_lane(v3, 1),
        w14 = i32x4.extract_lane(v3, 2),
        w15 = i32x4.extract_lane(v3, 3)

      h += Sigma1_256(e) + Ch32(e, f, g) + 0x428a2f98 + w0
      d += h
      h += Sigma0_256(a) + Maj32(a, b, c)
      g += Sigma1_256(d) + Ch32(d, e, f) + 0x71374491 + w1
      c += g
      g += Sigma0_256(h) + Maj32(h, a, b)
      f += Sigma1_256(c) + Ch32(c, d, e) + 0xb5c0fbcf + w2
      b += f
      f += Sigma0_256(g) + Maj32(g, h, a)
      e += Sigma1_256(b) + Ch32(b, c, d) + 0xe9b5dba5 + w3
      a += e
      e += Sigma0_256(f) + Maj32(f, g, h)
      d += Sigma1_256(a) + Ch32(a, b, c) + 0x3956c25b + w4
      h += d
      d += Sigma0_256(e) + Maj32(e, f, g)
      c += Sigma1_256(h) + Ch32(h, a, b) + 0x59f111f1 + w5
      g += c
      c += Sigma0_256(d) + Maj32(d, e, f)
      b += Sigma1_256(g) + Ch32(g, h, a) + 0x923f82a4 + w6
      f += b
      b += Sigma0_256(c) + Maj32(c, d, e)
      a += Sigma1_256(f) + Ch32(f, g, h) + 0xab1c5ed5 + w7
      e += a
      a += Sigma0_256(b) + Maj32(b, c, d)
      h += Sigma1_256(e) + Ch32(e, f, g) + 0xd807aa98 + w8
      d += h
      h += Sigma0_256(a) + Maj32(a, b, c)
      g += Sigma1_256(d) + Ch32(d, e, f) + 0x12835b01 + w9
      c += g
      g += Sigma0_256(h) + Maj32(h, a, b)
      f += Sigma1_256(c) + Ch32(c, d, e) + 0x243185be + w10
      b += f
      f += Sigma0_256(g) + Maj32(g, h, a)
      e += Sigma1_256(b) + Ch32(b, c, d) + 0x550c7dc3 + w11
      a += e
      e += Sigma0_256(f) + Maj32(f, g, h)
      d += Sigma1_256(a) + Ch32(a, b, c) + 0x72be5d74 + w12
      h += d
      d += Sigma0_256(e) + Maj32(e, f, g)
      c += Sigma1_256(h) + Ch32(h, a, b) + 0x80deb1fe + w13
      g += c
      c += Sigma0_256(d) + Maj32(d, e, f)
      b += Sigma1_256(g) + Ch32(g, h, a) + 0x9bdc06a7 + w14
      f += b
      b += Sigma0_256(c) + Maj32(c, d, e)
      a += Sigma1_256(f) + Ch32(f, g, h) + 0xc19bf174 + w15
      e += a
      a += Sigma0_256(b) + Maj32(b, c, d)

      for (let i = 16; i < 64; i += 16) {
        let kPtr = changetype<usize>(SHA256_K) + (i << 2)

        let v_i_15_12 = i32x4.shuffle(v0, v1, 1, 2, 3, 4)
        let v_i_7_4 = i32x4.shuffle(v2, v3, 1, 2, 3, 4)
        let v_part = i32x4.add(i32x4.add(v0, InternalSIMD.sigma0_256_simd(v_i_15_12)), v_i_7_4)

        w0 = i32x4.extract_lane(v_part, 0) + sigma1_256(w14)
        h += Sigma1_256(e) + Ch32(e, f, g) + load<u32>(kPtr + 0) + w0
        d += h
        h += Sigma0_256(a) + Maj32(a, b, c)
        w1 = i32x4.extract_lane(v_part, 1) + sigma1_256(w15)
        g += Sigma1_256(d) + Ch32(d, e, f) + load<u32>(kPtr + 4) + w1
        c += g
        g += Sigma0_256(h) + Maj32(h, a, b)
        w2 = i32x4.extract_lane(v_part, 2) + sigma1_256(w0)
        f += Sigma1_256(c) + Ch32(c, d, e) + load<u32>(kPtr + 8) + w2
        b += f
        f += Sigma0_256(g) + Maj32(g, h, a)
        w3 = i32x4.extract_lane(v_part, 3) + sigma1_256(w1)
        e += Sigma1_256(b) + Ch32(b, c, d) + load<u32>(kPtr + 12) + w3
        a += e
        e += Sigma0_256(f) + Maj32(f, g, h)
        v0 = i32x4(w0, w1, w2, w3)

        let v_i_15_12_b = i32x4.shuffle(v1, v2, 1, 2, 3, 4)
        let v_i_7_4_b = i32x4.shuffle(v3, v0, 1, 2, 3, 4)
        let v_part_b = i32x4.add(i32x4.add(v1, InternalSIMD.sigma0_256_simd(v_i_15_12_b)), v_i_7_4_b)
        w4 = i32x4.extract_lane(v_part_b, 0) + sigma1_256(w2)
        d += Sigma1_256(a) + Ch32(a, b, c) + load<u32>(kPtr + 16) + w4
        h += d
        d += Sigma0_256(e) + Maj32(e, f, g)
        w5 = i32x4.extract_lane(v_part_b, 1) + sigma1_256(w3)
        c += Sigma1_256(h) + Ch32(h, a, b) + load<u32>(kPtr + 20) + w5
        g += c
        c += Sigma0_256(d) + Maj32(d, e, f)
        w6 = i32x4.extract_lane(v_part_b, 2) + sigma1_256(w4)
        b += Sigma1_256(g) + Ch32(g, h, a) + load<u32>(kPtr + 24) + w6
        f += b
        b += Sigma0_256(c) + Maj32(c, d, e)
        w7 = i32x4.extract_lane(v_part_b, 3) + sigma1_256(w5)
        a += Sigma1_256(f) + Ch32(f, g, h) + load<u32>(kPtr + 28) + w7
        e += a
        a += Sigma0_256(b) + Maj32(b, c, d)
        v1 = i32x4(w4, w5, w6, w7)

        let v_i_15_12_c = i32x4.shuffle(v2, v3, 1, 2, 3, 4)
        let v_i_7_4_c = i32x4.shuffle(v0, v1, 1, 2, 3, 4)
        let v_part_c = i32x4.add(i32x4.add(v2, InternalSIMD.sigma0_256_simd(v_i_15_12_c)), v_i_7_4_c)
        w8 = i32x4.extract_lane(v_part_c, 0) + sigma1_256(w6)
        h += Sigma1_256(e) + Ch32(e, f, g) + load<u32>(kPtr + 32) + w8
        d += h
        h += Sigma0_256(a) + Maj32(a, b, c)
        w9 = i32x4.extract_lane(v_part_c, 1) + sigma1_256(w7)
        g += Sigma1_256(d) + Ch32(d, e, f) + load<u32>(kPtr + 36) + w9
        c += g
        g += Sigma0_256(h) + Maj32(h, a, b)
        w10 = i32x4.extract_lane(v_part_c, 2) + sigma1_256(w8)
        f += Sigma1_256(c) + Ch32(c, d, e) + load<u32>(kPtr + 40) + w10
        b += f
        f += Sigma0_256(g) + Maj32(g, h, a)
        w11 = i32x4.extract_lane(v_part_c, 3) + sigma1_256(w9)
        e += Sigma1_256(b) + Ch32(b, c, d) + load<u32>(kPtr + 44) + w11
        a += e
        e += Sigma0_256(f) + Maj32(f, g, h)
        v2 = i32x4(w8, w9, w10, w11)

        let v_i_15_12_d = i32x4.shuffle(v3, v0, 1, 2, 3, 4)
        let v_i_7_4_d = i32x4.shuffle(v1, v2, 1, 2, 3, 4)
        let v_part_d = i32x4.add(i32x4.add(v3, InternalSIMD.sigma0_256_simd(v_i_15_12_d)), v_i_7_4_d)
        w12 = i32x4.extract_lane(v_part_d, 0) + sigma1_256(w10)
        d += Sigma1_256(a) + Ch32(a, b, c) + load<u32>(kPtr + 48) + w12
        h += d
        d += Sigma0_256(e) + Maj32(e, f, g)
        w13 = i32x4.extract_lane(v_part_d, 1) + sigma1_256(w11)
        c += Sigma1_256(h) + Ch32(h, a, b) + load<u32>(kPtr + 52) + w13
        g += c
        c += Sigma0_256(d) + Maj32(d, e, f)
        w14 = i32x4.extract_lane(v_part_d, 2) + sigma1_256(w12)
        b += Sigma1_256(g) + Ch32(g, h, a) + load<u32>(kPtr + 56) + w14
        f += b
        b += Sigma0_256(c) + Maj32(c, d, e)
        w15 = i32x4.extract_lane(v_part_d, 3) + sigma1_256(w13)
        a += Sigma1_256(f) + Ch32(f, g, h) + load<u32>(kPtr + 60) + w15
        e += a
        a += Sigma0_256(b) + Maj32(b, c, d)
        v3 = i32x4(w12, w13, w14, w15)
      }

      h0 += a
      h1 += b
      h2 += c
      h3 += d
      h4 += e
      h5 += f
      h6 += g
      h7 += h
      pos += 64
      n -= 64
    }

    store<u32>(stPtr + 0, h0)
    store<u32>(stPtr + 4, h1)
    store<u32>(stPtr + 8, h2)
    store<u32>(stPtr + 12, h3)
    store<u32>(stPtr + 16, h4)
    store<u32>(stPtr + 20, h5)
    store<u32>(stPtr + 24, h6)
    store<u32>(stPtr + 28, h7)

    return n
  }

  static _hashInit(): Uint8Array {
    let st = new Uint8Array(32 + 64)
    let stPtr = st.dataStart
    store<u64>(stPtr + 0, unchecked(SHA256_IV[0]))
    store<u64>(stPtr + 8, unchecked(SHA256_IV[1]))
    store<u64>(stPtr + 16, unchecked(SHA256_IV[2]))
    store<u64>(stPtr + 24, unchecked(SHA256_IV[3]))
    return st
  }

  static _hashUpdate_raw(st: Uint8Array, mPtr: usize, n: isize, r: isize): isize {
    let pos: isize = 0
    let stPtr = st.dataStart

    if (r > 0) {
      let copiable = min(n, 64 - r)
      memory.copy(stPtr + 32 + r, mPtr, copiable)
      r += copiable
      n -= copiable
      pos += copiable
      if (r === 64) {
        InternalSIMD._hashblocks(stPtr, stPtr + 32, 64)
        r = 0
      }
    }
    if (n >= 64) {
      let blocks_len = n & ~63
      InternalSIMD._hashblocks(stPtr, mPtr + pos, blocks_len)
      pos += blocks_len
      n -= blocks_len
    }
    if (n > 0) {
      memory.copy(stPtr + 32, mPtr + pos, n)
      r = n
    }
    return r
  }

  static _hashFinal_raw(st: Uint8Array, outPtr: usize, t: isize, r: isize): void {
    let padded = new Uint8Array(128)
    let paddedPtr = padded.dataStart
    let stPtr = st.dataStart

    memory.copy(paddedPtr, stPtr + 32, r)
    padded[<aisize>r] = 0x80
    if (r < 56) {
      store64_be_arr(padded, 64 - 8, (<u64>t) << 3)
      InternalSIMD._hashblocks(stPtr, paddedPtr, 64)
    } else {
      store64_be_arr(padded, 128 - 8, (<u64>t) << 3)
      InternalSIMD._hashblocks(stPtr, paddedPtr, 128)
    }

    store32_be(outPtr + 0, load<u32>(stPtr + 0))
    store32_be(outPtr + 4, load<u32>(stPtr + 4))
    store32_be(outPtr + 8, load<u32>(stPtr + 8))
    store32_be(outPtr + 12, load<u32>(stPtr + 12))
    store32_be(outPtr + 16, load<u32>(stPtr + 16))
    store32_be(outPtr + 20, load<u32>(stPtr + 20))
    store32_be(outPtr + 24, load<u32>(stPtr + 24))
    store32_be(outPtr + 28, load<u32>(stPtr + 28))
  }

  static _hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
    let st = InternalSIMD._hashInit()
    let r = InternalSIMD._hashUpdate_raw(st, mPtr, n, 0)
    InternalSIMD._hashFinal_raw(st, outPtr, n, r)
  }
}

@final
export class Sha256SIMD {
  static hash(m: Uint8Array): Uint8Array {
    let h = new Uint8Array(32)
    InternalSIMD._hash_raw(h.dataStart, m.dataStart, m.length)
    return h
  }
}
