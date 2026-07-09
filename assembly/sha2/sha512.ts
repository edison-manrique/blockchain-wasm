import { SHA512_K, SHA512_IV, SHA512_HASH_BYTES } from "./constants"
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
export class Internal {
  static _hashblocks(stPtr: usize, mPtr: usize, n: isize): isize {
    let h0 = load<u64>(stPtr + 0)
    let h1 = load<u64>(stPtr + 8)
    let h2 = load<u64>(stPtr + 16)
    let h3 = load<u64>(stPtr + 24)
    let h4 = load<u64>(stPtr + 32)
    let h5 = load<u64>(stPtr + 40)
    let h6 = load<u64>(stPtr + 48)
    let h7 = load<u64>(stPtr + 56)

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

      // Load 16 words into locals and do rounds 0-15
      // We use a sliding window of variables to avoid reassignments

      let w0 = bswap(load<u64>(mPtr + pos + 0))
      h += Sigma1_512(e) + Ch64(e, f, g) + 0x428a2f98d728ae22 + w0
      d += h
      h += Sigma0_512(a) + Maj64(a, b, c)
      let w1 = bswap(load<u64>(mPtr + pos + 8))
      g += Sigma1_512(d) + Ch64(d, e, f) + 0x7137449123ef65cd + w1
      c += g
      g += Sigma0_512(h) + Maj64(h, a, b)
      let w2 = bswap(load<u64>(mPtr + pos + 16))
      f += Sigma1_512(c) + Ch64(c, d, e) + 0xb5c0fbcfec4d3b2f + w2
      b += f
      f += Sigma0_512(g) + Maj64(g, h, a)
      let w3 = bswap(load<u64>(mPtr + pos + 24))
      e += Sigma1_512(b) + Ch64(b, c, d) + 0xe9b5dba58189dbbc + w3
      a += e
      e += Sigma0_512(f) + Maj64(f, g, h)
      let w4 = bswap(load<u64>(mPtr + pos + 32))
      d += Sigma1_512(a) + Ch64(a, b, c) + 0x3956c25bf348b538 + w4
      h += d
      d += Sigma0_512(e) + Maj64(e, f, g)
      let w5 = bswap(load<u64>(mPtr + pos + 40))
      c += Sigma1_512(h) + Ch64(h, a, b) + 0x59f111f1b605d019 + w5
      g += c
      c += Sigma0_512(d) + Maj64(d, e, f)
      let w6 = bswap(load<u64>(mPtr + pos + 48))
      b += Sigma1_512(g) + Ch64(g, h, a) + 0x923f82a4af194f9b + w6
      f += b
      b += Sigma0_512(c) + Maj64(c, d, e)
      let w7 = bswap(load<u64>(mPtr + pos + 56))
      a += Sigma1_512(f) + Ch64(f, g, h) + 0xab1c5ed5da6d8118 + w7
      e += a
      a += Sigma0_512(b) + Maj64(b, c, d)

      let w8 = bswap(load<u64>(mPtr + pos + 64))
      h += Sigma1_512(e) + Ch64(e, f, g) + 0xd807aa98a3030242 + w8
      d += h
      h += Sigma0_512(a) + Maj64(a, b, c)
      let w9 = bswap(load<u64>(mPtr + pos + 72))
      g += Sigma1_512(d) + Ch64(d, e, f) + 0x12835b0145706fbe + w9
      c += g
      g += Sigma0_512(h) + Maj64(h, a, b)
      let w10 = bswap(load<u64>(mPtr + pos + 80))
      f += Sigma1_512(c) + Ch64(c, d, e) + 0x243185be4ee4b28c + w10
      b += f
      f += Sigma0_512(g) + Maj64(g, h, a)
      let w11 = bswap(load<u64>(mPtr + pos + 88))
      e += Sigma1_512(b) + Ch64(b, c, d) + 0x550c7dc3d5ffb4e2 + w11
      a += e
      e += Sigma0_512(f) + Maj64(f, g, h)
      let w12 = bswap(load<u64>(mPtr + pos + 96))
      d += Sigma1_512(a) + Ch64(a, b, c) + 0x72be5d74f27b896f + w12
      h += d
      d += Sigma0_512(e) + Maj64(e, f, g)
      let w13 = bswap(load<u64>(mPtr + pos + 104))
      c += Sigma1_512(h) + Ch64(h, a, b) + 0x80deb1fe3b1696b1 + w13
      g += c
      c += Sigma0_512(d) + Maj64(d, e, f)
      let w14 = bswap(load<u64>(mPtr + pos + 112))
      b += Sigma1_512(g) + Ch64(g, h, a) + 0x9bdc06a725c71235 + w14
      f += b
      b += Sigma0_512(c) + Maj64(c, d, e)
      let w15 = bswap(load<u64>(mPtr + pos + 120))
      a += Sigma1_512(f) + Ch64(f, g, h) + 0xc19bf174cf692694 + w15
      e += a
      a += Sigma0_512(b) + Maj64(b, c, d)

      // Rounds 16-79 (unrolled 16 at a time)
      for (let i = 16; i < 80; i += 16) {
        let kPtr = changetype<usize>(SHA512_K) + (i << 3)

        w0 += sigma1_512(w14) + w9 + sigma0_512(w1)
        h += Sigma1_512(e) + Ch64(e, f, g) + load<u64>(kPtr + 0) + w0
        d += h
        h += Sigma0_512(a) + Maj64(a, b, c)
        w1 += sigma1_512(w15) + w10 + sigma0_512(w2)
        g += Sigma1_512(d) + Ch64(d, e, f) + load<u64>(kPtr + 8) + w1
        c += g
        g += Sigma0_512(h) + Maj64(h, a, b)
        w2 += sigma1_512(w0) + w11 + sigma0_512(w3)
        f += Sigma1_512(c) + Ch64(c, d, e) + load<u64>(kPtr + 16) + w2
        b += f
        f += Sigma0_512(g) + Maj64(g, h, a)
        w3 += sigma1_512(w1) + w12 + sigma0_512(w4)
        e += Sigma1_512(b) + Ch64(b, c, d) + load<u64>(kPtr + 24) + w3
        a += e
        e += Sigma0_512(f) + Maj64(f, g, h)
        w4 += sigma1_512(w2) + w13 + sigma0_512(w5)
        d += Sigma1_512(a) + Ch64(a, b, c) + load<u64>(kPtr + 32) + w4
        h += d
        d += Sigma0_512(e) + Maj64(e, f, g)
        w5 += sigma1_512(w3) + w14 + sigma0_512(w6)
        c += Sigma1_512(h) + Ch64(h, a, b) + load<u64>(kPtr + 40) + w5
        g += c
        c += Sigma0_512(d) + Maj64(d, e, f)
        w6 += sigma1_512(w4) + w15 + sigma0_512(w7)
        b += Sigma1_512(g) + Ch64(g, h, a) + load<u64>(kPtr + 48) + w6
        f += b
        b += Sigma0_512(c) + Maj64(c, d, e)
        w7 += sigma1_512(w5) + w0 + sigma0_512(w8)
        a += Sigma1_512(f) + Ch64(f, g, h) + load<u64>(kPtr + 56) + w7
        e += a
        a += Sigma0_512(b) + Maj64(b, c, d)

        w8 += sigma1_512(w6) + w1 + sigma0_512(w9)
        h += Sigma1_512(e) + Ch64(e, f, g) + load<u64>(kPtr + 64) + w8
        d += h
        h += Sigma0_512(a) + Maj64(a, b, c)
        w9 += sigma1_512(w7) + w2 + sigma0_512(w10)
        g += Sigma1_512(d) + Ch64(d, e, f) + load<u64>(kPtr + 72) + w9
        c += g
        g += Sigma0_512(h) + Maj64(h, a, b)
        w10 += sigma1_512(w8) + w3 + sigma0_512(w11)
        f += Sigma1_512(c) + Ch64(c, d, e) + load<u64>(kPtr + 80) + w10
        b += f
        f += Sigma0_512(g) + Maj64(g, h, a)
        w11 += sigma1_512(w9) + w4 + sigma0_512(w12)
        e += Sigma1_512(b) + Ch64(b, c, d) + load<u64>(kPtr + 88) + w11
        a += e
        e += Sigma0_512(f) + Maj64(f, g, h)
        w12 += sigma1_512(w10) + w5 + sigma0_512(w13)
        d += Sigma1_512(a) + Ch64(a, b, c) + load<u64>(kPtr + 96) + w12
        h += d
        d += Sigma0_512(e) + Maj64(e, f, g)
        w13 += sigma1_512(w11) + w6 + sigma0_512(w14)
        c += Sigma1_512(h) + Ch64(h, a, b) + load<u64>(kPtr + 104) + w13
        g += c
        c += Sigma0_512(d) + Maj64(d, e, f)
        w14 += sigma1_512(w12) + w7 + sigma0_512(w15)
        b += Sigma1_512(g) + Ch64(g, h, a) + load<u64>(kPtr + 112) + w14
        f += b
        b += Sigma0_512(c) + Maj64(c, d, e)
        w15 += sigma1_512(w13) + w8 + sigma0_512(w0)
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
    let st = new Uint8Array(192) // 64 (state) + 128 (buffer)
    Internal._hashInit_ptr(st.dataStart)
    return st
  }

  static _hashInit_ptr(stPtr: usize): void {
    store<u64>(stPtr + 0, unchecked(SHA512_IV[0]))
    store<u64>(stPtr + 8, unchecked(SHA512_IV[1]))
    store<u64>(stPtr + 16, unchecked(SHA512_IV[2]))
    store<u64>(stPtr + 24, unchecked(SHA512_IV[3]))
    store<u64>(stPtr + 32, unchecked(SHA512_IV[4]))
    store<u64>(stPtr + 40, unchecked(SHA512_IV[5]))
    store<u64>(stPtr + 48, unchecked(SHA512_IV[6]))
    store<u64>(stPtr + 56, unchecked(SHA512_IV[7]))
    // Zero out the 128-byte buffer area for safety
    memory.fill(stPtr + 64, 0, 128)
  }

  static _hashUpdate(st: Uint8Array, m: Uint8Array, n: isize, r: isize): isize {
    return Internal._hashUpdate_ptr(st.dataStart, m.dataStart, n, r)
  }

  static _hashUpdate_ptr(stPtr: usize, mPtr: usize, n: isize, r: isize): isize {
    let pos: isize = 0

    if (r > 0) {
      let copiable = min(n, 128 - r)
      memory.copy(stPtr + 64 + r, mPtr, copiable)
      r += copiable
      n -= copiable
      pos += copiable
      if (r === 128) {
        Internal._hashblocks(stPtr, stPtr + 64, 128)
        r = 0
      }
    }
    if (n >= 128) {
      let blocks_len = n & ~127
      Internal._hashblocks(stPtr, mPtr + pos, blocks_len)
      pos += blocks_len
      n -= blocks_len
    }
    if (n > 0) {
      memory.copy(stPtr + 64, mPtr + pos, n)
      r = n
    }
    return r
  }

  static _hashFinal(st: Uint8Array, out: Uint8Array, t: isize, r: isize): void {
    // This allocates in stub, but we need it for backward compatibility
    // Use _hashFinal_ptr to avoid allocation
    let padded = new Uint8Array(256)
    Internal._hashFinal_ptr(st.dataStart, padded.dataStart, out.dataStart, t, r)
  }

  static _hashFinal_ptr(stPtr: usize, paddedPtr: usize, outPtr: usize, t: isize, r: isize): void {
    memory.copy(paddedPtr, stPtr + 64, r)
    store<u8>(paddedPtr + <usize>r, 0x80)

    if (r < 112) {
      // Zero everything from r+1 to the end of the 128-byte block
      memory.fill(paddedPtr + <usize>r + 1, 0, 128 - <usize>r - 1)
      store64_be(paddedPtr + 128 - 8, (<u64>t) << 3)
      Internal._hashblocks(stPtr, paddedPtr, 128)
    } else {
      // Zero everything from r+1 to the end of the 256-byte block
      memory.fill(paddedPtr + <usize>r + 1, 0, 256 - <usize>r - 1)
      store64_be(paddedPtr + 256 - 8, (<u64>t) << 3)
      Internal._hashblocks(stPtr, paddedPtr, 256)
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

  static _hash(out: Uint8Array, m: Uint8Array, n: isize): void {
    let st = Internal._hashInit()
    let r = Internal._hashUpdate(st, m, n, 0)
    Internal._hashFinal(st, out, n, r)
  }

  static _hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
    let st = Internal._hashInit()
    let r = Internal._hashUpdate_raw(st, mPtr, n, 0)
    Internal._hashFinal_raw(st, outPtr, n, r)
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
        Internal._hashblocks(stPtr, stPtr + 64, 128)
        r = 0
      }
    }
    if (n >= 128) {
      let blocks_len = n & ~127
      Internal._hashblocks(stPtr, mPtr + pos, blocks_len)
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
      Internal._hashblocks(stPtr, paddedPtr, 128)
    } else {
      store64_be_arr(padded, 256 - 8, (<u64>t) << 3)
      Internal._hashblocks(stPtr, paddedPtr, 256)
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

  static _hmac(m: Uint8Array, k: Uint8Array): Uint8Array {
    if (k.length > 128) {
      k = Sha512.hash(k)
    }
    let b = new Uint8Array(128)
    for (let i = 0; i < 128; i++) {
      b[i] = (i < k.length ? k[i] : 0) ^ 0x36
    }
    let out = new Uint8Array(64)
    let st = Internal._hashInit()
    let r = Internal._hashUpdate(st, b, b.length, 0)
    r = Internal._hashUpdate(st, m, m.length, r)
    Internal._hashFinal(st, out, b.length + m.length, r)

    for (let i = 0; i < 128; i++) {
      b[i] = (i < k.length ? k[i] : 0) ^ 0x5c
    }

    st = Internal._hashInit()
    r = Internal._hashUpdate(st, b, b.length, 0)
    r = Internal._hashUpdate(st, out, out.length, r)
    Internal._hashFinal(st, out, b.length + out.length, r)
    return out
  }
}

@final
export class Sha512 {
  r: u64 = 0
  t: u64 = 0
  st: Uint8Array

  constructor() {
    this.st = Internal._hashInit()
  }

  update(m: Uint8Array): void {
    let n = m.length
    this.t += n
    this.r = Internal._hashUpdate(this.st, m, n, this.r as isize)
  }

  final(): Uint8Array {
    let h = new Uint8Array(<aisize>SHA512_HASH_BYTES)
    Internal._hashFinal(this.st, h, this.t as isize, this.r as isize)
    return h
  }

  static hash(m: Uint8Array): Uint8Array {
    let h = new Uint8Array(<aisize>SHA512_HASH_BYTES)
    Internal._hash(h, m, m.length)
    return h
  }

  static hmac(m: Uint8Array, k: Uint8Array): Uint8Array {
    return Internal._hmac(m, k)
  }
}
