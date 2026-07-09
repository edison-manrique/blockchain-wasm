import { SHA256_K, SHA256_IV, SHA256_HASH_BYTES } from "./constants"
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
export class Internal {
  static _hashblocks(stPtr: usize, mPtr: usize, n: isize): isize {
    let h0 = load<u32>(stPtr + 0)
    let h1 = load<u32>(stPtr + 4)
    let h2 = load<u32>(stPtr + 8)
    let h3 = load<u32>(stPtr + 12)
    let h4 = load<u32>(stPtr + 16)
    let h5 = load<u32>(stPtr + 20)
    let h6 = load<u32>(stPtr + 24)
    let h7 = load<u32>(stPtr + 28)

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

      // Load 16 words into locals and do rounds 0-15
      // We use a sliding window of variables to avoid reassignments

      let w0 = bswap(load<u32>(mPtr + pos + 0))
      h += Sigma1_256(e) + Ch32(e, f, g) + 0x428a2f98 + w0
      d += h
      h += Sigma0_256(a) + Maj32(a, b, c)
      let w1 = bswap(load<u32>(mPtr + pos + 4))
      g += Sigma1_256(d) + Ch32(d, e, f) + 0x71374491 + w1
      c += g
      g += Sigma0_256(h) + Maj32(h, a, b)
      let w2 = bswap(load<u32>(mPtr + pos + 8))
      f += Sigma1_256(c) + Ch32(c, d, e) + 0xb5c0fbcf + w2
      b += f
      f += Sigma0_256(g) + Maj32(g, h, a)
      let w3 = bswap(load<u32>(mPtr + pos + 12))
      e += Sigma1_256(b) + Ch32(b, c, d) + 0xe9b5dba5 + w3
      a += e
      e += Sigma0_256(f) + Maj32(f, g, h)
      let w4 = bswap(load<u32>(mPtr + pos + 16))
      d += Sigma1_256(a) + Ch32(a, b, c) + 0x3956c25b + w4
      h += d
      d += Sigma0_256(e) + Maj32(e, f, g)
      let w5 = bswap(load<u32>(mPtr + pos + 20))
      c += Sigma1_256(h) + Ch32(h, a, b) + 0x59f111f1 + w5
      g += c
      c += Sigma0_256(d) + Maj32(d, e, f)
      let w6 = bswap(load<u32>(mPtr + pos + 24))
      b += Sigma1_256(g) + Ch32(g, h, a) + 0x923f82a4 + w6
      f += b
      b += Sigma0_256(c) + Maj32(c, d, e)
      let w7 = bswap(load<u32>(mPtr + pos + 28))
      a += Sigma1_256(f) + Ch32(f, g, h) + 0xab1c5ed5 + w7
      e += a
      a += Sigma0_256(b) + Maj32(b, c, d)

      let w8 = bswap(load<u32>(mPtr + pos + 32))
      h += Sigma1_256(e) + Ch32(e, f, g) + 0xd807aa98 + w8
      d += h
      h += Sigma0_256(a) + Maj32(a, b, c)
      let w9 = bswap(load<u32>(mPtr + pos + 36))
      g += Sigma1_256(d) + Ch32(d, e, f) + 0x12835b01 + w9
      c += g
      g += Sigma0_256(h) + Maj32(h, a, b)
      let w10 = bswap(load<u32>(mPtr + pos + 40))
      f += Sigma1_256(c) + Ch32(c, d, e) + 0x243185be + w10
      b += f
      f += Sigma0_256(g) + Maj32(g, h, a)
      let w11 = bswap(load<u32>(mPtr + pos + 44))
      e += Sigma1_256(b) + Ch32(b, c, d) + 0x550c7dc3 + w11
      a += e
      e += Sigma0_256(f) + Maj32(f, g, h)
      let w12 = bswap(load<u32>(mPtr + pos + 48))
      d += Sigma1_256(a) + Ch32(a, b, c) + 0x72be5d74 + w12
      h += d
      d += Sigma0_256(e) + Maj32(e, f, g)
      let w13 = bswap(load<u32>(mPtr + pos + 52))
      c += Sigma1_256(h) + Ch32(h, a, b) + 0x80deb1fe + w13
      g += c
      c += Sigma0_256(d) + Maj32(d, e, f)
      let w14 = bswap(load<u32>(mPtr + pos + 56))
      b += Sigma1_256(g) + Ch32(g, h, a) + 0x9bdc06a7 + w14
      f += b
      b += Sigma0_256(c) + Maj32(c, d, e)
      let w15 = bswap(load<u32>(mPtr + pos + 60))
      a += Sigma1_256(f) + Ch32(f, g, h) + 0xc19bf174 + w15
      e += a
      a += Sigma0_256(b) + Maj32(b, c, d)

      // Rounds 16-63 (unrolled 16 at a time)
      for (let i = 16; i < 64; i += 16) {
        let kPtr = changetype<usize>(SHA256_K) + (i << 2)

        w0 += sigma1_256(w14) + w9 + sigma0_256(w1)
        h += Sigma1_256(e) + Ch32(e, f, g) + load<u32>(kPtr + 0) + w0
        d += h
        h += Sigma0_256(a) + Maj32(a, b, c)
        w1 += sigma1_256(w15) + w10 + sigma0_256(w2)
        g += Sigma1_256(d) + Ch32(d, e, f) + load<u32>(kPtr + 4) + w1
        c += g
        g += Sigma0_256(h) + Maj32(h, a, b)
        w2 += sigma1_256(w0) + w11 + sigma0_256(w3)
        f += Sigma1_256(c) + Ch32(c, d, e) + load<u32>(kPtr + 8) + w2
        b += f
        f += Sigma0_256(g) + Maj32(g, h, a)
        w3 += sigma1_256(w1) + w12 + sigma0_256(w4)
        e += Sigma1_256(b) + Ch32(b, c, d) + load<u32>(kPtr + 12) + w3
        a += e
        e += Sigma0_256(f) + Maj32(f, g, h)
        w4 += sigma1_256(w2) + w13 + sigma0_256(w5)
        d += Sigma1_256(a) + Ch32(a, b, c) + load<u32>(kPtr + 16) + w4
        h += d
        d += Sigma0_256(e) + Maj32(e, f, g)
        w5 += sigma1_256(w3) + w14 + sigma0_256(w6)
        c += Sigma1_256(h) + Ch32(h, a, b) + load<u32>(kPtr + 20) + w5
        g += c
        c += Sigma0_256(d) + Maj32(d, e, f)
        w6 += sigma1_256(w4) + w15 + sigma0_256(w7)
        b += Sigma1_256(g) + Ch32(g, h, a) + load<u32>(kPtr + 24) + w6
        f += b
        b += Sigma0_256(c) + Maj32(c, d, e)
        w7 += sigma1_256(w5) + w0 + sigma0_256(w8)
        a += Sigma1_256(f) + Ch32(f, g, h) + load<u32>(kPtr + 28) + w7
        e += a
        a += Sigma0_256(b) + Maj32(b, c, d)

        w8 += sigma1_256(w6) + w1 + sigma0_256(w9)
        h += Sigma1_256(e) + Ch32(e, f, g) + load<u32>(kPtr + 32) + w8
        d += h
        h += Sigma0_256(a) + Maj32(a, b, c)
        w9 += sigma1_256(w7) + w2 + sigma0_256(w10)
        g += Sigma1_256(d) + Ch32(d, e, f) + load<u32>(kPtr + 36) + w9
        c += g
        g += Sigma0_256(h) + Maj32(h, a, b)
        w10 += sigma1_256(w8) + w3 + sigma0_256(w11)
        f += Sigma1_256(c) + Ch32(c, d, e) + load<u32>(kPtr + 40) + w10
        b += f
        f += Sigma0_256(g) + Maj32(g, h, a)
        w11 += sigma1_256(w9) + w4 + sigma0_256(w12)
        e += Sigma1_256(b) + Ch32(b, c, d) + load<u32>(kPtr + 44) + w11
        a += e
        e += Sigma0_256(f) + Maj32(f, g, h)
        w12 += sigma1_256(w10) + w5 + sigma0_256(w13)
        d += Sigma1_256(a) + Ch32(a, b, c) + load<u32>(kPtr + 48) + w12
        h += d
        d += Sigma0_256(e) + Maj32(e, f, g)
        w13 += sigma1_256(w11) + w6 + sigma0_256(w14)
        c += Sigma1_256(h) + Ch32(h, a, b) + load<u32>(kPtr + 52) + w13
        g += c
        c += Sigma0_256(d) + Maj32(d, e, f)
        w14 += sigma1_256(w12) + w7 + sigma0_256(w15)
        b += Sigma1_256(g) + Ch32(g, h, a) + load<u32>(kPtr + 56) + w14
        f += b
        b += Sigma0_256(c) + Maj32(c, d, e)
        w15 += sigma1_256(w13) + w8 + sigma0_256(w0)
        a += Sigma1_256(f) + Ch32(f, g, h) + load<u32>(kPtr + 60) + w15
        e += a
        a += Sigma0_256(b) + Maj32(b, c, d)
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

  static _hashInit_ptr(stPtr: usize): void {
    store<u64>(stPtr + 0, unchecked(SHA256_IV[0]))
    store<u64>(stPtr + 8, unchecked(SHA256_IV[1]))
    store<u64>(stPtr + 16, unchecked(SHA256_IV[2]))
    store<u64>(stPtr + 24, unchecked(SHA256_IV[3]))
  }

  static _hashUpdate_ptr(stPtr: usize, mPtr: usize, n: isize, r: isize): isize {
    let pos: isize = 0
    if (r > 0) {
      let copiable = min(n, 64 - r)
      memory.copy(stPtr + 32 + r, mPtr, copiable)
      r += copiable
      n -= copiable
      pos += copiable
      if (r === 64) {
        Internal._hashblocks(stPtr, stPtr + 32, 64)
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
      memory.copy(stPtr + 32, mPtr + pos, n)
      r = n
    }
    return r
  }

  static _hashFinal_ptr(stPtr: usize, paddedPtr: usize, outPtr: usize, t: isize, r: isize): void {
    memory.copy(paddedPtr, stPtr + 32, r)
    store<u8>(paddedPtr + r, 0x80)
    for (let i = r + 1; i < 128; i++) store<u8>(paddedPtr + i, 0)

    if (r < 56) {
      store32_be(paddedPtr + 64 - 8, <u32>(((<u64>t) << 3) >> 32))
      store32_be(paddedPtr + 64 - 4, <u32>((<u64>t) << 3))
      Internal._hashblocks(stPtr, paddedPtr, 64)
    } else {
      store32_be(paddedPtr + 128 - 8, <u32>(((<u64>t) << 3) >> 32))
      store32_be(paddedPtr + 128 - 4, <u32>((<u64>t) << 3))
      Internal._hashblocks(stPtr, paddedPtr, 128)
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

  static _hashInit(): Uint8Array {
    let st = new Uint8Array(32 + 64)
    Internal._hashInit_ptr(st.dataStart)
    return st
  }

  static _hashUpdate(st: Uint8Array, m: Uint8Array, n: isize, r: isize): isize {
    return Internal._hashUpdate_ptr(st.dataStart, m.dataStart, n, r)
  }

  static _hashFinal(st: Uint8Array, out: Uint8Array, t: isize, r: isize): void {
    let padded = new Uint8Array(128)
    Internal._hashFinal_ptr(st.dataStart, padded.dataStart, out.dataStart, t, r)
  }

  static _hash(out: Uint8Array, m: Uint8Array, n: isize): void {
    let st = Internal._hashInit()
    let r = Internal._hashUpdate(st, m, n, 0)
    Internal._hashFinal(st, out, n, r)
  }

  static _hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
    let st = new Uint8Array(96)
    let padded = new Uint8Array(128)
    Internal._hashInit_ptr(st.dataStart)
    let r = Internal._hashUpdate_ptr(st.dataStart, mPtr, n, 0)
    Internal._hashFinal_ptr(st.dataStart, padded.dataStart, outPtr, n, r)
  }

  static _hmac(m: Uint8Array, k: Uint8Array): Uint8Array {
    if (k.length > 64) {
      k = Sha256.hash(k)
    }
    let b = new Uint8Array(64)
    for (let i = 0; i < 64; i++) {
      b[i] = (i < k.length ? k[i] : 0) ^ 0x36
    }
    let out = new Uint8Array(32)
    let st = Internal._hashInit()
    let r = Internal._hashUpdate(st, b, b.length, 0)
    r = Internal._hashUpdate(st, m, m.length, r)
    Internal._hashFinal(st, out, b.length + m.length, r)

    for (let i = 0; i < 64; i++) {
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
export class Sha256 {
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
    let h = new Uint8Array(<aisize>SHA256_HASH_BYTES)
    Internal._hashFinal(this.st, h, this.t as isize, this.r as isize)
    return h
  }

  static hash(m: Uint8Array): Uint8Array {
    let h = new Uint8Array(<aisize>SHA256_HASH_BYTES)
    Internal._hash(h, m, m.length)
    return h
  }

  static hmac(m: Uint8Array, k: Uint8Array): Uint8Array {
    return Internal._hmac(m, k)
  }

  static __SCRATCH: usize = heap.alloc(512) as usize

  static hmac_ptr(outPtr: usize, kPtr: usize, kLen: isize, mPtr: usize, mLen: isize): void {
    let scratch = Sha256.__SCRATCH
    let k_buf = scratch // 64 bytes
    let b = scratch + 64 // 64 bytes
    let st = scratch + 128 // 96 bytes
    let padded = scratch + 224 // 128 bytes
    // Total used: 352 bytes

    // Prepara k_buf
    if (kLen > 64) {
      // Si la clave excede 64 bytes se debe hashear primero.
      // Nosotros nunca superaremos 64b para Secp256k1/RFC6979.
      return
    } else {
      memory.copy(k_buf, kPtr, kLen)
      for (let i = kLen; i < 64; i++) {
        store<u8>(k_buf + i, 0)
      }
    }

    // Inner hash
    for (let i = 0; i < 64; i++) {
      store<u8>(b + i, load<u8>(k_buf + i) ^ 0x36)
    }

    Internal._hashInit_ptr(st)
    let r = Internal._hashUpdate_ptr(st, b, 64, 0)
    r = Internal._hashUpdate_ptr(st, mPtr, mLen, r)
    Internal._hashFinal_ptr(st, padded, outPtr, 64 + mLen, r)

    // Outer hash
    for (let i = 0; i < 64; i++) {
      store<u8>(b + i, load<u8>(k_buf + i) ^ 0x5c)
    }

    Internal._hashInit_ptr(st)
    r = Internal._hashUpdate_ptr(st, b, 64, 0)
    r = Internal._hashUpdate_ptr(st, outPtr, 32, r)
    Internal._hashFinal_ptr(st, padded, outPtr, 64 + 32, r)
  }
}
