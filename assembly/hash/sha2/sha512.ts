/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  sha2/sha512.ts — SHA-512 + HMAC-SHA512 (FIPS 180-4 / RFC 2104)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Algoritmo ORIGINAL validado al 100 % (bswap<u64> nativo, el que ya pasaba
 * todos los vectores). Lógica idéntica al código que funcionaba.
 *
 * ── ÚNICO CAMBIO: base del scratch = align8(HASH_WORK_PTR) (zona disjunta de
 * la arena de secp256k1), en vez de la memoria privada original. Ver sha256.ts
 * para el razonamiento de reentrancia (idéntico, con anchos de 64 bits).
 *
 * Contexto @unmanaged de 208 B. Layout HMAC sobre HASH_WORK:
 *   k_buf[128] | b[128] | ctx[208] | padded[256] = 720 B; verify añade 64 B.
 */
import { SHA512_K, SHA512_IV } from "./constants"
import { HASH_WORK_PTR, align8 } from "../../utils/memory"
import { store64_be, sigma0_512, sigma1_512, Sigma0_512, Sigma1_512, Ch64, Maj64 } from "./common"

/**
 * Contexto SHA-512 unmanaged (208 bytes).
 * Layout: [0..63] state (8×u64) | [64..191] buffer (128 B) |
 *         [192..199] totalLen (u64) | [200..203] bufferLen (u32) | [204..207] pad.
 */
@unmanaged
export class Sha512Context {
  static readonly SIZE: usize = 208

  @inline get statePtr(): usize {
    return changetype<usize>(this)
  }
  @inline get bufferPtr(): usize {
    return changetype<usize>(this) + 64
  }

  @inline getTotalLen(): u64 {
    return load<u64>(changetype<usize>(this) + 192)
  }
  @inline setTotalLen(val: u64): void {
    store<u64>(changetype<usize>(this) + 192, val)
  }
  @inline getBufferLen(): u32 {
    return load<u32>(changetype<usize>(this) + 200)
  }
  @inline setBufferLen(val: u32): void {
    store<u32>(changetype<usize>(this) + 200, val)
  }

  @inline
  init(): void {
    const st = this.statePtr
    store<u64>(st + 0, unchecked(SHA512_IV[0]))
    store<u64>(st + 8, unchecked(SHA512_IV[1]))
    store<u64>(st + 16, unchecked(SHA512_IV[2]))
    store<u64>(st + 24, unchecked(SHA512_IV[3]))
    store<u64>(st + 32, unchecked(SHA512_IV[4]))
    store<u64>(st + 40, unchecked(SHA512_IV[5]))
    store<u64>(st + 48, unchecked(SHA512_IV[6]))
    store<u64>(st + 56, unchecked(SHA512_IV[7]))
    this.setTotalLen(0)
    this.setBufferLen(0)
  }
}

export class Sha512 {
  /** Bucle de compresión sobre bloques de 128 bytes (16 rounds + 64 en bucle). */
  static compress(stPtr: usize, mPtr: usize, n: isize): isize {
    let h0 = load<u64>(stPtr + 0),
      h1 = load<u64>(stPtr + 8)
    let h2 = load<u64>(stPtr + 16),
      h3 = load<u64>(stPtr + 24)
    let h4 = load<u64>(stPtr + 32),
      h5 = load<u64>(stPtr + 40)
    let h6 = load<u64>(stPtr + 48),
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

      // ── MENSAJE: con bswap (1 swap por palabra de 64 bits) ──
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
      a += Sigma0_512(b) + Maj64(b, c, d) // ✅ FIX: era "e +="
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
      a += Sigma0_512(b) + Maj64(b, c, d) // ✅ FIX: era "e +="

      for (let i = 16; i < 80; i += 16) {
        let kPtr = changetype<usize>(SHA512_K) + (i << 3) // K: SIN bswap

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
        a += Sigma0_512(b) + Maj64(b, c, d) // ✅ FIX: era "e +="

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
        a += Sigma0_512(b) + Maj64(b, c, d) // ✅ FIX: era "e +="
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
  /** Streaming: alimenta n bytes al contexto. */
  static update(ctx: Sha512Context, mPtr: usize, n: isize): void {
    if (n <= 0) return

    ctx.setTotalLen(ctx.getTotalLen() + <u64>n)
    let r = ctx.getBufferLen()
    let pos: isize = 0
    const stPtr = ctx.statePtr
    const bufPtr = ctx.bufferPtr

    if (r > 0) {
      let copiable = min(n, 128 - <isize>r)
      memory.copy(bufPtr + r, mPtr, copiable)
      r += <u32>copiable
      n -= copiable
      pos += copiable
      if (r === 128) {
        Sha512.compress(stPtr, bufPtr, 128)
        r = 0
      }
    }

    if (n >= 128) {
      let blocks_len = n & ~127
      Sha512.compress(stPtr, mPtr + pos, blocks_len)
      pos += blocks_len
      n -= blocks_len
    }

    if (n > 0) {
      memory.copy(bufPtr, mPtr + pos, n)
      r = <u32>n
    }

    ctx.setBufferLen(r)
  }

  /** Finaliza: padding estándar + digest de 64 bytes en outPtr. */
  static final(ctx: Sha512Context, paddedPtr: usize, outPtr: usize): void {
    const r = ctx.getBufferLen()
    const t = ctx.getTotalLen()
    const stPtr = ctx.statePtr
    const bufPtr = ctx.bufferPtr

    memory.copy(paddedPtr, bufPtr, r)
    store<u8>(paddedPtr + r, 0x80)

    if (r < 112) {
      memory.fill(paddedPtr + r + 1, 0, 128 - r - 1)
      store64_be(paddedPtr + 128 - 8, t << 3)
      Sha512.compress(stPtr, paddedPtr, 128)
    } else {
      memory.fill(paddedPtr + r + 1, 0, 256 - r - 1)
      store64_be(paddedPtr + 256 - 8, t << 3)
      Sha512.compress(stPtr, paddedPtr, 256)
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

  /** SHA-512 one-shot (zero-alloc). Escribe 64 bytes en outPtr. */
  static hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
    const scratchPtr = align8(HASH_WORK_PTR)
    const ctx = changetype<Sha512Context>(scratchPtr)
    const paddedPtr = align8(scratchPtr + Sha512Context.SIZE)

    ctx.init()
    Sha512.update(ctx, mPtr, n)
    Sha512.final(ctx, paddedPtr, outPtr)
  }

  /**
   * HMAC-SHA512 interno (zero-alloc). Layout sobre HASH_WORK:
   * k_buf[128] | b[128] | ctx[208] | padded[256] = 720 B.
   */
  private static hmac_compute(outPtr: usize, kPtr: usize, kLen: isize, mPtr: usize, mLen: isize): void {
    const scratchPtr = align8(HASH_WORK_PTR)
    const k_buf = scratchPtr
    const b = align8(k_buf + 128)
    const ctx = changetype<Sha512Context>(align8(b + 128))
    const padded = align8(changetype<usize>(ctx) + Sha512Context.SIZE)

    memory.fill(k_buf, 0, 128)
    if (kLen > 128) {
      Sha512.hash_raw(k_buf, kPtr, kLen)
      kLen = 64
    } else if (kLen > 0) {
      memory.copy(k_buf, kPtr, kLen)
    }

    // Inner: H((k ⊕ 0x36) || msg)
    for (let i = 0; i < 128; i++) {
      store<u8>(b + i, load<u8>(k_buf + i) ^ 0x36)
    }
    ctx.init()
    Sha512.update(ctx, b, 128)
    Sha512.update(ctx, mPtr, mLen)
    Sha512.final(ctx, padded, outPtr)

    // Outer: H((k ⊕ 0x5c) || innerHash)
    for (let i = 0; i < 128; i++) {
      store<u8>(b + i, load<u8>(k_buf + i) ^ 0x5c)
    }
    ctx.init()
    Sha512.update(ctx, b, 128)
    Sha512.update(ctx, outPtr, 64)
    Sha512.final(ctx, padded, outPtr)
  }

  /** HMAC-SHA512 one-shot (zero-alloc). Escribe 64 bytes en outPtr. */
  static hmac_raw(outPtr: usize, kPtr: usize, kLen: isize, mPtr: usize, mLen: isize): void {
    Sha512.hmac_compute(outPtr, kPtr, kLen, mPtr, mLen)
  }

  /**
   * Verifica HMAC-SHA512 en TIEMPO CONSTANTE (XOR + OR, 64 iters, sin early-exit).
   * `computed` en [720,784), disjunto del layout de hmac_compute ([0,720)).
   */
  static hmac_verify_raw(kPtr: usize, kLen: isize, mPtr: usize, mLen: isize, macPtr: usize, macLen: isize): bool {
    if (macLen !== 64) return false

    const scratchPtr = align8(HASH_WORK_PTR)
    const computed = align8(scratchPtr + 720)

    Sha512.hmac_compute(computed, kPtr, kLen, mPtr, mLen)

    let diff: u32 = 0
    for (let i = 0; i < 64; i++) {
      diff |= load<u8>(computed + i) ^ load<u8>(macPtr + i)
    }
    return diff === 0
  }
}
