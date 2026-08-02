/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  field/mulmod.ts — Multiplicación y squaring FUSED mod P
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * mulMod / sqrMod = (a · b) mod P  y  (a²) mod P  en UN SOLO pipeline.
 *
 * "Fused" = el producto 512-bit NUNCA se escribe a memoria: se mantiene en
 * registros r0..r7 y se reduce in-place. Esto elimina el round-trip de
 * mul()→reduce() (que escribiría y re-leería 64 bytes). Es la operación más
 * caliente de toda la curva (cada double/add hace 4–7 mulMod), así que esta
 * fusión es la optimización de rendimiento más importante del módulo.
 *
 * Los productos 64×64→128 se calculan INLINE en registros (NO vía mul64, que
 * escribe a memoria y rompería la fusión). La etapa de reducción es idéntica a
 * reduce.ts pero opera sobre r0..r7 en vez de leer de memoria.
 *
 * Lógica EXACTA de BigInt256.mulMod / sqrMod.
 */
import { P0, P1, P2, P3 } from "../constants"

/**
 * mulMod: res = (a · b) mod P. Fused (Comba en registros + reducción inline).
 */
// @ts-ignore
@inline
export function mulMod(res: usize, a: usize, b: usize): void {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)
  const b0 = load<u64>(b)
  const b1 = load<u64>(b, 8)
  const b2 = load<u64>(b, 16)
  const b3 = load<u64>(b, 24)

  let r0: u64, r1: u64, r2: u64, r3: u64
  let r4: u64, r5: u64, r6: u64, r7: u64

  let acc0: u64 = 0
  let acc1: u64 = 0
  let acc2: u64 = 0
  let carry: u64
  let x: u64, y: u64, x_lo: u64, x_hi: u64, y_lo: u64, y_hi: u64
  let p0: u64, p1: u64, p2: u64, p3: u64, mid: u64, c1: u64, c2: u64
  let prod_lo: u64, prod_hi: u64

  // ── Col 0 ──
  x = a0; y = b0
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1)
  acc0 = p0 + (mid << 32); c2 = u64(acc0 < p0)
  acc1 = p3 + (mid >> 32) + (c1 << 32) + c2
  r0 = acc0; acc0 = acc1; acc1 = 0

  // ── Col 1 ──
  x = a0; y = b1
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  x = a1; y = b0
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  r1 = acc0; acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 2 ──
  x = a0; y = b2
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  x = a1; y = b1
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  x = a2; y = b0
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  r2 = acc0; acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 3 ──
  x = a0; y = b3
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  x = a1; y = b2
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  x = a2; y = b1
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  x = a3; y = b0
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  r3 = acc0; acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 4 ──
  x = a1; y = b3
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  x = a2; y = b2
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  x = a3; y = b1
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  r4 = acc0; acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 5 ──
  x = a2; y = b3
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  x = a3; y = b2
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  r5 = acc0; acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 6 ──
  x = a3; y = b3
  x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
  p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
  mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
  acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry
  r6 = acc0; r7 = acc1

  // ═══════════════════════════════════════════════════════════════════════
  // ETAPA 2: reducción in-place de r0..r7 (r0..r3 = L, r4..r7 = H)
  // ═══════════════════════════════════════════════════════════════════════
  let ov: u64 = 0

  // h0 = r4
  {
    const h0 = r4
    const lo = h0 & 0xffffffff, hi = h0 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32), p_hi = (hi * 977) >> 32
    const s_lo = h0 << 32, s_hi = h0 >> 32
    let sum = r0 + p_lo; let c = u64(sum < r0); sum += s_lo; c += u64(sum < s_lo); r0 = sum
    r1 += p_hi + s_hi + c; ov = u64(r1 < p_hi + s_hi + c)
  }
  // h1 = r5
  {
    const h1 = r5
    const lo = h1 & 0xffffffff, hi = h1 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32), p_hi = (hi * 977) >> 32
    const s_lo = h1 << 32, s_hi = h1 >> 32
    let sum = r1 + p_lo; let c = u64(sum < r1); sum += s_lo; c += u64(sum < s_lo); r1 = sum
    r2 += p_hi + s_hi + c + ov; ov = u64(r2 < p_hi + s_hi + c + ov)
  }
  // h2 = r6
  {
    const h2 = r6
    const lo = h2 & 0xffffffff, hi = h2 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32), p_hi = (hi * 977) >> 32
    const s_lo = h2 << 32, s_hi = h2 >> 32
    let sum = r2 + p_lo; let c = u64(sum < r2); sum += s_lo; c += u64(sum < s_lo); r2 = sum
    r3 += p_hi + s_hi + c + ov; ov = u64(r3 < p_hi + s_hi + c + ov)
  }
  // h3 = r7
  {
    const h3 = r7
    const lo = h3 & 0xffffffff, hi = h3 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32), p_hi = (hi * 977) >> 32
    const s_lo = h3 << 32, s_hi = h3 >> 32
    let sum = r3 + p_lo; let c = u64(sum < r3); sum += s_lo; c += u64(sum < s_lo); r3 = sum
    ov = p_hi + s_hi + c + ov
  }
  // overflow final
  {
    const p_lo = ov * 977, s_lo = ov << 32, s_hi = ov >> 32
    let sum = r0 + p_lo; let c = u64(sum < r0); sum += s_lo; c += u64(sum < s_lo); r0 = sum
    r1 += s_hi + c; const c2 = u64(r1 < s_hi + c); r2 += c2; const c3 = u64(r2 < c2); r3 += c3
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ETAPA 3: normalización final (si ≥ P, restar P una vez)
  // ═══════════════════════════════════════════════════════════════════════
  let gt = false
  if (r3 > P3) gt = true
  else if (r3 == P3) {
    if (r2 > P2) gt = true
    else if (r2 == P2) {
      if (r1 > P1) gt = true
      else if (r1 == P1) {
        if (r0 >= P0) gt = true
      }
    }
  }
  if (gt) {
    let d0 = r0 - P0; let b = u64(d0 > r0); r0 = d0
    let d1 = r1 - P1 - b; b = u64(d1 > r1) | (u64(d1 == r1) & b); r1 = d1
    let d2 = r2 - P2 - b; b = u64(d2 > r2) | (u64(d2 == r2) & b); r2 = d2
    r3 = r3 - P3 - b
  }

  store<u64>(res, r0)
  store<u64>(res, r1, 8)
  store<u64>(res, r2, 16)
  store<u64>(res, r3, 24)
}

/**
 * sqrMod: res = (a²) mod P. Fused (squaring simétrico en registros + reducción).
 * 10 mult en vez de 16 (cruzados duplicados, cuadrados una vez).
 */
// @ts-ignore
@inline
export function sqrMod(res: usize, a: usize): void {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)

  let r0: u64, r1: u64, r2: u64, r3: u64
  let r4: u64, r5: u64, r6: u64, r7: u64

  let acc0: u64 = 0
  let acc1: u64 = 0
  let acc2: u64 = 0
  let carry: u64
  let prod_lo: u64, prod_hi: u64

  // ── Col 0: a0² ──
  {
    const lo = a0 & 0xffffffff, hi = a0 >> 32
    const p0 = lo * lo, p1 = lo * hi, p3 = hi * hi
    const mid = p1 + p1, cmid = u64(mid < p1)
    const rlo = p0 + (mid << 32), clo = u64(rlo < p0)
    acc0 = rlo; acc1 = p3 + (mid >> 32) + (cmid << 32) + clo
  }
  r0 = acc0; acc0 = acc1; acc1 = 0

  // ── Col 1: 2·a0·a1 ──
  {
    const x = a0, y = a1
    const x_lo = x & 0xffffffff, x_hi = x >> 32, y_lo = y & 0xffffffff, y_hi = y >> 32
    const p0 = x_lo * y_lo, p1 = x_lo * y_hi, p2 = x_hi * y_lo, p3 = x_hi * y_hi
    const mid = p1 + p2, c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); const c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  }
  r1 = acc0; acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 2: 2·a0·a2 + a1² ──
  {
    let x = a0, y = a2
    let x_lo = x & 0xffffffff, x_hi = x >> 32, y_lo = y & 0xffffffff, y_hi = y >> 32
    let p0 = x_lo * y_lo, p1 = x_lo * y_hi, p2 = x_hi * y_lo, p3 = x_hi * y_hi
    let mid = p1 + p2, c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); let c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    // a1²
    const lo = a1 & 0xffffffff, hi = a1 >> 32
    const sq0 = lo * lo, sq1 = lo * hi, sq3 = hi * hi
    const msq = sq1 + sq1, cmsq = u64(msq < sq1); prod_lo = sq0 + (msq << 32); const clo = u64(prod_lo < sq0); prod_hi = sq3 + (msq >> 32) + (cmsq << 32) + clo
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  }
  r2 = acc0; acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 3: 2·(a0·a3 + a1·a2) ──
  {
    let x = a0, y = a3
    let x_lo = x & 0xffffffff, x_hi = x >> 32, y_lo = y & 0xffffffff, y_hi = y >> 32
    let p0 = x_lo * y_lo, p1 = x_lo * y_hi, p2 = x_hi * y_lo, p3 = x_hi * y_hi
    let mid = p1 + p2, c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); let c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    // 2·a1·a2
    x = a1; y = a2
    x_lo = x & 0xffffffff; x_hi = x >> 32; y_lo = y & 0xffffffff; y_hi = y >> 32
    p0 = x_lo * y_lo; p1 = x_lo * y_hi; p2 = x_hi * y_lo; p3 = x_hi * y_hi
    mid = p1 + p2; c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  }
  r3 = acc0; acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 4: 2·a1·a3 + a2² ──
  {
    let x = a1, y = a3
    let x_lo = x & 0xffffffff, x_hi = x >> 32, y_lo = y & 0xffffffff, y_hi = y >> 32
    let p0 = x_lo * y_lo, p1 = x_lo * y_hi, p2 = x_hi * y_lo, p3 = x_hi * y_hi
    let mid = p1 + p2, c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); let c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    // a2²
    const lo = a2 & 0xffffffff, hi = a2 >> 32
    const sq0 = lo * lo, sq1 = lo * hi, sq3 = hi * hi
    const msq = sq1 + sq1, cmsq = u64(msq < sq1); prod_lo = sq0 + (msq << 32); const clo = u64(prod_lo < sq0); prod_hi = sq3 + (msq >> 32) + (cmsq << 32) + clo
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  }
  r4 = acc0; acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 5: 2·a2·a3 ──
  {
    const x = a2, y = a3
    const x_lo = x & 0xffffffff, x_hi = x >> 32, y_lo = y & 0xffffffff, y_hi = y >> 32
    const p0 = x_lo * y_lo, p1 = x_lo * y_hi, p2 = x_hi * y_lo, p3 = x_hi * y_hi
    const mid = p1 + p2, c1 = u64(mid < p1); prod_lo = p0 + (mid << 32); const c2 = u64(prod_lo < p0); prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  }
  r5 = acc0; acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 6: a3² ──
  {
    const lo = a3 & 0xffffffff, hi = a3 >> 32
    const sq0 = lo * lo, sq1 = lo * hi, sq3 = hi * hi
    const msq = sq1 + sq1, cmsq = u64(msq < sq1); prod_lo = sq0 + (msq << 32); const clo = u64(prod_lo < sq0); prod_hi = sq3 + (msq >> 32) + (cmsq << 32) + clo
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry
  }
  r6 = acc0; r7 = acc1

  // ═══════════════════════════════════════════════════════════════════════
  // ETAPA 2: reducción in-place (idéntica a mulMod)
  // ═══════════════════════════════════════════════════════════════════════
  let ov: u64 = 0
  {
    const h0 = r4
    const lo = h0 & 0xffffffff, hi = h0 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32), p_hi = (hi * 977) >> 32
    const s_lo = h0 << 32, s_hi = h0 >> 32
    let sum = r0 + p_lo; let c = u64(sum < r0); sum += s_lo; c += u64(sum < s_lo); r0 = sum
    r1 += p_hi + s_hi + c; ov = u64(r1 < p_hi + s_hi + c)
  }
  {
    const h1 = r5
    const lo = h1 & 0xffffffff, hi = h1 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32), p_hi = (hi * 977) >> 32
    const s_lo = h1 << 32, s_hi = h1 >> 32
    let sum = r1 + p_lo; let c = u64(sum < r1); sum += s_lo; c += u64(sum < s_lo); r1 = sum
    r2 += p_hi + s_hi + c + ov; ov = u64(r2 < p_hi + s_hi + c + ov)
  }
  {
    const h2 = r6
    const lo = h2 & 0xffffffff, hi = h2 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32), p_hi = (hi * 977) >> 32
    const s_lo = h2 << 32, s_hi = h2 >> 32
    let sum = r2 + p_lo; let c = u64(sum < r2); sum += s_lo; c += u64(sum < s_lo); r2 = sum
    r3 += p_hi + s_hi + c + ov; ov = u64(r3 < p_hi + s_hi + c + ov)
  }
  {
    const h3 = r7
    const lo = h3 & 0xffffffff, hi = h3 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32), p_hi = (hi * 977) >> 32
    const s_lo = h3 << 32, s_hi = h3 >> 32
    let sum = r3 + p_lo; let c = u64(sum < r3); sum += s_lo; c += u64(sum < s_lo); r3 = sum
    ov = p_hi + s_hi + c + ov
  }
  {
    const p_lo = ov * 977, s_lo = ov << 32, s_hi = ov >> 32
    let sum = r0 + p_lo; let c = u64(sum < r0); sum += s_lo; c += u64(sum < s_lo); r0 = sum
    r1 += s_hi + c; const c2 = u64(r1 < s_hi + c); r2 += c2; const c3 = u64(r2 < c2); r3 += c3
  }

  // ETAPA 3: normalización final
  let gt = false
  if (r3 > P3) gt = true
  else if (r3 == P3) {
    if (r2 > P2) gt = true
    else if (r2 == P2) {
      if (r1 > P1) gt = true
      else if (r1 == P1) {
        if (r0 >= P0) gt = true
      }
    }
  }
  if (gt) {
    let d0 = r0 - P0; let b = u64(d0 > r0); r0 = d0
    let d1 = r1 - P1 - b; b = u64(d1 > r1) | (u64(d1 == r1) & b); r1 = d1
    let d2 = r2 - P2 - b; b = u64(d2 > r2) | (u64(d2 == r2) & b); r2 = d2
    r3 = r3 - P3 - b
  }

  store<u64>(res, r0)
  store<u64>(res, r1, 8)
  store<u64>(res, r2, 16)
  store<u64>(res, r3, 24)
}