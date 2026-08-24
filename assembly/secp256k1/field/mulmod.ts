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

  reduce512(res, r0, r1, r2, r3, r4, r5, r6, r7)
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

  reduce512(res, r0, r1, r2, r3, r4, r5, r6, r7)
}

// @ts-ignore
@inline
function mul977_lo(h: u64): u64 {
  const lo: u64 = (h & 0xffffffff) * 977
  const hi: u64 = (h >> 32) * 977
  return lo + ((hi & 0xffffffff) << 32)
}

// @ts-ignore
@inline
function mul977_hi(h: u64): u64 {
  const lo: u64 = (h & 0xffffffff) * 977
  const hi: u64 = (h >> 32) * 977
  const mid: u64 = lo + ((hi & 0xffffffff) << 32)
  return (hi >> 32) + u64(mid < lo)
}

/**
 * Reducción pseudo-Mersenne de 512 bits a 256 bits mod P (secp256k1).
 * P = 2^256 - 2^32 - 977  ⇒  2^256 ≡ 2^32 + 977 (mod P).
 */
// @ts-ignore
@inline
function reduce512(
  res: usize,
  r0: u64, r1: u64, r2: u64, r3: u64,
  r4: u64, r5: u64, r6: u64, r7: u64
): void {
  const p0: u64 = mul977_lo(r4)
  const c0: u64 = mul977_hi(r4)
  const p1_raw: u64 = mul977_lo(r5)
  const c1: u64 = mul977_hi(r5)
  const p2_raw: u64 = mul977_lo(r6)
  const c2: u64 = mul977_hi(r6)
  const p3_raw: u64 = mul977_lo(r7)
  const c3: u64 = mul977_hi(r7)

  const p1: u64 = p1_raw + c0
  const carry1: u64 = u64(p1 < c0)
  const p2: u64 = p2_raw + c1 + carry1
  const carry2: u64 = u64(p2 < (c1 + carry1))
  const p3: u64 = p3_raw + c2 + carry2
  const carry3: u64 = u64(p3 < (c2 + carry2))
  const t4: u64 = c3 + carry3

  const s0: u64 = r4 << 32
  const s1: u64 = (r5 << 32) | (r4 >> 32)
  const s2: u64 = (r6 << 32) | (r5 >> 32)
  const s3: u64 = (r7 << 32) | (r6 >> 32)
  const s4: u64 = r7 >> 32

  let sum0: u64 = r0 + p0
  let c: u64 = u64(sum0 < r0)
  sum0 += s0
  c += u64(sum0 < s0)

  let sum1: u64 = r1 + p1
  let c_next: u64 = u64(sum1 < r1)
  sum1 += s1
  c_next += u64(sum1 < s1)
  sum1 += c
  c_next += u64(sum1 < c)
  c = c_next

  let sum2: u64 = r2 + p2
  c_next = u64(sum2 < r2)
  sum2 += s2
  c_next += u64(sum2 < s2)
  sum2 += c
  c_next += u64(sum2 < c)
  c = c_next

  let sum3: u64 = r3 + p3
  c_next = u64(sum3 < r3)
  sum3 += s3
  c_next += u64(sum3 < s3)
  sum3 += c
  c_next += u64(sum3 < c)
  c = c_next

  const ov: u64 = t4 + s4 + c

  const ov_p0: u64 = ov * 977
  const ov_s0: u64 = ov << 32
  const ov_s1: u64 = ov >> 32

  sum0 += ov_p0
  c = u64(sum0 < ov_p0)
  sum0 += ov_s0
  c += u64(sum0 < ov_s0)

  sum1 += ov_s1
  c_next = u64(sum1 < ov_s1)
  sum1 += c
  c_next += u64(sum1 < c)
  c = c_next

  sum2 += c
  c = u64(sum2 < c)
  sum3 += c
  c = u64(sum3 < c)

  if (c != 0) {
    sum0 += 977
    let c2: u64 = u64(sum0 < 977)
    sum0 += (1 as u64) << 32
    c2 += u64(sum0 < ((1 as u64) << 32))
    sum1 += c2
    c2 = u64(sum1 < c2)
    sum2 += c2
    c2 = u64(sum2 < c2)
    sum3 += c2
  }

  while (true) {
    let gt = false
    if (sum3 > P3) gt = true
    else if (sum3 == P3) {
      if (sum2 > P2) gt = true
      else if (sum2 == P2) {
        if (sum1 > P1) gt = true
        else if (sum1 == P1) {
          if (sum0 >= P0) gt = true
        }
      }
    }
    if (!gt) break
    const d0: u64 = sum0 - P0
    let b: u64 = u64(d0 > sum0)
    sum0 = d0
    const d1: u64 = sum1 - P1 - b
    b = u64(d1 > sum1) | (u64(d1 == sum1) & b)
    sum1 = d1
    const d2: u64 = sum2 - P2 - b
    b = u64(d2 > sum2) | (u64(d2 == sum2) & b)
    sum2 = d2
    sum3 = sum3 - P3 - b
  }

  store<u64>(res, sum0)
  store<u64>(res, sum1, 8)
  store<u64>(res, sum2, 16)
  store<u64>(res, sum3, 24)
}