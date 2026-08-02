/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  field/mul.ts — Multiplicación y squaring (256×256 → 512 bits)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * mul  → producto completo 256×256 → 512 bits (Comba, columnas desenrolladas).
 * sqr  → squaring 256 → 512 bits, aprovechando simetría (10 mult en vez de 16).
 *
 * Versión "a memoria": escribe los 512 bits en `res` (64 bytes). Para multiplicar
 * mod P en un solo paso (fused, sin materializar los 512 bits) usa mulMod/sqrMod
 * de mulmod.ts.
 *
 * Los productos 64×64→128 se calculan en variables locales (prod_lo/prod_hi),
 * transcripción literal del BigInt256.mul/sqr original validado.
 */

/**
 * Multiplicación 64×64 → 128 bits (emulada con 4 mult 32×32).
 * Devuelve el producto como dos u64 (low, high) vía punteros de salida.
 */
// @ts-ignore
@inline
function mul64(x: u64, y: u64, loOut: usize, hiOut: usize): void {
  const xlo = x & 0xffffffff
  const xhi = x >> 32
  const ylo = y & 0xffffffff
  const yhi = y >> 32

  const p0 = xlo * ylo
  const p1 = xlo * yhi
  const p2 = xhi * ylo
  const p3 = xhi * yhi

  const mid = p1 + p2
  const c1 = u64(mid < p1)

  const lo = p0 + (mid << 32)
  const c2 = u64(lo < p0)
  const hi = p3 + (mid >> 32) + (c1 << 32) + c2

  store<u64>(loOut, lo)
  store<u64>(hiOut, hi)
}

/**
 * Multiplicación completa: res (64 B) = a · b (512 bits). Comba por columnas.
 */
// @ts-ignore
@inline
export function mul(res: usize, a: usize, b: usize): void {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)
  const b0 = load<u64>(b)
  const b1 = load<u64>(b, 8)
  const b2 = load<u64>(b, 16)
  const b3 = load<u64>(b, 24)

  let acc0: u64 = 0
  let acc1: u64 = 0
  let acc2: u64 = 0
  let carry: u64
  let prod_lo: u64
  let prod_hi: u64

  // ── Col 0: a0·b0 ──
  mul64(a0, b0, res, res + 8)
  acc0 = load<u64>(res, 8)
  acc1 = 0

  // ── Col 1: a0·b1 + a1·b0 ──
  mul64(a0, b1, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  mul64(a1, b0, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  store<u64>(res, acc0, 8)
  acc0 = acc1
  acc1 = acc2
  acc2 = 0

  // ── Col 2: a0·b2 + a1·b1 + a2·b0 ──
  mul64(a0, b2, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  mul64(a1, b1, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  mul64(a2, b0, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  store<u64>(res, acc0, 16)
  acc0 = acc1
  acc1 = acc2
  acc2 = 0

  // ── Col 3: a0·b3 + a1·b2 + a2·b1 + a3·b0 ──
  mul64(a0, b3, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  mul64(a1, b2, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  mul64(a2, b1, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  mul64(a3, b0, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  store<u64>(res, acc0, 24)
  acc0 = acc1
  acc1 = acc2
  acc2 = 0

  // ── Col 4: a1·b3 + a2·b2 + a3·b1 ──
  mul64(a1, b3, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  mul64(a2, b2, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  mul64(a3, b1, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  store<u64>(res, acc0, 32)
  acc0 = acc1
  acc1 = acc2
  acc2 = 0

  // ── Col 5: a2·b3 + a3·b2 ──
  mul64(a2, b3, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  mul64(a3, b2, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  store<u64>(res, acc0, 40)
  acc0 = acc1
  acc1 = acc2
  acc2 = 0

  // ── Col 6: a3·b3 ──  (FIX: acumula el carry-alto entrante con +=, como cols 1–5)
  mul64(a3, b3, res + 48, res + 56)
  prod_lo = load<u64>(res + 48)
  prod_hi = load<u64>(res + 56)
  acc0 += prod_lo
  carry = u64(acc0 < prod_lo)
  acc1 += prod_hi + carry
  acc2 += u64(acc1 < prod_hi + carry)
  store<u64>(res, acc0, 48)
  store<u64>(res, acc1, 56)
}

/**
 * Squaring 256 → 512 bits aprovechando simetría (10 mult en vez de 16).
 * Los términos cruzados se duplican (2·ai·aj); los cuadrados (ai²) una vez.
 * Lógica EXACTA del BigInt256.sqr original.
 */
// @ts-ignore
@inline
export function sqr(res: usize, a: usize): void {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)

  let acc0: u64 = 0
  let acc1: u64 = 0
  let acc2: u64 = 0
  let prod_lo: u64
  let prod_hi: u64
  let carry: u64

  // ── Col 0: a0² ──
  {
    const lo = a0 & 0xffffffff, hi = a0 >> 32
    const p0 = lo * lo, p1 = lo * hi, p3 = hi * hi
    const mid = p1 + p1
    const cmid = u64(mid < p1)
    const rlo = p0 + (mid << 32)
    const clo = u64(rlo < p0)
    acc0 = rlo
    acc1 = p3 + (mid >> 32) + (cmid << 32) + clo
  }
  store<u64>(res, acc0)
  acc0 = acc1; acc1 = 0

  // ── Col 1: 2·a0·a1 ──
  {
    const xlo = a0 & 0xffffffff, xhi = a0 >> 32
    const ylo = a1 & 0xffffffff, yhi = a1 >> 32
    const p0 = xlo * ylo, p1 = xlo * yhi, p2 = xhi * ylo, p3 = xhi * yhi
    const mid = p1 + p2, c1 = u64(mid < p1)
    prod_lo = p0 + (mid << 32); const c2 = u64(prod_lo < p0)
    prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  }
  store<u64>(res, acc0, 8)
  acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 2: 2·a0·a2 + a1² ──
  {
    let xlo = a0 & 0xffffffff, xhi = a0 >> 32
    let ylo = a2 & 0xffffffff, yhi = a2 >> 32
    let p0 = xlo * ylo, p1 = xlo * yhi, p2 = xhi * ylo, p3 = xhi * yhi
    let mid = p1 + p2, c1 = u64(mid < p1)
    prod_lo = p0 + (mid << 32); let c2 = u64(prod_lo < p0)
    prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    // a1²
    const lo = a1 & 0xffffffff, hi = a1 >> 32
    const sq0 = lo * lo, sq1 = lo * hi, sq3 = hi * hi
    const msq = sq1 + sq1, cmsq = u64(msq < sq1)
    prod_lo = sq0 + (msq << 32); const clo = u64(prod_lo < sq0)
    prod_hi = sq3 + (msq >> 32) + (cmsq << 32) + clo
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  }
  store<u64>(res, acc0, 16)
  acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 3: 2·(a0·a3 + a1·a2) ──
  {
    let xlo = a0 & 0xffffffff, xhi = a0 >> 32
    let ylo = a3 & 0xffffffff, yhi = a3 >> 32
    let p0 = xlo * ylo, p1 = xlo * yhi, p2 = xhi * ylo, p3 = xhi * yhi
    let mid = p1 + p2, c1 = u64(mid < p1)
    prod_lo = p0 + (mid << 32); let c2 = u64(prod_lo < p0)
    prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    // 2·a1·a2
    xlo = a1 & 0xffffffff; xhi = a1 >> 32
    ylo = a2 & 0xffffffff; yhi = a2 >> 32
    p0 = xlo * ylo; p1 = xlo * yhi; p2 = xhi * ylo; p3 = xhi * yhi
    mid = p1 + p2; c1 = u64(mid < p1)
    prod_lo = p0 + (mid << 32); c2 = u64(prod_lo < p0)
    prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  }
  store<u64>(res, acc0, 24)
  acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 4: 2·a1·a3 + a2² ──
  {
    let xlo = a1 & 0xffffffff, xhi = a1 >> 32
    let ylo = a3 & 0xffffffff, yhi = a3 >> 32
    let p0 = xlo * ylo, p1 = xlo * yhi, p2 = xhi * ylo, p3 = xhi * yhi
    let mid = p1 + p2, c1 = u64(mid < p1)
    prod_lo = p0 + (mid << 32); let c2 = u64(prod_lo < p0)
    prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    // a2²
    const lo = a2 & 0xffffffff, hi = a2 >> 32
    const sq0 = lo * lo, sq1 = lo * hi, sq3 = hi * hi
    const msq = sq1 + sq1, cmsq = u64(msq < sq1)
    prod_lo = sq0 + (msq << 32); const clo = u64(prod_lo < sq0)
    prod_hi = sq3 + (msq >> 32) + (cmsq << 32) + clo
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  }
  store<u64>(res, acc0, 32)
  acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 5: 2·a2·a3 ──
  {
    const xlo = a2 & 0xffffffff, xhi = a2 >> 32
    const ylo = a3 & 0xffffffff, yhi = a3 >> 32
    const p0 = xlo * ylo, p1 = xlo * yhi, p2 = xhi * ylo, p3 = xhi * yhi
    const mid = p1 + p2, c1 = u64(mid < p1)
    prod_lo = p0 + (mid << 32); const c2 = u64(prod_lo < p0)
    prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
    acc0 += prod_lo; carry = u64(acc0 < prod_lo); acc1 += prod_hi + carry; acc2 += u64(acc1 < prod_hi + carry)
  }
  store<u64>(res, acc0, 40)
  acc0 = acc1; acc1 = acc2; acc2 = 0

  // ── Col 6: a3² ──
  {
    const lo = a3 & 0xffffffff, hi = a3 >> 32
    const sq0 = lo * lo, sq1 = lo * hi, sq3 = hi * hi
    const msq = sq1 + sq1, cmsq = u64(msq < sq1)
    prod_lo = sq0 + (msq << 32); const clo = u64(prod_lo < sq0)
    prod_hi = sq3 + (msq >> 32) + (cmsq << 32) + clo
    acc0 += prod_lo; carry = u64(acc0 < prod_lo)
    acc1 += prod_hi + carry
  }
  store<u64>(res, acc0, 48)
  store<u64>(res, acc1, 56)
}