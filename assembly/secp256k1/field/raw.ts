/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  field/raw.ts — Aritmética 256-bit "cruda" (sin módulo)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Operaciones sobre enteros de 256 bits (4 limbs u64, little-endian) SIN
 * reducción modular. COMPARTIDAS por field (mod P) y scalar (mod N) — aquí
 * está la lógica que antes se duplicaba en BigInt256 y Scalar256.
 *
 *  • addRaw / subRaw → devuelven el carry/borrow final (para reducción)
 *  • mulWide / sqrWide → producto completo 256×256 → 512 bits (Comba)
 *  • cmp / isZero / shr1Raw / select64 → utilidades
 *
 * Convención de offsets: limb0 en +0, limb1 en +8, limb2 en +16, limb3 en +24
 * (offsets ABSOLUTOS, coherente con el layout de puntos [X][Y][Z]).
 *
 * Todo @inline: el compilador (asc -O3) inlinea estas funciones entre módulos,
 * así el rendimiento es idéntico al inlining manual del código original.
 */

/**
 * Suma 256-bit: res = a + b. Retorna el carry final (0 o 1).
 * res puede ser == a o == b (in-place).
 */
// @ts-ignore
@inline
export function addRaw(res: usize, a: usize, b: usize): u64 {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)
  const b0 = load<u64>(b)
  const b1 = load<u64>(b, 8)
  const b2 = load<u64>(b, 16)
  const b3 = load<u64>(b, 24)

  const s0 = a0 + b0
  let c = u64(s0 < a0)
  const s1 = a1 + b1 + c
  c = u64(s1 < a1) | (u64(s1 == a1) & c)
  const s2 = a2 + b2 + c
  c = u64(s2 < a2) | (u64(s2 == a2) & c)
  const s3 = a3 + b3 + c
  c = u64(s3 < a3) | (u64(s3 == a3) & c)

  store<u64>(res, s0)
  store<u64>(res, s1, 8)
  store<u64>(res, s2, 16)
  store<u64>(res, s3, 24)
  return c
}

/**
 * Resta 256-bit: res = a − b. Retorna el borrow final (0 o 1).
 * res puede ser == a o == b (in-place).
 */
// @ts-ignore
@inline
export function subRaw(res: usize, a: usize, b: usize): u64 {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)
  const b0 = load<u64>(b)
  const b1 = load<u64>(b, 8)
  const b2 = load<u64>(b, 16)
  const b3 = load<u64>(b, 24)

  const d0 = a0 - b0
  let bor = u64(d0 > a0)
  const d1 = a1 - b1 - bor
  bor = u64(d1 > a1) | (u64(d1 == a1) & bor)
  const d2 = a2 - b2 - bor
  bor = u64(d2 > a2) | (u64(d2 == a2) & bor)
  const d3 = a3 - b3 - bor

  store<u64>(res, d0)
  store<u64>(res, d1, 8)
  store<u64>(res, d2, 16)
  store<u64>(res, d3, 24)
  return bor
}

/**
 * Selección constant-time: retorna a si mask == 0, b si mask == ~0.
 */
// @ts-ignore
@inline
export function select64(a: u64, b: u64, mask: u64): u64 {
  return (a & ~mask) | (b & mask)
}

/**
 * Multiplicación 64×64 → 128 bits (emulada con 4 mult 32×32).
 * Escribe el producto de 128 bits en out (low en +0, high en +8).
 */
// @ts-ignore
@inline
export function mul64(out: usize, x: u64, y: u64): void {
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

  store<u64>(out, lo)
  store<u64>(out, hi, 8)
}

/**
 * Multiplicación completa 256×256 → 512 bits (Comba, columnas desenrolladas).
 * res debe apuntar a 64 bytes (8 limbs). Lógica EXACTA del BigInt256.mul original.
 */
// @ts-ignore
/* @inline
export function mulWide(res: usize, a: usize, b: usize): void {
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

  // ── Col 0: a0·b0 ──
  {
    mul64(res, a0, b0)
    acc0 = load<u64>(res, 8)
  }
  acc1 = 0

  // ── Col 1: a0·b1 + a1·b0 ──
  {
    const t = res // reutilizamos una zona temporal de res (escribiremos encima al final)
    // a0·b1
    let lo: u64, hi: u64
    {
      mul64(res + 48, a0, b1) // zona alta de res como scratch (no escrita aún)
      lo = load<u64>(res + 48)
      hi = load<u64>(res + 56)
    }
    acc0 += lo
    carry = u64(acc0 < lo)
    acc1 += hi + carry
    acc2 += u64(acc1 < hi + carry)
    // a1·b0
    {
      mul64(res + 48, a1, b0)
      lo = load<u64>(res + 48)
      hi = load<u64>(res + 56)
    }
    acc0 += lo
    carry = u64(acc0 < lo)
    acc1 += hi + carry
    acc2 += u64(acc1 < hi + carry)
  }
  store<u64>(res, acc0, 8)
  acc0 = acc1
  acc1 = acc2
  acc2 = 0

  // ── Col 2: a0·b2 + a1·b1 + a2·b0 ──
  {
    let lo: u64, hi: u64
    mul64(res + 48, a0, b2); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
    mul64(res + 48, a1, b1); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
    mul64(res + 48, a2, b0); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
  }
  store<u64>(res, acc0, 16)
  acc0 = acc1
  acc1 = acc2
  acc2 = 0

  // ── Col 3: a0·b3 + a1·b2 + a2·b1 + a3·b0 ──
  {
    let lo: u64, hi: u64
    mul64(res + 48, a0, b3); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
    mul64(res + 48, a1, b2); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
    mul64(res + 48, a2, b1); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
    mul64(res + 48, a3, b0); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
  }
  store<u64>(res, acc0, 24)
  acc0 = acc1
  acc1 = acc2
  acc2 = 0

  // ── Col 4: a1·b3 + a2·b2 + a3·b1 ──
  {
    let lo: u64, hi: u64
    mul64(res + 48, a1, b3); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
    mul64(res + 48, a2, b2); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
    mul64(res + 48, a3, b1); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
  }
  store<u64>(res, acc0, 32)
  acc0 = acc1
  acc1 = acc2
  acc2 = 0

  // ── Col 5: a2·b3 + a3·b2 ──
  {
    let lo: u64, hi: u64
    mul64(res + 48, a2, b3); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
    mul64(res + 48, a3, b2); lo = load<u64>(res + 48); hi = load<u64>(res + 56)
    acc0 += lo; carry = u64(acc0 < lo); acc1 += hi + carry; acc2 += u64(acc1 < hi + carry)
  }
  store<u64>(res, acc0, 40)
  acc0 = acc1
  acc1 = acc2
  acc2 = 0

  // ── Col 6: a3·b3 ──
  {
    mul64(res + 48, a3, b3)
    acc0 += load<u64>(res + 48)
    carry = u64(acc0 < load<u64>(res + 48))
    acc1 = load<u64>(res + 56) + carry
  }
  store<u64>(res, acc0, 48)
  store<u64>(res, acc1, 56)
} */

/**
 * Comparación 256-bit: retorna 1 si a > b, -1 si a < b, 0 si a == b.
 */
// @ts-ignore
@inline
export function cmp(a: usize, b: usize): i32 {
  const a3 = load<u64>(a, 24)
  const b3 = load<u64>(b, 24)
  if (a3 > b3) return 1
  if (a3 < b3) return -1
  const a2 = load<u64>(a, 16)
  const b2 = load<u64>(b, 16)
  if (a2 > b2) return 1
  if (a2 < b2) return -1
  const a1 = load<u64>(a, 8)
  const b1 = load<u64>(b, 8)
  if (a1 > b1) return 1
  if (a1 < b1) return -1
  const a0 = load<u64>(a)
  const b0 = load<u64>(b)
  if (a0 > b0) return 1
  if (a0 < b0) return -1
  return 0
}

/**
 * ¿Es cero? (256 bits)
 */
// @ts-ignore
@inline
export function isZero(a: usize): bool {
  return (load<u64>(a) | load<u64>(a, 8) | load<u64>(a, 16) | load<u64>(a, 24)) == 0
}

/**
 * Shift right 1 bit in-place (256 bits, lógico).
 */
// @ts-ignore
@inline
export function shr1Raw(a: usize): void {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)
  store<u64>(a, (a0 >> 1) | (a1 << 63))
  store<u64>(a, (a1 >> 1) | (a2 << 63), 8)
  store<u64>(a, (a2 >> 1) | (a3 << 63), 16)
  store<u64>(a, a3 >> 1, 24)
}