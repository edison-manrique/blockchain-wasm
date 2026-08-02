/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  field/reduce.ts — Reducción modular 512 → 256 bits (mod P)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Reduce un número de 512 bits (8 limbs) a 256 bits módulo P, usando la
 * forma especial de secp256k1:
 *
 *   P = 2^256 − C,  con  C = 2^32 + 977 = 0x1000003D1
 *
 * Si x = L + H·2^256  (L = limbs bajos, H = limbs altos), entonces:
 *   x mod P ≡ L + H·C (mod P)
 *
 * Cada limb alto h[i] contribuye h[i]·C = h[i]·(2^32 + 977) a los limbs bajos,
 * con propagación de carry. Tras procesar h0..h3 queda un overflow global `ov`
 * (pequeño) que se reduce una vez más. Finalmente, si el resultado ≥ P, se
 * resta P (una sola resta basta: el resultado tras la reducción es < 2P).
 *
 * Lógica EXACTA del BigInt256.reduce original.
 */
import { isGreaterOrEqualP, subP } from "./addsub"

/**
 * reduce: res (32 B) = a (64 B, 512 bits) mod P.
 */
// @ts-ignore
@inline
export function reduce(res: usize, a: usize): void {
  // Limbs bajos (L) → resultado parcial
  let r0 = load<u64>(a)
  let r1 = load<u64>(a, 8)
  let r2 = load<u64>(a, 16)
  let r3 = load<u64>(a, 24)

  // Limbs altos (H)
  const h0 = load<u64>(a, 32)
  const h1 = load<u64>(a, 40)
  const h2 = load<u64>(a, 48)
  const h3 = load<u64>(a, 56)

  let ov: u64 = 0

  // ── h0 contribuye h0·(2^32 + 977) a r0, r1 ──
  {
    const lo = h0 & 0xffffffff
    const hi = h0 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32)
    const p_hi = (hi * 977) >> 32
    const s_lo = h0 << 32
    const s_hi = h0 >> 32

    let sum = r0 + p_lo
    let c = u64(sum < r0)
    sum += s_lo
    c += u64(sum < s_lo)
    r0 = sum

    r1 += p_hi + s_hi + c
    ov = u64(r1 < p_hi + s_hi + c)
  }

  // ── h1 contribuye a r1, r2 ──
  {
    const lo = h1 & 0xffffffff
    const hi = h1 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32)
    const p_hi = (hi * 977) >> 32
    const s_lo = h1 << 32
    const s_hi = h1 >> 32

    let sum = r1 + p_lo
    let c = u64(sum < r1)
    sum += s_lo
    c += u64(sum < s_lo)
    r1 = sum

    r2 += p_hi + s_hi + c + ov
    ov = u64(r2 < p_hi + s_hi + c + ov)
  }

  // ── h2 contribuye a r2, r3 ──
  {
    const lo = h2 & 0xffffffff
    const hi = h2 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32)
    const p_hi = (hi * 977) >> 32
    const s_lo = h2 << 32
    const s_hi = h2 >> 32

    let sum = r2 + p_lo
    let c = u64(sum < r2)
    sum += s_lo
    c += u64(sum < s_lo)
    r2 = sum

    r3 += p_hi + s_hi + c + ov
    ov = u64(r3 < p_hi + s_hi + c + ov)
  }

  // ── h3 contribuye a r3 y al overflow global ──
  {
    const lo = h3 & 0xffffffff
    const hi = h3 >> 32
    const p_lo = lo * 977 + ((hi * 977) << 32)
    const p_hi = (hi * 977) >> 32
    const s_lo = h3 << 32
    const s_hi = h3 >> 32

    let sum = r3 + p_lo
    let c = u64(sum < r3)
    sum += s_lo
    c += u64(sum < s_lo)
    r3 = sum

    ov = p_hi + s_hi + c + ov
  }

  // ── Reducir el overflow global: ov·(2^32 + 977) ──
  // ov es pequeño (< 2^32 típicamente), así p_hi = 0.
  {
    const p_lo = ov * 977
    const s_lo = ov << 32
    const s_hi = ov >> 32

    let sum = r0 + p_lo
    let c = u64(sum < r0)
    sum += s_lo
    c += u64(sum < s_lo)
    r0 = sum

    r1 += s_hi + c
    const c2 = u64(r1 < s_hi + c)
    r2 += c2
    const c3 = u64(r2 < c2)
    r3 += c3
  }

  // ── Escritura del resultado parcial ──
  store<u64>(res, r0)
  store<u64>(res, r1, 8)
  store<u64>(res, r2, 16)
  store<u64>(res, r3, 24)

  // ── Normalización final: si ≥ P, restar P (una resta basta) ──
  if (isGreaterOrEqualP(res)) {
    subP(res, res)
  }
}