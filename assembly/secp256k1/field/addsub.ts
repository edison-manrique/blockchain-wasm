/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  field/addsub.ts — Suma y resta modular mod P (constant-time)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * add / sub mod P con selección branchless (select64), idénticas a las del
 * BigInt256 original. subP asume a ≥ P (resta sin conditional). addP_shr1 se
 * usa en la inversa modular (BEEA): (a + P) >> 1.
 */
import { P0, P1, P2, P3 } from "../constants"
import { select64 } from "./raw"

/**
 * Suma modular: res = (a + b) mod P. Constant-time (branchless).
 */
// @ts-ignore
@inline
export function add(res: usize, a: usize, b: usize): void {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)
  const b0 = load<u64>(b)
  const b1 = load<u64>(b, 8)
  const b2 = load<u64>(b, 16)
  const b3 = load<u64>(b, 24)

  // SUMA = a + b
  const s0 = a0 + b0
  let c = u64(s0 < a0)
  const s1 = a1 + b1 + c
  c = u64(s1 < a1) | (u64(s1 == a1) & c)
  const s2 = a2 + b2 + c
  c = u64(s2 < a2) | (u64(s2 == a2) & c)
  const s3 = a3 + b3 + c
  c = u64(s3 < a3) | (u64(s3 == a3) & c)

  // DIFF = SUMA − P
  const d0 = s0 - P0
  let bor = u64(d0 > s0)
  const d1 = s1 - P1 - bor
  bor = u64(d1 > s1) | (u64(d1 == s1) & bor)
  const d2 = s2 - P2 - bor
  bor = u64(d2 > s2) | (u64(d2 == s2) & bor)
  const d3 = s3 - P3 - bor
  bor = u64(d3 > s3) | (u64(d3 == s3) & bor)

  // Usar DIFF si hubo carry global (c=1) O no hubo borrow (bor=0, i.e. SUMA ≥ P)
  const useDiff = c | (1 - bor)
  const mask = 0 - useDiff

  store<u64>(res, select64(s0, d0, mask))
  store<u64>(res, select64(s1, d1, mask), 8)
  store<u64>(res, select64(s2, d2, mask), 16)
  store<u64>(res, select64(s3, d3, mask), 24)
}

/**
 * Resta modular: res = (a − b) mod P. Constant-time (branchless).
 */
// @ts-ignore
@inline
export function sub(res: usize, a: usize, b: usize): void {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)
  const b0 = load<u64>(b)
  const b1 = load<u64>(b, 8)
  const b2 = load<u64>(b, 16)
  const b3 = load<u64>(b, 24)

  // DIFF = a − b
  const d0 = a0 - b0
  let bor = u64(d0 > a0)
  const d1 = a1 - b1 - bor
  bor = u64(d1 > a1) | (u64(d1 == a1) & bor)
  const d2 = a2 - b2 - bor
  bor = u64(d2 > a2) | (u64(d2 == a2) & bor)
  const d3 = a3 - b3 - bor
  bor = u64(d3 > a3) | (u64(d3 == a3) & bor)

  // ADD_P = DIFF + P (por si DIFF fue negativo)
  const p0 = d0 + P0
  let c = u64(p0 < d0)
  const p1 = d1 + P1 + c
  c = u64(p1 < d1) | (u64(p1 == d1) & c)
  const p2 = d2 + P2 + c
  c = u64(p2 < d2) | (u64(p2 == d2) & c)
  const p3 = d3 + P3 + c

  // Usar ADD_P si hubo borrow (resultado negativo)
  const mask = 0 - bor

  store<u64>(res, select64(d0, p0, mask))
  store<u64>(res, select64(d1, p1, mask), 8)
  store<u64>(res, select64(d2, p2, mask), 16)
  store<u64>(res, select64(d3, p3, mask), 24)
}

/**
 * Resta P: res = a − P. ASUME a ≥ P (sin conditional).
 */
// @ts-ignore
@inline
export function subP(res: usize, a: usize): void {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)

  const r0 = a0 - P0
  let b = u64(r0 > a0)
  const r1 = a1 - P1 - b
  b = u64(r1 > a1) | (u64(r1 == a1) & b)
  const r2 = a2 - P2 - b
  b = u64(r2 > a2) | (u64(r2 == a2) & b)
  const r3 = a3 - P3 - b

  store<u64>(res, r0)
  store<u64>(res, r1, 8)
  store<u64>(res, r2, 16)
  store<u64>(res, r3, 24)
}

/**
 * ¿Es a ≥ P?
 */
// @ts-ignore
@inline
export function isGreaterOrEqualP(a: usize): bool {
  const a3 = load<u64>(a, 24)
  if (a3 > P3) return true
  if (a3 < P3) return false
  const a2 = load<u64>(a, 16)
  if (a2 > P2) return true
  if (a2 < P2) return false
  const a1 = load<u64>(a, 8)
  if (a1 > P1) return true
  if (a1 < P1) return false
  return load<u64>(a) >= P0
}

/**
 * (a + P) >> 1 in-place — usado en la inversa modular BEEA.
 * Idéntico al BigInt256.addP_and_shr1 original.
 */
// @ts-ignore
@inline
export function addP_shr1(a: usize): void {
  const a0 = load<u64>(a)
  const a1 = load<u64>(a, 8)
  const a2 = load<u64>(a, 16)
  const a3 = load<u64>(a, 24)

  const s0 = a0 + P0
  let c = u64(s0 < a0)
  const s1 = a1 + P1 + c
  c = u64(s1 < a1) | (u64(s1 == a1) & c)
  const s2 = a2 + P2 + c
  c = u64(s2 < a2) | (u64(s2 == a2) & c)
  const s3 = a3 + P3 + c
  c = u64(s3 < a3) | (u64(s3 == a3) & c)

  store<u64>(a, (s0 >> 1) | (s1 << 63))
  store<u64>(a, (s1 >> 1) | (s2 << 63), 8)
  store<u64>(a, (s2 >> 1) | (s3 << 63), 16)
  store<u64>(a, (s3 >> 1) | (c << 63), 24)
}