/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  glv/glv.ts — Endomorfismo GLV: multiplicación k·P acelerada
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * φ(x, y) = (BETA·x, y) es un endomorfismo con φ(P) = λ·P. Entonces
 * k·P = k1·P + k2·φ(P) con k1, k2 de ~128 bits ⇒ dos escalares cortos.
 *
 * Zero-alloc:
 *   • Tabla de G (16 entradas) en data segment, init lazy (flag).
 *   • Constantes de retícula en data segment, init lazy (flag).
 *   • Tabla dinámica (P arbitrario) y todos los temps en la arena (save/restore).
 *
 * `mul` es aliasing-safe: `res` puede ser == `p` (in-place).
 */
import {
  P0, P1, P2, P3,
  BETA_0, BETA_1, BETA_2, BETA_3,
  A1_0, A1_1, B1_0, B1_1, A2_0, A2_1, A2_2,
  N0, N1, N2, N3, NH0, NH1, NH2, NH3,
} from "../constants"
import { Arena } from "../../utils/arena"
import { mulMod, sub as subP } from "../field"
import { mul as mulWide, addRaw, sub as subN, reduce, cmp } from "../scalar"
import { compute as wnafCompute } from "../wnaf"
import { addMixed, double, setInfinity, toAffine, batchToAffine, generator } from "../point"

// ── Tabla de G en data segment (2 × 8 entradas afines de 64 B = 1 KB) ─────
const G_TABLE_1: usize = memory.data(512)
const G_TABLE_2: usize = memory.data(512)
let gTableReady: bool = false

// ── Constantes de la retícula en data segment ─────────────────────────────
const _B2: usize = memory.data(32) // b2 = a1
const _B1: usize = memory.data(32) // b1
const _A1: usize = memory.data(32) // a1
const _A2: usize = memory.data(32) // a2
const _N: usize = memory.data(32)  // N
const _NH: usize = memory.data(32) // (N−1)/2
let latticeReady: bool = false

// @ts-ignore
@inline
function initLattice(): void {
  if (latticeReady) return
  store<u64>(_B2, A1_0); store<u64>(_B2, A1_1, 8); store<u64>(_B2, 0, 16); store<u64>(_B2, 0, 24)
  store<u64>(_B1, B1_0); store<u64>(_B1, B1_1, 8); store<u64>(_B1, 0, 16); store<u64>(_B1, 0, 24)
  store<u64>(_A1, A1_0); store<u64>(_A1, A1_1, 8); store<u64>(_A1, 0, 16); store<u64>(_A1, 0, 24)
  store<u64>(_A2, A2_0); store<u64>(_A2, A2_1, 8); store<u64>(_A2, A2_2, 16); store<u64>(_A2, 0, 24)
  store<u64>(_N, N0); store<u64>(_N, N1, 8); store<u64>(_N, N2, 16); store<u64>(_N, N3, 24)
  store<u64>(_NH, NH0); store<u64>(_NH, NH1, 8); store<u64>(_NH, NH2, 16); store<u64>(_NH, NH3, 24)
  latticeReady = true
}

// @ts-ignore
@inline
function addOne(p: usize): void {
  let a0 = load<u64>(p) + 1
  store<u64>(p, a0)
  if (a0 == 0) {
    let a1 = load<u64>(p, 8) + 1
    store<u64>(p, a1, 8)
    if (a1 == 0) {
      let a2 = load<u64>(p, 16) + 1
      store<u64>(p, a2, 16)
      if (a2 == 0) store<u64>(p, load<u64>(p, 24) + 1, 24)
    }
  }
}

/**
 * Descomposición GLV: k = k1 + k2·λ (mod N), |k1|,|k2| ≤ N>>1.
 * Escribe |k1| en k1, |k2| en k2, y signos en signs[0]/signs[1] (1 = negativo).
 * Redondeo al entero más cercano: c = (k·b + (N−1)/2) >> 256.
 */
export function decompose(k: usize, k1: usize, k2: usize, signs: usize): void {
  initLattice()
  const ctx = Arena.save()
  const wide = Arena.alloc(64)
  const c1 = Arena.alloc(32)
  const c2 = Arena.alloc(32)
  const v1 = Arena.alloc(32)
  const v2 = Arena.alloc(32)
  const v3 = Arena.alloc(32)
  const v4 = Arena.alloc(32)

  // c1 = round(k·b2 / N)
  mulWide(wide, k, _B2)
  memory.copy(c1, wide + 32, 32)
  if (addRaw(wide, wide, _NH)) addOne(c1)

  // c2 = round(k·b1 / N)
  mulWide(wide, k, _B1)
  memory.copy(c2, wide + 32, 32)
  if (addRaw(wide, wide, _NH)) addOne(c2)

  // v1 = c1·a1 mod N ; v2 = c2·a2 mod N
  mulWide(wide, c1, _A1); reduce(v1, wide)
  mulWide(wide, c2, _A2); reduce(v2, wide)

  // k1 = k − v1 − v2 (mod N)
  subN(k1, k, v1)
  subN(k1, k1, v2)

  // v3 = c1·b1 mod N ; v4 = c2·b2 mod N
  mulWide(wide, c1, _B1); reduce(v3, wide)
  mulWide(wide, c2, _B2); reduce(v4, wide)

  // k2 = v3 − v4 (mod N)
  subN(k2, v3, v4)

  // Balanceo de signos: si ki > (N−1)/2 ⇒ ki = N − ki, signo = 1
  // (con '>' estricto la cota |ki| ≤ (N−1)/2 = N>>1 es exacta)
  store<u8>(signs, 0)
  store<u8>(signs + 1, 0)
  if (cmp(k1, _NH) > 0) {
    subN(k1, _N, k1)
    store<u8>(signs, 1)
  }
  if (cmp(k2, _NH) > 0) {
    subN(k2, _N, k2)
    store<u8>(signs + 1, 1)
  }

  Arena.restore(ctx)
}

/**
 * Tabla afín de impares {P, 3P, 5P, …, (2·count−1)P} (para wNAF).
 * `table` debe tener ≥ count·64 bytes. Zero-alloc (arena).
 */
export function precomputeTable(table: usize, p: usize, count: i32): void {
  const ctx = Arena.save()
  const p2 = Arena.alloc(96)
  const p2aff = Arena.alloc(64)
  const cur = Arena.alloc(96)
  const jacs = Arena.alloc(<usize>(count * 96))

  double(p2, p)            // p2 = 2P (Jacobiano)
  toAffine(p2aff, p2)      // p2aff = 2P (afín)
  memory.copy(cur, p, 96)  // cur = P
  memory.copy(jacs, p, 96) // jacs[0] = P

  // Acumula 3P, 5P, … en Jacobiano (addMixed) SIN normalizar cada paso.
  for (let i: i32 = 1; i < count; i++) {
    addMixed(cur, cur, p2aff, p2aff + 32) // cur += 2P
    memory.copy(jacs + <usize>(i * 96), cur, 96)
  }

  // Una única inversión modular normaliza los `count` puntos (antes: count).
  batchToAffine(table, jacs, count)
  Arena.restore(ctx)
}

/** Inicializa (una vez) la tabla de G y φ(G). */
export function initGTable(): void {
  if (gTableReady) return
  const ctx = Arena.save()
  const gJac = Arena.alloc(96)
  const beta = Arena.alloc(32)
  const betaP = Arena.alloc(96)

  memory.copy(gJac, generator(), 96) // G (Jacobiano, Z=1)
  precomputeTable(G_TABLE_1, gJac, 8)

  // φ(G) = (BETA·Gx, Gy, 1)
  store<u64>(beta, BETA_0); store<u64>(beta, BETA_1, 8)
  store<u64>(beta, BETA_2, 16); store<u64>(beta, BETA_3, 24)
  mulMod(betaP, gJac, beta)               // X' = BETA·Gx (mod P)
  memory.copy(betaP + 32, gJac + 32, 32)  // Y' = Gy
  memory.copy(betaP + 64, gJac + 64, 32)  // Z' = 1
  precomputeTable(G_TABLE_2, betaP, 8)

  gTableReady = true
  Arena.restore(ctx)
}

/**
 * Multiplicación GLV: res = k·P (Jacobiano, 96 B). Aliasing-safe (res puede == p).
 * Si P == G usa la tabla precomputada; si no, construye una tabla dinámica en la arena.
 */
export function mul(res: usize, p: usize, k: usize): void {
  const ctx = Arena.save()
  const k1 = Arena.alloc(32)
  const k2 = Arena.alloc(32)
  const signs = Arena.alloc(2)
  const wnaf1 = Arena.alloc(264)
  const wnaf2 = Arena.alloc(264)
  const acc = Arena.alloc(96)
  const ty = Arena.alloc(32)
  const prime = Arena.alloc(32)

  decompose(k, k1, k2, signs)
  const neg1 = load<u8>(signs) != 0
  const neg2 = load<u8>(signs + 1) != 0

  const len1 = wnafCompute(wnaf1, k1, 5)
  const len2 = wnafCompute(wnaf2, k2, 5)

  // ¿P es el generador G? (comparando coordenadas afines X, Y)
  const g = generator()
  const isG =
    load<u64>(p) == load<u64>(g) &&
    load<u64>(p, 8) == load<u64>(g, 8) &&
    load<u64>(p, 16) == load<u64>(g, 16) &&
    load<u64>(p, 24) == load<u64>(g, 24) &&
    load<u64>(p, 32) == load<u64>(g, 32) &&
    load<u64>(p, 40) == load<u64>(g, 40) &&
    load<u64>(p, 48) == load<u64>(g, 48) &&
    load<u64>(p, 56) == load<u64>(g, 56)

  let table1: usize
  let table2: usize
  if (isG) {
    initGTable()
    table1 = G_TABLE_1
    table2 = G_TABLE_2
  } else {
    const dyn = Arena.alloc(1024) // 2 tablas × 8 × 64
    table1 = dyn
    table2 = dyn + 512
    precomputeTable(table1, p, 8)

    // φ(P) = (BETA·X, Y). Los múltiplos impares de φ(P) son φ(impares de P):
    // table2[j] = (BETA · table1[j].X, table1[j].Y). Evita 8 inversas + 7
    // addMixed de una segunda precomputación.
    const betaP = Arena.alloc(32)
    store<u64>(betaP, BETA_0); store<u64>(betaP, BETA_1, 8)
    store<u64>(betaP, BETA_2, 16); store<u64>(betaP, BETA_3, 24)
    for (let j: i32 = 0; j < 8; j++) {
      const src = table1 + <usize>(j * 64)
      const dst = table2 + <usize>(j * 64)
      mulMod(dst, src, betaP)
      memory.copy(dst + 32, src + 32, 32)
    }
  }

  // Primo del campo P (para negar coordenadas Y)
  store<u64>(prime, P0); store<u64>(prime, P1, 8)
  store<u64>(prime, P2, 16); store<u64>(prime, P3, 24)

  setInfinity(acc)
  let first = true
  const maxLen = len1 > len2 ? len1 : len2

  for (let i = maxLen - 1; i >= 0; i--) {
    if (!first) double(acc, acc)

    if (i < len1) {
      const d = load<i8>(wnaf1 + i)
      if (d != 0) {
        const idx = <usize>((d < 0 ? -d : d) - 1) >> 1
        const q = table1 + idx * 64
        let sgn = d < 0
        if (neg1) sgn = !sgn
        if (sgn) subP(ty, prime, q + 32) // ty = P − q.Y  (mod P)
        else memory.copy(ty, q + 32, 32)
        if (first) {
          memory.copy(acc, q, 32)
          memory.copy(acc + 32, ty, 32)
          store<u64>(acc + 64, 1); store<u64>(acc + 72, 0)
          store<u64>(acc + 80, 0); store<u64>(acc + 88, 0)
          first = false
        } else {
          addMixed(acc, acc, q, ty)
        }
      }
    }

    if (i < len2) {
      const d = load<i8>(wnaf2 + i)
      if (d != 0) {
        const idx = <usize>((d < 0 ? -d : d) - 1) >> 1
        const q = table2 + idx * 64
        let sgn = d < 0
        if (neg2) sgn = !sgn
        if (sgn) subP(ty, prime, q + 32)
        else memory.copy(ty, q + 32, 32)
        if (first) {
          memory.copy(acc, q, 32)
          memory.copy(acc + 32, ty, 32)
          store<u64>(acc + 64, 1); store<u64>(acc + 72, 0)
          store<u64>(acc + 80, 0); store<u64>(acc + 88, 0)
          first = false
        } else {
          addMixed(acc, acc, q, ty)
        }
      }
    }
  }

  memory.copy(res, acc, 96)
  Arena.restore(ctx)
}