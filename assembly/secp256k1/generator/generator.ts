/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  generator/generator.ts — Multiplicación fija k·G (tabla precomputada + GLV)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Window method con endomorfismo GLV:
 *   k = k1 + k2·λ  (|ki| < 2^129),  ki = Σ u_i · 2^(w·i)
 *   k·G = Σ_i u1_i · T1[i] + u2_i · T2[i]
 *   T1[i][j] = j · 2^(w·i) · G        T2[i][j] = j · 2^(w·i) · φ(G)
 *
 * Zero-alloc:
 *   • T1/T2 en DATA SEGMENT (memory.data) — cero heap, cero memory.grow.
 *   • init() lazy: llena las tablas una vez (batch normalize, 1 modInverse/lote).
 *   • multiplyG usa la arena con save/restore.
 *
 * Parámetros (verificados: |ki| ≤ 129 bits; STEPS=17 cubre 136 bits):
 *   WINDOW=8, ENTRIES=256, STEPS=17  →  T1+T2 = 544 KB.
 *   (Para binario más pequeño: WINDOW=6, ENTRIES=64, STEPS=22 → 180 KB.)
 */
import { P0, P1, P2, P3, BETA_0, BETA_1, BETA_2, BETA_3 } from "../constants"
import { Arena } from "../../utils/arena"
import { mulMod, sqrMod, sub, modInverse } from "../field"
import { double, addMixed, toAffine, generator, setInfinity } from "../point"
import { decompose } from "../glv"

// ── Parámetros de la tabla fija ───────────────────────────────────────────
const WINDOW: i32 = 8
const ENTRIES: i32 = 256 // 1 << WINDOW
const STEPS: i32 = 17    // ceil(129/8); cubre |ki| < 2^136
const WIN_MASK: u64 = 0xff // (1 << WINDOW) - 1
const T_SIZE: usize = <usize>(STEPS * ENTRIES * 64)

// Tablas en data segment (zeroed en compile-time; init() las llena en runtime).
const T1: usize = memory.data(<i32>T_SIZE) // T1[i][j] = j · 2^(8i) · G   (afín)
const T2: usize = memory.data(<i32>T_SIZE) // T2[i][j] = j · 2^(8i) · φ(G) (afín)
let initialized: bool = false

/** Extrae WINDOW bits de `ptr` en la posición `start` (little-endian). */
// @ts-ignore
@inline
function extractWindow(ptr: usize, start: i32): i32 {
  const byte_off = <usize>(start >> 3)
  const bit_off = <u64>(start & 7)
  return <i32>((load<u64>(ptr + byte_off) >> bit_off) & WIN_MASK)
}

/**
 * Batch normalize: normaliza jac_src[1..n-1] (Jacobiano, 96 B c/u) a
 * dest[1..n-1] (afín, 64 B c/u) con Montgomery batch inversion (1 modInverse).
 * dest[0] no se toca (la entrada 0 no se usa: u=0 ⇒ skip).
 */
function batchNormalize(dest: usize, jac_src: usize, n: i32): void {
  const ctx = Arena.save()
  const products = Arena.alloc(<usize>(n * 32))
  const inv_zs = Arena.alloc(<usize>(n * 32))
  const tmp = Arena.alloc(32)
  const zi2 = Arena.alloc(32)
  const zi3 = Arena.alloc(32)

  // products[1] = Z_1 ; products[i] = products[i-1] · Z_i
  memory.copy(products + 32, jac_src + 96 + 64, 32)
  for (let i = 2; i < n; i++) {
    mulMod(products + <usize>(i * 32), products + <usize>((i - 1) * 32), jac_src + <usize>(i * 96) + 64)
  }

  // tmp = (Z_1·Z_2·…·Z_{n-1})⁻¹
  modInverse(tmp, products + <usize>((n - 1) * 32))

  // inv_z[i] = tmp · products[i-1] ;  tmp ← tmp · Z_i
  for (let i = n - 1; i > 1; i--) {
    mulMod(inv_zs + <usize>(i * 32), tmp, products + <usize>((i - 1) * 32))
    mulMod(tmp, tmp, jac_src + <usize>(i * 96) + 64)
  }
  memory.copy(inv_zs + 32, tmp, 32) // inv_z[1]

  // afín: x = X·zi²,  y = Y·zi³
  for (let i = 1; i < n; i++) {
    const iz = inv_zs + <usize>(i * 32)
    const src = jac_src + <usize>(i * 96)
    const dst = dest + <usize>(i * 64)
    sqrMod(zi2, iz)
    mulMod(zi3, zi2, iz)
    mulMod(dst, src, zi2)
    mulMod(dst + 32, src + 32, zi3)
  }

  Arena.restore(ctx)
}

/** Precomputa T1 y T2 (llamado una vez, lazy desde multiplyG). */
export function init(): void {
  if (initialized) return
  const ctx = Arena.save()

  const base1 = Arena.alloc(96)  // 2^(8i)·G   (Jacobiano)
  const base2 = Arena.alloc(96)  // 2^(8i)·φ(G)
  const acc = Arena.alloc(96)
  const affBase = Arena.alloc(64) // base afín (para addMixed)
  const beta = Arena.alloc(32)
  const tempJac = Arena.alloc(<usize>(ENTRIES * 96)) // lote de puntos Jacobianos

  // base1 = G ;  base2 = φ(G) = (BETA·Gx, Gy, 1)
  memory.copy(base1, generator(), 96)
  store<u64>(beta, BETA_0); store<u64>(beta, BETA_1, 8)
  store<u64>(beta, BETA_2, 16); store<u64>(beta, BETA_3, 24)
  mulMod(base2, base1, beta)              // X' = BETA·Gx
  memory.copy(base2 + 32, base1 + 32, 32) // Y' = Gy
  memory.copy(base2 + 64, base1 + 64, 32) // Z' = 1

  for (let i = 0; i < STEPS; i++) {
    const dest1 = T1 + <usize>(i * ENTRIES * 64)
    const dest2 = T2 + <usize>(i * ENTRIES * 64)

    // ── T1[i][j] = j · base1 ──
    toAffine(affBase, base1)
    memory.copy(acc, base1, 96)
    memory.copy(tempJac + 96, base1, 96) // tempJac[1] = base1
    for (let j = 2; j < ENTRIES; j++) {
      addMixed(acc, acc, affBase, affBase + 32) // acc = j·base1
      memory.copy(tempJac + <usize>(j * 96), acc, 96)
    }
    batchNormalize(dest1, tempJac, ENTRIES)

    // ── T2[i][j] = j · base2 ──
    toAffine(affBase, base2)
    memory.copy(acc, base2, 96)
    memory.copy(tempJac + 96, base2, 96)
    for (let j = 2; j < ENTRIES; j++) {
      addMixed(acc, acc, affBase, affBase + 32)
      memory.copy(tempJac + <usize>(j * 96), acc, 96)
    }
    batchNormalize(dest2, tempJac, ENTRIES)

    // ── avanza: base ← 2^8 · base ──
    if (i < STEPS - 1) {
      for (let d = 0; d < WINDOW; d++) {
        double(base1, base1)
        double(base2, base2)
      }
    }
  }

  initialized = true
  Arena.restore(ctx)
}

/**
 * multiplyG: res = k·G (Jacobiano, 96 B). k se lee de `k` (32 B).
 * Aliasing-safe (res puede ser == k).
 */
export function multiplyG(res: usize, k: usize): void {
  init()
  const ctx = Arena.save()
  const k1 = Arena.alloc(32)
  const k2 = Arena.alloc(32)
  const signs = Arena.alloc(2)
  const acc = Arena.alloc(96)
  const ty = Arena.alloc(32)
  const prime = Arena.alloc(32)

  decompose(k, k1, k2, signs)
  const neg1 = load<u8>(signs) != 0
  const neg2 = load<u8>(signs + 1) != 0

  store<u64>(prime, P0); store<u64>(prime, P1, 8)
  store<u64>(prime, P2, 16); store<u64>(prime, P3, 24)

  setInfinity(acc)
  let first = true

  for (let i = 0; i < STEPS; i++) {
    const u1 = extractWindow(k1, i * WINDOW)
    const u2 = extractWindow(k2, i * WINDOW)

    if (u1 > 0) {
      const p = T1 + <usize>((i * ENTRIES + u1) * 64)
      if (neg1) sub(ty, prime, p + 32) // ty = P − Y  (negación)
      else memory.copy(ty, p + 32, 32)
      if (first) {
        memory.copy(acc, p, 32)
        memory.copy(acc + 32, ty, 32)
        store<u64>(acc + 64, 1); store<u64>(acc + 72, 0)
        store<u64>(acc + 80, 0); store<u64>(acc + 88, 0)
        first = false
      } else {
        addMixed(acc, acc, p, ty)
      }
    }

    if (u2 > 0) {
      const p = T2 + <usize>((i * ENTRIES + u2) * 64)
      if (neg2) sub(ty, prime, p + 32)
      else memory.copy(ty, p + 32, 32)
      if (first) {
        memory.copy(acc, p, 32)
        memory.copy(acc + 32, ty, 32)
        store<u64>(acc + 64, 1); store<u64>(acc + 72, 0)
        store<u64>(acc + 80, 0); store<u64>(acc + 88, 0)
        first = false
      } else {
        addMixed(acc, acc, p, ty)
      }
    }
  }

  memory.copy(res, acc, 96)
  Arena.restore(ctx)
}