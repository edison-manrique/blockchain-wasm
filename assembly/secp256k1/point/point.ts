/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  point/point.ts — Aritmética de curva secp256k1 (coordenadas Jacobianas)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Zero-alloc: todos los temporales se reservan en la arena Memory con
 * save/restore (RAII). NO hay registros globales compartidos → es imposible
 * la colisión de registros que plagaba al Point legacy.
 *
 * Layout Jacobiano (96 B): [ X (32) | Y (32) | Z (32) ]   Z==0 ⇒ infinito
 * Layout Afín      (64 B): [ X (32) | Y (32) ]
 *
 * Todas las funciones son aliasing-safe: `res` puede ser == a cualquier
 * entrada (los parciales van a la arena y se copian al destino al final).
 */
import { GY_0, GY_1, GY_2, GY_3, GX_0, GX_1, GX_2, GX_3, P0, P1, P2, P3 } from "../constants"
import { Memory } from "../../utils/memory"
import { mulMod, sqrMod, add, sub, modInverse } from "../field"

// ── Constantes de curva en data segment (cero alloc) ──────────────────────
// memory.data reserva 96 bytes ZEROED en compile-time y devuelve su offset.
// Los inicializamos una única vez en el start del módulo (código top-level),
// que es cuando AssemblyScript ejecuta las sentencias fuera de función.
const _INF: usize = memory.data(96)
const _GEN: usize = memory.data(96)

// ── Inicialización top-level (corre 1 vez al instanciar el módulo) ────────
// _INF = infinito canónico (X=1, Y=1, Z=0). Z ya queda 0 por el zero-init.
store<u64>(_INF, 1, 0)
store<u64>(_INF, 1, 32)

// _GEN = G en Jacobiano (X, Y, Z=1)
store<u64>(_GEN, GX_0, 0)
store<u64>(_GEN, GX_1, 8)
store<u64>(_GEN, GX_2, 16)
store<u64>(_GEN, GX_3, 24)
store<u64>(_GEN, GY_0, 32)
store<u64>(_GEN, GY_1, 40)
store<u64>(_GEN, GY_2, 48)
store<u64>(_GEN, GY_3, 56)
store<u64>(_GEN, 1, 64)
/** Punto en el infinito (constante, no modificar). */
// @ts-ignore
@inline
export function infinity(): usize {
  return _INF
}

/** Generador G en Jacobiano (constante, no modificar). */
// @ts-ignore
@inline
export function generator(): usize {
  return _GEN
}

/** Escribe G (Jacobiano, Z=1) en `res` (96 B). */
export function setGenerator(res: usize): void {
  memory.copy(res, _GEN, 96)
}

/** ¿Es p el punto en el infinito? (Z == 0) */
// @ts-ignore
@inline
export function isInfinity(p: usize): bool {
  return (
    load<u64>(p, 64) == 0 &&
    load<u64>(p, 72) == 0 &&
    load<u64>(p, 80) == 0 &&
    load<u64>(p, 88) == 0
  )
}

/** Escribe el infinito canónico (X=1, Y=1, Z=0) en `res` (96 B). */
// @ts-ignore
@inline
export function setInfinity(res: usize): void {
  store<u64>(res, 1)
  store<u64>(res, 0, 8)
  store<u64>(res, 0, 16)
  store<u64>(res, 0, 24)
  store<u64>(res, 1, 32)
  store<u64>(res, 0, 40)
  store<u64>(res, 0, 48)
  store<u64>(res, 0, 56)
  store<u64>(res, 0, 64)
  store<u64>(res, 0, 72)
  store<u64>(res, 0, 80)
  store<u64>(res, 0, 88)
}

/** Comparación de dos elementos de campo (4 limbs). */
// @ts-ignore
@inline
function eqField(a: usize, b: usize): bool {
  return (
    load<u64>(a) == load<u64>(b) &&
    load<u64>(a, 8) == load<u64>(b, 8) &&
    load<u64>(a, 16) == load<u64>(b, 16) &&
    load<u64>(a, 24) == load<u64>(b, 24)
  )
}

/**
 * Doubling: res = 2·P  (fórmula dbl-2009-l para a=0: 2M + 5S + 6add).
 *
 *   A = X²;  B = Y²;  C = B²
 *   D = 2·((X+B)² − A − C)
 *   E = 3·A;  F = E²
 *   X' = F − 2·D;  Y' = E·(D − X') − 8·C;  Z' = (Y+Z)² − B − C
 */
export function double(res: usize, p: usize): void {
  if (isInfinity(p)) {
    setInfinity(res)
    return
  }

  const ctx = Memory.save()
  const A = Memory.alloc(32)
  const B = Memory.alloc(32)
  const C = Memory.alloc(32)
  const D = Memory.alloc(32)
  const E = Memory.alloc(32)
  const F = Memory.alloc(32)
  const t = Memory.alloc(32)
  const X3 = Memory.alloc(32)
  const Y3 = Memory.alloc(32)
  const Z3 = Memory.alloc(32)

  const x = p
  const y = p + 32
  const z = p + 64

  sqrMod(A, x)            // A = X²
  sqrMod(B, y)            // B = Y²
  sqrMod(C, B)            // C = B² = Y⁴

  add(t, x, B)            // t = X + B
  sqrMod(t, t)            // t = (X+B)²
  sub(t, t, A)            // t − A
  sub(t, t, C)            // t − C
  add(D, t, t)            // D = 2·((X+B)² − A − C)

  add(E, A, A)            // E = 2A
  add(E, E, A)            // E = 3A
  sqrMod(F, E)            // F = E²

  add(t, D, D)            // t = 2D
  sub(X3, F, t)           // X' = F − 2D

  sub(t, D, X3)           // t = D − X'
  mulMod(t, E, t)         // t = E·(D − X')
  add(C, C, C)            // 2C
  add(C, C, C)            // 4C
  add(C, C, C)            // 8C
  sub(Y3, t, C)           // Y' = E·(D − X') − 8C

  add(t, y, z)            // t = Y + Z
  sqrMod(t, t)            // t = (Y+Z)²
  sub(t, t, B)            // − B
  // Z' = 2·Y·Z  (fórmula simple y correcta para a=0; reemplaza la fórmula
  // original (Y+Z)² − B − C que queda invalidada cuando C se reutiliza para 8C)
  mulMod(Z3, y, z)
  add(Z3, Z3, Z3)

  memory.copy(res, X3, 32)
  memory.copy(res + 32, Y3, 32)
  memory.copy(res + 64, Z3, 32)

  Memory.restore(ctx)
}

/**
 * Addition: res = P + Q  (fórmula add-2007-bl: 11M + 5S + 9add).
 * Maneja infinito, doubling (P==Q) y P==−Q (resultado infinito).
 */
export function addPoint(res: usize, p: usize, q: usize): void {
  if (isInfinity(p)) {
    memory.copy(res, q, 96)
    return
  }
  if (isInfinity(q)) {
    memory.copy(res, p, 96)
    return
  }

  const ctx = Memory.save()
  const z1z1 = Memory.alloc(32)
  const z2z2 = Memory.alloc(32)
  const u1 = Memory.alloc(32)
  const u2 = Memory.alloc(32)
  const s1 = Memory.alloc(32)
  const s2 = Memory.alloc(32)
  const h = Memory.alloc(32)
  const r = Memory.alloc(32)
  const h2 = Memory.alloc(32)
  const h3 = Memory.alloc(32)
  const v = Memory.alloc(32)
  const t = Memory.alloc(32)
  const X3 = Memory.alloc(32)
  const Y3 = Memory.alloc(32)
  const Z3 = Memory.alloc(32)

  const x1 = p
  const y1 = p + 32
  const z1 = p + 64
  const x2 = q
  const y2 = q + 32
  const z2 = q + 64

  sqrMod(z1z1, z1)        // Z1²
  sqrMod(z2z2, z2)        // Z2²
  mulMod(u1, x1, z2z2)    // U1 = X1·Z2²
  mulMod(u2, x2, z1z1)    // U2 = X2·Z1²
  mulMod(s1, z2z2, z2)    // Z2³
  mulMod(s1, s1, y1)      // S1 = Y1·Z2³
  mulMod(s2, z1z1, z1)    // Z1³
  mulMod(s2, s2, y2)      // S2 = Y2·Z1³

  if (eqField(u1, u2)) {
    if (eqField(s1, s2)) {
      Memory.restore(ctx)
      double(res, p)      // P == Q
      return
    }
    Memory.restore(ctx)
    setInfinity(res)      // P == −Q
    return
  }

  sub(h, u2, u1)          // H = U2 − U1
  sub(r, s2, s1)          // R = S2 − S1
  sqrMod(h2, h)           // H²
  mulMod(h3, h, h2)       // H³
  mulMod(v, u1, h2)       // V = U1·H²

  sqrMod(t, r)            // R²
  sub(t, t, h3)           // − H³
  add(X3, v, v)           // 2V
  sub(X3, t, X3)          // X' = R² − H³ − 2V

  sub(t, v, X3)           // V − X'
  mulMod(t, r, t)         // R·(V − X')
  mulMod(Y3, s1, h3)      // S1·H³
  sub(Y3, t, Y3)          // Y' = R·(V − X') − S1·H³

  mulMod(Z3, z1, z2)      // Z1·Z2
  mulMod(Z3, Z3, h)       // Z' = Z1·Z2·H

  memory.copy(res, X3, 32)
  memory.copy(res + 32, Y3, 32)
  memory.copy(res + 64, Z3, 32)

  Memory.restore(ctx)
}

/**
 * Mixed addition: res = P + Q, con Q afín (Z=1). q_x, q_y son punteros de 32 B.
 * Más barata que `add` (ahorra las multiplicaciones por Z2). 7M + 4S + 9add.
 */
export function addMixed(res: usize, p: usize, q_x: usize, q_y: usize): void {
  if (isInfinity(p)) {
    memory.copy(res, q_x, 32)
    memory.copy(res + 32, q_y, 32)
    store<u64>(res + 64, 1)
    store<u64>(res + 72, 0)
    store<u64>(res + 80, 0)
    store<u64>(res + 88, 0)
    return
  }

  const ctx = Memory.save()
  const z1z1 = Memory.alloc(32)
  const u2 = Memory.alloc(32)
  const z1z1z1 = Memory.alloc(32)
  const s2 = Memory.alloc(32)
  const h = Memory.alloc(32)
  const r = Memory.alloc(32)
  const h2 = Memory.alloc(32)
  const h3 = Memory.alloc(32)
  const v = Memory.alloc(32)
  const t = Memory.alloc(32)
  const X3 = Memory.alloc(32)
  const Y3 = Memory.alloc(32)
  const Z3 = Memory.alloc(32)

  const x1 = p
  const y1 = p + 32
  const z1 = p + 64

  sqrMod(z1z1, z1)         // Z1²
  mulMod(u2, q_x, z1z1)    // U2 = X2·Z1²
  mulMod(z1z1z1, z1z1, z1) // Z1³
  mulMod(s2, q_y, z1z1z1)  // S2 = Y2·Z1³

  if (eqField(x1, u2)) {
    if (eqField(y1, s2)) {
      Memory.restore(ctx)
      double(res, p)
      return
    }
    Memory.restore(ctx)
    setInfinity(res)
    return
  }

  sub(h, u2, x1)           // H = U2 − X1
  sub(r, s2, y1)           // R = S2 − Y1
  sqrMod(h2, h)            // H²
  mulMod(h3, h, h2)        // H³
  mulMod(v, x1, h2)        // V = X1·H²

  sqrMod(t, r)             // R²
  sub(t, t, h3)            // − H³
  add(X3, v, v)            // 2V
  sub(X3, t, X3)           // X' = R² − H³ − 2V

  sub(t, v, X3)            // V − X'
  mulMod(t, r, t)          // R·(V − X')
  mulMod(Y3, y1, h3)       // Y1·H³
  sub(Y3, t, Y3)           // Y' = R·(V − X') − Y1·H³

  mulMod(Z3, z1, h)        // Z' = Z1·H

  memory.copy(res, X3, 32)
  memory.copy(res + 32, Y3, 32)
  memory.copy(res + 64, Z3, 32)

  Memory.restore(ctx)
}

/** Negación: res = −P = (X, P−Y, Z). Aliasing-safe. */
export function negate(res: usize, p: usize): void {
  const ctx = Memory.save()
  const prime = Memory.alloc(32)
  const Y3 = Memory.alloc(32)
  store<u64>(prime, P0)
  store<u64>(prime, P1, 8)
  store<u64>(prime, P2, 16)
  store<u64>(prime, P3, 24)
  sub(Y3, prime, p + 32)   // Y' = P − Y
  memory.copy(res, p, 32)
  memory.copy(res + 32, Y3, 32)
  memory.copy(res + 64, p + 64, 32)
  Memory.restore(ctx)
}

/**
 * Conversión Jacobiano → Afín: res (64 B) = (X/Z², Y/Z³).
 * El infinito se mapea a (0, 0).
 */
export function toAffine(res: usize, p: usize): void {
  if (isInfinity(p)) {
    // 8 stores con offset literal (el offset de store DEBE ser compile-time).
    store<u64>(res, 0, 0)
    store<u64>(res, 0, 8)
    store<u64>(res, 0, 16)
    store<u64>(res, 0, 24)
    store<u64>(res, 0, 32)
    store<u64>(res, 0, 40)
    store<u64>(res, 0, 48)
    store<u64>(res, 0, 56)
    return
  }
  const ctx = Memory.save()
  const zi = Memory.alloc(32)
  const zi2 = Memory.alloc(32)
  const zi3 = Memory.alloc(32)
  const X = Memory.alloc(32)
  const Y = Memory.alloc(32)

  modInverse(zi, p + 64)   // zi = Z⁻¹
  sqrMod(zi2, zi)          // zi² = Z⁻²
  mulMod(zi3, zi2, zi)     // zi³ = Z⁻³
  mulMod(X, p, zi2)        // X/Z²
  mulMod(Y, p + 32, zi3)   // Y/Z³

  memory.copy(res, X, 32)
  memory.copy(res + 32, Y, 32)
  Memory.restore(ctx)
}

/**
 * Igualdad de puntos Jacobianos (sin normalizar):
 *   X1·Z2² == X2·Z1²  ∧  Y1·Z2³ == Y2·Z1³
 */
export function eqJacobian(a: usize, b: usize): bool {
  const ctx = Memory.save()
  const z1_2 = Memory.alloc(32)
  const z2_2 = Memory.alloc(32)
  const z1_3 = Memory.alloc(32)
  const z2_3 = Memory.alloc(32)
  const t1 = Memory.alloc(32)
  const t2 = Memory.alloc(32)

  sqrMod(z1_2, a + 64)
  sqrMod(z2_2, b + 64)
  mulMod(t1, a, z2_2)      // X1·Z2²
  mulMod(t2, b, z1_2)      // X2·Z1²
  if (!eqField(t1, t2)) {
    Memory.restore(ctx)
    return false
  }
  mulMod(z1_3, z1_2, a + 64)
  mulMod(z2_3, z2_2, b + 64)
  mulMod(t1, a + 32, z2_3) // Y1·Z2³
  mulMod(t2, b + 32, z1_3) // Y2·Z1³
  const ok = eqField(t1, t2)
  Memory.restore(ctx)
  return ok
}