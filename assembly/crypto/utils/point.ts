/**
 * Point: Operaciones de Curva Elíptica secp256k1
 *
 * OPTIMIZACIÓN NIVEL WORLD-CLASS:
 * 1. Global Static Scratchpad: Elimina el 100% de los `alloc` en tiempo de ejecución.
 * 2. Arithmetic Fusing: Usa `BigInt256.mulMod` para todo (adiós temporales de 512 bits).
 * 3. Variable Reuse: Algoritmos diseñados para reutilizar solo 6-7 "registros" de memoria.
 * 4. Zero-Copy: Escribe directamente en el destino cuando es posible.
 */

import { BigInt256 } from "./bigint256"

// No importamos CryptoMemory porque ya no lo necesitamos para allocs dinámicos.

@final
export class Point {
  // ========================================================================
  // MEMORIA ESTÁTICA (SCRATCHPAD)
  // Pre-asignamos 1KB de memoria contigua para operaciones temporales.
  // Esto simula registros de CPU extendidos y evita tocar el Heap Manager.
  // ========================================================================
  static readonly SCRATCH_SIZE: usize = 2048
  static readonly SCRATCH: usize = heap.alloc(Point.SCRATCH_SIZE)

  // "Registros" de memoria estática (punteros constantes)
  // t0-t9: 32 bytes (Field elements)
  static readonly t0: usize = Point.SCRATCH + 0
  static readonly t1: usize = Point.SCRATCH + 32
  static readonly t2: usize = Point.SCRATCH + 64
  static readonly t3: usize = Point.SCRATCH + 96
  static readonly t4: usize = Point.SCRATCH + 128
  static readonly t5: usize = Point.SCRATCH + 160
  static readonly t6: usize = Point.SCRATCH + 192
  static readonly t7: usize = Point.SCRATCH + 224
  static readonly t8: usize = Point.SCRATCH + 256
  static readonly t9: usize = Point.SCRATCH + 288
  // t10-t19: 128 bytes (Points / Wide buffers)
  static readonly t10: usize = Point.SCRATCH + 320
  static readonly t11: usize = Point.SCRATCH + 448
  static readonly t12: usize = Point.SCRATCH + 576
  static readonly t13: usize = Point.SCRATCH + 704
  static readonly t14: usize = Point.SCRATCH + 832
  static readonly t15: usize = Point.SCRATCH + 960
  static readonly t16: usize = Point.SCRATCH + 1088
  static readonly t17: usize = Point.SCRATCH + 1216
  static readonly t18: usize = Point.SCRATCH + 1344
  static readonly t19: usize = Point.SCRATCH + 1472

  // Constantes del Generador G
  static readonly G_X0: u64 = 0x59f2815b16f81798
  static readonly G_X1: u64 = 0x029bfcdb2dce28d9
  static readonly G_X2: u64 = 0x55a06295ce870b07
  static readonly G_X3: u64 = 0x79be667ef9dcbbac

  static readonly G_Y0: u64 = 0x9c47d08ffb10d4b8
  static readonly G_Y1: u64 = 0xfd17b448a6855419
  static readonly G_Y2: u64 = 0x5da4fbfc0e1108a8
  static readonly G_Y3: u64 = 0x483ada7726a3c465

  static __INF_PTR: usize = 0
  /**
   * Crear punto en infinito
   */
  static infinity(): usize {
    if (Point.__INF_PTR == 0) {
      const p = heap.alloc(96) as usize
      // X=1, Y=1, Z=0
      store<u64>(p, 1, 0)
      store<u64>(p, 0, 8)
      store<u64>(p, 0, 16)
      store<u64>(p, 0, 24)
      store<u64>(p + 32, 1, 0)
      store<u64>(p + 32, 0, 8)
      store<u64>(p + 32, 0, 16)
      store<u64>(p + 32, 0, 24)
      store<u64>(p + 64, 0, 0)
      store<u64>(p + 64, 0, 8)
      store<u64>(p + 64, 0, 16)
      store<u64>(p + 64, 0, 24)
      Point.__INF_PTR = p
    }
    return Point.__INF_PTR
  }

  static __G_PTR: usize = 0
  /**
   * Crear generador G
   */
  static generator(): usize {
    if (Point.__G_PTR == 0) {
      const p = heap.alloc(96) as usize
      store<u64>(p, Point.G_X0, 0)
      store<u64>(p, Point.G_X1, 8)
      store<u64>(p, Point.G_X2, 16)
      store<u64>(p, Point.G_X3, 24)
      store<u64>(p + 32, Point.G_Y0, 0)
      store<u64>(p + 32, Point.G_Y1, 8)
      store<u64>(p + 32, Point.G_Y2, 16)
      store<u64>(p + 32, Point.G_Y3, 24)
      // Z=1
      store<u64>(p + 64, 1, 0)
      store<u64>(p + 64, 0, 8)
      store<u64>(p + 64, 0, 16)
      store<u64>(p + 64, 0, 24)
      Point.__G_PTR = p
    }
    return Point.__G_PTR
  }

  @inline
  static isInfinity(p: usize): bool {
    // Check Z == 0
    return load<u64>(p, 64) == 0 && load<u64>(p, 72) == 0 && load<u64>(p, 80) == 0 && load<u64>(p, 88) == 0
  }

  /**
   * Point Doubling Optimizado: res = 2*P
   *
   * Fórmula optimizada para a=0 (secp256k1):
   * 1. S = 4*X*Y^2
   * 2. M = 3*X^2
   * 3. X' = M^2 - 2*S
   * 4. Y' = M*(S - X') - 8*Y^4
   * 5. Z' = 2*Y*Z
   *
   * Usa memoria estática (Zero Alloc)
   */
  static double(res: usize, p: usize): void {
    if (Point.isInfinity(p)) {
      memory.copy(res, p, 96)
      return
    }

    const x = p
    const y = p + 32
    const z = p + 64

    // Registros temporales estáticos
    const t0 = Point.t0 // Y^2
    const t1 = Point.t1 // S
    const t2 = Point.t2 // M
    const t3 = Point.t3 // Temp

    // 1. t0 = Y^2
    BigInt256.sqrMod(t0, y)

    // 2. S = 4 * X * Y^2 = 4 * X * t0
    // Primero t1 = X * t0
    BigInt256.mulMod(t1, x, t0)
    // t1 = 2*t1
    BigInt256.add(t1, t1, t1) // AddMod is just Add/Sub logic in BigInt256.add
    // t1 = 4*t1 (S)
    BigInt256.add(t1, t1, t1)

    // 3. M = 3 * X^2
    // t2 = X^2
    BigInt256.sqrMod(t2, x)
    // t3 = 2*t2
    BigInt256.add(t3, t2, t2)
    // t2 = 3*t2 (M)
    BigInt256.add(t2, t2, t3)

    // Calculamos Z' temprano para liberar Z original si res == p
    // Z' = 2*Y*Z
    // Usamos res+64 directamente si es seguro, o un temp. Usamos temp t3 para seguridad.
    BigInt256.mulMod(t3, y, z)
    BigInt256.add(t3, t3, t3)
    // Guardar Z' en t4 para usar t3 después
    const z_prime = Point.t4
    memory.copy(z_prime, t3, 32)

    // 4. X' = M^2 - 2*S
    // t3 = M^2
    BigInt256.sqrMod(t3, t2)
    // X' (output) = t3 - 2*S
    // Calculate 2*S in scratch t5
    const s2 = Point.t5
    BigInt256.add(s2, t1, t1)

    // Escribimos X' directamente a res (offset 0)
    BigInt256.sub(res, t3, s2)

    // 5. Y' = M*(S - X') - 8*Y^4
    // t0 es Y^2. t5 = Y^4
    BigInt256.sqrMod(s2, t0) // Reusamos s2 como Y^4 temporal
    // 8*Y^4
    BigInt256.add(s2, s2, s2) // 2
    BigInt256.add(s2, s2, s2) // 4
    BigInt256.add(s2, s2, s2) // 8

    // S - X' (t1 - res)
    // Necesitamos cargar X' de res o tenerlo en temp. Está en res.
    BigInt256.sub(t0, t1, res) // t0 = S - X'

    // t0 = M * (S - X')
    BigInt256.mulMod(t0, t2, t0)

    // Y' = t0 - 8Y^4
    BigInt256.sub(res + 32, t0, s2)

    // Escribir Z'
    memory.copy(res + 64, z_prime, 32)
  }

  /**
   * Point Addition Optimizado: res = P + Q
   * Zero Alloc.
   */
  static add(res: usize, p: usize, q: usize): void {
    if (Point.isInfinity(p)) {
      memory.copy(res, q, 96)
      return
    }
    if (Point.isInfinity(q)) {
      memory.copy(res, p, 96)
      return
    }

    const x1 = p
    const y1 = p + 32
    const z1 = p + 64
    const x2 = q
    const y2 = q + 32
    const z2 = q + 64

    // Registros
    const z1z1 = Point.t0
    const z2z2 = Point.t1
    const u1 = Point.t2
    const u2 = Point.t3
    const s1 = Point.t4
    const s2 = Point.t5
    const h = Point.t6
    const r = Point.t7

    // U1 = X1*Z2^2
    BigInt256.sqrMod(z2z2, z2)
    BigInt256.mulMod(u1, x1, z2z2)

    // U2 = X2*Z1^2
    BigInt256.sqrMod(z1z1, z1)
    BigInt256.mulMod(u2, x2, z1z1)

    // S1 = Y1*Z2^3
    BigInt256.mulMod(s1, z2z2, z2) // s1 = Z2^3
    BigInt256.mulMod(s1, s1, y1)

    // S2 = Y2*Z1^3
    BigInt256.mulMod(s2, z1z1, z1) // s2 = Z1^3
    BigInt256.mulMod(s2, s2, y2)

    // Check equality
    if (Point.eq(u1, u2)) {
      if (Point.eq(s1, s2)) {
        Point.double(res, p)
        return
      } else {
        memory.copy(res, Point.infinity(), 96)
        return
      }
    }

    // H = U2 - U1
    BigInt256.sub(h, u2, u1)
    // R = S2 - S1
    BigInt256.sub(r, s2, s1)

    // Z3 = Z1*Z2*H
    // Calculamos esto primero y guardamos en t8 para liberar z1, z2
    const z3 = Point.t8
    BigInt256.mulMod(z3, z1, z2)
    BigInt256.mulMod(z3, z3, h)

    // H^2 = t0 (reusado)
    const h2 = Point.t0
    BigInt256.sqrMod(h2, h)

    // H^3 = t1 (reusado)
    const h3 = Point.t1
    BigInt256.mulMod(h3, h, h2)

    // U1*H^2 = t2 (reusado)
    const u1h2 = Point.t2
    BigInt256.mulMod(u1h2, u1, h2)

    // X3 = R^2 - H^3 - 2*U1*H^2
    // R^2 en t3
    const r2 = Point.t3
    BigInt256.sqrMod(r2, r)

    BigInt256.sub(res, r2, h3) // X3 = R^2 - H^3
    // t4 = 2*U1*H^2
    // FIX: Use t9 instead of t4, because t4 (s1) is needed later.
    const temp = Point.t9
    BigInt256.add(temp, u1h2, u1h2)
    BigInt256.sub(res, res, temp) // X3 final

    // Y3 = R*(U1*H^2 - X3) - S1*H^3
    // temp = U1*H^2 - X3
    BigInt256.sub(temp, u1h2, res)
    BigInt256.mulMod(temp, temp, r) // R * (...)

    // S1*H^3 en t5
    const s1h3 = Point.t5
    BigInt256.mulMod(s1h3, s1, h3)

    BigInt256.sub(res + 32, temp, s1h3)

    // Escribir Z3
    memory.copy(res + 64, z3, 32)
  }

  /**
   * Mixed Addition: res = P + Q (Q es Affine, Z=1)
   * Ahorra multiplicaciones porque Z2 = 1.
   */
  /**
   * Mixed Addition: res = P + Q (Q es Affine, Z=1)
   * Fórmula optimizada para secp256k1 (a=0):
   * 7 mul, 3 sqr, 9 add/sub
   */
  static addMixed(res: usize, p: usize, q_x: usize, q_y: usize): void {
    if (Point.isInfinity(p)) {
      memory.copy(res, q_x, 32)
      memory.copy(res + 32, q_y, 32)
      store<u64>(res + 64, 1, 0)
      store<u64>(res + 72, 0, 0)
      store<u64>(res + 80, 0, 0)
      store<u64>(res + 88, 0, 0)
      return
    }

    const x1 = p,
      y1 = p + 32,
      z1 = p + 64
    const x2 = q_x,
      y2 = q_y

    const z1z1 = Point.t0
    BigInt256.sqrMod(z1z1, z1) // Z1^2

    const u2 = Point.t1
    BigInt256.mulMod(u2, x2, z1z1) // U2 = X2*Z1^2

    const s2 = Point.t2
    const z1z1z1 = Point.t3
    BigInt256.mulMod(z1z1z1, z1z1, z1)
    BigInt256.mulMod(s2, y2, z1z1z1) // S2 = Y2*Z1^3

    if (Point.eq(x1, u2)) {
      if (Point.eq(y1, s2)) {
        Point.double(res, p)
        return
      } else {
        for (let i = 0; i < 96; i += 8) store<u64>(res + i, 0)
        return
      }
    }

    const h = Point.t1 // reuse u2
    BigInt256.sub(h, u2, x1) // H = U2 - X1

    const r = Point.t2 // reuse s2
    BigInt256.sub(r, s2, y1) // R = S2 - Y1

    const h2 = Point.t4
    BigInt256.sqrMod(h2, h) // H^2

    const h3 = Point.t5
    BigInt256.mulMod(h3, h, h2) // H^3

    const v = Point.t6
    BigInt256.mulMod(v, x1, h2) // V = X1*H^2

    // X3 = R^2 - H^3 - 2*V
    const r2 = Point.t7
    BigInt256.sqrMod(r2, r)
    BigInt256.sub(res, r2, h3)
    BigInt256.add(Point.t8, v, v)
    BigInt256.sub(res, res, Point.t8)

    // Y3 = R*(V - X3) - Y1*H^3
    BigInt256.sub(v, v, res)
    BigInt256.mulMod(v, v, r)
    BigInt256.mulMod(Point.t8, y1, h3)
    BigInt256.sub(res + 32, v, Point.t8)

    // Z3 = Z1 * H
    BigInt256.mulMod(res + 64, z1, h)
  }

  static negate(res: usize, p: usize): void {
    // res.X = p.X
    memory.copy(res, p, 32)
    // res.Y = P - p.Y
    const prime = Point.t0 // reuse scratch as prime storage temporarily? Or just load.
    // Better just call subP logic. P - Y is basically subP(0, Y) which wraps or standard logic.
    // Safer: BigInt256.P - Y.
    // We need to construct P in a temp var to use sub.
    store<u64>(Point.t0, BigInt256.P0, 0)
    store<u64>(Point.t0, BigInt256.P1, 8)
    store<u64>(Point.t0, BigInt256.P2, 16)
    store<u64>(Point.t0, BigInt256.P3, 24)
    BigInt256.sub(res + 32, Point.t0, p + 32)
    // res.Z = p.Z
    memory.copy(res + 64, p + 64, 32)
  }

  // ========== Helpers ==========

  /**
   * Multiplicación modular en el campo
   */
  @inline
  static mulMod(res: usize, a: usize, b: usize): void {
    BigInt256.mulMod(res, a, b)
  }

  /**
   * Suma modular en el campo
   */
  @inline
  static addMod(res: usize, a: usize, b: usize): void {
    BigInt256.add(res, a, b)
  }

  /**
   * Resta modular en el campo
   */
  @inline
  static subMod(res: usize, a: usize, b: usize): void {
    BigInt256.sub(res, a, b)
  }

  /**
   * Doblar módulo P: res = 2*a mod P
   */
  @inline
  static doubleMod(res: usize, a: usize): void {
    BigInt256.add(res, a, a)
  }

  /**
   * Comparar dos puntos en coordenadas Jacobianas
   * (X1, Y1, Z1) == (X2, Y2, Z2) Check:
   * X1 * Z2^2 == X2 * Z1^2
   * Y1 * Z2^3 == Y2 * Z1^3
   */
  static eqJacobian(a: usize, b: usize): bool {
    const x1 = a
    const y1 = a + 32
    const z1 = a + 64
    const x2 = b
    const y2 = b + 32
    const z2 = b + 64

    // Registros estáticos
    const z1_2 = Point.t0
    const z2_2 = Point.t1
    const term1 = Point.t2
    const term2 = Point.t3

    // Z1^2, Z2^2
    BigInt256.sqrMod(z1_2, z1)
    BigInt256.sqrMod(z2_2, z2)

    // Check X: X1*Z2^2 == X2*Z1^2
    BigInt256.mulMod(term1, x1, z2_2)
    BigInt256.mulMod(term2, x2, z1_2)

    if (!Point.eq(term1, term2)) {
      return false
    }

    // Z1^3, Z2^3
    const z1_3 = Point.t4
    const z2_3 = Point.t5
    BigInt256.mulMod(z1_3, z1_2, z1)
    BigInt256.mulMod(z2_3, z2_2, z2)

    // Check Y: Y1*Z2^3 == Y2*Z1^3
    BigInt256.mulMod(term1, y1, z2_3) // Reuse term1
    BigInt256.mulMod(term2, y2, z1_3) // Reuse term2

    return Point.eq(term1, term2)
  }

  /**
   * Convert Jacobian Point to Affine Coordinates (x, y) stored at 'res'
   */
  static toAffine(res: usize, p: usize): void {
    if (Point.isInfinity(p)) {
      for (let i = 0; i < 64; i += 8) store<u64>(res + i, 0)
      return
    }
    const z = p + 64
    const zi = Point.t10
    BigInt256.modInverse(zi, z)
    const zi2 = Point.t11
    BigInt256.sqrMod(zi2, zi)
    const zi3 = Point.t12
    BigInt256.mulMod(zi3, zi2, zi)
    BigInt256.mulMod(res, p, zi2)
    BigInt256.mulMod(res + 32, p + 32, zi3)
  }

  // Comparación rápida usando registros
  static eq(a: usize, b: usize): bool {
    return (
      load<u64>(a, 0) == load<u64>(b, 0) &&
      load<u64>(a, 8) == load<u64>(b, 8) &&
      load<u64>(a, 16) == load<u64>(b, 16) &&
      load<u64>(a, 24) == load<u64>(b, 24)
    )
  }
}
