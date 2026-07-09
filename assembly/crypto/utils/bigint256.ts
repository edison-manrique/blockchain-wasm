/**
 * BigInt256 Ultra-Optimizado para WASM
 *
 * Inspirado en la implementación de Zig, con las siguientes optimizaciones:
 * 1. Uso de 4×u64 limbs (en lugar de 8×u32)
 * 2. Aritmética nativa de 64-bit de WASM
 * 3. Loops desenrollados manualmente
 * 4. Comba multiplication para reducir dependencias
 * 5. Reducción modular especializada para secp256k1
 * 6. Operaciones in-place sin allocaciones
 * 7. Constant-time operations para seguridad
 *
 * Estructura de memoria (256 bits = 32 bytes):
 * [limb0: u64][limb1: u64][limb2: u64][limb3: u64]
 *
 * P = 2^256 - 2^32 - 977 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 * C = 2^32 + 977 = 0x1000003D1 (constante de reducción)
 */

import { Memory } from "../../utils/Memory"

@final
export class BigInt256 {
  // Constante P (secp256k1 prime) en 4×u64 limbs
  static readonly P0: u64 = 0xfffffffefffffc2f
  static readonly P1: u64 = 0xffffffffffffffff
  static readonly P2: u64 = 0xffffffffffffffff
  static readonly P3: u64 = 0xffffffffffffffff

  // Constante de reducción C = 2^32 + 977
  static readonly C: u64 = 0x1000003d1

  /**
   * Suma modular: res = (a + b) mod P
   * OPTIMIZADO: Zero-Alloc, Branchless, Register-based.
   */
  @inline
  static add(res: usize, a: usize, b: usize): void {
    // 1. Cargar A y B en registros
    let a0 = load<u64>(a, 0)
    let a1 = load<u64>(a, 8)
    let a2 = load<u64>(a, 16)
    let a3 = load<u64>(a, 24)
    let b0 = load<u64>(b, 0)
    let b1 = load<u64>(b, 8)
    let b2 = load<u64>(b, 16)
    let b3 = load<u64>(b, 24)

    // 2. Calcular SUMA = a + b
    let s0 = a0 + b0
    let c = u64(s0 < a0)
    let s1 = a1 + b1 + c
    c = u64(s1 < a1) | (u64(s1 == a1) & c) // Carry robusto
    let s2 = a2 + b2 + c
    c = u64(s2 < a2) | (u64(s2 == a2) & c)
    let s3 = a3 + b3 + c
    c = u64(s3 < a3) | (u64(s3 == a3) & c)

    // c ahora es 1 si hubo overflow de 256 bits

    // 3. Detectar si SUMA >= P
    // Condición: (carry == 1) OR (s3 > P3) OR (s3==P3 && s2 > P2) ...
    // P = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    // Atajo lógico: Solo necesitamos reducir si hay carry global O el número es >= P
    // Para simplificar y hacerlo branchless: calculamos (SUMA - P).
    // Si (SUMA - P) no genera borrow (underflow), entonces SUMA >= P.

    // Calcular DIFF = SUMA - P
    // P constant hardcoded for speed
    let d0 = s0 - BigInt256.P0
    let bor = u64(d0 > s0)
    let d1 = s1 - BigInt256.P1 - bor
    bor = u64(d1 > s1) | (u64(d1 == s1) & bor) // Borrow robusto
    let d2 = s2 - BigInt256.P2 - bor
    bor = u64(d2 > s2) | (u64(d2 == s2) & bor)
    let d3 = s3 - BigInt256.P3 - bor
    bor = u64(d3 > s3) | (u64(d3 == s3) & bor)

    // Lógica de Selección (Constant Time):
    // Si hubo carry original (c=1), el resultado es DIFF (SUMA - P).
    // Si NO hubo carry pero SUMA >= P (bor=0), el resultado es DIFF.
    // Si NO hubo carry y SUMA < P (bor=1), el resultado es SUMA.

    // mask debe ser 111...111 si queremos DIFF, 000...000 si queremos SUMA.
    // Queremos DIFF si: (c == 1) OR (bor == 0)

    // Nota: bor es 1 si (SUMA < P). bor es 0 si (SUMA >= P).
    // Si c=1, significa > 2^256, por tanto > P. Definitivamente restar P.

    let use_diff = c | (1 - bor) // 1 si carry O no-borrow.

    // Expandir mask a 64 bits (0 o FFFFFFFFFFFFFFFF)
    let mask = 0 - use_diff

    // 4. Selección y Escritura
    store<u64>(res, BigInt256.select_u64(s0, d0, mask), 0)
    store<u64>(res, BigInt256.select_u64(s1, d1, mask), 8)
    store<u64>(res, BigInt256.select_u64(s2, d2, mask), 16)
    store<u64>(res, BigInt256.select_u64(s3, d3, mask), 24)
  }

  /**
   * Resta modular: res = (a - b) mod P
   * OPTIMIZADO: Zero-Alloc, Branchless.
   */
  @inline
  static sub(res: usize, a: usize, b: usize): void {
    let a0 = load<u64>(a, 0)
    let a1 = load<u64>(a, 8)
    let a2 = load<u64>(a, 16)
    let a3 = load<u64>(a, 24)
    let b0 = load<u64>(b, 0)
    let b1 = load<u64>(b, 8)
    let b2 = load<u64>(b, 16)
    let b3 = load<u64>(b, 24)

    // 1. DIFF = a - b
    let d0 = a0 - b0
    let bor = u64(d0 > a0)
    let d1 = a1 - b1 - bor
    bor = u64(d1 > a1) | (u64(d1 == a1) & bor)
    let d2 = a2 - b2 - bor
    bor = u64(d2 > a2) | (u64(d2 == a2) & bor)
    let d3 = a3 - b3 - bor
    bor = u64(d3 > a3) | (u64(d3 == a3) & bor)

    // Si bor = 1, el resultado es negativo. Necesitamos sumar P.
    // ADD_P = DIFF + P

    let p0 = d0 + BigInt256.P0
    let c = u64(p0 < d0)
    let p1 = d1 + BigInt256.P1 + c
    c = u64(p1 < d1) | (u64(p1 == d1) & c)
    let p2 = d2 + BigInt256.P2 + c
    c = u64(p2 < d2) | (u64(p2 == d2) & c)
    let p3 = d3 + BigInt256.P3 + c

    // Selección: Si hubo borrow inicial, usamos ADD_P, si no, usamos DIFF.
    let mask = 0 - bor

    store<u64>(res, BigInt256.select_u64(d0, p0, mask), 0)
    store<u64>(res, BigInt256.select_u64(d1, p1, mask), 8)
    store<u64>(res, BigInt256.select_u64(d2, p2, mask), 16)
    store<u64>(res, BigInt256.select_u64(d3, p3, mask), 24)
  }

  // Helpers auxiliares que puedes mantener o inlinar si prefieres:
  @inline
  static subP(res: usize, a: usize): void {
    // Implementación branchless rápida: a - P. Se asume a >= P.
    // Si no estás seguro, usa sub() normal.
    // Por consistencia con "Zero Alloc", reimplementamos in-place:
    let a0 = load<u64>(a, 0)
    let a1 = load<u64>(a, 8)
    let a2 = load<u64>(a, 16)
    let a3 = load<u64>(a, 24)
    let r0 = a0 - BigInt256.P0
    let b = u64(r0 > a0)
    let r1 = a1 - BigInt256.P1 - b
    b = u64(r1 > a1) | (u64(r1 == a1) & b)
    let r2 = a2 - BigInt256.P2 - b
    b = u64(r2 > a2) | (u64(r2 == a2) & b)
    let r3 = a3 - BigInt256.P3 - b

    store<u64>(res, r0, 0)
    store<u64>(res, r1, 8)
    store<u64>(res, r2, 16)
    store<u64>(res, r3, 24)
  }

  /**
   * Check if a >= P
   */
  @inline
  static isGreaterOrEqualP(a: usize): bool {
    const a3 = load<u64>(a, 24)
    if (a3 > BigInt256.P3) return true
    if (a3 < BigInt256.P3) return false

    const a2 = load<u64>(a, 16)
    if (a2 > BigInt256.P2) return true
    if (a2 < BigInt256.P2) return false

    const a1 = load<u64>(a, 8)
    if (a1 > BigInt256.P1) return true
    if (a1 < BigInt256.P1) return false

    return load<u64>(a, 0) >= BigInt256.P0
  }

  /**
   * Multiplicación completa: 256×256 → 512 bits
   * res debe tener 64 bytes (8×u64)
   *
   * Implementa Comba multiplication:
   * - Acumula diagonales completas
   * - Minimiza dependencias de datos
   * - Usa acumulador de 128 bits (emulado con u64 high/low)
   */
  @inline
  static mul(res: usize, a: usize, b: usize): void {
    // 1. Cargar todo a registros locales (Locals en WASM)
    const a0 = load<u64>(a, 0)
    const a1 = load<u64>(a, 8)
    const a2 = load<u64>(a, 16)
    const a3 = load<u64>(a, 24)

    const b0 = load<u64>(b, 0)
    const b1 = load<u64>(b, 8)
    const b2 = load<u64>(b, 16)
    const b3 = load<u64>(b, 24)

    // Acumuladores de estado (192 bits: low, mid, high)
    let acc0: u64 = 0
    let acc1: u64 = 0
    let acc2: u64 = 0

    let carry: u64

    // Variables temporales para el inlining de mul64x64
    let x: u64, y: u64
    let x_lo: u64, x_hi: u64
    let y_lo: u64, y_hi: u64
    let p0: u64, p1: u64, p2: u64, p3: u64
    let mid: u64, c1: u64, c2: u64
    let prod_lo: u64, prod_hi: u64

    // ===================================
    // Col 0 (a0*b0)
    // ===================================
    {
      x = a0
      y = b0
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32

      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi

      mid = p1 + p2
      c1 = u64(mid < p1)

      acc0 = p0 + (mid << 32)
      c2 = u64(acc0 < p0)

      acc1 = p3 + (mid >> 32) + (c1 << 32) + c2
    }

    store<u64>(res, acc0, 0)
    acc0 = acc1
    acc1 = 0

    // ===================================
    // Col 1 (a0*b1 + a1*b0)
    // ===================================
    // a0*b1
    {
      x = a0
      y = b1
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    // a1*b0
    {
      x = a1
      y = b0
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }

    store<u64>(res, acc0, 8)
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // ===================================
    // Col 2 (a0*b2 + a1*b1 + a2*b0)
    // ===================================
    // a0*b2
    {
      x = a0
      y = b2
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    // a1*b1
    {
      x = a1
      y = b1
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    // a2*b0
    {
      x = a2
      y = b0
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }

    store<u64>(res, acc0, 16)
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // ===================================
    // Col 3 (a0*b3 + a1*b2 + a2*b1 + a3*b0)
    // ===================================
    // a0*b3
    {
      x = a0
      y = b3
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    // a1*b2
    {
      x = a1
      y = b2
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    // a2*b1
    {
      x = a2
      y = b1
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    // a3*b0
    {
      x = a3
      y = b0
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }

    store<u64>(res, acc0, 24)
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // ===================================
    // Col 4 (a1*b3 + a2*b2 + a3*b1)
    // ===================================
    // a1*b3
    {
      x = a1
      y = b3
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    // a2*b2
    {
      x = a2
      y = b2
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    // a3*b1
    {
      x = a3
      y = b1
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }

    store<u64>(res, acc0, 32)
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // ===================================
    // Col 5 (a2*b3 + a3*b2)
    // ===================================
    // a2*b3
    {
      x = a2
      y = b3
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    // a3*b2
    {
      x = a3
      y = b2
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }

    store<u64>(res, acc0, 40)
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // ===================================
    // Col 6 (a3*b3)
    // ===================================
    // a3*b3
    {
      x = a3
      y = b3
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
    }

    store<u64>(res, acc0, 48)
    store<u64>(res, acc1, 56)
  }

  /**
   * Fused Multiply-Reduce: res = (a * b) mod P
   *
   * LA ARMA SECRETA:
   * Combina la multiplicación y la reducción en un solo pipeline de registros.
   * Elimina la escritura/lectura de los 64 bytes intermedios (512 bits).
   * Reduce la latencia de memoria a casi cero.
   */
  @inline
  static mulMod(res: usize, a: usize, b: usize): void {
    // ==============================================================
    // ETAPA 1: Multiplicación (Comba) -> Registros r0..r7
    // ==============================================================

    const a0 = load<u64>(a, 0)
    const a1 = load<u64>(a, 8)
    const a2 = load<u64>(a, 16)
    const a3 = load<u64>(a, 24)
    const b0 = load<u64>(b, 0)
    const b1 = load<u64>(b, 8)
    const b2 = load<u64>(b, 16)
    const b3 = load<u64>(b, 24)

    // Salidas de 512 bits mantenidas en registros
    let r0: u64, r1: u64, r2: u64, r3: u64
    let r4: u64, r5: u64, r6: u64, r7: u64

    let acc0: u64 = 0,
      acc1: u64 = 0,
      acc2: u64 = 0
    let carry: u64
    let x: u64, y: u64, x_lo: u64, x_hi: u64, y_lo: u64, y_hi: u64
    let p0: u64, p1: u64, p2: u64, p3: u64, mid: u64, c1: u64, c2: u64
    let prod_lo: u64, prod_hi: u64

    // --- Col 0 ---
    {
      x = a0
      y = b0
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      acc0 = p0 + (mid << 32)
      c2 = u64(acc0 < p0)
      acc1 = p3 + (mid >> 32) + (c1 << 32) + c2
    }
    r0 = acc0
    acc0 = acc1
    acc1 = 0 // r0 listo

    // --- Col 1 ---
    {
      x = a0
      y = b1
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    {
      x = a1
      y = b0
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    r1 = acc0
    acc0 = acc1
    acc1 = acc2
    acc2 = 0 // r1 listo

    // --- Col 2 ---
    {
      x = a0
      y = b2
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    {
      x = a1
      y = b1
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    {
      x = a2
      y = b0
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    r2 = acc0
    acc0 = acc1
    acc1 = acc2
    acc2 = 0 // r2 listo

    // --- Col 3 ---
    {
      x = a0
      y = b3
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    {
      x = a1
      y = b2
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    {
      x = a2
      y = b1
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    {
      x = a3
      y = b0
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    r3 = acc0
    acc0 = acc1
    acc1 = acc2
    acc2 = 0 // r3 listo

    // --- Col 4 ---
    {
      x = a1
      y = b3
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    {
      x = a2
      y = b2
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    {
      x = a3
      y = b1
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    r4 = acc0
    acc0 = acc1
    acc1 = acc2
    acc2 = 0 // r4 listo (h0)

    // --- Col 5 ---
    {
      x = a2
      y = b3
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    {
      x = a3
      y = b2
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    r5 = acc0
    acc0 = acc1
    acc1 = acc2
    acc2 = 0 // r5 listo (h1)

    // --- Col 6 ---
    {
      x = a3
      y = b3
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
    }
    r6 = acc0 // r6 listo (h2)
    r7 = acc1 // r7 listo (h3)

    // ==============================================================
    // ETAPA 2: Reducción (r0..r7) -> In-Place
    // r0..r3 son Low, r4..r7 son High (h0..h3)
    // ==============================================================

    // Acumulador de overflow global
    let ov: u64 = 0

    // PROCESAR h0 (r4)
    {
      const h0 = r4
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

    // PROCESAR h1 (r5)
    {
      const h1 = r5
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

    // PROCESAR h2 (r6)
    {
      const h2 = r6
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

    // PROCESAR h3 (r7)
    {
      const h3 = r7
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

    // Reducir Overflow Final (ov)
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
      let c2 = u64(r1 < s_hi + c)
      r2 += c2
      let c3 = u64(r2 < c2)
      r3 += c3
    }

    // ==============================================================
    // ETAPA 3: Normalización y Escritura Final
    // ==============================================================

    // Normalización condicional final (Branchless-ish)
    // r0..r3 contiene el resultado. Comprobamos si >= P.
    // Usamos el mismo truco que en add/sub pero simplificado para reducir size.
    // Aquí podemos usar if porque la probabilidad de necesitar corrección es muy baja
    // y para el branch predictor es casi siempre "not taken".

    // Check >= P
    let gt = false
    if (r3 > BigInt256.P3) gt = true
    else if (r3 == BigInt256.P3) {
      if (r2 > BigInt256.P2) gt = true
      else if (r2 == BigInt256.P2) {
        if (r1 > BigInt256.P1) gt = true
        else if (r1 == BigInt256.P1) {
          if (r0 >= BigInt256.P0) gt = true
        }
      }
    }

    if (gt) {
      // r = r - P
      let d0 = r0 - BigInt256.P0
      let b = u64(d0 > r0)
      r0 = d0
      let d1 = r1 - BigInt256.P1 - b
      b = u64(d1 > r1) | (u64(d1 == r1) & b)
      r1 = d1
      let d2 = r2 - BigInt256.P2 - b
      b = u64(d2 > r2) | (u64(d2 == r2) & b)
      r2 = d2
      let d3 = r3 - BigInt256.P3 - b
      r3 = d3
    }

    store<u64>(res, r0, 0)
    store<u64>(res, r1, 8)
    store<u64>(res, r2, 16)
    store<u64>(res, r3, 24)
  }

  /**
   * Squaring optimizado: res = a²
   *
   * Optimizaciones:
   * 1. Reduce ops de mul de 16 a 10 (aprovecha simetría).
   * 2. Inlining total de aritmética (sin llamadas a helpers).
   */
  @inline
  static sqr(res: usize, a: usize): void {
    // 1. Cargar limbs
    const a0 = load<u64>(a, 0)
    const a1 = load<u64>(a, 8)
    const a2 = load<u64>(a, 16)
    const a3 = load<u64>(a, 24)

    let acc0: u64 = 0
    let acc1: u64 = 0
    let acc2: u64 = 0

    let prod_lo: u64
    let prod_hi: u64
    let carry: u64

    // Columna 0: a0^2
    {
      const lo = u64(u32(a0))
      const hi = a0 >> 32
      const p0 = lo * lo
      const p1 = lo * hi
      const p3 = hi * hi
      const mid_sq = p1 + p1
      const c_mid = u64(mid_sq < p1)
      const lo_res = p0 + (mid_sq << 32)
      const c_lo = u64(lo_res < p0)
      const hi_res = p3 + (mid_sq >> 32) + (c_mid << 32) + c_lo

      acc0 = lo_res
      acc1 = hi_res
    }

    store<u64>(res, acc0, 0)
    acc0 = acc1
    acc1 = 0

    // Columna 1: 2 * a0 * a1
    {
      const x = a0
      const y = a1
      const x_lo = u64(u32(x))
      const x_hi = x >> 32
      const y_lo = u64(u32(y))
      const y_hi = y >> 32
      const p0 = x_lo * y_lo
      const p1 = x_lo * y_hi
      const p2 = x_hi * y_lo
      const p3 = x_hi * y_hi
      const mid = p1 + p2
      const c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      const c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }

    store<u64>(res, acc0, 8)
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // Columna 2: 2 * a0 * a2 + a1^2
    {
      // 2 * a0 * a2
      const x = a0
      const y = a2
      const x_lo = u64(u32(x))
      const x_hi = x >> 32
      const y_lo = u64(u32(y))
      const y_hi = y >> 32
      const p0 = x_lo * y_lo
      const p1 = x_lo * y_hi
      const p2 = x_hi * y_lo
      const p3 = x_hi * y_hi
      const mid = p1 + p2
      const c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      const c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)

      // a1^2
      const d_lo = u64(u32(a1))
      const d_hi = a1 >> 32
      const dp0 = d_lo * d_lo
      const dp1 = d_lo * d_hi
      const mid_sq = dp1 + dp1
      const c_mid = u64(mid_sq < dp1)
      prod_lo = dp0 + (mid_sq << 32)
      const c_lo = u64(prod_lo < dp0)
      prod_hi = d_hi * d_hi + (mid_sq >> 32) + (c_mid << 32) + c_lo

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }

    store<u64>(res, acc0, 16)
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // Columna 3: 2 * (a0*a3 + a1*a2)
    {
      // 2 * a0 * a3
      let x = a0
      let y = a3
      let x_lo = u64(u32(x))
      let x_hi = x >> 32
      let y_lo = u64(u32(y))
      let y_hi = y >> 32
      let p0 = x_lo * y_lo
      let p1 = x_lo * y_hi
      let p2 = x_hi * y_lo
      let p3 = x_hi * y_hi
      let mid = p1 + p2
      let c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      let c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)

      // 2 * a1 * a2
      x = a1
      y = a2
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }

    store<u64>(res, acc0, 24)
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // Columna 4: 2 * a1 * a3 + a2^2
    {
      // 2 * a1 * a3
      const x = a1
      const y = a3
      const x_lo = u64(u32(x))
      const x_hi = x >> 32
      const y_lo = u64(u32(y))
      const y_hi = y >> 32
      const p0 = x_lo * y_lo
      const p1 = x_lo * y_hi
      const p2 = x_hi * y_lo
      const p3 = x_hi * y_hi
      const mid = p1 + p2
      const c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      const c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)

      // a2^2
      const d_lo = u64(u32(a2))
      const d_hi = a2 >> 32
      const dp0 = d_lo * d_lo
      const dp1 = d_lo * d_hi
      const mid_sq = dp1 + dp1
      const c_mid = u64(mid_sq < dp1)
      prod_lo = dp0 + (mid_sq << 32)
      const c_lo = u64(prod_lo < dp0)
      prod_hi = d_hi * d_hi + (mid_sq >> 32) + (c_mid << 32) + c_lo

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }

    store<u64>(res, acc0, 32)
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // Columna 5: 2 * a2 * a3
    {
      const x = a2
      const y = a3
      const x_lo = u64(u32(x))
      const x_hi = x >> 32
      const y_lo = u64(u32(y))
      const y_hi = y >> 32
      const p0 = x_lo * y_lo
      const p1 = x_lo * y_hi
      const p2 = x_hi * y_lo
      const p3 = x_hi * y_hi
      const mid = p1 + p2
      const c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      const c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }

    store<u64>(res, acc0, 40)
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // Columna 6: a3^2
    {
      const d_lo = u64(u32(a3))
      const d_hi = a3 >> 32
      const dp0 = d_lo * d_lo
      const dp1 = d_lo * d_hi
      const mid_sq = dp1 + dp1
      const c_mid = u64(mid_sq < dp1)
      prod_lo = dp0 + (mid_sq << 32)
      const c_lo = u64(prod_lo < dp0)
      prod_hi = d_hi * d_hi + (mid_sq >> 32) + (c_mid << 32) + c_lo

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
    }

    store<u64>(res, acc0, 48)
    store<u64>(res, acc1, 56)
  }

  // [INSERTED OPTIMIZATION]: Fused Modular Squaring
  // Calculates (a^2) mod P without 512-bit writes and utilizing symmetry
  @inline
  static sqrMod(res: usize, a: usize): void {
    const a0 = load<u64>(a, 0)
    const a1 = load<u64>(a, 8)
    const a2 = load<u64>(a, 16)
    const a3 = load<u64>(a, 24)

    // Output registers (512-bit product)
    let r0: u64, r1: u64, r2: u64, r3: u64
    let r4: u64, r5: u64, r6: u64, r7: u64

    let acc0: u64 = 0
    let acc1: u64 = 0
    let acc2: u64 = 0
    let carry: u64

    // Helpers for squaring
    let prod_lo: u64, prod_hi: u64

    // --- Col 0 (a0^2) ---
    {
      const lo = u64(u32(a0))
      const hi = a0 >> 32
      const p0 = lo * lo
      const p1 = lo * hi
      const p3 = hi * hi
      const mid = p1 + p1
      const c_mid = u64(mid < p1)
      const res_lo = p0 + (mid << 32)
      const c_lo = u64(res_lo < p0)
      const res_hi = p3 + (mid >> 32) + (c_mid << 32) + c_lo

      acc0 = res_lo
      acc1 = res_hi
    }
    r0 = acc0
    acc0 = acc1
    acc1 = 0

    // --- Col 1 (2*a0*a1) ---
    {
      const x = a0
      const y = a1
      const x_lo = u64(u32(x))
      const x_hi = x >> 32
      const y_lo = u64(u32(y))
      const y_hi = y >> 32
      const p0 = x_lo * y_lo
      const p1 = x_lo * y_hi
      const p2 = x_hi * y_lo
      const p3 = x_hi * y_hi
      const mid = p1 + p2
      const c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      const c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      // Double it
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    r1 = acc0
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // --- Col 2 (2*a0*a2 + a1^2) ---
    {
      // 2*a0*a2
      let x = a0
      let y = a2
      let x_lo = u64(u32(x))
      let x_hi = x >> 32
      let y_lo = u64(u32(y))
      let y_hi = y >> 32
      let p0 = x_lo * y_lo
      let p1 = x_lo * y_hi
      let p2 = x_hi * y_lo
      let p3 = x_hi * y_hi
      let mid = p1 + p2
      let c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      let c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)

      // a1^2
      const lo = u64(u32(a1))
      const hi = a1 >> 32
      const sq0 = lo * lo
      const sq1 = lo * hi
      const sq3 = hi * hi
      const mid_sq = sq1 + sq1
      const c_mid_sq = u64(mid_sq < sq1)
      prod_lo = sq0 + (mid_sq << 32)
      const c_lo_sq = u64(prod_lo < sq0)
      prod_hi = sq3 + (mid_sq >> 32) + (c_mid_sq << 32) + c_lo_sq

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    r2 = acc0
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // --- Col 3 (2*(a0*a3 + a1*a2)) ---
    {
      // 2*a0*a3
      let x = a0
      let y = a3
      let x_lo = u64(u32(x))
      let x_hi = x >> 32
      let y_lo = u64(u32(y))
      let y_hi = y >> 32
      let p0 = x_lo * y_lo
      let p1 = x_lo * y_hi
      let p2 = x_hi * y_lo
      let p3 = x_hi * y_hi
      let mid = p1 + p2
      let c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      let c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)

      // 2*a1*a2
      x = a1
      y = a2
      x_lo = u64(u32(x))
      x_hi = x >> 32
      y_lo = u64(u32(y))
      y_hi = y >> 32
      p0 = x_lo * y_lo
      p1 = x_lo * y_hi
      p2 = x_hi * y_lo
      p3 = x_hi * y_hi
      mid = p1 + p2
      c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    r3 = acc0
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // --- Col 4 (2*a1*a3 + a2^2) ---
    {
      // 2*a1*a3
      let x = a1
      let y = a3
      let x_lo = u64(u32(x))
      let x_hi = x >> 32
      let y_lo = u64(u32(y))
      let y_hi = y >> 32
      let p0 = x_lo * y_lo
      let p1 = x_lo * y_hi
      let p2 = x_hi * y_lo
      let p3 = x_hi * y_hi
      let mid = p1 + p2
      let c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      let c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)

      // a2^2
      const lo = u64(u32(a2))
      const hi = a2 >> 32
      const sq0 = lo * lo
      const sq1 = lo * hi
      const sq3 = hi * hi
      const mid_sq = sq1 + sq1
      const c_mid_sq = u64(mid_sq < sq1)
      prod_lo = sq0 + (mid_sq << 32)
      const c_lo_sq = u64(prod_lo < sq0)
      prod_hi = sq3 + (mid_sq >> 32) + (c_mid_sq << 32) + c_lo_sq

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    r4 = acc0
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // --- Col 5 (2*a2*a3) ---
    {
      let x = a2
      let y = a3
      let x_lo = u64(u32(x))
      let x_hi = x >> 32
      let y_lo = u64(u32(y))
      let y_hi = y >> 32
      let p0 = x_lo * y_lo
      let p1 = x_lo * y_hi
      let p2 = x_hi * y_lo
      let p3 = x_hi * y_hi
      let mid = p1 + p2
      let c1 = u64(mid < p1)
      prod_lo = p0 + (mid << 32)
      let c2 = u64(prod_lo < p0)
      prod_hi = p3 + (mid >> 32) + (c1 << 32) + c2

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
      acc2 += u64(acc1 < prod_hi + carry)
    }
    r5 = acc0
    acc0 = acc1
    acc1 = acc2
    acc2 = 0

    // --- Col 6 (a3^2) ---
    {
      const lo = u64(u32(a3))
      const hi = a3 >> 32
      const sq0 = lo * lo
      const sq1 = lo * hi
      const sq3 = hi * hi
      const mid_sq = sq1 + sq1
      const c_mid_sq = u64(mid_sq < sq1)
      prod_lo = sq0 + (mid_sq << 32)
      const c_lo_sq = u64(prod_lo < sq0)
      prod_hi = sq3 + (mid_sq >> 32) + (c_mid_sq << 32) + c_lo_sq

      acc0 += prod_lo
      carry = u64(acc0 < prod_lo)
      acc1 += prod_hi + carry
    }
    r6 = acc0
    r7 = acc1

    // ==============================================================
    // ETAPA 2: Reducción (Reutilizada de mulMod)
    // ==============================================================
    // Acumulador de overflow global
    let ov: u64 = 0

    // PROCESAR h0 (r4)
    {
      const h0 = r4
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

    // PROCESAR h1 (r5)
    {
      const h1 = r5
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

    // PROCESAR h2 (r6)
    {
      const h2 = r6
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

    // PROCESAR h3 (r7)
    {
      const h3 = r7
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

    // Reducir Overflow Final (ov)
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
      let c2 = u64(r1 < s_hi + c)
      r2 += c2
      let c3 = u64(r2 < c2)
      r3 += c3
    }

    // Normalización
    let gt = false
    if (r3 > BigInt256.P3) gt = true
    else if (r3 == BigInt256.P3) {
      if (r2 > BigInt256.P2) gt = true
      else if (r2 == BigInt256.P2) {
        if (r1 > BigInt256.P1) gt = true
        else if (r1 == BigInt256.P1) {
          if (r0 >= BigInt256.P0) gt = true
        }
      }
    }

    if (gt) {
      let d0 = r0 - BigInt256.P0
      let b = u64(d0 > r0)
      r0 = d0
      let d1 = r1 - BigInt256.P1 - b
      b = u64(d1 > r1) | (u64(d1 == r1) & b)
      r1 = d1
      let d2 = r2 - BigInt256.P2 - b
      b = u64(d2 > r2) | (u64(d2 == r2) & b)
      r2 = d2
      let d3 = r3 - BigInt256.P3 - b
      r3 = d3
    }

    store<u64>(res, r0, 0)
    store<u64>(res, r1, 8)
    store<u64>(res, r2, 16)
    store<u64>(res, r3, 24)
  }

  /**
   * Reducción modular para secp256k1
   *
   * Input: 512-bit número en `a` (8×u64 = 64 bytes)
   * Output: 256-bit número en `res` (4×u64 = 32 bytes)
   *
   * Fórmula: P = 2^256 - C donde C = 2^32 + 977 = 0x1000003D1
   *
   * Si x = L + H·2^256, entonces:
   * x mod P ≡ L + H·C (mod P)
   */
  @inline
  static reduce(res: usize, a: usize): void {
    // Carga de la entrada de 512 bits
    let r0 = load<u64>(a, 0)
    let r1 = load<u64>(a, 8)
    let r2 = load<u64>(a, 16)
    let r3 = load<u64>(a, 24)
    const h0 = load<u64>(a, 32)
    const h1 = load<u64>(a, 40)
    const h2 = load<u64>(a, 48)
    const h3 = load<u64>(a, 56)

    let ov: u64 = 0

    // Reducción: cada h[i] contribuye con h[i] * (2^32 + 977)
    // h0 contribuye a r0, r1
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

    // h1 contribuye a r1, r2
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

    // h2 contribuye a r2, r3
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

    // h3 contribuye a r3 y desbordamiento global (ov)
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

    // Reducir el overflow acumulado: ov * (2^32 + 977)
    {
      const p_lo = ov * 977
      const s_lo = ov << 32
      const s_hi = ov >> 32
      // p_hi de ov*977 es 0 porque ov es muy pequeño (< 2^32)

      let sum = r0 + p_lo
      let c = u64(sum < r0)
      sum += s_lo
      c += u64(sum < s_lo)
      r0 = sum

      r1 += s_hi + c
      let c2 = u64(r1 < s_hi + c)
      r2 += c2
      let c3 = u64(r2 < c2)
      r3 += c3
    }

    store<u64>(res, r0, 0)
    store<u64>(res, r1, 8)
    store<u64>(res, r2, 16)
    store<u64>(res, r3, 24)

    if (BigInt256.isGreaterOrEqualP(res)) {
      BigInt256.subP(res, res)
    }
  }

  /**
   * Compara si a >= b
   */
  @inline
  static isGreaterOrEqual(a: usize, b: usize): bool {
    const a3 = load<u64>(a, 24)
    const b3 = load<u64>(b, 24)
    if (a3 > b3) return true
    if (a3 < b3) return false

    const a2 = load<u64>(a, 16)
    const b2 = load<u64>(b, 16)
    if (a2 > b2) return true
    if (a2 < b2) return false

    const a1 = load<u64>(a, 8)
    const b1 = load<u64>(b, 8)
    if (a1 > b1) return true
    if (a1 < b1) return false

    return load<u64>(a, 0) >= load<u64>(b, 0)
  }

  /**
   * Check if value is zero
   */
  @inline
  static isZero(a: usize): bool {
    return load<u64>(a, 0) == 0 && load<u64>(a, 8) == 0 && load<u64>(a, 16) == 0 && load<u64>(a, 24) == 0
  }

  /**
   * Load BigInt256 from Big-Endian bytes (32 bytes)
   */
  static fromBytes(res: usize, bytes: Uint8Array): void {
    if (bytes.length != 32) {
      // Handle error or assume padded? For simplicity, assume 32.
      // Or unchecked?
      return
    }
    let ptr = bytes.dataStart
    store<u64>(res + 24, bswap(load<u64>(ptr)))
    store<u64>(res + 16, bswap(load<u64>(ptr + 8)))
    store<u64>(res + 8, bswap(load<u64>(ptr + 16)))
    store<u64>(res + 0, bswap(load<u64>(ptr + 24)))
  }

  /**
   * Store BigInt256 to Big-Endian bytes (32 bytes)
   */
  static toBytes(a: usize, out: Uint8Array): void {
    if (out.length != 32) return
    let ptr = out.dataStart
    store<u64>(ptr, bswap(load<u64>(a + 24)))
    store<u64>(ptr + 8, bswap(load<u64>(a + 16)))
    store<u64>(ptr + 16, bswap(load<u64>(a + 8)))
    store<u64>(ptr + 24, bswap(load<u64>(a + 0)))
  }

  /**
   * BEEA Constant-Space modular inverse
   */
  static modInverse(res: usize, a: usize): void {
    if (BigInt256.isZero(a)) {
      store<u64>(res, 0, 0)
      store<u64>(res, 0, 8)
      store<u64>(res, 0, 16)
      store<u64>(res, 0, 24)
      return
    }

    const ctx = Memory.save()
    const u = Memory.alloc(32)
    const v = Memory.alloc(32)
    const x1 = Memory.alloc(32)
    const x2 = Memory.alloc(32)

    memory.copy(u, a, 32)
    store<u64>(v, BigInt256.P0, 0)
    store<u64>(v, BigInt256.P1, 8)
    store<u64>(v, BigInt256.P2, 16)
    store<u64>(v, BigInt256.P3, 24)

    store<u64>(x1, 1, 0)
    store<u64>(x1, 0, 8)
    store<u64>(x1, 0, 16)
    store<u64>(x1, 0, 24)

    store<u64>(x2, 0, 0)
    store<u64>(x2, 0, 8)
    store<u64>(x2, 0, 16)
    store<u64>(x2, 0, 24)

    while (!BigInt256.isZero(u)) {
      while ((load<u64>(u, 0) & 1) == 0) {
        BigInt256.shr1_raw(u)
        if ((load<u64>(x1, 0) & 1) == 0) {
          BigInt256.shr1_raw(x1)
        } else {
          BigInt256.addP_and_shr1(x1)
        }
      }
      while ((load<u64>(v, 0) & 1) == 0) {
        BigInt256.shr1_raw(v)
        if ((load<u64>(x2, 0) & 1) == 0) {
          BigInt256.shr1_raw(x2)
        } else {
          BigInt256.addP_and_shr1(x2)
        }
      }

      if (BigInt256.cmp_raw(u, v) >= 0) {
        BigInt256.sub_raw256(u, u, v)
        BigInt256.sub(x1, x1, x2)
      } else {
        BigInt256.sub_raw256(v, v, u)
        BigInt256.sub(x2, x2, x1)
      }
    }

    memory.copy(res, x2, 32)
    Memory.restore(ctx)
  }

  @inline
  static shr1_raw(a: usize): void {
    let a3 = load<u64>(a, 24),
      a2 = load<u64>(a, 16)
    let a1 = load<u64>(a, 8),
      a0 = load<u64>(a, 0)
    store<u64>(a, (a0 >>> 1) | (a1 << 63), 0)
    store<u64>(a, (a1 >>> 1) | (a2 << 63), 8)
    store<u64>(a, (a2 >>> 1) | (a3 << 63), 16)
    store<u64>(a, a3 >>> 1, 24)
  }

  @inline
  static addP_and_shr1(a: usize): void {
    let a0 = load<u64>(a, 0),
      a1 = load<u64>(a, 8)
    let a2 = load<u64>(a, 16),
      a3 = load<u64>(a, 24)
    let s0 = a0 + BigInt256.P0
    let c = u64(s0 < a0)
    let s1 = a1 + BigInt256.P1 + c
    c = u64(s1 < a1) | (u64(s1 == a1) & c)
    let s2 = a2 + BigInt256.P2 + c
    c = u64(s2 < a2) | (u64(s2 == a2) & c)
    let s3 = a3 + BigInt256.P3 + c
    c = u64(s3 < a3) | (u64(s3 == a3) & c)
    store<u64>(a, (s0 >>> 1) | (s1 << 63), 0)
    store<u64>(a, (s1 >>> 1) | (s2 << 63), 8)
    store<u64>(a, (s2 >>> 1) | (s3 << 63), 16)
    store<u64>(a, (s3 >>> 1) | (c << 63), 24)
  }

  @inline
  static cmp_raw(a: usize, b: usize): i32 {
    let a3 = load<u64>(a, 24),
      b3 = load<u64>(b, 24)
    if (a3 > b3) return 1
    if (a3 < b3) return -1
    let a2 = load<u64>(a, 16),
      b2 = load<u64>(b, 16)
    if (a2 > b2) return 1
    if (a2 < b2) return -1
    let a1 = load<u64>(a, 8),
      b1 = load<u64>(b, 8)
    if (a1 > b1) return 1
    if (a1 < b1) return -1
    let a0 = load<u64>(a, 0),
      b0 = load<u64>(b, 0)
    if (a0 > b0) return 1
    if (a0 < b0) return -1
    return 0
  }

  @inline
  static sub_raw256(res: usize, a: usize, b: usize): void {
    let a0 = load<u64>(a, 0),
      b0 = load<u64>(b, 0)
    let r0 = a0 - b0
    let bor = u64(r0 > a0)
    let a1 = load<u64>(a, 8),
      b1 = load<u64>(b, 8)
    let r1 = a1 - b1 - bor
    bor = u64(r1 > a1) | (u64(r1 == a1) & bor)
    let a2 = load<u64>(a, 16),
      b2 = load<u64>(b, 16)
    let r2 = a2 - b2 - bor
    bor = u64(r2 > a2) | (u64(r2 == a2) & bor)
    let a3 = load<u64>(a, 24),
      b3 = load<u64>(b, 24)
    let r3 = a3 - b3 - bor
    store<u64>(res, r0, 0)
    store<u64>(res, r1, 8)
    store<u64>(res, r2, 16)
    store<u64>(res, r3, 24)
  }

  /**
   * Constant-time select
   * Retorna a si mask == 0, b si mask == 0xFFFFFFFFFFFFFFFF
   */
  @inline
  static select_u64(a: u64, b: u64, mask: u64): u64 {
    return (a & ~mask) | (b & mask)
  }
}
