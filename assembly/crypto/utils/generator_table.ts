import { BigInt256 } from "./bigint256"
import { Point } from "./point"
import { GLV } from "./glv"

@final
export class GeneratorTable {
  /**
   * STABLE HIGH-PERFORMANCE FIXED-BASE
   * Window size w=10, steps d=13 (covers up to 130 bits per GLV scalar).
   * Total Table Memory: 13 steps * 1024 entries * 64 bytes * 2 tables = 1.66 MB.
   * Total Memory: ~5 MB. Extremely stable under 16MB.
   */
  static readonly WINDOW: i32 = 10
  static readonly STEPS: i32 = 13
  static readonly ENTRIES: i32 = 1024 // 1 << 10

  static readonly T1: usize = heap.alloc(GeneratorTable.STEPS * GeneratorTable.ENTRIES * 64)
  static readonly T2: usize = heap.alloc(GeneratorTable.STEPS * GeneratorTable.ENTRIES * 64)

  private static readonly TEMP_JAC: usize = heap.alloc(GeneratorTable.ENTRIES * 96)
  private static readonly PRODUCTS: usize = heap.alloc(GeneratorTable.ENTRIES * 32)
  private static readonly INV_ZS_BUF: usize = heap.alloc(GeneratorTable.ENTRIES * 32)

  private static isInitialized: bool = false

  static init(): void {
    if (GeneratorTable.isInitialized) return

    const base1 = heap.alloc(96)
    const base2 = heap.alloc(96)

    // G
    store<u64>(base1, Point.G_X0, 0)
    store<u64>(base1, Point.G_X1, 8)
    store<u64>(base1, Point.G_X2, 16)
    store<u64>(base1, Point.G_X3, 24)
    store<u64>(base1 + 32, Point.G_Y0, 0)
    store<u64>(base1 + 32, Point.G_Y1, 8)
    store<u64>(base1 + 32, Point.G_Y2, 16)
    store<u64>(base1 + 32, Point.G_Y3, 24)
    store<u64>(base1 + 64, 1, 0)
    store<u64>(base1 + 72, 0, 0)
    store<u64>(base1 + 80, 0, 0)
    store<u64>(base1 + 88, 0, 0)

    // phi(G)
    const beta = heap.alloc(32)
    store<u64>(beta, GLV.BETA0, 0)
    store<u64>(beta, GLV.BETA1, 8)
    store<u64>(beta, GLV.BETA2, 16)
    store<u64>(beta, GLV.BETA3, 24)
    BigInt256.mulMod(base2, base1, beta)
    memory.copy(base2 + 32, base1 + 32, 32)
    store<u64>(base2 + 64, 1, 0)
    store<u64>(base2 + 72, 0, 0)
    store<u64>(base2 + 80, 0, 0)
    store<u64>(base2 + 88, 0, 0)

    const acc = heap.alloc(96)
    const aff_step_base = heap.alloc(64)

    for (let i = 0; i < GeneratorTable.STEPS; i++) {
      const dest_off = i * GeneratorTable.ENTRIES * 64

      // Window T1
      memory.copy(acc, base1, 96)
      Point.toAffine(aff_step_base, base1)
      memory.copy(GeneratorTable.TEMP_JAC + 96, base1, 96)
      for (let j = 2; j < GeneratorTable.ENTRIES; j++) {
        Point.addMixed(acc, acc, aff_step_base, aff_step_base + 32)
        memory.copy(GeneratorTable.TEMP_JAC + <usize>j * 96, acc, 96)
      }
      GeneratorTable.batchNormalize(GeneratorTable.T1 + dest_off, GeneratorTable.TEMP_JAC, GeneratorTable.ENTRIES)

      // Window T2
      memory.copy(acc, base2, 96)
      Point.toAffine(aff_step_base, base2)
      memory.copy(GeneratorTable.TEMP_JAC + 96, base2, 96)
      for (let j = 2; j < GeneratorTable.ENTRIES; j++) {
        Point.addMixed(acc, acc, aff_step_base, aff_step_base + 32)
        memory.copy(GeneratorTable.TEMP_JAC + <usize>j * 96, acc, 96)
      }
      GeneratorTable.batchNormalize(GeneratorTable.T2 + dest_off, GeneratorTable.TEMP_JAC, GeneratorTable.ENTRIES)

      // Advance bases by 2^10
      if (i < GeneratorTable.STEPS - 1) {
        for (let k = 0; k < 10; k++) {
          Point.double(base1, base1)
          Point.double(base2, base2)
        }
      }
    }
    GeneratorTable.isInitialized = true
  }

  private static batchNormalize(table_dest: usize, jac_src: usize, n: i32): void {
    const products = GeneratorTable.PRODUCTS
    const inv_zs = GeneratorTable.INV_ZS_BUF
    const tmp = Point.t13 // Use higher register to avoid addMixed conflict

    memory.copy(products + 32, jac_src + 96 + 64, 32)
    for (let i = 2; i < n; i++) {
      BigInt256.mulMod(products + <usize>i * 32, products + <usize>(i - 1) * 32, jac_src + <usize>i * 96 + 64)
    }

    BigInt256.modInverse(tmp, products + <usize>(n - 1) * 32)

    for (let i = n - 1; i > 1; i--) {
      let zi = jac_src + <usize>i * 96 + 64
      BigInt256.mulMod(inv_zs + <usize>i * 32, tmp, products + <usize>(i - 1) * 32)
      BigInt256.mulMod(tmp, tmp, zi)
    }
    memory.copy(inv_zs + 32, tmp, 32)

    const zi2 = Point.t14
    const zi3 = Point.t15
    for (let i = 1; i < n; i++) {
      const iz = inv_zs + <usize>i * 32
      const src = jac_src + <usize>i * 96
      const dst = table_dest + <usize>i * 64

      BigInt256.sqrMod(zi2, iz)
      BigInt256.mulMod(zi3, zi2, iz)
      BigInt256.mulMod(dst, src, zi2)
      BigInt256.mulMod(dst + 32, src + 32, zi3)
    }
  }

  static multiply(res: usize, k: usize): void {
    const k1 = Point.t10
    const k2 = Point.t11
    const signs = Point.t12
    GLV.decompose(k, k1, k2, signs)

    const neg1 = load<u8>(signs) != 0
    const neg2 = load<u8>(signs + 1) != 0

    const acc = Point.t13
    for (let i = 0; i < 96; i += 8) store<u64>(acc + i, 0)

    const ty = Point.t14
    const prime = Point.t15
    store<u64>(prime, BigInt256.P0, 0)
    store<u64>(prime, BigInt256.P1, 8)
    store<u64>(prime, BigInt256.P2, 16)
    store<u64>(prime, BigInt256.P3, 24)

    for (let i = 0; i < GeneratorTable.STEPS; i++) {
      const u1 = GeneratorTable.extract10(k1, i * 10)
      const u2 = GeneratorTable.extract10(k2, i * 10)

      if (u1 > 0) {
        const p = GeneratorTable.T1 + <usize>(i * GeneratorTable.ENTRIES + u1) * 64
        if (neg1) BigInt256.sub(ty, prime, p + 32)
        else memory.copy(ty, p + 32, 32)
        Point.addMixed(acc, acc, p, ty)
      }

      if (u2 > 0) {
        const p = GeneratorTable.T2 + <usize>(i * GeneratorTable.ENTRIES + u2) * 64
        if (neg2) BigInt256.sub(ty, prime, p + 32)
        else memory.copy(ty, p + 32, 32)
        Point.addMixed(acc, acc, p, ty)
      }
    }

    memory.copy(res, acc, 96)
  }

  @inline
  private static extract10(ptr: usize, start: i32): i32 {
    const byte_off = <usize>(start >> 3)
    const bit_off = start & 7
    let v = load<u64>(ptr + byte_off) >>> bit_off
    return <i32>(v & 0x3ff)
  }
}

GeneratorTable.init()
