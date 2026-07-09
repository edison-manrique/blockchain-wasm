import { BigInt256 } from "./bigint256"
import { Scalar256 } from "./scalar256"
import { Point } from "./point"
import { WNAF } from "./wnaf"

@final
export class GLV {
  // GLV Constants
  static readonly BETA0: u64 = 0xc1396c28719501ee
  static readonly BETA1: u64 = 0x9cf0497512f58995
  static readonly BETA2: u64 = 0x6e64479eac3434e9
  static readonly BETA3: u64 = 0x7ae96a2b657c0710

  static readonly A1_0: u64 = 0xe86c90e49284eb15
  static readonly A1_1: u64 = 0x3086d221a7d46bcd
  static readonly B1_0: u64 = 0x6f547fa90abfe4c3
  static readonly B1_1: u64 = 0xe4437ed6010e8828
  static readonly A2_0: u64 = 0x57c1108d9d44cfd8
  static readonly A2_1: u64 = 0x14ca50f7a8e2f3f6
  static readonly A2_2: u64 = 0x0000000000000001

  // Cache for G (8 entries per table for window 5)
  static readonly TABLE_ENTRIES: i32 = 8
  static readonly TABLE_SIZE: i32 = GLV.TABLE_ENTRIES * 64 // 512 bytes
  static readonly G_TABLE_1: usize = heap.alloc(GLV.TABLE_SIZE)
  static readonly G_TABLE_2: usize = heap.alloc(GLV.TABLE_SIZE)
  static is_G_Initialized: bool = false

  // Scratchpad
  static readonly SCRATCH_SIZE: usize = 4096
  static readonly SCRATCH: usize = heap.alloc(GLV.SCRATCH_SIZE)

  /**
   * GLV Multiplication: res = k * P
   */
  static mul(res: usize, p: usize, k: usize): void {
    const scr = GLV.SCRATCH

    // 1. Identification and Initialization of G
    const isG = load<u64>(p, 0) == Point.G_X0 && load<u64>(p, 32) == Point.G_Y0
    if (isG && !GLV.is_G_Initialized) {
      GLV.initG(p)
    }

    // 2. Decomposition of K into k1, k2
    const k1 = scr + 0
    const k2 = scr + 32
    const signs = scr + 64
    GLV.decompose(k, k1, k2, signs)

    const neg1 = load<u8>(signs) != 0
    const neg2 = load<u8>(signs + 1) != 0

    // 3. wNAF computation (Window size 5)
    const wnaf1 = scr + 128
    const wnaf2 = scr + 300
    const len1 = WNAF.compute(wnaf1, k1, 5)
    const len2 = WNAF.compute(wnaf2, k2, 5)

    // 4. Tables setup
    let table1: usize
    let table2: usize

    if (isG) {
      table1 = GLV.G_TABLE_1
      table2 = GLV.G_TABLE_2
    } else {
      const dyn_base = scr + 512
      table1 = dyn_base
      table2 = dyn_base + 512
      const temp_storage = dyn_base + 1024
      GLV.precomputeTableAffine(table1, p, 8, temp_storage)

      const beta = temp_storage
      store<u64>(beta, GLV.BETA0, 0)
      store<u64>(beta, GLV.BETA1, 8)
      store<u64>(beta, GLV.BETA2, 16)
      store<u64>(beta, GLV.BETA3, 24)

      const betaP = temp_storage + 32
      BigInt256.mulMod(betaP, p, beta)
      memory.copy(betaP + 32, p + 32, 32)
      memory.copy(betaP + 64, p + 64, 32)
      GLV.precomputeTableAffine(table2, betaP, 8, temp_storage + 128)
    }

    // 5. Accumulation Loop (Interleaved wNAF)
    const acc = scr + 2560
    // Init as infinity
    store<u64>(acc + 64, 0, 0)
    store<u64>(acc + 72, 0, 0)
    store<u64>(acc + 80, 0, 0)
    store<u64>(acc + 88, 0, 0)

    const ty = scr + 2656
    const P_field = scr + 2688
    store<u64>(P_field, BigInt256.P0, 0)
    store<u64>(P_field, BigInt256.P1, 8)
    store<u64>(P_field, BigInt256.P2, 16)
    store<u64>(P_field, BigInt256.P3, 24)

    let first = true
    const maxLen = len1 > len2 ? len1 : len2

    for (let i = maxLen - 1; i >= 0; i--) {
      if (!first) Point.double(acc, acc)

      // Scalar 1
      if (i < len1) {
        const d = load<i8>(wnaf1 + i)
        if (d != 0) {
          const idx = (<usize>((d < 0 ? -d : d) - 1)) >> 1
          const q = table1 + idx * 64
          let sign = d < 0
          if (neg1) sign = !sign
          if (sign) BigInt256.sub(ty, P_field, q + 32)
          else memory.copy(ty, q + 32, 32)

          if (first) {
            memory.copy(acc, q, 32)
            memory.copy(acc + 32, ty, 32)
            store<u64>(acc + 64, 1, 0)
            store<u64>(acc + 72, 0, 0)
            store<u64>(acc + 80, 0, 0)
            store<u64>(acc + 88, 0, 0)
            first = false
          } else {
            Point.addMixed(acc, acc, q, ty)
          }
        }
      }

      // Scalar 2
      if (i < len2) {
        const d = load<i8>(wnaf2 + i)
        if (d != 0) {
          const idx = (<usize>((d < 0 ? -d : d) - 1)) >> 1
          const q = table2 + idx * 64
          let sign = d < 0
          if (neg2) sign = !sign
          if (sign) BigInt256.sub(ty, P_field, q + 32)
          else memory.copy(ty, q + 32, 32)

          if (first) {
            memory.copy(acc, q, 32)
            memory.copy(acc + 32, ty, 32)
            store<u64>(acc + 64, 1, 0)
            store<u64>(acc + 72, 0, 0)
            store<u64>(acc + 80, 0, 0)
            store<u64>(acc + 88, 0, 0)
            first = false
          } else {
            Point.addMixed(acc, acc, q, ty)
          }
        }
      }
    }

    memory.copy(res, acc, 96)
  }

  static initG(p: usize): void {
    const temp = GLV.SCRATCH + 3072
    GLV.precomputeTableAffine(GLV.G_TABLE_1, p, 8, temp)

    const beta = temp
    store<u64>(beta, GLV.BETA0, 0)
    store<u64>(beta, GLV.BETA1, 8)
    store<u64>(beta, GLV.BETA2, 16)
    store<u64>(beta, GLV.BETA3, 24)

    const betaP = temp + 32
    BigInt256.mulMod(betaP, p, beta)
    memory.copy(betaP + 32, p + 32, 32)
    memory.copy(betaP + 64, p + 64, 32)

    GLV.precomputeTableAffine(GLV.G_TABLE_2, betaP, 8, temp + 128)
    GLV.is_G_Initialized = true
  }

  static decompose(k: usize, k1: usize, k2: usize, signs: usize): void {
    const scr = GLV.SCRATCH
    const base = scr + 1024
    const n_half = base
    store<u64>(n_half, 0xdfe92f46681b20a0, 0)
    store<u64>(n_half, 0x5d576e7357a4501d, 8)
    store<u64>(n_half, 0xffffffffffffffff, 16)
    store<u64>(n_half, 0x7fffffffffffffff, 24)

    const b2 = base + 32
    store<u64>(b2, GLV.A1_0, 0)
    store<u64>(b2, GLV.A1_1, 8)
    store<u64>(b2, 0, 16)
    store<u64>(b2, 0, 24)

    const b1_abs = base + 64
    store<u64>(b1_abs, GLV.B1_0, 0)
    store<u64>(b1_abs, GLV.B1_1, 8)
    store<u64>(b1_abs, 0, 16)
    store<u64>(b1_abs, 0, 24)

    const wide = base + 384
    Scalar256.mulWide(wide, k, b2)
    const c1 = base + 160
    memory.copy(c1, wide + 32, 32)
    if (Scalar256.addRaw(wide, wide, n_half)) Scalar256.addU64(c1, c1, 1)

    Scalar256.mulWide(wide, k, b1_abs)
    const c2_abs = base + 288
    memory.copy(c2_abs, wide + 32, 32)
    if (Scalar256.addRaw(wide, wide, n_half)) Scalar256.addU64(c2_abs, c2_abs, 1)

    const a1 = base + 320
    store<u64>(a1, GLV.A1_0, 0)
    store<u64>(a1, GLV.A1_1, 8)
    store<u64>(a1, 0, 16)
    store<u64>(a1, 0, 24)
    const a2 = base + 352
    store<u64>(a2, GLV.A2_0, 0)
    store<u64>(a2, GLV.A2_1, 8)
    store<u64>(a2, GLV.A2_2, 16)
    store<u64>(a2, 0, 24)

    const v1 = base + 448
    Scalar256.mulWide(wide, c1, a1)
    Scalar256.reduce(v1, wide)
    const v2 = base + 480
    Scalar256.mulWide(wide, c2_abs, a2)
    Scalar256.reduce(v2, wide)

    Scalar256.sub(k1, k, v1)
    Scalar256.sub(k1, k1, v2)

    const v3 = base + 512
    Scalar256.mulWide(wide, c1, b1_abs)
    Scalar256.reduce(v3, wide)
    const v4 = base + 544
    Scalar256.mulWide(wide, c2_abs, b2)
    Scalar256.reduce(v4, wide)

    Scalar256.sub(k2, v3, v4)

    const n = base + 576
    store<u64>(n, Scalar256.N0, 0)
    store<u64>(n, Scalar256.N1, 8)
    store<u64>(n, Scalar256.N2, 16)
    store<u64>(n, Scalar256.N3, 24)
    store<u8>(signs, 0, 0)
    store<u8>(signs + 1, 0, 0)

    if (Scalar256.isGreaterOrEqual(k1, n_half)) {
      Scalar256.sub(k1, n, k1)
      store<u8>(signs, 1, 0)
    }
    if (Scalar256.isGreaterOrEqual(k2, n_half)) {
      Scalar256.sub(k2, n, k2)
      store<u8>(signs + 1, 1, 0)
    }
  }

  static precomputeTableAffine(table: usize, p: usize, count: i32, temp: usize): void {
    const points = temp
    const p2 = temp + count * 96
    const cur = temp + count * 96 + 96
    const prods = cur + 96
    const inv_zs = prods + count * 32
    const tmp = inv_zs + count * 32
    const zi2 = tmp + 32
    const zi3 = zi2 + 32

    Point.double(p2, p)
    memory.copy(cur, p, 96)
    for (let i = 0; i < count; i++) {
      memory.copy(points + <usize>i * 96, cur, 96)
      if (i < count - 1) Point.add(cur, cur, p2)
    }

    memory.copy(prods, points + 64, 32)
    for (let i = 1; i < count; i++)
      BigInt256.mulMod(prods + <usize>i * 32, prods + <usize>(i - 1) * 32, points + <usize>i * 96 + 64)

    BigInt256.modInverse(tmp, prods + <usize>(count - 1) * 32)
    for (let i = count - 1; i > 0; i--) {
      BigInt256.mulMod(inv_zs + <usize>i * 32, tmp, prods + <usize>(i - 1) * 32)
      BigInt256.mulMod(tmp, tmp, points + <usize>i * 96 + 64)
    }
    memory.copy(inv_zs, tmp, 32)

    for (let i = 0; i < count; i++) {
      const iz = inv_zs + <usize>i * 32
      BigInt256.sqrMod(zi2, iz)
      BigInt256.mulMod(zi3, zi2, iz)
      BigInt256.mulMod(table + <usize>i * 64, points + <usize>i * 96, zi2)
      BigInt256.mulMod(table + <usize>i * 64 + 32, points + <usize>i * 96 + 32, zi3)
    }
  }
}
