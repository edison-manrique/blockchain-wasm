/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  wnaf.test.ts — Correctitud + memoria + velocidad + comparación del wNAF
 *  con MÉTRICAS COMPLETAS: tiempo de compilación, tamaño de binario, throughput.
 * ═══════════════════════════════════════════════════════════════════════════
 *  Corre con:  bun test test/wnaf.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult, type CompileOptions } from "./utils/wasm"

const ENTRY = "assembly/secp256k1/wnaf/index.ts"

let wasm: WasmInstance
let lastCompile: CompileResult
let IN: number
let OUT: number

async function loadModule(opts: CompileOptions | string = {}): Promise<WasmInstance> {
  lastCompile = await Wasm.compile(ENTRY, opts)
  return Wasm.load(lastCompile.binary)
}

// wNAF de referencia en JS (para comparar)
function wnafRef(k: bigint, w: number): number[] {
  const twoW = 1 << w
  const half = 1 << (w - 1)
  const out: number[] = []
  let n = k
  while (n > 0n) {
    let d = 0
    if (n & 1n) {
      const m = Number(n % BigInt(twoW))
      d = m >= half ? m - twoW : m
      n -= BigInt(d)
    }
    out.push(d)
    n >>= 1n
  }
  return out
}

/** Lee el wNAF (i8) desde OUT como array de enteros con signo. */
function readWnaf(len: number): number[] {
  const out: number[] = []
  for (let i = 0; i < len; i++) {
    let v = wasm.u8[OUT + i]
    if (v > 127) v -= 256 // i8 sign-extend
    out.push(v)
  }
  return out
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("wnaf — correctitud", () => {
  beforeAll(async () => {
    wasm = await loadModule()
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("métricas de compilación (profile test)", () => {
    Wasm.printCompileStats(lastCompile, "wnaf · test")
    expect(lastCompile.mode).toBe("memory")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
    expect(lastCompile.binary.byteLength).toBe(lastCompile.sizeBytes)
    expect(lastCompile.compileTimeMs).toBeGreaterThanOrEqual(0)
  })

  test("WASM cargado", () => {
    expect(wasm.exports.compute).toBeFunction()
  })

  const cases: [string, bigint][] = [
    ["1", 1n],
    ["3", 3n],
    ["pequeño", 0x12345n],
    ["mediano", 0xdeadbeefcafebaben],
    ["grande", 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n],
    ["256 bits", (0xf3b9cac2fc632551n << 192n) | 0xdeadbeefcafebaben]
  ]

  for (const [name, k] of cases) {
    test(`wNAF(${name}) coincide con la referencia (w=5)`, () => {
      wasm.writeU256(IN, k)
      const len: number = wasm.exports.compute(OUT, IN, 5)
      expect(readWnaf(len)).toEqual(wnafRef(k, 5))
    })
  }

  test("propiedad NAF: no hay dos dígitos impares consecutivos", () => {
    const k = 0x123456789abcdef0fedcba9876543210n
    wasm.writeU256(IN, k)
    const len: number = wasm.exports.compute(OUT, IN, 5)
    let prevOdd = false
    for (const v of readWnaf(len)) {
      const odd = v !== 0
      expect(odd && prevOdd).toBe(false) // nunca dos impares seguidos
      prevOdd = odd
    }
  })

  test("reconstrucción: Σ digit·2^i == k", () => {
    const k = 0x9f8e7d6c5b4a39281706f5e4d3c2b1a0n
    wasm.writeU256(IN, k)
    const len: number = wasm.exports.compute(OUT, IN, 5)
    let acc = 0n
    let pow = 1n
    for (const v of readWnaf(len)) {
      acc += BigInt(v) * pow
      pow <<= 1n
    }
    expect(acc).toBe(k)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA (zero-alloc guarantee)
// ═══════════════════════════════════════════════════════════════════════════

describe("wnaf — memoria", () => {
  beforeAll(async () => {
    wasm = await loadModule() // cache RAM hit
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.writeU256(IN, 0xdeadbeefcafebabe1234567890abcdefn)
  }, 120_000)

  test("compute no causa memory.grow", () => {
    Wasm.assertZeroAlloc("compute", wasm, () => wasm.exports.compute(OUT, IN, 5), 5000)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD (throughput)
// ═══════════════════════════════════════════════════════════════════════════

describe("wnaf — velocidad", () => {
  beforeAll(async () => {
    wasm = await loadModule("bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.writeU256(IN, 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n)
  }, 120_000)

  test("métricas de compilación (profile bench)", () => {
    Wasm.printCompileStats(lastCompile, "wnaf · bench")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
  })

  test("throughput compute (w=5 vs w=8)", () => {
    const results = Wasm.benchSuite(
      [
        { name: "compute w=5", fn: () => wasm.exports.compute(OUT, IN, 5), iterations: 500_000 },
        { name: "compute w=8", fn: () => wasm.exports.compute(OUT, IN, 8), iterations: 500_000 }
      ],
      100_000,
      { warmup: 5000, runs: 3 }
    )
    Wasm.printResults(results)
    const c5 = results.find((r) => r.name === "compute w=5")!
    expect(c5.nsPerOp).toBeLessThan(5000) // sanity: compute es barato
    expect(c5.cvPct).toBeLessThan(15)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) COMPARACIÓN DE BUILDS Y VENTANAS (métricas completas)
// ═══════════════════════════════════════════════════════════════════════════

describe("wnaf — comparación", () => {
  test("builds -O1 vs -O3: compile + size + speed (compute w=5)", async () => {
    const report = await Wasm.benchCompileCompare(
      ENTRY,
      { label: "O1", opts: "test+o1" },
      { label: "O3", opts: "bench+o3" },
      (w) => {
        const i = w.num("PARAM_IN_PTR")
        const o = w.num("PARAM_OUT_PTR")
        w.writeU256(i, 0xdeadbeefcafebabe1234567890abcdefn)
        return () => w.exports.compute(o, i, 5)
      },
      1_000_000,
      { warmup: 5000, runs: 5 }
    )
    Wasm.printCompileCompare(report)
    expect(report.a.sizeBytes).toBeGreaterThan(0)
    expect(report.b.sizeBytes).toBeGreaterThan(0)
    expect(report.speedRatio).toBeGreaterThan(0.3)
    expect(report.speedRatio).toBeLessThan(3.0)
  }, 120_000)

  test("paridad de correctitud -O1 == -O3 (compute)", async () => {
    const w1 = await Wasm.load((await Wasm.compile(ENTRY, "test+o1")).binary)
    const w3 = await Wasm.load((await Wasm.compile(ENTRY, "bench+o3")).binary)
    const i1 = w1.num("PARAM_IN_PTR"),
      o1 = w1.num("PARAM_OUT_PTR")
    const i3 = w3.num("PARAM_IN_PTR"),
      o3 = w3.num("PARAM_OUT_PTR")
    const k = 0x123456789abcdef0fedcba9876543210n
    w1.writeU256(i1, k)
    w3.writeU256(i3, k)
    const len1: number = w1.exports.compute(o1, i1, 5)
    const len3: number = w3.exports.compute(o3, i3, 5)
    expect(len1).toBe(len3)
    const d1: number[] = []
    const d3: number[] = []
    for (let j = 0; j < len1; j++) {
      d1.push(w1.u8[o1 + j])
      d3.push(w3.u8[o3 + j])
    }
    expect(d1).toEqual(d3)
  }, 120_000)

  // Ventana mayor ⇒ dígitos más esparcidos (menos no-ceros) ⇒ menos sumas en la
  // multiplicación escalar. Es el trade-off relevante del wNAF.
  test("ventanas: w=8 produce ≤ dígitos no-ceros que w=5 (densidad)", () => {
    const k = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n
    wasm.writeU256(IN, k)
    const countNonZero = (w: number): number => {
      const len: number = wasm.exports.compute(OUT, IN, w)
      let c = 0
      for (let i = 0; i < len; i++) if (wasm.u8[OUT + i] !== 0) c++
      return c
    }
    const nz5 = countNonZero(5)
    const nz8 = countNonZero(8)
    console.log(`  w=5: ${nz5} no-ceros  |  w=8: ${nz8} no-ceros`)
    expect(nz5).toBeGreaterThan(0)
    expect(nz8).toBeLessThanOrEqual(nz5) // ventana mayor ⇒ más ceros
  })
})
