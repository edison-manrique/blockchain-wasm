/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  scalar.test.ts — Correctitud + memoria + velocidad + comparación (mod N)
 *  con MÉTRICAS COMPLETAS: tiempo de compilación, tamaño de binario, throughput.
 * ═══════════════════════════════════════════════════════════════════════════
 *  Corre con:  bun test test/scalar.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult, type CompileOptions } from "./utils/wasm"

const ENTRY = "assembly/secp256k1/scalar/index.ts"
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const INV2 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1n
const A_BIG = 0x1234567890abcdef112233445566778899aabbccddeeff001122334455667788n

let wasm: WasmInstance
let lastCompile: CompileResult
let IN: number
let OUT: number
const S = 32
const in0 = () => IN
const in1 = () => IN + S
const out0 = () => OUT
const out1 = () => OUT + S

async function loadModule(opts: CompileOptions | string = {}): Promise<WasmInstance> {
  lastCompile = await Wasm.compile(ENTRY, opts)
  return Wasm.load(lastCompile.binary)
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("scalar (mod N) — correctitud", () => {
  beforeAll(async () => {
    wasm = await loadModule()
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("métricas de compilación (profile test)", () => {
    Wasm.printCompileStats(lastCompile, "scalar · test")
    expect(lastCompile.mode).toBe("memory")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
    expect(lastCompile.binary.byteLength).toBe(lastCompile.sizeBytes)
    expect(lastCompile.compileTimeMs).toBeGreaterThanOrEqual(0)
  })

  test("WASM cargado y punteros de I/O disponibles", () => {
    expect(wasm.exports.mulMod).toBeFunction()
    expect(wasm.exports.modInverse).toBeFunction()
    expect(Number.isFinite(IN)).toBe(true)
    expect(OUT).toBeGreaterThan(IN)
  })

  test("add(2, 3) = 5", () => {
    wasm.writeU256(in0(), 2n)
    wasm.writeU256(in1(), 3n)
    wasm.exports.add(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(5n)
  })

  test("add(N−1, 1) = 0 (envuelve mod N)", () => {
    wasm.writeU256(in0(), N - 1n)
    wasm.writeU256(in1(), 1n)
    wasm.exports.add(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(0n)
  })

  test("sub(3, 2) = 1", () => {
    wasm.writeU256(in0(), 3n)
    wasm.writeU256(in1(), 2n)
    wasm.exports.sub(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(1n)
  })

  test("sub(2, 3) = N−1 (envuelve mod N)", () => {
    wasm.writeU256(in0(), 2n)
    wasm.writeU256(in1(), 3n)
    wasm.exports.sub(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(N - 1n)
  })

  test("mulMod(2, 3) = 6", () => {
    wasm.writeU256(in0(), 2n)
    wasm.writeU256(in1(), 3n)
    wasm.exports.mulMod(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(6n)
  })

  test("mulMod por la identidad: mulMod(a, 1) = a", () => {
    wasm.writeU256(in0(), A_BIG)
    wasm.writeU256(in1(), 1n)
    wasm.exports.mulMod(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(A_BIG)
  })

  test("mulMod(N−1, N−1) = 1  (pues (N−1)² ≡ 1)", () => {
    wasm.writeU256(in0(), N - 1n)
    wasm.writeU256(in1(), N - 1n)
    wasm.exports.mulMod(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(1n)
  })

  test("sqrMod(x) == mulMod(x, x)", () => {
    const x = 0xdeadbeefcafebabe1234567890abcdefn
    wasm.writeU256(in0(), x)
    wasm.exports.sqrMod(out0(), in0())
    const sq = wasm.read(out0(), 32)
    wasm.writeU256(in0(), x)
    wasm.writeU256(in1(), x)
    wasm.exports.mulMod(out0(), in0(), in1())
    expect(Wasm.bytesToHex(wasm.read(out0(), 32))).toBe(Wasm.bytesToHex(sq))
  })

  test("reduce(mul(a, b)) == mulMod(a, b)", () => {
    const a = 0x11111111111111112222222222222222n
    const b = 0x33333333333333334444444444444444n
    wasm.writeU256(in0(), a)
    wasm.writeU256(in1(), b)
    wasm.exports.mul(OUT, in0(), in1())
    wasm.exports.reduce(in0(), OUT)
    const reduced = wasm.read(in0(), 32)
    wasm.writeU256(in0(), a)
    wasm.writeU256(in1(), b)
    wasm.exports.mulMod(out0(), in0(), in1())
    expect(Wasm.bytesToHex(reduced)).toBe(Wasm.bytesToHex(wasm.read(out0(), 32)))
  })

  test("modInverse(2) = (N+1)/2 (valor exacto)", () => {
    wasm.writeU256(in0(), 2n)
    wasm.exports.modInverse(out0(), in0())
    expect(wasm.readU256(out0())).toBe(INV2)
  })

  test("modInverse(2) · 2 ≡ 1 (mod N)", () => {
    wasm.writeU256(in0(), 2n)
    wasm.exports.modInverse(out0(), in0())
    wasm.exports.mulMod(out1(), out0(), in0())
    expect(wasm.readU256(out1())).toBe(1n)
  })

  test("modInverse(a) · a ≡ 1 (mod N) con a grande", () => {
    wasm.writeU256(in0(), A_BIG)
    wasm.exports.modInverse(out0(), in0())
    wasm.exports.mulMod(out1(), out0(), in0())
    expect(wasm.readU256(out1())).toBe(1n)
  })

  test("modInverse(0) = 0", () => {
    wasm.writeU256(in0(), 0n)
    wasm.exports.modInverse(out0(), in0())
    expect(wasm.readU256(out0())).toBe(0n)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA (zero-alloc guarantee)
// ═══════════════════════════════════════════════════════════════════════════

describe("scalar (mod N) — memoria", () => {
  beforeAll(async () => {
    wasm = await loadModule()
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.writeU256(in0(), 0xdeadbeefcafebaben)
    wasm.writeU256(in1(), 0x1234567890abcdefn)
  }, 120_000)

  test("mulMod / sqrMod no causan memory.grow", () => {
    Wasm.assertZeroAlloc("mulMod", wasm, () => wasm.exports.mulMod(out0(), in0(), in1()), 5000)
    Wasm.assertZeroAlloc("sqrMod", wasm, () => wasm.exports.sqrMod(out0(), in0()), 5000)
  })

  test("reduce no causa memory.grow", () => {
    wasm.exports.mul(OUT, in0(), in1())
    Wasm.assertZeroAlloc("reduce", wasm, () => wasm.exports.reduce(in0(), OUT), 3000)
  })

  test("modInverse no causa memory.grow (arena save/restore)", () => {
    wasm.writeU256(in0(), 12345n)
    Wasm.assertZeroAlloc("modInverse", wasm, () => wasm.exports.modInverse(out0(), in0()), 1500)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD (throughput)
// ═══════════════════════════════════════════════════════════════════════════

describe("scalar (mod N) — velocidad", () => {
  beforeAll(async () => {
    wasm = await loadModule("bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.writeU256(in0(), 0xdeadbeefcafebaben)
    wasm.writeU256(in1(), 0x1234567890abcdefn)
  }, 120_000)

  test("métricas de compilación (profile bench)", () => {
    Wasm.printCompileStats(lastCompile, "scalar · bench")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
  })

  test("throughput de operaciones", () => {
    wasm.exports.mul(OUT, in0(), in1())
    const results = Wasm.benchSuite(
      [
        { name: "add", fn: () => wasm.exports.add(out0(), in0(), in1()), iterations: 2_000_000 },
        { name: "sub", fn: () => wasm.exports.sub(out0(), in0(), in1()), iterations: 2_000_000 },
        { name: "mulMod", fn: () => wasm.exports.mulMod(out0(), in0(), in1()), iterations: 500_000 },
        { name: "sqrMod", fn: () => wasm.exports.sqrMod(out0(), in0()), iterations: 500_000 },
        { name: "reduce", fn: () => wasm.exports.reduce(in0(), OUT), iterations: 500_000 },
        { name: "modInv", fn: () => wasm.exports.modInverse(out0(), in0()), iterations: 20_000 }
      ],
      100_000,
      { warmup: 2000, runs: 3 }
    )
    Wasm.printResults(results)

    const mulMod = results.find((r) => r.name === "mulMod")!
    expect(mulMod.nsPerOp).toBeLessThan(2000) // sanity: < 2 µs (no es fused)
    expect(mulMod.cvPct).toBeLessThan(15)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) COMPARACIÓN DE BUILDS Y ALGORITMOS (métricas completas)
// ═══════════════════════════════════════════════════════════════════════════

describe("scalar (mod N) — comparación", () => {
  test("builds -O0 vs -O1: compile + size + speed", async () => {
    const report = await Wasm.benchCompileCompare(
      ENTRY,
      { label: "O0", opts: "test" },
      { label: "O1", opts: "test+o1" },
      (w) => {
        const i = w.num("PARAM_IN_PTR")
        const o = w.num("PARAM_OUT_PTR")
        w.writeU256(i, 0xdeadbeefcafebaben)
        w.writeU256(i + 32, 0x1234567890abcdefn)
        return () => w.exports.mulMod(o, i, i + 32)
      },
      300_000,
      { warmup: 3000, runs: 5 }
    )
    Wasm.printCompileCompare(report)

    expect(report.a.sizeBytes).toBeGreaterThan(0)
    expect(report.b.sizeBytes).toBeGreaterThan(0)
    expect(report.speedRatio).toBeGreaterThan(0.3)
    expect(report.speedRatio).toBeLessThan(3.0)
  }, 120_000)

  test("paridad de correctitud -O0 == -O1 (mulMod(N−1,N−1)=1)", async () => {
    const w1 = await Wasm.load((await Wasm.compile(ENTRY, "test")).binary)
    const w3 = await Wasm.load((await Wasm.compile(ENTRY, "test+o1")).binary)
    const i1 = w1.num("PARAM_IN_PTR"),
      o1 = w1.num("PARAM_OUT_PTR")
    const i3 = w3.num("PARAM_IN_PTR"),
      o3 = w3.num("PARAM_OUT_PTR")
    w1.writeU256(i1, N - 1n)
    w1.writeU256(i1 + 32, N - 1n)
    w3.writeU256(i3, N - 1n)
    w3.writeU256(i3 + 32, N - 1n)
    w1.exports.mulMod(o1, i1, i1 + 32)
    w3.exports.mulMod(o3, i3, i3 + 32)
    expect(w1.readU256(o1)).toBe(1n)
    expect(w3.readU256(o3)).toBe(1n)
  }, 120_000)

  test("algoritmos: sqrMod vs mulMod(a,a) — la simetría gana", async () => {
    const w = await Wasm.load((await Wasm.compile(ENTRY, "test+o1")).binary)
    const i = w.num("PARAM_IN_PTR")
    const o = w.num("PARAM_OUT_PTR")
    w.writeU256(i, 0xdeadbeefcafebaben)
    const r = Wasm.benchCompare(
      "sqrMod",
      () => w.exports.sqrMod(o, i),
      "mulMod(a,a)",
      () => w.exports.mulMod(o, i, i),
      500_000,
      { warmup: 3000, runs: 5 }
    )
    console.log(`  Ganador: ${r.winner}  (ratio sqr/mul = ${r.ratio.toFixed(2)}x)`)
    expect(r.winner).toBe("sqrMod")
    expect(r.ratio).toBeLessThan(1.0)
  }, 120_000)
})
