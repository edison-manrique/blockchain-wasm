/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  generator.test.ts — Correctitud + memoria + velocidad + comparación (k·G)
 *  con MÉTRICAS COMPLETAS: tiempo de compilación, tamaño de binario, throughput.
 * ═══════════════════════════════════════════════════════════════════════════
 *  Layout in-place (PARAM_IN/OUT de 96 B c/u):
 *    IN  (96B) = resultado k·G (Jacobiano)
 *    OUT (96B) = [out0: k (32B)] [out1: afín (64B)]
 *  Corre con:  bun test test/generator.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult, type CompileOptions } from "./utils/wasm"

const ENTRY = "assembly/secp256k1/generator/index.ts"
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const G_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
const G_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n

let wasm: WasmInstance
let lastCompile: CompileResult
let IN: number
let OUT: number
const S = 32
const out0 = () => OUT
const out1 = () => OUT + S

async function loadModule(opts: CompileOptions | string = {}): Promise<WasmInstance> {
  lastCompile = await Wasm.compile(ENTRY, opts)
  return Wasm.load(lastCompile.binary)
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("generator — correctitud", () => {
  beforeAll(async () => {
    wasm = await loadModule() // profile "test"; init() corre en el primer multiplyG
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 240_000)

  test("métricas de compilación (profile test)", () => {
    Wasm.printCompileStats(lastCompile, "generator · test")
    expect(lastCompile.mode).toBe("memory")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
    expect(lastCompile.binary.byteLength).toBe(lastCompile.sizeBytes)
  })

  test("WASM cargado", () => {
    expect(wasm.exports.multiplyG).toBeFunction()
    expect(wasm.exports.init).toBeFunction()
  })

  test("multiplyG(1) = G", () => {
    wasm.writeU256(out0(), 1n)
    wasm.exports.multiplyG(IN, out0())
    wasm.exports.toAffine(out1(), IN)
    expect(wasm.readU256(out1())).toBe(G_X)
    expect(wasm.readU256(out1() + 32)).toBe(G_Y)
  })

  test("multiplyG(0) = infinito", () => {
    wasm.writeU256(out0(), 0n)
    wasm.exports.multiplyG(IN, out0())
    expect(wasm.exports.isInfinity(IN)).toBeTruthy()
  })

  test("multiplyG(k) == glv.mul(k, G)  (oráculo)", () => {
    const ks = [
      2n, 3n, 255n, 256n, 257n, 12345n,
      0xdeadbeefcafebaben,
      0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n,
      N - 1n
    ]
    for (const k of ks) {
      // multiplyG (tabla fija)
      wasm.writeU256(out0(), k)
      wasm.exports.multiplyG(IN, out0())
      wasm.exports.toAffine(out1(), IN)
      const xGen = wasm.readU256(out1())
      const yGen = wasm.readU256(out1() + 32)

      // oráculo: glv.mul(k, G)
      wasm.exports.mulGLV(IN, wasm.exports.generator(), out0())
      wasm.exports.toAffine(out0(), IN)
      expect(xGen).toBe(wasm.readU256(out0()))
      expect(yGen).toBe(wasm.readU256(out0() + 32))
    }
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA (zero-alloc guarantee)
// ═══════════════════════════════════════════════════════════════════════════

describe("generator — memoria", () => {
  beforeAll(async () => {
    wasm = await loadModule() // cache RAM hit
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 240_000)

  test("init() no causa memory.grow (tablas en data segment)", () => {
    wasm.exports.init() // fuerza init (idempotente)
    const pagesBefore = wasm.memoryPages()
    wasm.exports.init()
    expect(wasm.memoryPages()).toBe(pagesBefore)
  })

  test("multiplyG no causa memory.grow", () => {
    wasm.writeU256(out0(), 12345n)
    Wasm.assertZeroAlloc("multiplyG", wasm, () => wasm.exports.multiplyG(IN, out0()), 200)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD (throughput)
// ═══════════════════════════════════════════════════════════════════════════

describe("generator — velocidad", () => {
  beforeAll(async () => {
    wasm = await loadModule("bench") // -O3 --converge (lento, ~1 min)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.writeU256(out0(), 0x123456789abcdefn)
  }, 300_000)

  test("métricas de compilación (profile bench)", () => {
    Wasm.printCompileStats(lastCompile, "generator · bench")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
  })

  test("throughput multiplyG", () => {
    const results = Wasm.benchSuite(
      [{ name: "multiplyG", fn: () => wasm.exports.multiplyG(IN, out0()), iterations: 5_000 }],
      1_000,
      { warmup: 300, runs: 3 }
    )
    Wasm.printResults(results)
    const mg = results.find((r) => r.name === "multiplyG")!
    expect(mg.nsPerOp).toBeLessThan(100_000) // sanity: < 100 µs por k·G
    expect(mg.cvPct).toBeLessThan(15)
  }, 60_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) COMPARACIÓN (tabla fija w=8 vs glv.mul tabla G w=5)
// ═══════════════════════════════════════════════════════════════════════════

describe("generator — comparación", () => {
  test("multiplyG (tabla fija w=8) vs glv.mul (tabla G w=5)", async () => {
    const w = await loadModule("bench") // cache RAM hit (ya compilado en velocidad)
    const i = w.num("PARAM_IN_PTR")
    const o = w.num("PARAM_OUT_PTR")
    w.writeU256(o, 0x123456789abcdefn)
    const r = Wasm.benchCompare(
      "multiplyG fija",
      () => w.exports.multiplyG(i, o),
      "glv.mul G",
      () => w.exports.mulGLV(i, w.exports.generator(), o),
      3_000,
      { warmup: 300, runs: 3 }
    )
    console.log(`  Ganador: ${r.winner}  (ratio fija/glv = ${r.ratio.toFixed(2)}x)`)
    expect(r.winner).toBe("multiplyG fija") // tabla fija evita doubles + precompute
    expect(r.ratio).toBeLessThan(1.0)       // fija más rápida ⇒ ratio fija/glv < 1
  }, 240_000)
})