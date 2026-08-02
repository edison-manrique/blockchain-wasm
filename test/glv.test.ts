/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  glv.test.ts — Correctitud + memoria + velocidad + comparación (endomorfismo GLV)
 *  con MÉTRICAS COMPLETAS: tiempo de compilación, tamaño de binario, throughput.
 * ═══════════════════════════════════════════════════════════════════════════
 *  Layout in-place (PARAM_IN/OUT de 96 B c/u):
 *    IN  (96B) = punto P Jacobiano (entrada) → resultado k·P (salida, in-place)
 *    OUT (96B) = [out0: k (32B)] [out1: libre] [out2: libre]
 *  Corre con:  bun test test/glv.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult, type CompileOptions } from "./utils/wasm"

const ENTRY = "assembly/secp256k1/glv/index.ts"
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const LAMBDA = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72n
const G_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
const G_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
const G3_X = 0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9n
const G3_Y = 0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672n

let wasm: WasmInstance
let lastCompile: CompileResult
let IN: number
let OUT: number
const S = 32
const out0 = () => OUT
const out1 = () => OUT + S
const out2 = () => OUT + 2 * S

async function loadModule(opts: CompileOptions | string = {}): Promise<WasmInstance> {
  lastCompile = await Wasm.compile(ENTRY, opts)
  return Wasm.load(lastCompile.binary)
}

function writeJac(base: number, x: bigint, y: bigint): void {
  wasm.writeU256(base, x)
  wasm.writeU256(base + 32, y)
  wasm.writeU256(base + 64, 1n)
}

/** Oráculo: resJac = k·P, P afín en pAff (64 B). Double-and-add MSB-first. */
function naiveMul(resJac: number, pAff: number, k: bigint): void {
  wasm.exports.setInfinity(resJac)
  if (k === 0n) return
  const bits = k.toString(2)
  let started = false
  for (let i = 0; i < bits.length; i++) {
    if (started) wasm.exports.double(resJac, resJac)
    if (bits[i] === "1") {
      if (!started) {
        wasm.writeU256(resJac, wasm.readU256(pAff))
        wasm.writeU256(resJac + 32, wasm.readU256(pAff + 32))
        wasm.writeU256(resJac + 64, 1n)
        started = true
      } else {
        wasm.exports.addMixed(resJac, resJac, pAff, pAff + 32)
      }
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("glv — correctitud", () => {
  beforeAll(async () => {
    wasm = await loadModule()
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("métricas de compilación (profile test)", () => {
    Wasm.printCompileStats(lastCompile, "glv · test")
    expect(lastCompile.mode).toBe("memory")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
    expect(lastCompile.binary.byteLength).toBe(lastCompile.sizeBytes)
    expect(lastCompile.compileTimeMs).toBeGreaterThanOrEqual(0)
  })

  test("WASM cargado", () => {
    expect(wasm.exports.decompose).toBeFunction()
    expect(wasm.exports.mul).toBeFunction()
  })

  test("decompose: k1 + k2·λ ≡ k (mod N), |ki| ≤ N/2", () => {
    const ks = [
      1n,
      2n,
      3n,
      12345n,
      0xdeadbeefcafebabe1234567890abcdefn,
      N - 1n,
      N / 2n,
      LAMBDA,
      (LAMBDA + 1n) % N,
      0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n
    ]
    for (const k of ks) {
      wasm.writeU256(IN, k)
      wasm.exports.decompose(IN, out0(), out1(), out2())
      const a1 = wasm.readU256(out0())
      const a2 = wasm.readU256(out1())
      const s1 = wasm.u8[out2()] !== 0
      const s2 = wasm.u8[out2() + 1] !== 0
      const k1s = s1 ? -a1 : a1
      const k2s = s2 ? -a2 : a2
      const recon = (((k1s + k2s * LAMBDA) % N) + N) % N
      expect(recon).toBe(k % N)
      expect(a1 <= N >> 1n).toBe(true)
      expect(a2 <= N >> 1n).toBe(true)
    }
  })

  test("glvMul(k, G) == naiveMul(k, G)", () => {
    const ks = [
      1n,
      2n,
      3n,
      255n,
      256n,
      257n,
      0x123456789abcdefn,
      0xdeadbeefcafebabe1234567890abcdefn,
      N - 1n,
      0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n
    ]
    for (const k of ks) {
      writeJac(IN, G_X, G_Y)
      wasm.writeU256(out0(), k)
      wasm.exports.mul(IN, IN, out0())
      wasm.exports.toAffine(out1(), IN)
      const xGlv = wasm.readU256(out1())
      const yGlv = wasm.readU256(out1() + 32)
      wasm.writeU256(out0(), G_X)
      wasm.writeU256(out0() + 32, G_Y)
      naiveMul(IN, out0(), k)
      wasm.exports.toAffine(out0(), IN)
      expect(xGlv).toBe(wasm.readU256(out0()))
      expect(yGlv).toBe(wasm.readU256(out0() + 32))
    }
  })

  test("glvMul(k, 3G) == naiveMul(k, 3G)  (P arbitrario, tabla dinámica)", () => {
    const ks = [1n, 7n, 1000n, 0xabcdef1234567890n, N - 1n]
    for (const k of ks) {
      writeJac(IN, G3_X, G3_Y)
      wasm.writeU256(out0(), k)
      wasm.exports.mul(IN, IN, out0())
      wasm.exports.toAffine(out1(), IN)
      const xGlv = wasm.readU256(out1())
      const yGlv = wasm.readU256(out1() + 32)
      wasm.writeU256(out0(), G3_X)
      wasm.writeU256(out0() + 32, G3_Y)
      naiveMul(IN, out0(), k)
      wasm.exports.toAffine(out0(), IN)
      expect(xGlv).toBe(wasm.readU256(out0()))
      expect(yGlv).toBe(wasm.readU256(out0() + 32))
    }
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA (zero-alloc guarantee)
// ═══════════════════════════════════════════════════════════════════════════

describe("glv — memoria", () => {
  beforeAll(async () => {
    wasm = await loadModule() // cache RAM hit
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("mul(G) no causa memory.grow (tabla en data segment)", () => {
    wasm.writeU256(out0(), 12345n)
    Wasm.assertZeroAlloc(
      "mul(G)",
      wasm,
      () => {
        writeJac(IN, G_X, G_Y)
        wasm.exports.mul(IN, IN, out0())
      },
      200
    )
  })

  test("mul(P arbitrario) no causa memory.grow (tabla en arena)", () => {
    wasm.writeU256(out0(), 12345n)
    Wasm.assertZeroAlloc(
      "mul(3G)",
      wasm,
      () => {
        writeJac(IN, G3_X, G3_Y)
        wasm.exports.mul(IN, IN, out0())
      },
      200
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD (throughput)
// ═══════════════════════════════════════════════════════════════════════════

describe("glv — velocidad", () => {
  beforeAll(async () => {
    wasm = await loadModule("bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.writeU256(out0(), 0x123456789abcdefn)
  }, 120_000)

  test("métricas de compilación (profile bench)", () => {
    Wasm.printCompileStats(lastCompile, "glv · bench")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
  })

  test("throughput glv.mul", () => {
    const results = Wasm.benchSuite(
      [
        {
          name: "mul(G)",
          fn: () => {
            writeJac(IN, G_X, G_Y)
            wasm.exports.mul(IN, IN, out0())
          },
          iterations: 1_000
        },
        {
          name: "mul(3G)",
          fn: () => {
            writeJac(IN, G3_X, G3_Y)
            wasm.exports.mul(IN, IN, out0())
          },
          iterations: 1_000
        }
      ],
      1_000,
      { warmup: 100, runs: 2 }
    )
    Wasm.printResults(results)
    const g = results.find((r) => r.name === "mul(G)")!
    expect(g.nsPerOp).toBeLessThan(200_000)
  }, 30_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) COMPARACIÓN DE BUILDS Y ALGORITMOS (métricas completas)
// ═══════════════════════════════════════════════════════════════════════════

describe("glv — comparación", () => {
  test("builds -O1 vs -O3: compile + size + speed (mul(G))", async () => {
    const report = await Wasm.benchCompileCompare(
      ENTRY,
      { label: "O1", opts: "test+o1" },
      { label: "O3", opts: "o3+noassert" },
      (w) => {
        const i = w.num("PARAM_IN_PTR")
        const o = w.num("PARAM_OUT_PTR")
        w.writeU256(o, 0x123456789abcdefn) // k fijo en out0
        return () => {
          w.writeU256(i, G_X)
          w.writeU256(i + 32, G_Y)
          w.writeU256(i + 64, 1n)
          w.exports.mul(i, i, o) // in-place
        }
      },
      5_000,
      { warmup: 200, runs: 3 }
    )
    Wasm.printCompileCompare(report)
    expect(report.a.sizeBytes).toBeGreaterThan(0)
    expect(report.b.sizeBytes).toBeGreaterThan(0)
    expect(report.speedRatio).toBeGreaterThan(0.3)
    expect(report.speedRatio).toBeLessThan(3.0)
  }, 240_000)

  test("paridad de correctitud -O1 == -O3 (glvMul(k, G))", async () => {
    const w1 = await Wasm.load((await Wasm.compile(ENTRY, "test+o1")).binary)
    const w3 = await Wasm.load((await Wasm.compile(ENTRY, "bench+o3")).binary)
    const i1 = w1.num("PARAM_IN_PTR"),
      o1 = w1.num("PARAM_OUT_PTR")
    const i3 = w3.num("PARAM_IN_PTR"),
      o3 = w3.num("PARAM_OUT_PTR")
    const k = 0xdeadbeefcafebabe1234567890abcdefn
    w1.writeU256(i1, G_X)
    w1.writeU256(i1 + 32, G_Y)
    w1.writeU256(i1 + 64, 1n)
    w3.writeU256(i3, G_X)
    w3.writeU256(i3 + 32, G_Y)
    w3.writeU256(i3 + 64, 1n)
    w1.writeU256(o1, k)
    w3.writeU256(o3, k)
    w1.exports.mul(i1, i1, o1)
    w1.exports.toAffine(o1 + 32, i1)
    w3.exports.mul(i3, i3, o3)
    w3.exports.toAffine(o3 + 32, i3)
    expect(w1.readU256(o1 + 32)).toBe(w3.readU256(o3 + 32))
    expect(w1.readU256(o1 + 64)).toBe(w3.readU256(o3 + 64))
  }, 180_000)

  test("algoritmos: mul(G) tabla fija vs mul(3G) tabla dinámica", async () => {
    const w = await Wasm.load((await Wasm.compile(ENTRY, "bench+o3")).binary) // cache RAM hit
    const i = w.num("PARAM_IN_PTR")
    const o = w.num("PARAM_OUT_PTR")
    w.writeU256(o, 0x123456789abcdefn)
    const r = Wasm.benchCompare(
      "mul(G) fija",
      () => {
        w.writeU256(i, G_X)
        w.writeU256(i + 32, G_Y)
        w.writeU256(i + 64, 1n)
        w.exports.mul(i, i, o)
      },
      "mul(3G) dyn",
      () => {
        w.writeU256(i, G3_X)
        w.writeU256(i + 32, G3_Y)
        w.writeU256(i + 64, 1n)
        w.exports.mul(i, i, o)
      },
      1_000,
      { warmup: 100, runs: 2 }
    )
    console.log(`  Ganador: ${r.winner}  (ratio fija/dyn = ${r.ratio.toFixed(2)}x)`)
    expect(r.winner).toBe("mul(G) fija") // tabla fija evita el precompute por llamada
    expect(r.ratio).toBeLessThan(1.0) // fija es MÁS rápida ⇒ ratio fija/dyn < 1
  }, 120_000)
})
