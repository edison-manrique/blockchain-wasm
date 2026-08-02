/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  point.test.ts — Correctitud + memoria + velocidad + comparación (secp256k1)
 *  con MÉTRICAS COMPLETAS: tiempo de compilación, tamaño de binario, throughput.
 * ═══════════════════════════════════════════════════════════════════════════
 *  Buffers (PARAM_IN / PARAM_OUT, 90 B c/u → 3 slots de 32 B):
 *    IN  = [ in0:32 ][ in1:32 ][ in2:32 ]   → punto Jacobiano (96 B) = P_IN
 *    OUT = [ out0:32 ][ out1:32 ][ out2:32 ] → punto Jacobiano (96 B) = P_OUT
 *    Afín (64 B) = out0..out1.
 *  Corre con:  bun test test/point.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult, type CompileOptions } from "./utils/wasm"

const ENTRY = "assembly/secp256k1/point/index.ts"
const P = (1n << 256n) - (1n << 32n) - 977n
const G_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
const G_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
const G2_X = 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5n
const G2_Y = 0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52an // verificado
const G3_X = 0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9n
const G3_Y = 0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672n

let wasm: WasmInstance
let lastCompile: CompileResult
let IN: number
let OUT: number
const S = 32
const out0 = () => OUT
const out1 = () => OUT + S
const P_IN = () => IN
const P_OUT = () => OUT

async function loadModule(opts: CompileOptions | string = {}): Promise<WasmInstance> {
  lastCompile = await Wasm.compile(ENTRY, opts)
  return Wasm.load(lastCompile.binary)
}

function writeJac(base: number, x: bigint, y: bigint): void {
  wasm.writeU256(base, x)
  wasm.writeU256(base + 32, y)
  wasm.writeU256(base + 64, 1n)
}
function readAffine(base: number): [bigint, bigint] {
  return [wasm.readU256(base), wasm.readU256(base + 32)]
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("point (secp256k1) — correctitud", () => {
  beforeAll(async () => {
    wasm = await loadModule()
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("métricas de compilación (profile test)", () => {
    Wasm.printCompileStats(lastCompile, "point · test")
    expect(lastCompile.mode).toBe("memory")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
    expect(lastCompile.binary.byteLength).toBe(lastCompile.sizeBytes)
    expect(lastCompile.compileTimeMs).toBeGreaterThanOrEqual(0)
  })

  test("WASM cargado y punteros de I/O disponibles", () => {
    expect(wasm.exports.double).toBeFunction()
    expect(wasm.exports.addPoint).toBeFunction()
    expect(wasm.exports.addMixed).toBeFunction()
    expect(wasm.exports.toAffine).toBeFunction()
    expect(OUT).toBeGreaterThan(IN)
  })

  test("generator() / infinity() exponen punteros válidos", () => {
    const g: number = wasm.exports.generator()
    const inf: number = wasm.exports.infinity()
    expect(Number.isFinite(g)).toBe(true)
    expect(Number.isFinite(inf)).toBe(true)
    expect(wasm.readU256(g)).toBe(G_X)
    expect(wasm.readU256(g + 32)).toBe(G_Y)
    expect(wasm.readU256(g + 64)).toBe(1n)
    expect(wasm.readU256(inf + 64)).toBe(0n)
  })

  test("G está en la curva: y² ≡ x³ + 7 (mod P)", () => {
    const lhs = (G_Y * G_Y) % P
    const rhs = (((((G_X * G_X) % P) * G_X) % P) + 7n) % P
    expect(lhs).toBe(rhs)
  })

  test("toAffine(generator) = (G_X, G_Y)", () => {
    wasm.exports.toAffine(out0(), wasm.exports.generator())
    const [x, y] = readAffine(out0())
    expect(x).toBe(G_X)
    expect(y).toBe(G_Y)
  })

  test("double(G) → 2G (vector conocido)", () => {
    writeJac(P_IN(), G_X, G_Y)
    wasm.exports.double(P_OUT(), P_IN())
    wasm.exports.toAffine(out0(), P_OUT())
    const [x, y] = readAffine(out0())
    expect(x).toBe(G2_X)
    expect(y).toBe(G2_Y)
  })

  test("add(G, G) == double(G)", () => {
    writeJac(P_IN(), G_X, G_Y)
    wasm.exports.double(P_OUT(), P_IN())
    const dbl = wasm.read(P_OUT(), 96)
    writeJac(P_IN(), G_X, G_Y)
    wasm.exports.addPoint(P_OUT(), P_IN(), P_IN())
    expect(Wasm.bytesToHex(wasm.read(P_OUT(), 96))).toBe(Wasm.bytesToHex(dbl))
  })

  test("addMixed(G, G_affine) == double(G)", () => {
    writeJac(P_IN(), G_X, G_Y)
    wasm.exports.double(P_OUT(), P_IN())
    const dbl = wasm.read(P_OUT(), 96)
    writeJac(P_IN(), G_X, G_Y)
    wasm.writeU256(out0(), G_X)
    wasm.writeU256(out1(), G_Y)
    wasm.exports.addMixed(P_OUT(), P_IN(), out0(), out1())
    expect(Wasm.bytesToHex(wasm.read(P_OUT(), 96))).toBe(Wasm.bytesToHex(dbl))
  })

  test("3G = double(G) + G (consistencia add vs double)", () => {
    writeJac(P_IN(), G_X, G_Y)
    wasm.exports.double(P_OUT(), P_IN())
    writeJac(P_IN(), G_X, G_Y)
    wasm.exports.addPoint(P_IN(), P_OUT(), P_IN())
    wasm.exports.toAffine(out0(), P_IN())
    const [x3, y3] = readAffine(out0())
    expect(x3).toBe(G3_X)
    expect(y3).toBe(G3_Y)
  })

  test("negate: G + (−G) = infinito", () => {
    writeJac(P_IN(), G_X, G_Y)
    wasm.exports.negate(P_OUT(), P_IN())
    wasm.exports.addPoint(P_IN(), P_IN(), P_OUT())
    expect(wasm.exports.isInfinity(P_IN())).toBeTruthy()
  })

  test("double(infinito) = infinito", () => {
    wasm.exports.setInfinity(P_IN())
    wasm.exports.double(P_OUT(), P_IN())
    expect(wasm.exports.isInfinity(P_OUT())).toBeTruthy()
  })

  test("add(infinito, G) = G", () => {
    wasm.exports.setInfinity(P_IN())
    writeJac(P_OUT(), G_X, G_Y)
    wasm.exports.addPoint(P_IN(), P_IN(), P_OUT())
    wasm.exports.toAffine(out0(), P_IN())
    const [x, y] = readAffine(out0())
    expect(x).toBe(G_X)
    expect(y).toBe(G_Y)
  })

  test("eqJacobian: G == G (y G != 2G)", () => {
    writeJac(P_IN(), G_X, G_Y)
    writeJac(P_OUT(), G_X, G_Y)
    expect(wasm.exports.eqJacobian(P_IN(), P_OUT())).toBeTruthy()
    wasm.exports.double(P_OUT(), P_IN())
    expect(wasm.exports.eqJacobian(P_IN(), P_OUT())).toBeFalsy()
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA (zero-alloc guarantee)
// ═══════════════════════════════════════════════════════════════════════════

describe("point (secp256k1) — memoria", () => {
  beforeAll(async () => {
    wasm = await loadModule() // cache RAM hit
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    writeJac(P_IN(), G_X, G_Y)
  }, 120_000)

  test("double / addPoint / addMixed no causan memory.grow", () => {
    Wasm.assertZeroAlloc("double", wasm, () => wasm.exports.double(P_OUT(), P_IN()), 3000)
    Wasm.assertZeroAlloc("addPoint", wasm, () => wasm.exports.addPoint(P_OUT(), P_IN(), P_IN()), 3000)
    wasm.writeU256(out0(), G_X)
    wasm.writeU256(out1(), G_Y)
    Wasm.assertZeroAlloc("addMixed", wasm, () => wasm.exports.addMixed(P_OUT(), P_IN(), out0(), out1()), 3000)
  })

  test("toAffine / negate no causan memory.grow", () => {
    Wasm.assertZeroAlloc("toAffine", wasm, () => wasm.exports.toAffine(out0(), P_IN()), 2000)
    Wasm.assertZeroAlloc("negate", wasm, () => wasm.exports.negate(P_OUT(), P_IN()), 3000)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD (throughput)
// ═══════════════════════════════════════════════════════════════════════════

describe("point (secp256k1) — velocidad", () => {
  beforeAll(async () => {
    wasm = await loadModule("bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    writeJac(P_IN(), G_X, G_Y)
    wasm.writeU256(out0(), G_X)
    wasm.writeU256(out1(), G_Y)
  }, 120_000)

  test("métricas de compilación (profile bench)", () => {
    Wasm.printCompileStats(lastCompile, "point · bench")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
  })

  test("throughput de operaciones de punto", () => {
    const results = Wasm.benchSuite(
      [
        { name: "double", fn: () => wasm.exports.double(P_OUT(), P_IN()), iterations: 200_000 },
        { name: "addPoint", fn: () => wasm.exports.addPoint(P_OUT(), P_IN(), P_IN()), iterations: 200_000 },
        { name: "addMixed", fn: () => wasm.exports.addMixed(P_OUT(), P_IN(), out0(), out1()), iterations: 200_000 },
        { name: "negate", fn: () => wasm.exports.negate(P_OUT(), P_IN()), iterations: 1_000_000 },
        { name: "toAffine", fn: () => wasm.exports.toAffine(out0(), P_IN()), iterations: 50_000 }
      ],
      100_000,
      { warmup: 2000, runs: 3 }
    )
    Wasm.printResults(results)
    const dbl = results.find((r) => r.name === "double")!
    expect(dbl.nsPerOp).toBeLessThan(5000)
    expect(dbl.cvPct).toBeLessThan(15)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) COMPARACIÓN DE BUILDS Y ALGORITMOS (métricas completas)
// ═══════════════════════════════════════════════════════════════════════════

describe("point (secp256k1) — comparación", () => {
  test("builds -O1 vs -O3: compile + size + speed (double)", async () => {
    const report = await Wasm.benchCompileCompare(
      ENTRY,
      { label: "O1", opts: "test+o1" },
      { label: "O3", opts: "bench+o3" },
      (w) => {
        const i = w.num("PARAM_IN_PTR")
        const o = w.num("PARAM_OUT_PTR")
        w.writeU256(i, G_X)
        w.writeU256(i + 32, G_Y)
        w.writeU256(i + 64, 1n)
        return () => w.exports.double(o, i)
      },
      200_000,
      { warmup: 2000, runs: 5 }
    )
    Wasm.printCompileCompare(report)
    expect(report.a.sizeBytes).toBeGreaterThan(0)
    expect(report.b.sizeBytes).toBeGreaterThan(0)
    expect(report.speedRatio).toBeGreaterThan(0.3)
    expect(report.speedRatio).toBeLessThan(3.0)
  }, 120_000)

  test("paridad de correctitud -O1 == -O3 (double(G) = 2G)", async () => {
    const w1 = await Wasm.load((await Wasm.compile(ENTRY, "test+o1")).binary)
    const w3 = await Wasm.load((await Wasm.compile(ENTRY, "bench+o3")).binary)
    const i1 = w1.num("PARAM_IN_PTR"),
      o1 = w1.num("PARAM_OUT_PTR")
    const i3 = w3.num("PARAM_IN_PTR"),
      o3 = w3.num("PARAM_OUT_PTR")
    w1.writeU256(i1, G_X)
    w1.writeU256(i1 + 32, G_Y)
    w1.writeU256(i1 + 64, 1n)
    w3.writeU256(i3, G_X)
    w3.writeU256(i3 + 32, G_Y)
    w3.writeU256(i3 + 64, 1n)
    w1.exports.double(o1, i1)
    w1.exports.toAffine(i1, o1)
    w3.exports.double(o3, i3)
    w3.exports.toAffine(i3, o3)
    expect(w1.readU256(i1)).toBe(G2_X)
    expect(w3.readU256(i3)).toBe(G2_X)
    expect(w1.readU256(i1)).toBe(w3.readU256(i3))
    expect(w1.readU256(i1 + 32)).toBe(w3.readU256(i3 + 32))
  }, 120_000)

  test("algoritmos: addPoint vs addMixed (P=3G, Q=G)", async () => {
    const r = Wasm.benchCompare(
      "addPoint",
      () => {
        writeJac(P_IN(), G3_X, G3_Y)
        writeJac(P_OUT(), G_X, G_Y)
        wasm.exports.addPoint(P_IN(), P_IN(), P_OUT())
      },
      "addMixed",
      () => {
        writeJac(P_IN(), G3_X, G3_Y)
        wasm.writeU256(P_OUT(), G_X)
        wasm.writeU256(P_OUT() + 32, G_Y)
        wasm.exports.addMixed(P_IN(), P_IN(), P_OUT(), P_OUT() + 32)
      },
      200_000,
      { warmup: 2000, runs: 3 }
    )
    console.log(`  Ganador: ${r.winner}  (ratio addPoint/addMixed = ${r.ratio.toFixed(2)}x)`)
    expect(r.winner).toBe("addMixed") // addMixed ahorra las mults de Z2 (Q afín)
    expect(r.ratio).toBeGreaterThan(1.0)
  }, 120_000)
})
