/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  field.test.ts — Correctitud + memoria + velocidad + comparación (mod P)
 *  con MÉTRICAS COMPLETAS: tiempo de compilación, tamaño de binario, throughput.
 * ═══════════════════════════════════════════════════════════════════════════
 *  Corre con:  bun test test/field.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult, type CompileOptions } from "./utils/wasm"

const ENTRY = "assembly/secp256k1/field/index.ts"
const G_X_BE = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
const P = (1n << 256n) - (1n << 32n) - 977n

let wasm: WasmInstance
let lastCompile: CompileResult
let IN: number
let OUT: number
const S = 32
const in0 = () => IN
const in1 = () => IN + S
const out0 = () => OUT
const out1 = () => OUT + S

/** Compila + carga, guardando las métricas de compilación en `lastCompile`. */
async function loadModule(opts: CompileOptions | string = {}): Promise<WasmInstance> {
  lastCompile = await Wasm.compile(ENTRY, opts)
  return Wasm.load(lastCompile.binary)
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("field (mod P) — correctitud", () => {
  beforeAll(async () => {
    wasm = await loadModule() // profile "test", mode "memory"
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("métricas de compilación (profile test)", () => {
    Wasm.printCompileStats(lastCompile, "field · test")
    expect(lastCompile.mode).toBe("memory")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
    expect(lastCompile.binary.byteLength).toBe(lastCompile.sizeBytes)
    expect(lastCompile.compileTimeMs).toBeGreaterThanOrEqual(0)
  })

  test("WASM cargado y punteros de I/O disponibles", () => {
    expect(wasm.exports.mulMod).toBeFunction()
    expect(Number.isFinite(IN)).toBe(true)
    expect(Number.isFinite(OUT)).toBe(true)
    expect(OUT).toBeGreaterThan(IN)
  })

  test("fromBytesPtr / toBytesPtr son inversos (G_X)", () => {
    const bytes = Wasm.hexToBytes(G_X_BE)
    wasm.write(in0(), bytes)
    wasm.exports.fromBytesPtr(out0(), in0())
    wasm.exports.toBytesPtr(out0(), in0())
    expect(Wasm.bytesToHex(wasm.read(in0(), 32))).toBe(G_X_BE)
  })

  test("add(2, 3) = 5", () => {
    wasm.writeU256(in0(), 2n)
    wasm.writeU256(in1(), 3n)
    wasm.exports.add(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(5n)
  })

  test("sub(3, 2) = 1", () => {
    wasm.writeU256(in0(), 3n)
    wasm.writeU256(in1(), 2n)
    wasm.exports.sub(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(1n)
  })

  test("sub(2, 3) envuelve mod P (y sumando 3 vuelve a 2)", () => {
    wasm.writeU256(in0(), 2n)
    wasm.writeU256(in1(), 3n)
    wasm.exports.sub(out0(), in0(), in1())
    expect(wasm.readU256(out0())).not.toBe(0n)
    wasm.writeU256(in1(), 3n)
    wasm.exports.add(out1(), out0(), in1())
    expect(wasm.readU256(out1())).toBe(2n)
  })

  test("mulMod por la identidad: mulMod(a, 1) = a", () => {
    wasm.writeU256(in0(), 0x123456789abcdefn)
    wasm.writeU256(in1(), 1n)
    wasm.exports.mulMod(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(0x123456789abcdefn)
  })

  test("mulMod(2, 3) = 6", () => {
    wasm.writeU256(in0(), 2n)
    wasm.writeU256(in1(), 3n)
    wasm.exports.mulMod(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(6n)
  })

  test("mulMod(P−1, P−1) = 1 (operandos de 256 bits completos)", () => {
    wasm.writeU256(in0(), P - 1n)
    wasm.writeU256(in1(), P - 1n)
    wasm.exports.mulMod(out0(), in0(), in1())
    expect(wasm.readU256(out0())).toBe(1n)
  })

  test("sqrMod(x) == mulMod(x, x) con x = P−1 (detecta bug de Col 6)", () => {
    const x = P - 1n
    wasm.writeU256(in0(), x)
    wasm.exports.sqrMod(out0(), in0())
    const sq = wasm.read(out0(), 32)
    wasm.writeU256(in0(), x)
    wasm.writeU256(in1(), x)
    wasm.exports.mulMod(out0(), in0(), in1())
    expect(Wasm.bytesToHex(wasm.read(out0(), 32))).toBe(Wasm.bytesToHex(sq))
  })

  test("sqrMod(x) == mulMod(x, x)", () => {
    const x = 0xdeadbeefcafebaben
    wasm.writeU256(in0(), x)
    wasm.exports.sqrMod(out0(), in0())
    const sq = wasm.read(out0(), 32)
    wasm.writeU256(in0(), x)
    wasm.writeU256(in1(), x)
    wasm.exports.mulMod(out0(), in0(), in1())
    expect(Wasm.bytesToHex(wasm.read(out0(), 32))).toBe(Wasm.bytesToHex(sq))
  })

  test("reduce(mul(a, b)) == mulMod(a, b)", () => {
    const a = 0x1111111111111111n
    const b = 0x2222222222222222n
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

  test("modInverse(2) · 2 ≡ 1 (mod P)", () => {
    wasm.writeU256(in0(), 2n)
    wasm.exports.modInverse(out0(), in0())
    wasm.exports.mulMod(out1(), out0(), in0())
    expect(wasm.readU256(out1())).toBe(1n)
  })

  test("modInverse(G_X) · G_X ≡ 1 (mod P)", () => {
    const gx = BigInt("0x" + G_X_BE)
    wasm.writeU256(in0(), gx)
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

describe("field (mod P) — memoria", () => {
  beforeAll(async () => {
    wasm = await loadModule() // cache RAM hit (mismo profile "test")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("mulMod no causa memory.grow", () => {
    wasm.writeU256(in0(), 0xdeadbeefn)
    wasm.writeU256(in1(), 0xcafebaben)
    Wasm.assertZeroAlloc("mulMod", wasm, () => wasm.exports.mulMod(out0(), in0(), in1()), 5000)
  })

  test("modInverse no causa memory.grow (arena save/restore)", () => {
    wasm.writeU256(in0(), 12345n)
    Wasm.assertZeroAlloc("modInverse", wasm, () => wasm.exports.modInverse(out0(), in0()), 2000)
  })

  test("add/sub/mul no causan memory.grow", () => {
    wasm.writeU256(in0(), 999n)
    wasm.writeU256(in1(), 1000n)
    Wasm.assertZeroAlloc(
      "add+sub+mul",
      wasm,
      () => {
        wasm.exports.add(out0(), in0(), in1())
        wasm.exports.sub(out1(), in0(), in1())
        wasm.exports.mul(OUT, in0(), in1())
      },
      5000
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD (throughput)
// ═══════════════════════════════════════════════════════════════════════════

describe("field (mod P) — velocidad", () => {
  beforeAll(async () => {
    wasm = await loadModule("bench") // profile "bench"
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.writeU256(in0(), 0xdeadbeefcafebaben)
    wasm.writeU256(in1(), 0x1234567890abcdefn)
  }, 120_000)

  test("métricas de compilación (profile bench)", () => {
    Wasm.printCompileStats(lastCompile, "field · bench")
    expect(lastCompile.sizeBytes).toBeGreaterThan(0)
  })

  test("throughput de operaciones", () => {
    const results = Wasm.benchSuite(
      [
        { name: "add", fn: () => wasm.exports.add(out0(), in0(), in1()), iterations: 2_000_000 },
        { name: "sub", fn: () => wasm.exports.sub(out0(), in0(), in1()), iterations: 2_000_000 },
        { name: "mulMod", fn: () => wasm.exports.mulMod(out0(), in0(), in1()), iterations: 1_000_000 },
        { name: "sqrMod", fn: () => wasm.exports.sqrMod(out0(), in0()), iterations: 1_000_000 },
        { name: "mul512", fn: () => wasm.exports.mul(OUT, in0(), in1()), iterations: 1_000_000 },
        { name: "reduce", fn: () => wasm.exports.reduce(in0(), OUT), iterations: 1_000_000 },
        { name: "modInv", fn: () => wasm.exports.modInverse(out0(), in0()), iterations: 50_000 }
      ],
      100_000,
      { warmup: 2000, runs: 3 }
    )
    Wasm.printResults(results)

    const mulMod = results.find((r) => r.name === "mulMod")!
    expect(mulMod.nsPerOp).toBeLessThan(1000) // sanity: < 1 µs
    expect(mulMod.cvPct).toBeLessThan(15) // medición estable
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) COMPARACIÓN DE BUILDS Y ALGORITMOS (métricas completas)
// ═══════════════════════════════════════════════════════════════════════════

describe("field (mod P) — comparación", () => {
  // Compara DOS COMPILACIONES: tiempo de compilación, tamaño y velocidad.
  test("builds -O1 vs -O3: compile + size + speed", async () => {
    const report = await Wasm.benchCompileCompare(
      ENTRY,
      { label: "O1", opts: "test+o1" },
      { label: "O3", opts: "bench+o3" },
      (w) => {
        const i = w.num("PARAM_IN_PTR")
        const o = w.num("PARAM_OUT_PTR")
        w.writeU256(i, 0xdeadbeefcafebaben)
        w.writeU256(i + 32, 0x1234567890abcdefn)
        return () => w.exports.mulMod(o, i, i + 32)
      },
      500_000,
      { warmup: 5000, runs: 5 }
    )
    Wasm.printCompileCompare(report)

    expect(report.a.sizeBytes).toBeGreaterThan(0)
    expect(report.b.sizeBytes).toBeGreaterThan(0)
    expect(report.speedRatio).toBeGreaterThan(0.3)
    expect(report.speedRatio).toBeLessThan(3.0)
  }, 120_000)

  // Paridad de correctitud entre builds (usa el cache RAM llenado arriba).
  test("paridad de correctitud -O1 == -O3 (mulMod(P−1,P−1)=1)", async () => {
    const w1 = await Wasm.load((await Wasm.compile(ENTRY, "test+o1")).binary)
    const w3 = await Wasm.load((await Wasm.compile(ENTRY, "bench+o3")).binary)
    const i1 = w1.num("PARAM_IN_PTR"),
      o1 = w1.num("PARAM_OUT_PTR")
    const i3 = w3.num("PARAM_IN_PTR"),
      o3 = w3.num("PARAM_OUT_PTR")
    w1.writeU256(i1, P - 1n)
    w1.writeU256(i1 + 32, P - 1n)
    w3.writeU256(i3, P - 1n)
    w3.writeU256(i3 + 32, P - 1n)
    w1.exports.mulMod(o1, i1, i1 + 32)
    w3.exports.mulMod(o3, i3, i3 + 32)
    expect(w1.readU256(o1)).toBe(1n)
    expect(w3.readU256(o3)).toBe(1n)
    expect(Wasm.bytesToHex(w1.read(o1, 32))).toBe(Wasm.bytesToHex(w3.read(o3, 32)))
  }, 120_000)

  // Compara ALGORITMOS (mismo build): sqrMod (10 mult) vs mulMod(a,a) (16 mult).
  test("algoritmos: sqrMod vs mulMod(a,a) — la simetría gana", async () => {
    const w = await Wasm.load((await Wasm.compile(ENTRY, "bench+o3")).binary)
    const i = w.num("PARAM_IN_PTR")
    const o = w.num("PARAM_OUT_PTR")
    w.writeU256(i, 0xdeadbeefcafebaben)
    const r = Wasm.benchCompare(
      "sqrMod",
      () => w.exports.sqrMod(o, i),
      "mulMod(a,a)",
      () => w.exports.mulMod(o, i, i),
      1_000_000,
      { warmup: 5000, runs: 5 }
    )
    console.log(`  Ganador: ${r.winner}  (ratio sqr/mul = ${r.ratio.toFixed(2)}x)`)
    expect(r.winner).toBe("sqrMod")
    expect(r.ratio).toBeLessThan(1.0)
  }, 120_000)
})
