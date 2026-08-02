/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  secp256k1.test.ts — Integración de la API pública (index.ts)
 * ═══════════════════════════════════════════════════════════════════════════
 *  Valida que todos los módulos funcionen JUNTOS a través de la superficie
 *  pública, con métricas de compilación.
 *  Corre con:  bun test test/secp256k1.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/secp256k1/index.ts"
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const G_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
const G_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
const G2_X = 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5n

let wasm: WasmInstance
let info: CompileResult
let IN: number
let OUT: number
const S = 32
const out0 = () => OUT
const out1 = () => OUT + S

describe("secp256k1 — integración (API pública)", () => {
  beforeAll(async () => {
    info = await Wasm.compile(ENTRY)
    wasm = await Wasm.load(info.binary)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 240_000)

  test("métricas de compilación (index.ts)", () => {
    Wasm.printCompileStats(info, "secp256k1 · index")
    expect(info.sizeBytes).toBeGreaterThan(0)
    expect(info.mode).toBe("memory")
  })

  test("superficie pública expuesta", () => {
    expect(wasm.exports.multiplyG).toBeFunction()
    expect(wasm.exports.glvMul).toBeFunction()
    expect(wasm.exports.double).toBeFunction()
    expect(wasm.exports.addPoint).toBeFunction()
    expect(wasm.exports.addMixed).toBeFunction()
    expect(wasm.exports.toAffine).toBeFunction()
    expect(wasm.exports.decompose).toBeFunction()
    expect(wasm.exports.wnafCompute).toBeFunction()
    expect(wasm.exports.generator).toBeFunction()
  })

  test("multiplyG(1) = G  (vía API pública)", () => {
    wasm.writeU256(out0(), 1n)
    wasm.exports.multiplyG(IN, out0())
    wasm.exports.toAffine(out1(), IN)
    expect(wasm.readU256(out1())).toBe(G_X)
    expect(wasm.readU256(out1() + 32)).toBe(G_Y)
  })

  test("double(G) = 2G  (vía API pública)", () => {
    const g: number = wasm.exports.generator()
    wasm.exports.double(IN, g)
    wasm.exports.toAffine(out1(), IN)
    expect(wasm.readU256(out1())).toBe(G2_X)
  })

  test("paridad: multiplyG(k) == glvMul(k, G)", () => {
    const ks = [7n, 12345n, 0xdeadbeefcafebaben, N - 1n]
    for (const k of ks) {
      wasm.writeU256(out0(), k)
      // tabla fija
      wasm.exports.multiplyG(IN, out0())
      wasm.exports.toAffine(out1(), IN)
      const xGen = wasm.readU256(out1())
      const yGen = wasm.readU256(out1() + 32)
      // GLV (oráculo)
      wasm.exports.glvMul(IN, wasm.exports.generator(), out0())
      wasm.exports.toAffine(out0(), IN)
      expect(xGen).toBe(wasm.readU256(out0()))
      expect(yGen).toBe(wasm.readU256(out0() + 32))
    }
  })

  test("addPoint(G, G) == double(G)  (vía API pública)", () => {
    const g: number = wasm.exports.generator()
    wasm.exports.double(IN, g)
    const dbl = wasm.read(IN, 96)
    wasm.exports.addPoint(IN, g, g)
    expect(Wasm.bytesToHex(wasm.read(IN, 96))).toBe(Wasm.bytesToHex(dbl))
  })

  test("zero-alloc: multiplyG no causa memory.grow", () => {
    wasm.writeU256(out0(), 999n)
    Wasm.assertZeroAlloc("multiplyG", wasm, () => wasm.exports.multiplyG(IN, out0()), 200)
  })
})