/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  keccak256.test.ts — Correctitud + memoria + velocidad de Keccak-256
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores: Ethereum (pycryptodome keccak_256), function selectors (ERC-20),
 *            edge cases de rate boundary (136 B), multi-bloque.
 *  Corre con:  bun test test/keccak256.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/hash/keccak256.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const enc = (s: string): Uint8Array => new TextEncoder().encode(s)
const hex = (bytes: Uint8Array): string => Wasm.bytesToHex(bytes)

// ═══════════════════════════════════════════════════════════════════════════
// 0) COMPILACIÓN
// ═══════════════════════════════════════════════════════════════════════════

describe("keccak256 — compilación", () => {
  test("compilar y reportar stats", async () => {
    const cr: CompileResult = await Wasm.compile(ENTRY, { profile: "bench" })
    Wasm.printCompileStats(cr, "bench")
    expect(cr.sizeBytes).toBeGreaterThan(1024)
    expect(cr.sizeBytes).toBeLessThan(65536)
    expect(cr.compileTimeMs).toBeGreaterThan(0)
    // WASM magic
    expect(cr.binary[0]).toBe(0x00)
    expect(cr.binary[1]).toBe(0x61)
    expect(cr.binary[2]).toBe(0x73)
    expect(cr.binary[3]).toBe(0x6d)
  }, 120_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("keccak256 — correctitud", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("WASM cargado — exports presentes", () => {
    expect(wasm.exports.keccak256_hash_raw).toBeFunction()
    expect(wasm.exports.keccak256_create_ctx).toBeFunction()
    expect(wasm.exports.keccak256_update_raw).toBeFunction()
    expect(wasm.exports.keccak256_final_raw).toBeFunction()
  })

  // ── Vectores generales (pycryptodome keccak_256) ────────────────────────
  const generalVectors: [string, string, string][] = [
    ["vacío", "", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"],
    ["abc", "abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"],
    ["testing", "testing", "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"],
    ["hello world", "hello world", "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"],
  ]

  for (const [name, msg, want] of generalVectors) {
    test(`keccak256(${name})`, () => {
      const m = enc(msg)
      wasm.write(IN, m)
      wasm.exports.keccak256_hash_raw(OUT, IN, m.length)
      expect(hex(wasm.read(OUT, 32))).toBe(want)
    })
  }

  // ── Ethereum function selectors (ERC-20) ────────────────────────────────
  test("selector: transfer(address,uint256) = 0xa9059cbb", () => {
    const sig = enc("transfer(address,uint256)")
    wasm.write(IN, sig)
    wasm.exports.keccak256_hash_raw(OUT, IN, sig.length)
    const hash = hex(wasm.read(OUT, 32))
    expect(hash).toBe("a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b")
    // Selector = primeros 4 bytes
    expect(hash.slice(0, 8)).toBe("a9059cbb")
  })

  test("selector: balanceOf(address) = 0x70a08231", () => {
    const sig = enc("balanceOf(address)")
    wasm.write(IN, sig)
    wasm.exports.keccak256_hash_raw(OUT, IN, sig.length)
    const hash = hex(wasm.read(OUT, 32))
    expect(hash).toBe("70a08231b98ef4ca268c9cc3f6b4590e4bfec28280db06bb5d45e689f2a360be")
    expect(hash.slice(0, 8)).toBe("70a08231")
  })

  test("selector: approve(address,uint256) = 0x095ea7b3", () => {
    const sig = enc("approve(address,uint256)")
    wasm.write(IN, sig)
    wasm.exports.keccak256_hash_raw(OUT, IN, sig.length)
    const hash = hex(wasm.read(OUT, 32))
    expect(hash).toBe("095ea7b334ae44009aa867bfb386f5c3b4b443ac6f0ee573fa91c4608fbadfba")
    expect(hash.slice(0, 8)).toBe("095ea7b3")
  })

  // ── Rate boundary (rate = 136 bytes) ────────────────────────────────────
  const rateBoundary: [string, number, number, string][] = [
    ["135 B (rate-1)", 135, 0x61, "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"],
    ["136 B (rate exacto)", 136, 0x61, "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"],
    ["137 B (rate+1)", 137, 0x61, "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39"],
  ]

  for (const [name, len, fill, want] of rateBoundary) {
    test(`keccak256(${name})`, () => {
      const m = new Uint8Array(len).fill(fill)
      wasm.write(IN, m)
      wasm.exports.keccak256_hash_raw(OUT, IN, m.length)
      expect(hex(wasm.read(OUT, 32))).toBe(want)
    })
  }

  // ── Multi-bloque ────────────────────────────────────────────────────────
  const multiBlock: [string, number, number, string][] = [
    ["200 B", 200, 0x62, "dbd0c053f63c64c156e3a86a2f0a64fa9cfaa347e61e7d28f7b591b4a6d5d17d"],
    ["272 B (2 bloques exactos)", 272, 0x63, "ad7ace922c13f7bacdf9cc8cbe845bb30e86e28c2e181c26d2ca3881d9fa8aea"],
    ["273 B (2 bloques + 1)", 273, 0x63, "1c76b21cc06334b41a54e20518fc2c3ac707017ddb23712a1a575306d2c1cd05"],
    ["1024 B", 1024, 0x64, "d775318e37e261a9014e32af163f0f7a7bf6c4854c85e313934e8400388dfd00"],
  ]

  for (const [name, len, fill, want] of multiBlock) {
    test(`keccak256(${name})`, () => {
      const m = new Uint8Array(len).fill(fill)
      wasm.write(IN, m)
      wasm.exports.keccak256_hash_raw(OUT, IN, m.length)
      expect(hex(wasm.read(OUT, 32))).toBe(want)
    })
  }

  // ── Hash de un hash (composición, como en Ethereum) ─────────────────────
  test("keccak256(SHA256('test')) — composición", () => {
    // SHA256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    const sha256OfTest = Wasm.hexToBytes("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
    wasm.write(IN, sha256OfTest)
    wasm.exports.keccak256_hash_raw(OUT, IN, 32)
    expect(hex(wasm.read(OUT, 32))).toBe("18d9fd51f282d2d134197b37b6f37b19a5179e2f2b345a0fe9e22578ea6f508e")
  })

  // ── Streaming == one-shot ───────────────────────────────────────────────
  test("streaming (3 fragmentos) == one-shot", () => {
    const msg = new Uint8Array(200).fill(0x62)
    wasm.write(IN, msg)
    wasm.exports.keccak256_hash_raw(OUT, IN, msg.length)
    const oneshot = hex(wasm.read(OUT, 32))
    // streaming: ctx en IN+256
    const ctx = IN + 256
    wasm.exports.keccak256_create_ctx(ctx)
    wasm.exports.keccak256_update_raw(ctx, IN, 50)
    wasm.exports.keccak256_update_raw(ctx, IN + 50, 100)
    wasm.exports.keccak256_update_raw(ctx, IN + 150, 50)
    wasm.exports.keccak256_final_raw(ctx, OUT)
    expect(hex(wasm.read(OUT, 32))).toBe(oneshot)
  })

  test("streaming byte-a-byte == one-shot", () => {
    const msg = enc("testing")
    wasm.write(IN, msg)
    wasm.exports.keccak256_hash_raw(OUT, IN, msg.length)
    const oneshot = hex(wasm.read(OUT, 32))
    // byte-a-byte
    const ctx = IN + 256
    wasm.exports.keccak256_create_ctx(ctx)
    for (let i = 0; i < msg.length; i++) {
      wasm.exports.keccak256_update_raw(ctx, IN + i, 1)
    }
    wasm.exports.keccak256_final_raw(ctx, OUT)
    expect(hex(wasm.read(OUT, 32))).toBe(oneshot)
  })

  test("streaming en boundary de rate (136+136+1)", () => {
    const msg = new Uint8Array(273).fill(0x63)
    wasm.write(IN, msg)
    wasm.exports.keccak256_hash_raw(OUT, IN, msg.length)
    const oneshot = hex(wasm.read(OUT, 32))
    // ✅ FIX: ctx DESPUÉS del mensaje (273 → align8 = 280)
    const ctx = IN + 280
    wasm.exports.keccak256_create_ctx(ctx)
    wasm.exports.keccak256_update_raw(ctx, IN, 136)
    wasm.exports.keccak256_update_raw(ctx, IN + 136, 136)
    wasm.exports.keccak256_update_raw(ctx, IN + 272, 1)
    wasm.exports.keccak256_final_raw(ctx, OUT)
    expect(hex(wasm.read(OUT, 32))).toBe(oneshot)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("keccak256 — memoria", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("one-shot no causa memory.grow", () => {
    const msg = enc("abc")
    wasm.write(IN, msg)
    Wasm.assertZeroAlloc("keccak256", wasm, () => wasm.exports.keccak256_hash_raw(OUT, IN, msg.length), 5000)
  })

  test("one-shot 1KB no causa memory.grow", () => {
    const msg = new Uint8Array(1024).fill(0x61)
    wasm.write(IN, msg)
    Wasm.assertZeroAlloc("keccak256-1KB", wasm, () => wasm.exports.keccak256_hash_raw(OUT, IN, 1024), 2000)
  })

  test("streaming no causa memory.grow", () => {
    const ctx = IN + 256
    const msg = new Uint8Array(300).fill(0x42)
    wasm.write(IN, msg)
    Wasm.assertZeroAlloc(
      "keccak256-stream",
      wasm,
      () => {
        wasm.exports.keccak256_create_ctx(ctx)
        wasm.exports.keccak256_update_raw(ctx, IN, 300)
        wasm.exports.keccak256_final_raw(ctx, OUT)
      },
      2000,
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD
// ═══════════════════════════════════════════════════════════════════════════

describe("keccak256 — velocidad", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY, "bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("throughput (1 KB)", () => {
    const msg = new Uint8Array(1024).fill(0x61)
    wasm.write(IN, msg)
    const r = Wasm.benchSpeed("keccak256(1KB)", 25_000, () => wasm.exports.keccak256_hash_raw(OUT, IN, 1024), {
      warmup: 200,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(50_000) // < 50 µs por 1 KB
    expect(r.cvPct).toBeLessThan(15)
  })

  test("latencia (32 B = input típico de hash)", () => {
    const msg = new Uint8Array(32).fill(0x62)
    wasm.write(IN, msg)
    const r = Wasm.benchSpeed("keccak256(32B)", 100_000, () => wasm.exports.keccak256_hash_raw(OUT, IN, 32), {
      warmup: 1000,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(5_000) // < 5 µs por hash de 32 B
  })

  test("latencia function selector (típico Ethereum)", () => {
    const sig = enc("transfer(address,uint256)")
    wasm.write(IN, sig)
    const r = Wasm.benchSpeed(
      "keccak256(selector)",
      100_000,
      () => wasm.exports.keccak256_hash_raw(OUT, IN, sig.length),
      { warmup: 1000, runs: 3 },
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(5_000)
  })

  test("throughput (1 KB)", () => {
    const msg = new Uint8Array(1024).fill(0x61)
    wasm.write(IN, msg)
    const r = Wasm.benchSpeed("keccak256(1KB)", 25_000, () => wasm.exports.keccak256_hash_raw(OUT, IN, 1024), {
      warmup: 200,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(50_000) // < 50 µs por 1 KB
    expect(r.cvPct).toBeLessThan(15)
  })
})
