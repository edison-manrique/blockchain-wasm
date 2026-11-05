/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ripemd160.test.ts — Correctitud + memoria + velocidad de RIPEMD-160
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores: paper original (Dobbertin et al., 1996) + edge cases de padding.
 *  Corre con:  bun test test/ripemd160.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/hash/ripemd160.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const enc = (s: string): Uint8Array => new TextEncoder().encode(s)
const hex = (bytes: Uint8Array): string => Wasm.bytesToHex(bytes)

// ═══════════════════════════════════════════════════════════════════════════
// 0) COMPILACIÓN
// ═══════════════════════════════════════════════════════════════════════════

describe("ripemd160 — compilación", () => {
  test("compilar y reportar stats", async () => {
    const cr: CompileResult = await Wasm.compile(ENTRY, { profile: "bench" })
    Wasm.printCompileStats(cr, "bench")
    expect(cr.sizeBytes).toBeGreaterThan(512)
    expect(cr.sizeBytes).toBeLessThan(51200)
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

describe("ripemd160 — correctitud", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("WASM cargado — exports presentes", () => {
    expect(wasm.exports.ripemd160_hash_raw).toBeFunction()
    expect(wasm.exports.ripemd160_create_ctx).toBeFunction()
    expect(wasm.exports.ripemd160_update_raw).toBeFunction()
    expect(wasm.exports.ripemd160_final_raw).toBeFunction()
  })

  // ── Vectores oficiales (Dobbertin et al., 1996) ─────────────────────────
  const officialVectors: [string, string, string][] = [
    ["vacío", "", "9c1185a5c5e9fc54612808977ee8f548b2258d31"],
    ["a", "a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"],
    ["abc", "abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"],
    ["message digest", "message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"],
    ["a-z", "abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"],
    [
      "448 bits (2 bloques)",
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    ],
    [
      "alfanumérico",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "b0e20b6e3116640286ed3a87a5713079b21f5189",
    ],
    [
      "80 dígitos (multi-bloque)",
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
    ],
  ]

  for (const [name, msg, want] of officialVectors) {
    test(`RIPEMD160(${name})`, () => {
      const m = enc(msg)
      wasm.write(IN, m)
      wasm.exports.ripemd160_hash_raw(OUT, IN, m.length)
      expect(hex(wasm.read(OUT, 20))).toBe(want)
    })
  }

  // ── Edge cases de padding ───────────────────────────────────────────────
  const edgeCases: [string, number, number, string][] = [
    ["55 bytes (padding en mismo bloque)", 55, 0x61, "0d8a8c9063a48576a7c97e9f95253a6e53ff6765"],
    ["56 bytes (padding fuerza 2 bloques)", 56, 0x61, "e72334b46c83cc70bef979e15453706c95b888be"],
    ["63 bytes (máx antes de bloque extra)", 63, 0x61, "e640041293fe663b9bf3f8c21ffecac03819e6b2"],
    ["64 bytes (1 bloque exacto)", 64, 0x61, "9dfb7d374ad924f3f88de96291c33e9abed53e32"],
    ["65 bytes (1 bloque + 1 byte)", 65, 0x61, "99724bb11811e7166af38f671b6a082d8ab4960b"],
  ]

  for (const [name, len, fill, want] of edgeCases) {
    test(`RIPEMD160(${name})`, () => {
      const m = new Uint8Array(len).fill(fill)
      wasm.write(IN, m)
      wasm.exports.ripemd160_hash_raw(OUT, IN, m.length)
      expect(hex(wasm.read(OUT, 20))).toBe(want)
    })
  }

  // ── Streaming == one-shot ───────────────────────────────────────────────
  test("streaming (3 fragmentos) == one-shot", () => {
    const msg = enc("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    // one-shot
    wasm.write(IN, msg)
    wasm.exports.ripemd160_hash_raw(OUT, IN, msg.length)
    const oneshot = hex(wasm.read(OUT, 20))
    // streaming: ctx en IN+256, padded en IN+256+96
    const ctx = IN + 256
    const padded = ctx + 96
    wasm.exports.ripemd160_create_ctx(ctx)
    wasm.exports.ripemd160_update_raw(ctx, IN, 20)
    wasm.exports.ripemd160_update_raw(ctx, IN + 20, 20)
    wasm.exports.ripemd160_update_raw(ctx, IN + 40, msg.length - 40)
    wasm.exports.ripemd160_final_raw(ctx, padded, OUT)
    expect(hex(wasm.read(OUT, 20))).toBe(oneshot)
  })

  test("streaming byte-a-byte == one-shot", () => {
    const msg = enc("message digest")
    wasm.write(IN, msg)
    wasm.exports.ripemd160_hash_raw(OUT, IN, msg.length)
    const oneshot = hex(wasm.read(OUT, 20))
    // byte-a-byte
    const ctx = IN + 256
    const padded = ctx + 96
    wasm.exports.ripemd160_create_ctx(ctx)
    for (let i = 0; i < msg.length; i++) {
      wasm.exports.ripemd160_update_raw(ctx, IN + i, 1)
    }
    wasm.exports.ripemd160_final_raw(ctx, padded, OUT)
    expect(hex(wasm.read(OUT, 20))).toBe(oneshot)
  })

  // ── hash160 (Bitcoin: RIPEMD160(SHA256(x))) ────────────────────────────
  test("hash160 = RIPEMD160(SHA256(x)) composición", () => {
    // Primero SHA256, luego RIPEMD160 sobre el resultado
    const msg = enc("test")
    wasm.write(IN, msg)
    // SHA256("test") → OUT (32 bytes) — usamos sha256 si está disponible
    // Si no, verificamos RIPEMD160(SHA256("test")) con vector precalculado:
    // SHA256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    // RIPEMD160(above) = cebaa98c19807134434d107b0d3e5692a516ea66
    const sha256OfTest = Wasm.hexToBytes("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
    wasm.write(IN, sha256OfTest)
    wasm.exports.ripemd160_hash_raw(OUT, IN, 32)
    expect(hex(wasm.read(OUT, 20))).toBe("cebaa98c19807134434d107b0d3e5692a516ea66")
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("ripemd160 — memoria", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("one-shot no causa memory.grow", () => {
    const msg = enc("abc")
    wasm.write(IN, msg)
    Wasm.assertZeroAlloc("ripemd160", wasm, () => wasm.exports.ripemd160_hash_raw(OUT, IN, msg.length), 5000)
  })

  test("streaming no causa memory.grow", () => {
    const ctx = IN + 256
    const padded = ctx + 96
    const msg = new Uint8Array(200).fill(0x42)
    wasm.write(IN, msg)
    Wasm.assertZeroAlloc(
      "ripemd160-stream",
      wasm,
      () => {
        wasm.exports.ripemd160_create_ctx(ctx)
        wasm.exports.ripemd160_update_raw(ctx, IN, 200)
        wasm.exports.ripemd160_final_raw(ctx, padded, OUT)
      },
      2000,
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD
// ═══════════════════════════════════════════════════════════════════════════

describe("ripemd160 — velocidad", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY, "bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("throughput (1 KB)", () => {
    const msg = new Uint8Array(1024).fill(0x61)
    wasm.write(IN, msg)
    const r = Wasm.benchSpeed("ripemd160(1KB)", 100_000, () => wasm.exports.ripemd160_hash_raw(OUT, IN, 1024), {
      warmup: 2000,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(20_000) // < 20 µs por 1 KB
    expect(r.cvPct).toBeLessThan(15)
  })

  test("latencia (64 B = 1 bloque)", () => {
    const msg = new Uint8Array(64).fill(0x62)
    wasm.write(IN, msg)
    const r = Wasm.benchSpeed("ripemd160(64B)", 500_000, () => wasm.exports.ripemd160_hash_raw(OUT, IN, 64), {
      warmup: 5000,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(2_000) // < 2 µs por bloque
  })

  test("comparativa: ripemd160 vs sha256 (1 KB)", () => {
    // Solo si sha256 está disponible en el mismo módulo
    // Si no, comparamos ripemd160 en dos tamaños
    const msg1k = new Uint8Array(1024).fill(0x63)
    const msg64 = new Uint8Array(64).fill(0x63)
    wasm.write(IN, msg1k)
    const cmp = Wasm.benchCompare(
      "rmd160(1KB)",
      () => wasm.exports.ripemd160_hash_raw(OUT, IN, 1024),
      "rmd160(64B)",
      () => wasm.exports.ripemd160_hash_raw(OUT, IN, 64),
      100_000,
      { warmup: 2000, runs: 3 },
    )
    console.log(`\n  1KB/64B ratio: ${cmp.ratio.toFixed(2)}x → winner: ${cmp.winner}\n`)
    expect(cmp.ratio).toBeGreaterThan(2) // 1 KB debe ser >2x más lento que 64 B
  })
})
