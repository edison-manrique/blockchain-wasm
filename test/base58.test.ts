/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  base58.test.ts — Correctitud + memoria + velocidad de Base58/Base58Check
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores: Bitcoin wiki, BIP-13 (P2SH), roundtrips, edge cases.
 *  Corre con:  bun test test/base58.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/utils/base58.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const hex = (bytes: Uint8Array): string => Wasm.bytesToHex(bytes)

// ── Helpers TS: índices ↔ string ──────────────────────────────────────────
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

function indicesToString(ptr: number, len: number): string {
  let s = ""
  for (let i = 0; i < len; i++) s += B58_ALPHABET[wasm.u8[ptr + i]]
  return s
}

function stringToIndices(s: string, ptr: number): void {
  for (let i = 0; i < s.length; i++) {
    wasm.u8[ptr + i] = B58_ALPHABET.indexOf(s[i])
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 0) COMPILACIÓN
// ═══════════════════════════════════════════════════════════════════════════

describe("base58 — compilación", () => {
  test("compilar y reportar stats", async () => {
    const cr: CompileResult = await Wasm.compile(ENTRY, { profile: "bench" })
    Wasm.printCompileStats(cr, "bench")
    expect(cr.sizeBytes).toBeGreaterThan(1024)
    expect(cr.sizeBytes).toBeLessThan(65536)
    expect(cr.compileTimeMs).toBeGreaterThan(0)
  }, 120_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD — Base58
// ═══════════════════════════════════════════════════════════════════════════

describe("base58 — correctitud", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("WASM cargado — exports presentes", () => {
    expect(wasm.exports.base58_encode_raw).toBeFunction()
    expect(wasm.exports.base58_decode_raw).toBeFunction()
    expect(wasm.exports.base58check_encode_raw).toBeFunction()
    expect(wasm.exports.base58check_decode_raw).toBeFunction()
    expect(wasm.exports.base58_indices_to_ascii).toBeFunction()
    expect(wasm.exports.base58_ascii_to_indices).toBeFunction()
  })

  // ── Encode (vectores Bitcoin wiki) ──────────────────────────────────────
  const encodeCases: [string, string, string][] = [
    ["vacío", "", ""],
    ["0x00", "00", "1"],
    ["0x0000", "0000", "11"],
    ["0x61 ('a')", "61", "2g"],
    ["0x626262 ('bbb')", "626262", "a3gV"],
    ["0x636363 ('ccc')", "636363", "aPEr"],
    [
      "10 bytes",
      "10c8511e7488863679640400033f79d4",
      "35CTsL9ssmwq8LEuMZEBiT", // ✅ FIX
    ],
    [
      "32 bytes (hash)",
      "ec1c8287ee9534dc47540885f34ff839456c3a22f9575a14de2f5e75e2e91483",
      "GtgRzkTTRecXX3ABYQk158Mi2Jfo1WXNJBFEcT4Ngv8r", // ✅ FIX
    ],
  ]

  for (const [name, inputHex, expected] of encodeCases) {
    test(`encode(${name})`, () => {
      const input = Wasm.hexToBytes(inputHex)
      wasm.write(IN, input)
      const len = wasm.exports.base58_encode_raw(OUT, IN, input.length)
      expect(indicesToString(OUT, len)).toBe(expected)
    })
  }

  // ── Decode (inversos de encode) ─────────────────────────────────────────
  const decodeCases: [string, string, string][] = [
    ["'1' → 0x00", "1", "00"],
    ["'11' → 0x0000", "11", "0000"],
    ["'2g' → 0x61", "2g", "61"],
    ["'a3gV' → 0x626262", "a3gV", "626262"],
    ["'aPEr' → 0x636363", "aPEr", "636363"],
    [
      "10 bytes",
      "35CTsL9ssmwq8LEuMZEBiT", // ✅ FIX
      "10c8511e7488863679640400033f79d4",
    ],
    [
      "32 bytes",
      "GtgRzkTTRecXX3ABYQk158Mi2Jfo1WXNJBFEcT4Ngv8r", // ✅ FIX
      "ec1c8287ee9534dc47540885f34ff839456c3a22f9575a14de2f5e75e2e91483",
    ],
  ]

  for (const [name, input, expectedHex] of decodeCases) {
    test(`decode(${name})`, () => {
      stringToIndices(input, IN)
      const len = wasm.exports.base58_decode_raw(OUT, IN, input.length)
      expect(len).toBeGreaterThan(0)
      expect(hex(wasm.read(OUT, len))).toBe(expectedHex)
    })
  }

  // ── Decode: carácter inválido ───────────────────────────────────────────
  test("decode con carácter inválido (idx=255) → -1", () => {
    // Escribir un índice ≥ 58
    wasm.u8[IN] = 58
    wasm.syncViews()
    const len = wasm.exports.base58_decode_raw(OUT, IN, 1)
    expect(len).toBe(-1)
  })

  // ── Roundtrip: encode(decode(x)) == x ───────────────────────────────────
  test("roundtrip encode∘decode (32 bytes aleatorios)", () => {
    const original = new Uint8Array(32)
    for (let i = 0; i < 32; i++) original[i] = (i * 37 + 13) & 0xff
    wasm.write(IN, original)
    // encode
    const encLen = wasm.exports.base58_encode_raw(OUT, IN, 32)
    // decode (de OUT → IN)
    const decLen = wasm.exports.base58_decode_raw(IN, OUT, encLen)
    expect(decLen).toBe(32)
    expect(hex(wasm.read(IN, 32))).toBe(hex(original))
  })

  test("roundtrip con ceros líderes", () => {
    const original = new Uint8Array([0, 0, 0, 0x48, 0x65, 0x6c, 0x6c, 0x6f])
    wasm.write(IN, original)
    const encLen = wasm.exports.base58_encode_raw(OUT, IN, original.length)
    const encoded = indicesToString(OUT, encLen)
    expect(encoded.startsWith("111")).toBe(true) // 3 ceros líderes → "111"
    // decode
    const decLen = wasm.exports.base58_decode_raw(IN, OUT, encLen)
    expect(decLen).toBe(8)
    expect(hex(wasm.read(IN, 8))).toBe("00000048656c6c6f")
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) CORRECTITUD — Base58Check
// ═══════════════════════════════════════════════════════════════════════════

describe("base58check — correctitud", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  // ── Encode (vectores verificados con Python hashlib) ────────────────────
  test("encode: P2PKH address (version 0x00 + 20 bytes)", () => {
    const payload = Wasm.hexToBytes("00010966776006953d5567439e5e39f86a0d273bee")
    wasm.write(IN, payload)
    const len = wasm.exports.base58check_encode_raw(OUT, IN, payload.length)
    expect(indicesToString(OUT, len)).toBe("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")
  })

  test("encode: P2SH address (version 0x05 + 20 bytes)", () => {
    const payload = Wasm.hexToBytes("05010966776006953d5567439e5e39f86a0d273bee")
    wasm.write(IN, payload)
    const len = wasm.exports.base58check_encode_raw(OUT, IN, payload.length)
    expect(indicesToString(OUT, len)).toBe("31nVrspaydBz8aMpxH9WkS2DuhgqS1fCuG") // ✅ FIX
  })

  // ── Decode (inversos) ───────────────────────────────────────────────────
  test("decode: P2PKH address", () => {
    const addr = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    stringToIndices(addr, IN)
    const len = wasm.exports.base58check_decode_raw(OUT, IN, addr.length)
    expect(len).toBe(21) // 1 byte version + 20 bytes hash
    expect(hex(wasm.read(OUT, len))).toBe("00010966776006953d5567439e5e39f86a0d273bee")
  })

  test("decode: P2SH address", () => {
    const addr = "31nVrspaydBz8aMpxH9WkS2DuhgqS1fCuG" // ✅ FIX
    stringToIndices(addr, IN)
    const len = wasm.exports.base58check_decode_raw(OUT, IN, addr.length)
    expect(len).toBe(21)
    expect(hex(wasm.read(OUT, len))).toBe("05010966776006953d5567439e5e39f86a0d273bee")
  })

  // ── Checksum inválido ───────────────────────────────────────────────────
  test("decode con checksum corrupto → -1", () => {
    const addr = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    stringToIndices(addr, IN)
    // Corromper el último índice (último dígito del checksum)
    wasm.u8[IN + addr.length - 1] ^= 1
    wasm.syncViews()
    const len = wasm.exports.base58check_decode_raw(OUT, IN, addr.length)
    expect(len).toBe(-1)
  })

  // ── Roundtrip Base58Check ───────────────────────────────────────────────
  test("roundtrip base58check encode∘decode", () => {
    const payload = new Uint8Array(21)
    payload[0] = 0x80 // WIF version
    for (let i = 1; i < 21; i++) payload[i] = (i * 11 + 7) & 0xff
    wasm.write(IN, payload)
    const encLen = wasm.exports.base58check_encode_raw(OUT, IN, 21)
    // decode
    const decLen = wasm.exports.base58check_decode_raw(IN, OUT, encLen)
    expect(decLen).toBe(21)
    expect(hex(wasm.read(IN, 21))).toBe(hex(payload))
  })

  // ── ASCII helpers ───────────────────────────────────────────────────────
  test("indices_to_ascii y ascii_to_indices (roundtrip)", () => {
    // Encode "Hello" (0x48656c6c6f) → índices base58
    const input = Wasm.hexToBytes("48656c6c6f")
    wasm.write(IN, input)
    const encLen = wasm.exports.base58_encode_raw(OUT, IN, 5)
    expect(encLen).toBe(7)

    // Convertir índices → ASCII (in-place en OUT)
    wasm.exports.base58_indices_to_ascii(OUT, encLen)
    const asciiBytes = wasm.read(OUT, encLen)
    expect(new TextDecoder().decode(asciiBytes)).toBe("9Ajdvzr")

    // ✅ FIX: usar wasm.write (syncViews + set atómico) en vez de loop manual
    const asciiPtr = IN + 128
    wasm.write(asciiPtr, asciiBytes)

    // Convertir ASCII → índices
    const rc = wasm.exports.base58_ascii_to_indices(asciiPtr, encLen)
    expect(rc).toBe(0)

    // Decodificar los índices de vuelta a bytes originales
    const decLen = wasm.exports.base58_decode_raw(OUT, asciiPtr, encLen)
    expect(decLen).toBe(5)
    expect(hex(wasm.read(OUT, decLen))).toBe("48656c6c6f")
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("base58 — memoria", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("encode no causa memory.grow", () => {
    const input = new Uint8Array(32).fill(0xab)
    wasm.write(IN, input)
    Wasm.assertZeroAlloc("b58-encode", wasm, () => wasm.exports.base58_encode_raw(OUT, IN, 32), 5000)
  })

  test("decode no causa memory.grow", () => {
    const addr = "GfHyex7R6sLN3p99rKP2Qr8UKGHvE4tNwyw2ft2dC9yd"
    stringToIndices(addr, IN)
    Wasm.assertZeroAlloc("b58-decode", wasm, () => wasm.exports.base58_decode_raw(OUT, IN, addr.length), 5000)
  })

  test("base58check encode no causa memory.grow", () => {
    const payload = Wasm.hexToBytes("00010966776006953d5567439e5e39f86a0d273bee")
    wasm.write(IN, payload)
    Wasm.assertZeroAlloc("b58check-enc", wasm, () => wasm.exports.base58check_encode_raw(OUT, IN, 21), 2000)
  })

  test("base58check decode no causa memory.grow", () => {
    const addr = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    stringToIndices(addr, IN)
    Wasm.assertZeroAlloc("b58check-dec", wasm, () => wasm.exports.base58check_decode_raw(OUT, IN, addr.length), 2000)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) VELOCIDAD
// ═══════════════════════════════════════════════════════════════════════════

describe("base58 — velocidad", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY, "bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("encode 32 bytes (típico: hash → address)", () => {
    const input = new Uint8Array(32).fill(0xab)
    wasm.write(IN, input)
    const r = Wasm.benchSpeed("b58-encode(32B)", 200_000, () => wasm.exports.base58_encode_raw(OUT, IN, 32), {
      warmup: 5000,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(10_000) // < 10 µs
  })

  test("decode 44 chars (típico: address → hash)", () => {
    const addr = "GfHyex7R6sLN3p99rKP2Qr8UKGHvE4tNwyw2ft2dC9yd"
    stringToIndices(addr, IN)
    const r = Wasm.benchSpeed("b58-decode(44ch)", 200_000, () => wasm.exports.base58_decode_raw(OUT, IN, addr.length), {
      warmup: 5000,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(10_000)
  })

  test("base58check encode (21 bytes → address)", () => {
    const payload = Wasm.hexToBytes("00010966776006953d5567439e5e39f86a0d273bee")
    wasm.write(IN, payload)
    const r = Wasm.benchSpeed("b58check-enc(21B)", 100_000, () => wasm.exports.base58check_encode_raw(OUT, IN, 21), {
      warmup: 2000,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(20_000) // incluye 2× SHA-256
  })
})
