/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  wif.test.ts — Correctitud + roundtrip de WIF (Wallet Import Format)
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores: Bitcoin wiki (https://en.bitcoin.it/wiki/Wallet_import_format)
 *  Corre con:  bun test test/wif.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance } from "./utils/wasm"

const ENTRY = "assembly/utils/wif.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const hex = (b: Uint8Array): string => Wasm.bytesToHex(b)

// ── Helpers TS (marshalling mínimo) ───────────────────────────────────────

function wifEncode(privKey: Uint8Array, compressed: boolean): string {
  wasm.write(IN, privKey)
  const len: number = wasm.exports.wif_encode_raw(OUT, IN, compressed ? 1 : 0)
  if (len <= 0) return ""
  wasm.exports.base58_indices_to_ascii(OUT, len)
  return new TextDecoder().decode(wasm.read(OUT, len))
}

function wifDecode(wif: string): { key: Uint8Array; compressed: boolean } | null {
  const ascii = new TextEncoder().encode(wif)
  wasm.write(IN, ascii)
  const rc: number = wasm.exports.base58_ascii_to_indices(IN, ascii.length)
  if (rc !== 0) return null
  const flags: number = wasm.exports.wif_decode_raw(OUT, IN, ascii.length)
  if (flags < 0) return null
  return { key: wasm.read(OUT, 32), compressed: flags === 2 }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("wif — correctitud", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("WASM cargado — exports presentes", () => {
    expect(wasm.exports.wif_encode_raw).toBeFunction()
    expect(wasm.exports.wif_decode_raw).toBeFunction()
    expect(wasm.exports.base58_indices_to_ascii).toBeFunction()
    expect(wasm.exports.base58_ascii_to_indices).toBeFunction()
  })

  // ── Vectores Bitcoin wiki ───────────────────────────────────────────────
  const vectors: [string, string, boolean, string][] = [
    [
      "uncompressed",
      "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d",
      false,
      "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    ],
    [
      "compressed",
      "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d",
      true,
      "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    ]
  ]

  for (const [name, keyHex, compressed, expectedWIF] of vectors) {
    test(`encode(${name})`, () => {
      const wif = wifEncode(Wasm.hexToBytes(keyHex), compressed)
      expect(wif).toBe(expectedWIF)
    })
  }

  for (const [name, keyHex, compressed, wifStr] of vectors) {
    test(`decode(${name})`, () => {
      const result = wifDecode(wifStr)
      expect(result).not.toBeNull()
      expect(hex(result!.key)).toBe(keyHex)
      expect(result!.compressed).toBe(compressed)
    })
  }

  // ── Prefijo correcto ────────────────────────────────────────────────────
  test("uncompressed empieza con '5'", () => {
    const key = new Uint8Array(32).fill(0x01)
    const wif = wifEncode(key, false)
    expect(wif[0]).toBe("5")
  })

  test("compressed empieza con 'K' o 'L'", () => {
    const key = new Uint8Array(32).fill(0x01)
    const wif = wifEncode(key, true)
    expect(wif[0] === "K" || wif[0] === "L").toBe(true)
  })

  // ── Roundtrip ───────────────────────────────────────────────────────────
  test("roundtrip compressed", () => {
    const key = new Uint8Array(32)
    for (let i = 0; i < 32; i++) key[i] = (i * 37 + 13) & 0xff
    const wif = wifEncode(key, true)
    const result = wifDecode(wif)
    expect(result).not.toBeNull()
    expect(hex(result!.key)).toBe(hex(key))
    expect(result!.compressed).toBe(true)
  })

  test("roundtrip uncompressed", () => {
    const key = new Uint8Array(32).fill(0xde)
    const wif = wifEncode(key, false)
    const result = wifDecode(wif)
    expect(result).not.toBeNull()
    expect(hex(result!.key)).toBe(hex(key))
    expect(result!.compressed).toBe(false)
  })

  // ── Casos inválidos ─────────────────────────────────────────────────────
  test("decode: string vacío → null", () => {
    expect(wifDecode("")).toBeNull()
  })

  test("decode: carácter inválido (0, O, I, l) → null", () => {
    expect(wifDecode("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyT0")).toBeNull() // '0'
    expect(wifDecode("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTO")).toBeNull() // 'O'
    expect(wifDecode("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTI")).toBeNull() // 'I'
    expect(wifDecode("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTl")).toBeNull() // 'l'
  })

  test("decode: checksum corrupto → null", () => {
    expect(wifDecode("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTK")).toBeNull()
  })

  test("decode: prefix incorrecto → null", () => {
    // Construir un Base58Check con prefix 0x00 (no 0x80)
    const fakePayload = new Uint8Array(33)
    fakePayload[0] = 0x00
    fakePayload.fill(0x42, 1)
    wasm.write(IN, fakePayload)
    const len = wasm.exports.base58check_encode_raw(OUT, IN, 33)
    wasm.exports.base58_indices_to_ascii(OUT, len)
    const fakeWIF = new TextDecoder().decode(wasm.read(OUT, len))
    expect(wifDecode(fakeWIF)).toBeNull()
  })

  test("decode: longitud incorrecta (20 bytes) → null", () => {
    const shortPayload = new Uint8Array(21)
    shortPayload[0] = 0x80
    shortPayload.fill(0x42, 1)
    wasm.write(IN, shortPayload)
    const len = wasm.exports.base58check_encode_raw(OUT, IN, 21)
    wasm.exports.base58_indices_to_ascii(OUT, len)
    const shortWIF = new TextDecoder().decode(wasm.read(OUT, len))
    expect(wifDecode(shortWIF)).toBeNull()
  })

  test("decode: sufijo compressed incorrecto → null", () => {
    // payload: [0x80, key(32), 0x02] — sufijo inválido
    const badPayload = new Uint8Array(34)
    badPayload[0] = 0x80
    badPayload.fill(0x42, 1, 33)
    badPayload[33] = 0x02 // debería ser 0x01
    wasm.write(IN, badPayload)
    const len = wasm.exports.base58check_encode_raw(OUT, IN, 34)
    wasm.exports.base58_indices_to_ascii(OUT, len)
    const badWIF = new TextDecoder().decode(wasm.read(OUT, len))
    expect(wifDecode(badWIF)).toBeNull()
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA
// ═══════════════════════════════════════════════════════════════════════════

describe("wif — memoria", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("encode no causa memory.grow", () => {
    const key = new Uint8Array(32).fill(0xab)
    wasm.write(IN, key)
    Wasm.assertZeroAlloc("wif-enc", wasm, () => wasm.exports.wif_encode_raw(OUT, IN, 1), 2000)
  })

  test("decode no causa memory.grow", () => {
    const wif = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    const ascii = new TextEncoder().encode(wif)
    wasm.write(IN, ascii)
    wasm.exports.base58_ascii_to_indices(IN, ascii.length)
    Wasm.assertZeroAlloc("wif-dec", wasm, () => wasm.exports.wif_decode_raw(OUT, IN, ascii.length), 2000)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD
// ═══════════════════════════════════════════════════════════════════════════

describe("wif — velocidad", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY, "bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("encode (32B → WIF)", () => {
    const key = new Uint8Array(32).fill(0xcd)
    wasm.write(IN, key)
    const r = Wasm.benchSpeed("wif-encode", 100_000, () => wasm.exports.wif_encode_raw(OUT, IN, 1), {
      warmup: 2000,
      runs: 3
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(20_000) // incluye 2× SHA-256 + base58
  })

  test("decode (WIF → 32B)", () => {
    const wif = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    const ascii = new TextEncoder().encode(wif)
    wasm.write(IN, ascii)
    wasm.exports.base58_ascii_to_indices(IN, ascii.length)
    const r = Wasm.benchSpeed("wif-decode", 100_000, () => wasm.exports.wif_decode_raw(OUT, IN, ascii.length), {
      warmup: 2000,
      runs: 3
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(20_000)
  })
})
