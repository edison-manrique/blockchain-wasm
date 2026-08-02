/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bech32.test.ts — Correctitud + memoria + velocidad de Bech32/Bech32m
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores: BIP-173 (SegWit v0), BIP-350 (Taproot v1), convertBits.
 *  Corre con:  bun test test/bech32.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance } from "./utils/wasm"

const ENTRY = "assembly/secp256k1/bech32.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const hex = (b: Uint8Array): string => Wasm.bytesToHex(b)
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// ── Helpers TS ────────────────────────────────────────────────────────────

function indicesToString(ptr: number, len: number): string {
  let s = ""
  for (let i = 0; i < len; i++) s += BECH32_CHARSET[wasm.u8[ptr + i]]
  return s
}

function stringToIndices(s: string, ptr: number): void {
  for (let i = 0; i < s.length; i++) {
    wasm.u8[ptr + i] = BECH32_CHARSET.indexOf(s[i].toLowerCase())
  }
  wasm.syncViews()
}

/** Encode completo: hrp + "1" + charset(data+checksum) */
function bech32Encode(hrp: string, data5bit: Uint8Array, enc: number): string {
  const hrpBytes = new TextEncoder().encode(hrp)
  const hrpPtr = IN
  const dataPtr = IN + 128
  const outPtr = OUT
  wasm.write(hrpPtr, hrpBytes)
  wasm.write(dataPtr, data5bit)
  const len: number = wasm.exports.bech32_encode_raw(outPtr, hrpPtr, hrpBytes.length, dataPtr, data5bit.length, enc)
  if (len <= 0) return ""
  wasm.exports.bech32_charset_to_ascii(outPtr, len)
  const charsetPart = new TextDecoder().decode(wasm.read(outPtr, len))
  return hrp + "1" + charsetPart
}

/** Decode completo: retorna { hrp, data5bit, encoding } o null */
function bech32Decode(addr: string): { data: Uint8Array; enc: number } | null {
  const sepIdx = addr.lastIndexOf("1")
  if (sepIdx < 1) return null
  const hrp = addr.slice(0, sepIdx)
  const dataPart = addr.slice(sepIdx + 1)
  if (dataPart.length < 6) return null

  const hrpBytes = new TextEncoder().encode(hrp)
  const hrpPtr = IN
  const srcPtr = IN + 128
  const outDataPtr = OUT
  const outLenPtr = OUT + 256

  wasm.write(hrpPtr, hrpBytes)
  stringToIndices(dataPart, srcPtr)

  const enc: number = wasm.exports.bech32_decode_raw(
    outDataPtr,
    outLenPtr,
    hrpPtr,
    hrpBytes.length,
    srcPtr,
    dataPart.length
  )
  if (enc < 0) return null

  const dataLen = new DataView(wasm.memory.buffer).getUint32(outLenPtr, true)
  return { data: wasm.read(outDataPtr, dataLen), enc }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("bech32 — correctitud", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("WASM cargado — exports presentes", () => {
    expect(wasm.exports.bech32_encode_raw).toBeFunction()
    expect(wasm.exports.bech32_decode_raw).toBeFunction()
    expect(wasm.exports.convert_bits_raw).toBeFunction()
    expect(wasm.exports.bech32_charset_to_ascii).toBeFunction()
    expect(wasm.exports.bech32_ascii_to_charset).toBeFunction()
  })

  // ── BIP-173: P2WPKH (witness v0, 20 bytes) ─────────────────────────────
  test("encode P2WPKH: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", () => {
    // witness program = 751e76e8199196d454941c45d1b3a323f1433bd6
    const prog = Wasm.hexToBytes("751e76e8199196d454941c45d1b3a323f1433bd6")
    // Convertir 8→5 bits
    wasm.write(IN, prog)
    const groupsLen = wasm.exports.convert_bits_raw(OUT, IN, 20, 8, 5, 1)
    expect(groupsLen).toBe(32) // 20*8/5 = 32
    // Prepend witness version (0)
    const data5 = new Uint8Array(groupsLen + 1)
    data5[0] = 0 // witness v0
    data5.set(wasm.read(OUT, groupsLen), 1)
    const addr = bech32Encode("bc", data5, 1) // BECH32
    expect(addr).toBe("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
  })

  // ── BIP-173: P2WSH (witness v0, 32 bytes) ──────────────────────────────
  test("encode P2WSH: bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", () => {
    const prog = Wasm.hexToBytes("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
    wasm.write(IN, prog)
    const groupsLen = wasm.exports.convert_bits_raw(OUT, IN, 32, 8, 5, 1)
    expect(groupsLen).toBe(52) // 32*8/5 = 51.2 → 52 con padding
    const data5 = new Uint8Array(groupsLen + 1)
    data5[0] = 0
    data5.set(wasm.read(OUT, groupsLen), 1)
    const addr = bech32Encode("bc", data5, 1)
    expect(addr).toBe("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
  })

  // ── BIP-350: P2TR (witness v1, 32 bytes, Bech32m) ──────────────────────
  test("encode P2TR: bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", () => {
    const prog = Wasm.hexToBytes("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    wasm.write(IN, prog)
    const groupsLen = wasm.exports.convert_bits_raw(OUT, IN, 32, 8, 5, 1)
    const data5 = new Uint8Array(groupsLen + 1)
    data5[0] = 1 // witness v1
    data5.set(wasm.read(OUT, groupsLen), 1)
    const addr = bech32Encode("bc", data5, 0x2bc830a3) // BECH32M
    expect(addr).toBe("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
  })

  // ── Decode P2WPKH ─────────────────────────────────────────────────────
  test("decode P2WPKH", () => {
    const result = bech32Decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    expect(result).not.toBeNull()
    expect(result!.enc).toBe(1) // BECH32
    // data[0] = witness version = 0
    expect(result!.data[0]).toBe(0)
    // Convertir data[1..] de 5→8 bits
    const data5 = result!.data.slice(1)
    wasm.write(IN, data5)
    const progLen = wasm.exports.convert_bits_raw(OUT, IN, data5.length, 5, 8, 0)
    expect(progLen).toBe(20)
    expect(hex(wasm.read(OUT, progLen))).toBe("751e76e8199196d454941c45d1b3a323f1433bd6")
  })

  // ── Decode P2TR (Bech32m) ─────────────────────────────────────────────
  test("decode P2TR (Bech32m)", () => {
    const result = bech32Decode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
    expect(result).not.toBeNull()
    expect(result!.enc).toBe(0x2bc830a3) // BECH32M
    expect(result!.data[0]).toBe(1) // witness v1
    const data5 = result!.data.slice(1)
    wasm.write(IN, data5)
    const progLen = wasm.exports.convert_bits_raw(OUT, IN, data5.length, 5, 8, 0)
    expect(progLen).toBe(32)
    expect(hex(wasm.read(OUT, progLen))).toBe("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
  })

  // ── convertBits roundtrip ─────────────────────────────────────────────
  test("convertBits 8→5→8 roundtrip (20 bytes)", () => {
    const original = Wasm.hexToBytes("751e76e8199196d454941c45d1b3a323f1433bd6")
    wasm.write(IN, original)
    // 8→5
    const len5 = wasm.exports.convert_bits_raw(OUT, IN, 20, 8, 5, 1)
    expect(len5).toBe(32)
    // 5→8
    const len8 = wasm.exports.convert_bits_raw(IN, OUT, len5, 5, 8, 0)
    expect(len8).toBe(20)
    expect(hex(wasm.read(IN, 20))).toBe("751e76e8199196d454941c45d1b3a323f1433bd6")
  })

  test("convertBits 8→5→8 roundtrip (32 bytes)", () => {
    const original = new Uint8Array(32)
    for (let i = 0; i < 32; i++) original[i] = (i * 17 + 5) & 0xff
    wasm.write(IN, original)
    const len5 = wasm.exports.convert_bits_raw(OUT, IN, 32, 8, 5, 1)
    const len8 = wasm.exports.convert_bits_raw(IN, OUT, len5, 5, 8, 0)
    expect(len8).toBe(32)
    expect(hex(wasm.read(IN, 32))).toBe(hex(original))
  })

  // ── Casos inválidos ───────────────────────────────────────────────────
  test("decode: checksum corrupto → null", () => {
    // Cambiar último carácter
    const result = bech32Decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
    expect(result).toBeNull()
  })

  test("decode: carácter inválido → null", () => {
    // 'b' no existe en el charset bech32
    const result = bech32Decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tb")
    expect(result).toBeNull()
  })

  test("convertBits: valor > fromBits → -1", () => {
    wasm.u8[IN] = 256 // imposible en u8, usar 0xFF con fromBits=5
    wasm.u8[IN] = 32 // 32 >= 2^5
    wasm.syncViews()
    const rc = wasm.exports.convert_bits_raw(OUT, IN, 1, 5, 8, 0)
    expect(rc).toBe(-1)
  })

  // ── charset helpers ───────────────────────────────────────────────────
  test("charset_to_ascii y ascii_to_charset roundtrip", () => {
    // Escribir índices [0,1,2,...,31]
    for (let i = 0; i < 32; i++) wasm.u8[IN + i] = i
    wasm.syncViews()
    wasm.exports.bech32_charset_to_ascii(IN, 32)
    const ascii = new TextDecoder().decode(wasm.read(IN, 32))
    expect(ascii).toBe("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
    // Convertir de vuelta
    wasm.write(IN, new TextEncoder().encode(ascii))
    const rc = wasm.exports.bech32_ascii_to_charset(IN, 32)
    expect(rc).toBe(0)
    for (let i = 0; i < 32; i++) {
      expect(wasm.u8[IN + i]).toBe(i)
    }
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA
// ═══════════════════════════════════════════════════════════════════════════

describe("bech32 — memoria", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("encode no causa memory.grow", () => {
    const prog = Wasm.hexToBytes("751e76e8199196d454941c45d1b3a323f1433bd6")
    wasm.write(IN, prog)
    const len5 = wasm.exports.convert_bits_raw(OUT, IN, 20, 8, 5, 1)
    const data5 = new Uint8Array(len5 + 1)
    data5[0] = 0
    data5.set(wasm.read(OUT, len5), 1)
    const hrpBytes = new TextEncoder().encode("bc")
    wasm.write(IN + 256, hrpBytes)
    wasm.write(IN + 300, data5)
    Wasm.assertZeroAlloc(
      "bech32-enc",
      wasm,
      () => wasm.exports.bech32_encode_raw(OUT, IN + 256, 2, IN + 300, data5.length, 1),
      5000
    )
  })

  test("convertBits no causa memory.grow", () => {
    const data = new Uint8Array(32).fill(0xab)
    wasm.write(IN, data)
    Wasm.assertZeroAlloc("convert", wasm, () => wasm.exports.convert_bits_raw(OUT, IN, 32, 8, 5, 1), 10000)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD
// ═══════════════════════════════════════════════════════════════════════════

describe("bech32 — velocidad", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY, "bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("encode P2WPKH (20 bytes → address)", () => {
    const prog = Wasm.hexToBytes("751e76e8199196d454941c45d1b3a323f1433bd6")
    wasm.write(IN, prog)
    const len5 = wasm.exports.convert_bits_raw(OUT, IN, 20, 8, 5, 1)
    const data5 = new Uint8Array(len5 + 1)
    data5[0] = 0
    data5.set(wasm.read(OUT, len5), 1)
    const hrpBytes = new TextEncoder().encode("bc")
    wasm.write(IN + 256, hrpBytes)
    wasm.write(IN + 300, data5)
    const r = Wasm.benchSpeed(
      "bech32-encode",
      200_000,
      () => wasm.exports.bech32_encode_raw(OUT, IN + 256, 2, IN + 300, data5.length, 1),
      { warmup: 5000, runs: 3 }
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(5_000)
  })

  test("convertBits 8→5 (32 bytes)", () => {
    const data = new Uint8Array(32).fill(0xcd)
    wasm.write(IN, data)
    const r = Wasm.benchSpeed("convert8to5", 500_000, () => wasm.exports.convert_bits_raw(OUT, IN, 32, 8, 5, 1), {
      warmup: 10000,
      runs: 3
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(2_000)
  })
})
