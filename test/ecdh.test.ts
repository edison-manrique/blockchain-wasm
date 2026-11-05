/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdh.test.ts — Correctitud + memoria + velocidad de ECDH secp256k1
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Validación por propiedades algebraicas + anclas (sin vectores transcritos):
 *   • ANCLA A G: sharedSecret(a, G) == pubkeyFromPrivkey(a)  (ambos son
 *     compressed(a·G)). Como pubkeyFromPrivkey ya está validado contra G
 *     (address/ecdsa), esto ancla ECDH a una referencia externa confiable
 *     Y cruza glv.mul contra multiplyG (validación de GLV de regalo).
 *   • SIMETRÍA Diffie-Hellman: sharedSecret(a, B) == sharedSecret(b, A).
 *   • COMPRESSED == UNCOMPRESSED en la pubkey de entrada.
 *   • Formato de salida (33 B, prefijo 02/03) y casos de error.
 *
 *  Corre con:  bun test test/ecdh.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/ecdh/index.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const hex = (b: Uint8Array): string => Wasm.bytesToHex(b)
const hb = (h: string): Uint8Array => Wasm.hexToBytes(h)

// ── Offsets ───────────────────────────────────────────────────────────────
const PRIV = 0 // IN
const PUB = 32 // IN (hasta 32+65 = 97)
const SHARED = 0 // OUT (33 B)
const PUBOUT = 64 // OUT (65 B)

// ── Anclas (hechos matemáticos de secp256k1) ──────────────────────────────
const G_COMP = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
const G_UNCOMP =
  "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
const PRIV1 = "0000000000000000000000000000000000000000000000000000000000000001"
const PRIV2 = "0000000000000000000000000000000000000000000000000000000000000002"
const PRIV3 = "0000000000000000000000000000000000000000000000000000000000000003"

// ── Cache de instancias ───────────────────────────────────────────────────
let _def: WasmInstance | null = null
let _bench: WasmInstance | null = null
async function useDefault(): Promise<void> {
  if (!_def) _def = await Wasm.compileAndLoad(ENTRY)
  wasm = _def
  IN = wasm.num("PARAM_IN_PTR")
  OUT = wasm.num("PARAM_OUT_PTR")
}
async function useBench(): Promise<void> {
  if (!_bench) _bench = await Wasm.compileAndLoad(ENTRY, "bench")
  wasm = _bench
  IN = wasm.num("PARAM_IN_PTR")
  OUT = wasm.num("PARAM_OUT_PTR")
}

// ── Helpers ─────────────────────────────────────────────────────────────

function shared(privHex: string, pubHex: string): string {
  wasm.write(IN + PRIV, hb(privHex))
  wasm.write(IN + PUB, hb(pubHex))
  const rc: number = wasm.exports.ecdh_shared_secret(OUT + SHARED, IN + PRIV, IN + PUB, pubHex.length / 2)
  expect(rc).toBe(33)
  return hex(wasm.read(OUT + SHARED, 33))
}

function sharedRc(privHex: string, pubHex: string, pubLen: number): number {
  wasm.write(IN + PRIV, hb(privHex))
  wasm.write(IN + PUB, hb(pubHex))
  return wasm.exports.ecdh_shared_secret(OUT + SHARED, IN + PRIV, IN + PUB, pubLen)
}

function pubC(privHex: string): string {
  wasm.write(IN + PRIV, hb(privHex))
  wasm.exports.pubkeyFromPrivkey(OUT + PUBOUT, IN + PRIV)
  return hex(wasm.read(OUT + PUBOUT, 33))
}

function pubU(privHex: string): string {
  wasm.write(IN + PRIV, hb(privHex))
  wasm.exports.pubkeyUncompressedFromPrivkey(OUT + PUBOUT, IN + PRIV)
  return hex(wasm.read(OUT + PUBOUT, 65))
}

// ═══════════════════════════════════════════════════════════════════════════
// 0) COMPILACIÓN
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdh — compilación", () => {
  test("compilar y reportar stats", async () => {
    const cr: CompileResult = await Wasm.compile(ENTRY, { profile: "bench" })
    Wasm.printCompileStats(cr, "bench")
    expect(cr.sizeBytes).toBeGreaterThan(1024)
    expect(cr.compileTimeMs).toBeGreaterThan(0)
  }, 300_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 1) ANCLA A G  (sharedSecret(a, G) == pubkeyFromPrivkey(a))
//    → valida ECDH y cruza glv.mul contra multiplyG
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdh — ancla a G", () => {
  beforeAll(useDefault, 300_000)

  test("anclas de pubkey (sanity)", () => {
    expect(pubC(PRIV1)).toBe(G_COMP)
    expect(pubU(PRIV1)).toBe(G_UNCOMP)
  })

  test("sharedSecret(1, G) == G compressed  [ancla absoluta]", () => {
    expect(shared(PRIV1, G_UNCOMP)).toBe(G_COMP)
  })

  test("sharedSecret(a, G) == pubkeyFromPrivkey(a)  [a = 2, 3]", () => {
    expect(shared(PRIV2, G_UNCOMP)).toBe(pubC(PRIV2))
    expect(shared(PRIV3, G_UNCOMP)).toBe(pubC(PRIV3))
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) SIMETRÍA DIFFIE-HELLMAN
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdh — simetría DH", () => {
  beforeAll(useDefault, 300_000)

  const pairs: [string, string][] = [
    [PRIV1, PRIV2],
    [PRIV1, PRIV3],
    [PRIV2, PRIV3]
  ]

  for (const [a, b] of pairs) {
    test(`shared(a,B) == shared(b,A)  [a=${a.slice(-1)}, b=${b.slice(-1)}]`, () => {
      const A = pubC(a)
      const B = pubC(b)
      expect(shared(a, B)).toBe(shared(b, A))
    })
  }
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) COMPRESSED == UNCOMPRESSED + FORMATO
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdh — compressed/uncompressed + formato", () => {
  beforeAll(useDefault, 300_000)

  test("compressed == uncompressed (misma pubkey de entrada)", () => {
    const Bc = pubC(PRIV3)
    const Bu = pubU(PRIV3)
    expect(shared(PRIV2, Bc)).toBe(shared(PRIV2, Bu))
  })

  test("salida = 33 B con prefijo 02/03", () => {
    const s = shared(PRIV2, pubC(PRIV3))
    expect(s.length).toBe(66) // 33 bytes
    const prefix = s.slice(0, 2)
    expect(prefix === "02" || prefix === "03").toBe(true)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) ERRORES
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdh — errores", () => {
  beforeAll(useDefault, 300_000)

  test("pubkey compressed con prefijo inválido (0x05) → -2", () => {
    const bad = "05" + "11".repeat(32)
    expect(sharedRc(PRIV1, bad, 33)).toBe(-2)
  })

  test("pubkey uncompressed con prefijo inválido (0x05) → -2", () => {
    const bad = "05" + "11".repeat(64)
    expect(sharedRc(PRIV1, bad, 65)).toBe(-2)
  })

  test("longitud de pubkey inválida (40 B) → -2", () => {
    const bad = "04" + "11".repeat(39)
    expect(sharedRc(PRIV1, bad, 40)).toBe(-2)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 5) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdh — memoria", () => {
  beforeAll(useDefault, 300_000)

  test("shared_secret no causa memory.grow", () => {
    const B = pubC(PRIV3)
    wasm.write(IN + PRIV, hb(PRIV2))
    wasm.write(IN + PUB, hb(B))
    Wasm.assertZeroAlloc(
      "ecdh",
      wasm,
      () => wasm.exports.ecdh_shared_secret(OUT + SHARED, IN + PRIV, IN + PUB, 33),
      300
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 6) VELOCIDAD (iteraciones reducidas, timeout 10 s)
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdh — velocidad", () => {
  beforeAll(useBench, 300_000)

  test("shared_secret (compressed input)", () => {
    const B = pubC(PRIV3)
    wasm.write(IN + PRIV, hb(PRIV2))
    wasm.write(IN + PUB, hb(B))
    const r = Wasm.benchSpeed(
      "ecdh",
      300,
      () => wasm.exports.ecdh_shared_secret(OUT + SHARED, IN + PRIV, IN + PUB, 33),
      { warmup: 50, runs: 3 }
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  }, 10_000)
})