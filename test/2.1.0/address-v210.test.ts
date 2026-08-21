/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  address-v210.test.ts — Nuevas direcciones v2.1.0 (Tron + P2PKH uncompressed)
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores verificados con implementación Python independiente
 *  (secp256k1 + keccak256 + ripemd160 + base58check):
 *    priv=1 → tron TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC / p2pkh_u 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
 *    priv=2 → tron TDvSsdrNM5eeXNL3czpa6AxLDHZA9nwe9K / p2pkh_u 1LagHJk2FyCV2VzrNHVqg3gYG4TSYwDV4m
 *    priv=3 → tron TKTX96CBxr5kvhjsDHcqoiPWZageGxoTW3 / p2pkh_u 1NZUP3JAc9JkmbvmoTv7nVgZGtyJjirKV1
 *
 *  NOTA off-curve: X=1 ESTÁ en la curva (1³+7=8 es residuo cuadrático mod P).
 *  El primer X pequeño sin raíz válida es X=5 (5³+7=132 no es RC) → OFF_CURVE_X = 5.
 *
 *  ⚠️ Los tests marcados con [HARDENING] requieren el Apéndice A (validación
 *     de 65 B en tron.ts y btc_p2pkh_uncompressed). Sin el parche, fallan.
 *
 *  Corre con:  bun test test/2.1.0/address-v210.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance } from "../utils/wasm"

const ENTRY = "assembly/address/index.ts"
const OFF_CURVE_X = 0x05 // primer X pequeño con y² = x³+7 sin raíz válida

let wasm: WasmInstance
let IN: number
let OUT: number

let _def: WasmInstance | null = null
let _bench: WasmInstance | null = null
async function defWasm(): Promise<WasmInstance> {
  if (!_def) _def = await Wasm.compileAndLoad(ENTRY)
  return _def
}
async function benchWasm(): Promise<WasmInstance> {
  if (!_bench) _bench = await Wasm.compileAndLoad(ENTRY, "bench")
  return _bench
}
async function useDefault(): Promise<void> {
  wasm = await defWasm()
  IN = wasm.num("PARAM_IN_PTR")
  OUT = wasm.num("PARAM_OUT_PTR")
}

// ── Vectores verificados v2.1.0 ─────────────────────────────────────────
interface VecV210 {
  priv: number
  comp: string
  uncomp: string
  p2pkh_u: string
  tron: string
}

const VECTORS_V210: VecV210[] = [
  {
    priv: 1,
    comp: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    uncomp:
      "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    p2pkh_u: "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
    tron: "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"
  },
  {
    priv: 2,
    comp: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    uncomp:
      "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" +
      "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a", // Y real de 2G
    p2pkh_u: "1LagHJk2FyCV2VzrNHVqg3gYG4TSYwDV4m",
    tron: "TDvSsdrNM5eeXNL3czpa6AxLDHZA9nwe9K"
  },
  {
    priv: 3,
    comp: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    uncomp:
      "04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" +
      "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672", // Y real de 3G
    p2pkh_u: "1NZUP3JAc9JkmbvmoTv7nVgZGtyJjirKV1",
    tron: "TKTX96CBxr5kvhjsDHcqoiPWZageGxoTW3"
  }
]

/** Pubkey compressed 33 B con X fuera de la curva (X = 5). */
function offCurveCompressed(prefix: number): Uint8Array {
  const bad = new Uint8Array(33)
  bad[0] = prefix
  bad[32] = OFF_CURVE_X // X = 0x00..05 → y² = 132, sin raíz mod P
  return bad
}

/** Uncompressed de priv=1 con Y alterada (fuera de la curva). */
function offCurveUncompressed(): Uint8Array {
  const bad = Wasm.hexToBytes(VECTORS_V210[0].uncomp)
  bad[64] = bad[64] ^ 0x01
  return bad
}

/** Llama una fn de dirección (pub en IN) → string ASCII. */
function callAddr(fn: string, pub: Uint8Array): string {
  wasm.write(IN, pub)
  const len: number = wasm.exports[fn](OUT, IN, pub.length)
  expect(len).toBeGreaterThan(0)
  return new TextDecoder().decode(wasm.read(OUT, len))
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) TRON (TRX)
// ═══════════════════════════════════════════════════════════════════════════

describe("address v2.1.0 — Tron", () => {
  beforeAll(useDefault, 300_000)

  for (const v of VECTORS_V210) {
    test(`priv=${v.priv} → Tron desde compressed`, () => {
      expect(callAddr("tron_address", Wasm.hexToBytes(v.comp))).toBe(v.tron)
    })

    test(`priv=${v.priv} → Tron desde uncompressed`, () => {
      expect(callAddr("tron_address", Wasm.hexToBytes(v.uncomp))).toBe(v.tron)
    })

    test(`priv=${v.priv} → Tron desde raw64 (X‖Y)`, () => {
      const raw64 = Wasm.hexToBytes(v.uncomp.slice(2)) // sin prefijo 0x04
      expect(callAddr("tron_address", raw64)).toBe(v.tron)
    })

    test(`priv=${v.priv} → Tron compressed == uncompressed`, () => {
      const a = callAddr("tron_address", Wasm.hexToBytes(v.comp))
      const b = callAddr("tron_address", Wasm.hexToBytes(v.uncomp))
      expect(a).toBe(b)
      expect(a).toBe(v.tron)
    })
  }

  test("Tron address empieza con 'T' y mide 34", () => {
    const tron = callAddr("tron_address", Wasm.hexToBytes(VECTORS_V210[0].comp))
    expect(tron[0]).toBe("T")
    expect(tron.length).toBe(34)
  })

  test("Tron rechaza pubkey con prefijo inválido (0x05)", () => {
    const bad = new Uint8Array(33)
    bad[0] = 0x05
    wasm.write(IN, bad)
    expect(wasm.exports.tron_address(OUT, IN, 33)).toBeLessThan(0)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) P2PKH UNCOMPRESSED (legacy)
// ═══════════════════════════════════════════════════════════════════════════

describe("address v2.1.0 — P2PKH uncompressed", () => {
  beforeAll(useDefault, 300_000)

  for (const v of VECTORS_V210) {
    test(`priv=${v.priv} → P2PKH uncompressed`, () => {
      expect(callAddr("btc_p2pkh_uncompressed", Wasm.hexToBytes(v.uncomp))).toBe(v.p2pkh_u)
    })

    test(`priv=${v.priv} → rechaza compressed (33 B)`, () => {
      wasm.write(IN, Wasm.hexToBytes(v.comp))
      expect(wasm.exports.btc_p2pkh_uncompressed(OUT, IN, 33)).toBeLessThan(0)
    })
  }

  test("P2PKH uncompressed empieza con '1'", () => {
    const addr = callAddr("btc_p2pkh_uncompressed", Wasm.hexToBytes(VECTORS_V210[0].uncomp))
    expect(addr[0]).toBe("1")
  })

  test("P2PKH uncompressed ≠ P2PKH compressed (misma clave)", () => {
    const u = callAddr("btc_p2pkh_uncompressed", Wasm.hexToBytes(VECTORS_V210[0].uncomp))
    const c = callAddr("btc_p2pkh", Wasm.hexToBytes(VECTORS_V210[0].comp))
    expect(u).not.toBe(c)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VALIDACIÓN DE CURVA EN DIRECCIONES (SEC-1 / SEC-2)
// ═══════════════════════════════════════════════════════════════════════════

describe("address v2.1.0 — validación de curva", () => {
  beforeAll(useDefault, 300_000)

  test("P2PKH rechaza X fuera de la curva (compressed)", () => {
    wasm.write(IN, offCurveCompressed(0x02))
    expect(wasm.exports.btc_p2pkh(OUT, IN, 33)).toBeLessThan(0)
  })

  test("P2WPKH rechaza X fuera de la curva", () => {
    wasm.write(IN, offCurveCompressed(0x03))
    expect(wasm.exports.btc_p2wpkh(OUT, IN, 33)).toBeLessThan(0)
  })

  test("P2SH-P2WPKH rechaza X fuera de la curva", () => {
    wasm.write(IN, offCurveCompressed(0x02))
    expect(wasm.exports.btc_p2sh_p2wpkh(OUT, IN, 33)).toBeLessThan(0)
  })

  test("P2TR rechaza X fuera de la curva", () => {
    wasm.write(IN, offCurveCompressed(0x02))
    expect(wasm.exports.btc_p2tr(OUT, IN, 33)).toBeLessThan(0)
  })

  test("ETH rechaza X fuera de la curva", () => {
    wasm.write(IN, offCurveCompressed(0x02))
    expect(wasm.exports.eth_address(OUT, IN, 33)).toBeLessThan(0)
  })

  test("Tron rechaza X fuera de la curva", () => {
    wasm.write(IN, offCurveCompressed(0x02))
    expect(wasm.exports.tron_address(OUT, IN, 33)).toBeLessThan(0)
  })

  test("[HARDENING] P2PKH uncompressed rechaza (X,Y) fuera de la curva", () => {
    wasm.write(IN, offCurveUncompressed())
    expect(wasm.exports.btc_p2pkh_uncompressed(OUT, IN, 65)).toBeLessThan(0)
  })

  test("ETH rechaza (X,Y) fuera de la curva (65 B)", () => {
    wasm.write(IN, offCurveUncompressed())
    expect(wasm.exports.eth_address(OUT, IN, 65)).toBeLessThan(0)
  })

  test("[HARDENING] Tron rechaza (X,Y) fuera de la curva (65 B)", () => {
    wasm.write(IN, offCurveUncompressed())
    expect(wasm.exports.tron_address(OUT, IN, 65)).toBeLessThan(0)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("address v2.1.0 — memoria", () => {
  beforeAll(useDefault, 300_000)
  const c = () => Wasm.hexToBytes(VECTORS_V210[0].comp)
  const u = () => Wasm.hexToBytes(VECTORS_V210[0].uncomp)

  test("Tron no causa memory.grow", () => {
    wasm.write(IN, c())
    Wasm.assertZeroAlloc("tron", wasm, () => wasm.exports.tron_address(OUT, IN, 33), 2000)
  })

  test("P2PKH uncompressed no causa memory.grow", () => {
    wasm.write(IN, u())
    Wasm.assertZeroAlloc("p2pkh_u", wasm, () => wasm.exports.btc_p2pkh_uncompressed(OUT, IN, 65), 2000)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 5) VELOCIDAD
// ═══════════════════════════════════════════════════════════════════════════

describe("address v2.1.0 — velocidad", () => {
  beforeAll(async () => {
    wasm = await benchWasm()
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 300_000)

  const c = () => Wasm.hexToBytes(VECTORS_V210[0].comp)
  const u = () => Wasm.hexToBytes(VECTORS_V210[0].uncomp)

  test("Tron (desde compressed)", () => {
    wasm.write(IN, c())
    const r = Wasm.benchSpeed("tron", 2_000, () => wasm.exports.tron_address(OUT, IN, 33), { warmup: 200, runs: 3 })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(100_000)
  }, 10_000)

  test("P2PKH uncompressed", () => {
    wasm.write(IN, u())
    const r = Wasm.benchSpeed("p2pkh_u", 5_000, () => wasm.exports.btc_p2pkh_uncompressed(OUT, IN, 65), { warmup: 500, runs: 3 })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(50_000)
  }, 10_000)
})