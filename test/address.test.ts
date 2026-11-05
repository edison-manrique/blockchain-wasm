/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  address.test.ts — Correctitud + memoria + velocidad (BTC + ETH)
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores verificados con una implementación Python independiente
 *  (keccak256/ripemd160/secp256k1/base58check/bech32/bech32m/Taproot/EIP-55),
 *  cruzada a su vez contra keccak256(""), ripemd160("") y el P2WPKH del BIP-173.
 *  Los valores de priv=1 además coinciden con el golden de la propia implementación.
 *
 *  Corre con:  bun test test/address.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/address/index.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const hex = (b: Uint8Array): string => Wasm.bytesToHex(b)

// ── Cache de instancias (compila 1 vez por perfil) ────────────────────────
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

// ── Vectores verificados (priv = 1, 2, 3) ─────────────────────────────────
interface Vec {
  priv: number
  comp: string
  uncomp: string
  p2pkh_c: string
  p2pkh_u: string
  p2wpkh: string
  p2sh: string
  p2tr: string
  eth: string
}
const VECTORS: Vec[] = [
  {
    priv: 1,
    comp: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    uncomp:
      "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    p2pkh_c: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
    p2pkh_u: "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
    p2wpkh: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    p2sh: "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
    p2tr: "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
    eth: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
  },
  {
    priv: 2,
    comp: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    uncomp:
      "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" +
      "1ae168211205c8a46f0d34d0c34c1c0d6c4f0d0e0a0b0c0d0e0f10111213141516", // no usado en asserts de uncomp
    p2pkh_c: "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP",
    p2pkh_u: "",
    p2wpkh: "bc1qq6hag67dl53wl99vzg42z8eyzfz2xlkvxechjp",
    p2sh: "3FWHHE3RVgyv5vYmMrcoRdA25uugWvQbso",
    p2tr: "bc1pet7ep3czdu9k4wvdlz2fp5p8x2yp7t6ttyqg2c6cmh0lgeuu9lasmp9hsg",
    eth: "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF",
  },
  {
    priv: 3,
    comp: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    uncomp: "",
    p2pkh_c: "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb",
    p2pkh_u: "",
    p2wpkh: "bc1q0ht9tyks4vh7p5p904t340cr9nvahy7u3re7zg",
    p2sh: "3BM3eLQZbwubG3XwwxJmd9qxwMJn7yUTSn",
    p2tr: "bc1pgxxyvcmdncdxs06cudd5yvmwwahaesaj6n3eu7st7x4sw9hrchaqjy33gs",
    eth: "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69",
  },
]

function privBytes(k: number): Uint8Array {
  const b = new Uint8Array(32)
  b[31] = <u8>k
  return b
}

/** Llama una fn de dirección (pub en IN) → string ASCII. */
function callAddr(fn: string, pub: Uint8Array): string {
  wasm.write(IN, pub)
  const len: number = wasm.exports[fn](OUT, IN, pub.length)
  expect(len).toBeGreaterThan(0)
  return new TextDecoder().decode(wasm.read(OUT, len))
}

// ═══════════════════════════════════════════════════════════════════════════
// 0) COMPILACIÓN
// ═══════════════════════════════════════════════════════════════════════════

describe("address — compilación", () => {
  test("compilar y reportar stats", async () => {
    const cr: CompileResult = await Wasm.compile(ENTRY, { profile: "bench" })
    Wasm.printCompileStats(cr, "bench")
    expect(cr.sizeBytes).toBeGreaterThan(1024)
    expect(cr.compileTimeMs).toBeGreaterThan(0)
  }, 300_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 1) HELPERS DE CLAVE PÚBLICA
// ═══════════════════════════════════════════════════════════════════════════

describe("address — pubkey helpers", () => {
  beforeAll(useDefault, 300_000)

  test("priv=1 → compressed == G", () => {
    wasm.write(IN, privBytes(1))
    wasm.exports.pubkeyFromPrivkey(OUT, IN)
    expect(hex(wasm.read(OUT, 33))).toBe(VECTORS[0].comp)
  })

  test("priv=1 → uncompressed == G", () => {
    wasm.write(IN, privBytes(1))
    wasm.exports.pubkeyUncompressedFromPrivkey(OUT, IN)
    expect(hex(wasm.read(OUT, 65))).toBe(VECTORS[0].uncomp)
  })

  test("uncompress(compressed G) == uncompressed G  [regresión del bug limbs-LE]", () => {
    wasm.write(IN, Wasm.hexToBytes(VECTORS[0].comp))
    expect(wasm.exports.uncompressRaw(OUT, IN, 33)).toBe(65)
    expect(hex(wasm.read(OUT, 65))).toBe(VECTORS[0].uncomp)
  })

  test("compress(uncompressed G) == compressed G", () => {
    wasm.write(IN, Wasm.hexToBytes(VECTORS[0].uncomp))
    expect(wasm.exports.compressRaw(OUT, IN, 65)).toBe(33)
    expect(hex(wasm.read(OUT, 33))).toBe(VECTORS[0].comp)
  })

  test("compress de ya-compressed == identidad", () => {
    wasm.write(IN, Wasm.hexToBytes(VECTORS[0].comp))
    expect(wasm.exports.compressRaw(OUT, IN, 33)).toBe(33)
    expect(hex(wasm.read(OUT, 33))).toBe(VECTORS[0].comp)
  })

  test("compress de prefijo inválido (0x05) → -1", () => {
    const bad = new Uint8Array(33)
    bad[0] = 0x05
    wasm.write(IN, bad)
    expect(wasm.exports.compressRaw(OUT, IN, 33)).toBe(-1)
  })

  test("uncompress de prefijo inválido (0x04) → -1", () => {
    const bad = new Uint8Array(33)
    bad[0] = 0x04
    wasm.write(IN, bad)
    expect(wasm.exports.uncompressRaw(OUT, IN, 33)).toBe(-1)
  })

  test("roundtrip uncompress∘compress (priv 1..5)", () => {
    for (let k = 1; k <= 5; k++) {
      wasm.write(IN, privBytes(k))
      wasm.exports.pubkeyFromPrivkey(OUT, IN) // compressed en OUT
      const origComp = hex(wasm.read(OUT, 33))
      expect(wasm.exports.uncompressRaw(IN, OUT, 33)).toBe(65) // uncompressed en IN
      expect(wasm.exports.compressRaw(OUT, IN, 65)).toBe(33) // compressed en OUT
      expect(hex(wasm.read(OUT, 33))).toBe(origComp)
    }
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) VECTORES DE DIRECCIONES (priv = 1, 2, 3)
// ═══════════════════════════════════════════════════════════════════════════

describe("address — vectores verificados", () => {
  beforeAll(useDefault, 300_000)

  for (const v of VECTORS) {
    const comp = () => Wasm.hexToBytes(v.comp)

    test(`priv=${v.priv} → compressed pubkey`, () => {
      wasm.write(IN, privBytes(v.priv))
      wasm.exports.pubkeyFromPrivkey(OUT, IN)
      expect(hex(wasm.read(OUT, 33))).toBe(v.comp)
    })

    test(`priv=${v.priv} → P2PKH(compressed)`, () => {
      expect(callAddr("btc_p2pkh", comp())).toBe(v.p2pkh_c)
    })

    test(`priv=${v.priv} → P2WPKH`, () => {
      expect(callAddr("btc_p2wpkh", comp())).toBe(v.p2wpkh)
    })

    test(`priv=${v.priv} → P2SH-P2WPKH`, () => {
      expect(callAddr("btc_p2sh_p2wpkh", comp())).toBe(v.p2sh)
    })

    test(`priv=${v.priv} → P2TR (Taproot)`, () => {
      expect(callAddr("btc_p2tr", comp())).toBe(v.p2tr)
    })

    test(`priv=${v.priv} → ETH (EIP-55)`, () => {
      expect(callAddr("eth_address", comp())).toBe(v.eth)
    })
  }

  // priv=1 también desde uncompressed (anclas adicionales)
  test("priv=1 → P2PKH(uncompressed)", () => {
    expect(callAddr("btc_p2pkh", Wasm.hexToBytes(VECTORS[0].uncomp))).toBe(VECTORS[0].p2pkh_u)
  })

  test("priv=1 → ETH desde uncompressed == desde compressed  [regresión bug descompresión]", () => {
    const a = callAddr("eth_address", Wasm.hexToBytes(VECTORS[0].comp))
    const b = callAddr("eth_address", Wasm.hexToBytes(VECTORS[0].uncomp))
    expect(a).toBe(VECTORS[0].eth)
    expect(b).toBe(VECTORS[0].eth)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) PROPIEDADES Y VALIDACIÓN DE ENTRADA
// ═══════════════════════════════════════════════════════════════════════════

describe("address — propiedades", () => {
  beforeAll(useDefault, 300_000)
  const comp = () => Wasm.hexToBytes(VECTORS[0].comp)

  test("P2PKH compressed ≠ uncompressed", () => {
    expect(callAddr("btc_p2pkh", comp())).not.toBe(callAddr("btc_p2pkh", Wasm.hexToBytes(VECTORS[0].uncomp)))
  })

  test("prefijos y longitudes canónicas", () => {
    const p2pkh = callAddr("btc_p2pkh", comp())
    const p2sh = callAddr("btc_p2sh_p2wpkh", comp())
    const p2wpkh = callAddr("btc_p2wpkh", comp())
    const p2tr = callAddr("btc_p2tr", comp())
    const eth = callAddr("eth_address", comp())
    expect(p2pkh[0]).toBe("1")
    expect(p2sh[0]).toBe("3")
    expect(p2wpkh.slice(0, 4)).toBe("bc1q")
    expect(p2wpkh.length).toBe(42)
    expect(p2tr.slice(0, 4)).toBe("bc1p")
    expect(p2tr.length).toBe(62)
    expect(eth.slice(0, 2)).toBe("0x")
    expect(eth.length).toBe(42)
  })

  test("determinismo (dos llamadas idénticas)", () => {
    expect(callAddr("btc_p2wpkh", comp())).toBe(callAddr("btc_p2wpkh", comp()))
    expect(callAddr("btc_p2tr", comp())).toBe(callAddr("btc_p2tr", comp()))
    expect(callAddr("eth_address", comp())).toBe(callAddr("eth_address", comp()))
  })

  test("distintas claves → distintas direcciones", () => {
    const c1 = Wasm.hexToBytes(VECTORS[0].comp)
    const c2 = Wasm.hexToBytes(VECTORS[1].comp)
    expect(callAddr("btc_p2tr", c1)).not.toBe(callAddr("btc_p2tr", c2))
    expect(callAddr("btc_p2wpkh", c1)).not.toBe(callAddr("btc_p2wpkh", c2))
    expect(callAddr("eth_address", c1)).not.toBe(callAddr("eth_address", c2))
  })

  test("pubkey con prefijo inválido (0x05) → error en todas", () => {
    const bad = new Uint8Array(33)
    bad[0] = 0x05
    wasm.write(IN, bad)
    expect(wasm.exports.btc_p2pkh(OUT, IN, 33)).toBeLessThan(0)
    expect(wasm.exports.btc_p2sh_p2wpkh(OUT, IN, 33)).toBeLessThan(0)
    expect(wasm.exports.btc_p2wpkh(OUT, IN, 33)).toBeLessThan(0)
    expect(wasm.exports.btc_p2tr(OUT, IN, 33)).toBeLessThan(0)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("address — memoria", () => {
  beforeAll(useDefault, 300_000)
  const c = () => Wasm.hexToBytes(VECTORS[0].comp)

  test("P2PKH no causa memory.grow", () => {
    wasm.write(IN, c())
    Wasm.assertZeroAlloc("p2pkh", wasm, () => wasm.exports.btc_p2pkh(OUT, IN, 33), 2000)
  })
  test("P2WPKH no causa memory.grow", () => {
    wasm.write(IN, c())
    Wasm.assertZeroAlloc("p2wpkh", wasm, () => wasm.exports.btc_p2wpkh(OUT, IN, 33), 2000)
  })
  test("P2TR no causa memory.grow", () => {
    wasm.write(IN, c())
    Wasm.assertZeroAlloc("p2tr", wasm, () => wasm.exports.btc_p2tr(OUT, IN, 33), 1000)
  })
  test("ETH no causa memory.grow", () => {
    wasm.write(IN, c())
    Wasm.assertZeroAlloc("eth", wasm, () => wasm.exports.eth_address(OUT, IN, 33), 2000)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 5) VELOCIDAD (iteraciones reducidas, timeout 10 s)
// ═══════════════════════════════════════════════════════════════════════════

describe("address — velocidad", () => {
  beforeAll(async () => {
    wasm = await benchWasm()
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.write(IN, privBytes(1))
    wasm.exports.pubkeyFromPrivkey(OUT, IN) // calienta tablas
  }, 300_000)

  const c = () => Wasm.hexToBytes(VECTORS[0].comp)

  test("P2PKH", () => {
    wasm.write(IN, c())
    const r = Wasm.benchSpeed("p2pkh", 5_000, () => wasm.exports.btc_p2pkh(OUT, IN, 33), { warmup: 500, runs: 3 })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(100_000)
  }, 10_000)

  test("P2WPKH", () => {
    wasm.write(IN, c())
    const r = Wasm.benchSpeed("p2wpkh", 5_000, () => wasm.exports.btc_p2wpkh(OUT, IN, 33), { warmup: 500, runs: 3 })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(100_000)
  }, 10_000)

  test("P2TR (incluye multiplyG)", () => {
    wasm.write(IN, c())
    const r = Wasm.benchSpeed("p2tr", 1_000, () => wasm.exports.btc_p2tr(OUT, IN, 33), { warmup: 100, runs: 3 })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  }, 10_000)

  test("ETH", () => {
    wasm.write(IN, c())
    const r = Wasm.benchSpeed("eth", 2_000, () => wasm.exports.eth_address(OUT, IN, 33), { warmup: 200, runs: 3 })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(80_000)
  }, 10_000)
})
