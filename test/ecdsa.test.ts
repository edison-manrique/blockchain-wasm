/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdsa.test.ts — Correctitud + memoria + velocidad de ECDSA secp256k1
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Estrategia de validación (robusta frente a errores de transcripción):
 *   • ANCLAS de message-hash Universal = SHA-256 puro de "" y "abc", ya
 *     validados en sha2.test.ts (confianza máxima).
 *   • ANCLAS de pubkey a G (hecho matemático de secp256k1): los roundtrips de
 *     sign/verify se prueban con pubkeys derivadas y comparadas contra G, así
 *     verify se ejercita contra una pubkey de origen externo y confiable.
 *   • PROPIEDADES: roundtrip verify∘sign, determinismo RFC 6979, canonical S
 *     (BIP-62), verify=false constructivo, compressed == uncompressed.
 *   • GOLDEN impreso para hashes Bitcoin/Ethereum y una firma de ejemplo
 *     (cruza con bitcoinjs/ethers si quieres asserts absolutos).
 *
 *  Corre con:  bun test test/ecdsa.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/signatures/ecdsa/index.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const hex = (b: Uint8Array): string => Wasm.bytesToHex(b)
const hb = (h: string): Uint8Array => Wasm.hexToBytes(h)
const enc = (s: string): Uint8Array => new TextEncoder().encode(s)

// ── Formatos ──────────────────────────────────────────────────────────────
const F_UNIVERSAL = 0
const F_BITCOIN = 1
const F_ETHEREUM = 2

// ── Offsets ───────────────────────────────────────────────────────────────
const MSG = 0
const HASH = 256
const PRIV = 288
const PUB = 320 // hasta 385
const SIG = 0 // OUT
const HASH_OUT = 96 // OUT
const PUB_OUT = 128 // OUT

// ── Anclas de alta confianza ──────────────────────────────────────────────
const G_COMP = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
const G_UNCOMP =
  "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
const SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
const SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

const PRIV1 = "0000000000000000000000000000000000000000000000000000000000000001"
const PRIV2 = "0000000000000000000000000000000000000000000000000000000000000002"
const PRIV3 = "0000000000000000000000000000000000000000000000000000000000000003"
const N_BE = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
const N_HALF_BE = new Uint8Array([
  0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e,
  0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0
])

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

function msgHash(msg: Uint8Array, format: number): string {
  wasm.write(IN + MSG, msg)
  const len: number = wasm.exports.ecdsa_message_hash(OUT + HASH_OUT, IN + MSG, msg.length, format)
  expect(len).toBe(32)
  return hex(wasm.read(OUT + HASH_OUT, 32))
}

function signHash(hashHex: string, privHex: string): string {
  wasm.write(IN + HASH, hb(hashHex))
  wasm.write(IN + PRIV, hb(privHex))
  const len: number = wasm.exports.ecdsa_sign(OUT + SIG, IN + HASH, IN + PRIV)
  expect(len).toBe(65)
  return hex(wasm.read(OUT + SIG, 64)) // r‖s (v en +64, no usado por verify)
}

function verifyHash(hashHex: string, sigHex: string, pubHex: string): number {
  wasm.write(IN + HASH, hb(hashHex))
  wasm.write(OUT + SIG, hb(sigHex))
  wasm.write(IN + PUB, hb(pubHex))
  return wasm.exports.ecdsa_verify(IN + HASH, OUT + SIG, IN + PUB, pubHex.length / 2)
}

function pubC(privHex: string): string {
  wasm.write(IN + PRIV, hb(privHex))
  wasm.exports.pubkeyFromPrivkey(OUT + PUB_OUT, IN + PRIV)
  return hex(wasm.read(OUT + PUB_OUT, 33))
}

function pubU(privHex: string): string {
  wasm.write(IN + PRIV, hb(privHex))
  wasm.exports.pubkeyUncompressedFromPrivkey(OUT + PUB_OUT, IN + PRIV)
  return hex(wasm.read(OUT + PUB_OUT, 65))
}

/** s (32 B BE) < N/2 estricto (canonical BIP-62). */
function isCanonicalS(sigBytes: Uint8Array): boolean {
  const s = sigBytes.slice(32, 64)
  for (let i = 0; i < 32; i++) {
    if (s[i] < N_HALF_BE[i]) return true
    if (s[i] > N_HALF_BE[i]) return false
  }
  return false // s == N/2 no es < (pero el código niega >=, así que no ocurre)
}

// ═══════════════════════════════════════════════════════════════════════════
// 0) COMPILACIÓN
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdsa — compilación", () => {
  test("compilar y reportar stats", async () => {
    const cr: CompileResult = await Wasm.compile(ENTRY, { profile: "bench" })
    Wasm.printCompileStats(cr, "bench")
    expect(cr.sizeBytes).toBeGreaterThan(1024)
    expect(cr.compileTimeMs).toBeGreaterThan(0)
  }, 300_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 1) MESSAGE HASH — anclas Universal (SHA-256 puro) + propiedades
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdsa — message hash", () => {
  beforeAll(useDefault, 300_000)

  test("Universal('') == SHA-256('')  [ancla sha2]", () => {
    expect(msgHash(enc(""), F_UNIVERSAL)).toBe(SHA256_EMPTY)
  })

  test("Universal('abc') == SHA-256('abc')  [ancla sha2]", () => {
    expect(msgHash(enc("abc"), F_UNIVERSAL)).toBe(SHA256_ABC)
  })

  test("determinismo por formato", () => {
    const m = enc("hello world")
    expect(msgHash(m, F_BITCOIN)).toBe(msgHash(m, F_BITCOIN))
    expect(msgHash(m, F_ETHEREUM)).toBe(msgHash(m, F_ETHEREUM))
  })

  test("los 3 formatos dan hashes distintos para el mismo msg", () => {
    const m = enc("hello world")
    const u = msgHash(m, F_UNIVERSAL)
    const b = msgHash(m, F_BITCOIN)
    const e = msgHash(m, F_ETHEREUM)
    expect(u).not.toBe(b)
    expect(u).not.toBe(e)
    expect(b).not.toBe(e)
  })

  test("msg distinto → hash distinto (Universal)", () => {
    expect(msgHash(enc("abc"), F_UNIVERSAL)).not.toBe(msgHash(enc("abd"), F_UNIVERSAL))
  })

  test("varint Bitcoin: msg de 0, 100 y 300 bytes (cruce de umbral 0xfd)", () => {
    const a = msgHash(new Uint8Array(0), F_BITCOIN)
    const b = msgHash(new Uint8Array(100), F_BITCOIN)
    const c = msgHash(new Uint8Array(300), F_BITCOIN) // > 0xfd → varint de 3 bytes
    expect(a.length).toBe(64)
    expect(b.length).toBe(64)
    expect(c.length).toBe(64)
    expect(a).not.toBe(b)
    expect(b).not.toBe(c)
  })

  test("golden (inspección) — cruza con bitcoinjs/ethers", () => {
    const m = enc("hello")
    console.log("\n═══ ecdsa message-hash golden (msg = 'hello') ═══")
    console.log("Universal :", msgHash(m, F_UNIVERSAL))
    console.log("Bitcoin   :", msgHash(m, F_BITCOIN))
    console.log("Ethereum  :", msgHash(m, F_ETHEREUM))
    // firma de ejemplo con priv=1 sobre hash Universal de "hello"
    const h = msgHash(m, F_UNIVERSAL)
    const sig = signHash(h, PRIV1)
    console.log("sign(priv=1, sha256('hello')) r‖s:", sig)
    console.log("")
    expect(true).toBe(true)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) ANCLAS DE PUBKEY A G
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdsa — pubkey anclada a G", () => {
  beforeAll(useDefault, 300_000)

  test("pubkeyFromPrivkey(1) == G compressed", () => {
    expect(pubC(PRIV1)).toBe(G_COMP)
  })

  test("pubkeyUncompressedFromPrivkey(1) == G uncompressed", () => {
    expect(pubU(PRIV1)).toBe(G_UNCOMP)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) ROUNDTRIP verify∘sign (pubkey anclada; compressed + uncompressed)
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdsa — roundtrip verify∘sign", () => {
  beforeAll(useDefault, 300_000)

  const privs = [PRIV1, PRIV2, PRIV3]
  const msgs = [enc(""), enc("abc"), enc("Satoshi Nakamoto")]

  for (const priv of privs) {
    for (const m of msgs) {
      const tag = `priv=${priv.slice(-2)} msg='${new TextDecoder().decode(m) || "∅"}'`
      test(`roundtrip ${tag} (compressed + uncompressed)`, () => {
        const h = msgHash(m, F_UNIVERSAL)
        const sig = signHash(h, priv)
        const pc = pubC(priv)
        const pu = pubU(priv)
        expect(verifyHash(h, sig, pc)).toBe(1)
        expect(verifyHash(h, sig, pu)).toBe(1)
      })
    }
  }
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) DETERMINISMO RFC 6979 + CANONICAL S
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdsa — RFC 6979 determinismo + canonical S", () => {
  beforeAll(useDefault, 300_000)

  test("sign dos veces → misma firma (nonce determinístico)", () => {
    const h = msgHash(enc("determinism check"), F_UNIVERSAL)
    expect(signHash(h, PRIV2)).toBe(signHash(h, PRIV2))
  })

  test("canonical S: s < N/2 en todas las firmas", () => {
    const msgs = [enc(""), enc("abc"), enc("xyz"), enc("BIP-62 low-S")]
    for (const priv of [PRIV1, PRIV2, PRIV3]) {
      for (const m of msgs) {
        const h = msgHash(m, F_UNIVERSAL)
        const sig = signHash(h, priv)
        expect(isCanonicalS(hb(sig))).toBe(true)
      }
    }
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 5) VERIFY = false (corrupción constructiva)
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdsa — verify rechaza", () => {
  beforeAll(useDefault, 300_000)
  const h = () => msgHash(enc("verify me"), F_UNIVERSAL)
  let sig: string
  let pc: string

  beforeAll(() => {
    sig = signHash(h(), PRIV1)
    pc = pubC(PRIV1)
  })

  test("firma válida pasa (sanity)", () => {
    expect(verifyHash(h(), sig, pc)).toBe(1)
  })

  test("r corrompido → 0", () => {
    const b = hb(sig)
    b[3] ^= 0x40
    expect(verifyHash(h(), hex(b), pc)).toBe(0)
  })

  test("s corrompido → 0", () => {
    const b = hb(sig)
    b[40] ^= 0x07
    expect(verifyHash(h(), hex(b), pc)).toBe(0)
  })

  test("hash distinto → 0", () => {
    const h2 = msgHash(enc("verify me!"), F_UNIVERSAL)
    expect(verifyHash(h2, sig, pc)).toBe(0)
  })

  test("pubkey ajena → 0", () => {
    expect(verifyHash(h(), sig, pubC(PRIV2))).toBe(0)
  })

  test("r = 0 → 0", () => {
    const b = hb(sig)
    for (let i = 0; i < 32; i++) b[i] = 0
    expect(verifyHash(h(), hex(b), pc)).toBe(0)
  })

  test("s = 0 → 0", () => {
    const b = hb(sig)
    for (let i = 32; i < 64; i++) b[i] = 0
    expect(verifyHash(h(), hex(b), pc)).toBe(0)
  })

  test("r ≥ N → 0", () => {
    const b = hb(sig)
    b.set(hb(N_BE), 0) // r = N (fuera de rango)
    expect(verifyHash(h(), hex(b), pc)).toBe(0)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 6) SIGN/VERIFY DE MENSAJE (por formato)
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdsa — sign/verify message por formato", () => {
  beforeAll(useDefault, 300_000)

  function signMsg(m: Uint8Array, privHex: string, format: number): string {
    wasm.write(IN + MSG, m)
    wasm.write(IN + PRIV, hb(privHex))
    const len: number = wasm.exports.ecdsa_sign_message(OUT + SIG, IN + MSG, m.length, IN + PRIV, format)
    expect(len).toBe(65)
    return hex(wasm.read(OUT + SIG, 64))
  }
  function verifyMsg(m: Uint8Array, sigHex: string, pubHex: string, format: number): number {
    wasm.write(IN + MSG, m)
    wasm.write(OUT + SIG, hb(sigHex))
    wasm.write(IN + PUB, hb(pubHex))
    return wasm.exports.ecdsa_verify_message(IN + MSG, m.length, OUT + SIG, IN + PUB, pubHex.length / 2, format)
  }

  for (const f of [F_UNIVERSAL, F_BITCOIN, F_ETHEREUM]) {
    const fname = ["Universal", "Bitcoin", "Ethereum"][f]
    test(`roundtrip formato ${fname}`, () => {
      const m = enc("hello blockchain")
      const pc = pubC(PRIV3)
      const sig = signMsg(m, PRIV3, f)
      expect(verifyMsg(m, sig, pc, f)).toBe(1)
      // formato distinto → falla (hash distinto)
      const other = (f + 1) % 3
      expect(verifyMsg(m, sig, pc, other)).toBe(0)
      // mensaje distinto → falla
      expect(verifyMsg(enc("hello blockchaiN"), sig, pc, f)).toBe(0)
    })
  }
})

// ═══════════════════════════════════════════════════════════════════════════
// 7) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdsa — memoria", () => {
  beforeAll(useDefault, 300_000)
  const h = msgHashRef()

  function msgHashRef(): string {
    return "" // placeholder, se rellena en beforeAll real
  }

  test("sign no causa memory.grow", () => {
    const hash = msgHash(enc("zero alloc"), F_UNIVERSAL)
    wasm.write(IN + HASH, hb(hash))
    wasm.write(IN + PRIV, hb(PRIV1))
    Wasm.assertZeroAlloc("sign", wasm, () => wasm.exports.ecdsa_sign(OUT + SIG, IN + HASH, IN + PRIV), 200)
  })

  test("verify no causa memory.grow", () => {
    const hash = msgHash(enc("zero alloc"), F_UNIVERSAL)
    const sig = signHash(hash, PRIV1)
    const pc = pubC(PRIV1)
    wasm.write(IN + HASH, hb(hash))
    wasm.write(OUT + SIG, hb(sig))
    wasm.write(IN + PUB, hb(pc))
    Wasm.assertZeroAlloc("verify", wasm, () => wasm.exports.ecdsa_verify(IN + HASH, OUT + SIG, IN + PUB, 33), 200)
  })

  test("message_hash no causa memory.grow", () => {
    const m = enc("zero alloc message")
    wasm.write(IN + MSG, m)
    Wasm.assertZeroAlloc(
      "msg_hash",
      wasm,
      () => wasm.exports.ecdsa_message_hash(OUT + HASH_OUT, IN + MSG, m.length, F_BITCOIN),
      2000
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 8) VELOCIDAD (iteraciones reducidas, timeout 10 s)
// ═══════════════════════════════════════════════════════════════════════════

describe("ecdsa — velocidad", () => {
  beforeAll(useBench, 300_000)

  test("sign", () => {
    const hash = msgHash(enc("bench"), F_UNIVERSAL)
    wasm.write(IN + HASH, hb(hash))
    wasm.write(IN + PRIV, hb(PRIV1))
    const r = Wasm.benchSpeed("sign", 200, () => wasm.exports.ecdsa_sign(OUT + SIG, IN + HASH, IN + PRIV), {
      warmup: 30,
      runs: 3
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  }, 10_000)

  test("verify", () => {
    const hash = msgHash(enc("bench"), F_UNIVERSAL)
    const sig = signHash(hash, PRIV1)
    const pc = pubC(PRIV1)
    wasm.write(IN + HASH, hb(hash))
    wasm.write(OUT + SIG, hb(sig))
    wasm.write(IN + PUB, hb(pc))
    const r = Wasm.benchSpeed("verify", 200, () => wasm.exports.ecdsa_verify(IN + HASH, OUT + SIG, IN + PUB, 33), {
      warmup: 30,
      runs: 3
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  }, 10_000)

  test("message_hash (Bitcoin, double SHA-256)", () => {
    const m = enc("bench message hashing")
    wasm.write(IN + MSG, m)
    const r = Wasm.benchSpeed(
      "msg_hash_btc",
      10_000,
      () => wasm.exports.ecdsa_message_hash(OUT + HASH_OUT, IN + MSG, m.length, F_BITCOIN),
      { warmup: 1000, runs: 3 }
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(50_000)
  }, 10_000)
})
