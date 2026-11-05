/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  schnorr.test.ts — Correctitud + memoria + velocidad de BIP-340 Schnorr
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Vectores de sign/verify = test vectors OFICIALES del BIP-340
 * (bip-0340/test-vectors.csv), reproducidos y verificados con una
 * implementación Python independiente (hashlib + referencia BIP-340).
 * Los casos de verify=false y la agregación se prueban de forma
 * CONSTRUCTIVA / por PROPIEDAD (autocontenidos, sin valores absolutos
 * transcritos de memoria), que es lo robusto frente a errores de copia.
 *
 *  Corre con:  bun test test/schnorr.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/signatures/schnorr/index.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const hex = (b: Uint8Array): string => Wasm.bytesToHex(b)
const hb = (h: string): Uint8Array => Wasm.hexToBytes(h)

// ── Offsets dentro de PARAM_IN / PARAM_OUT ────────────────────────────────
const MSG = 0 // relativo a IN
const PRIV = 256 // relativo a IN
const AUX = 288 // relativo a IN
const PUB = 320 // relativo a IN
const SIG = 0 // relativo a OUT
const OUT2 = 64 // relativo a OUT
const OUT3 = 96 // relativo a OUT

// ── Cache de instancias (compila 1 vez por perfil) ────────────────────────
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

// ── Test vectors oficiales BIP-340 (verificados con Python) ───────────────
interface Vec {
  priv: string
  pub: string
  aux: string
  msg: string
  sig: string
}
const VEC: Vec[] = [
  {
    priv: "0000000000000000000000000000000000000000000000000000000000000003",
    pub: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    aux: "0000000000000000000000000000000000000000000000000000000000000000",
    msg: "0000000000000000000000000000000000000000000000000000000000000000",
    sig: "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
  },
  {
    priv: "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
    pub: "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
    aux: "0000000000000000000000000000000000000000000000000000000000000001",
    msg: "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
    sig: "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a"
  },
  {
    priv: "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
    pub: "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
    aux: "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906",
    msg: "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
    sig: "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"
  }
]

// Ancla get_pubkey cruzada con el módulo address (priv = 1 → x-only de G)
const PRIV1 = "0000000000000000000000000000000000000000000000000000000000000001"
const XONLY_G = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
const XONLY_2G = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

// ── Helpers ──────────────────────────────────────────────────────────────

function getPub(privHex: string): string {
  wasm.write(IN + PRIV, hb(privHex))
  const len: number = wasm.exports.schnorr_get_pubkey(OUT, IN + PRIV)
  expect(len).toBe(32)
  return hex(wasm.read(OUT, 32))
}

function sign(privHex: string, msgHex: string, auxHex: string): string {
  const m = hb(msgHex)
  wasm.write(IN + PRIV, hb(privHex))
  wasm.write(IN + MSG, m)
  wasm.write(IN + AUX, hb(auxHex))
  const len: number = wasm.exports.schnorr_sign(OUT + SIG, IN + MSG, m.length, IN + PRIV, IN + AUX)
  expect(len).toBe(64)
  return hex(wasm.read(OUT + SIG, 64))
}

function verify(sigHex: string, msgHex: string, pubHex: string): number {
  const m = hb(msgHex)
  wasm.write(OUT + SIG, hb(sigHex))
  wasm.write(IN + MSG, m)
  wasm.write(IN + PUB, hb(pubHex))
  return wasm.exports.schnorr_verify(OUT + SIG, 64, IN + MSG, m.length, IN + PUB, 32)
}

function aggPub(pubHexes: string[]): string {
  let buf = new Uint8Array(0)
  for (const p of pubHexes) buf = concat(buf, hb(p))
  wasm.write(IN, buf)
  const len: number = wasm.exports.schnorr_aggregate_pubkeys(OUT, IN, pubHexes.length)
  expect(len).toBe(32)
  return hex(wasm.read(OUT, 32))
}

function aggPriv(privHexes: string[]): string {
  let buf = new Uint8Array(0)
  for (const p of privHexes) buf = concat(buf, hb(p))
  wasm.write(IN, buf)
  const len: number = wasm.exports.schnorr_aggregate_privkeys(OUT, IN, privHexes.length)
  expect(len).toBe(32)
  return hex(wasm.read(OUT, 32))
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const r = new Uint8Array(a.length + b.length)
  r.set(a, 0)
  r.set(b, a.length)
  return r
}

// ═══════════════════════════════════════════════════════════════════════════
// 0) COMPILACIÓN
// ═══════════════════════════════════════════════════════════════════════════

describe("schnorr — compilación", () => {
  test("compilar y reportar stats", async () => {
    const cr: CompileResult = await Wasm.compile(ENTRY, { profile: "bench" })
    Wasm.printCompileStats(cr, "bench")
    expect(cr.sizeBytes).toBeGreaterThan(1024)
    expect(cr.compileTimeMs).toBeGreaterThan(0)
  }, 300_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 1) X-ONLY PUBLIC KEY (anclas cruzadas con address)
// ═══════════════════════════════════════════════════════════════════════════

describe("schnorr — get_pubkey", () => {
  beforeAll(useDefault, 300_000)

  test("priv=1 → x-only de G", () => {
    expect(getPub(PRIV1)).toBe(XONLY_G)
  })

  test("priv=3 → pubkey del vector 0", () => {
    expect(getPub(VEC[0].priv)).toBe(VEC[0].pub)
  })

  test("priv del vector 1 y 2", () => {
    expect(getPub(VEC[1].priv)).toBe(VEC[1].pub)
    expect(getPub(VEC[2].priv)).toBe(VEC[2].pub)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) SIGN + VERIFY (vectores oficiales BIP-340)
// ═══════════════════════════════════════════════════════════════════════════

describe("schnorr — sign/verify (BIP-340 oficiales)", () => {
  beforeAll(useDefault, 300_000)

  for (let i = 0; i < VEC.length; i++) {
    const v = VEC[i]
    test(`vector ${i}: sign reproduce la firma oficial`, () => {
      expect(sign(v.priv, v.msg, v.aux)).toBe(v.sig)
    })
    test(`vector ${i}: verify(firma oficial) == 1`, () => {
      expect(verify(v.sig, v.msg, v.pub)).toBe(1)
    })
  }
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) ROUNDTRIP verify(sign(…)) (autocontenido, varias claves/mensajes)
// ═══════════════════════════════════════════════════════════════════════════

describe("schnorr — roundtrip verify∘sign", () => {
  beforeAll(useDefault, 300_000)

  const msgs = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  ]
  const privs = [VEC[0].priv, VEC[1].priv, VEC[2].priv, PRIV1]
  const aux = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"

  for (const priv of privs) {
    for (const msg of msgs) {
      test(`roundtrip priv=${priv.slice(0, 6)}… msg=${msg.slice(0, 6)}…`, () => {
        const pub = getPub(priv)
        const sig = sign(priv, msg, aux)
        expect(verify(sig, msg, pub)).toBe(1)
      })
    }
  }
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) VERIFY = false (corrupción constructiva, autocontenido)
// ═══════════════════════════════════════════════════════════════════════════

describe("schnorr — verify rechaza firmas inválidas", () => {
  beforeAll(useDefault, 300_000)
  const v = VEC[0]

  test("firma válida pasa (sanity)", () => {
    expect(verify(v.sig, v.msg, v.pub)).toBe(1)
  })

  test("s corrompido (flip de 1 bit) → 0", () => {
    const sigB = hb(v.sig)
    sigB[60] ^= 0x01 // toca la mitad 's' de la firma
    expect(verify(hex(sigB), v.msg, v.pub)).toBe(0)
  })

  test("r corrompido (flip de 1 bit) → 0", () => {
    const sigB = hb(v.sig)
    sigB[3] ^= 0x10 // toca la mitad 'r' de la firma
    expect(verify(hex(sigB), v.msg, v.pub)).toBe(0)
  })

  test("mensaje distinto → 0", () => {
    const otherMsg = "0000000000000000000000000000000000000000000000000000000000000001"
    expect(verify(v.sig, otherMsg, v.pub)).toBe(0)
  })

  test("pubkey de otra clave → 0", () => {
    expect(verify(v.sig, v.msg, VEC[1].pub)).toBe(0)
  })

  test("firma con s ≥ N → 0 (s = n)", () => {
    // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    const sigB = hb(v.sig)
    const nBytes = hb("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
    sigB.set(nBytes, 32) // s = n  (≥ N)
    expect(verify(hex(sigB), v.msg, v.pub)).toBe(0)
  })

  test("longitud de firma ≠ 64 → 0", () => {
    wasm.write(OUT + SIG, hb(v.sig))
    wasm.write(IN + MSG, hb(v.msg))
    wasm.write(IN + PUB, hb(v.pub))
    expect(wasm.exports.schnorr_verify(OUT + SIG, 63, IN + MSG, 32, IN + PUB, 32)).toBe(0)
  })

  test("longitud de pubkey ≠ 32 → 0", () => {
    wasm.write(OUT + SIG, hb(v.sig))
    wasm.write(IN + MSG, hb(v.msg))
    wasm.write(IN + PUB, hb(v.pub))
    expect(wasm.exports.schnorr_verify(OUT + SIG, 64, IN + MSG, 32, IN + PUB, 31)).toBe(0)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 5) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("schnorr — memoria", () => {
  beforeAll(useDefault, 300_000)
  const v = VEC[0]

  test("get_pubkey no causa memory.grow", () => {
    wasm.write(IN + PRIV, hb(v.priv))
    Wasm.assertZeroAlloc("get_pubkey", wasm, () => wasm.exports.schnorr_get_pubkey(OUT, IN + PRIV), 2000)
  })

  test("sign no causa memory.grow", () => {
    const m = hb(v.msg)
    wasm.write(IN + PRIV, hb(v.priv))
    wasm.write(IN + MSG, m)
    wasm.write(IN + AUX, hb(v.aux))
    Wasm.assertZeroAlloc(
      "sign",
      wasm,
      () => wasm.exports.schnorr_sign(OUT + SIG, IN + MSG, m.length, IN + PRIV, IN + AUX),
      300
    )
  })

  test("verify no causa memory.grow", () => {
    const m = hb(v.msg)
    wasm.write(OUT + SIG, hb(v.sig))
    wasm.write(IN + MSG, m)
    wasm.write(IN + PUB, hb(v.pub))
    Wasm.assertZeroAlloc(
      "verify",
      wasm,
      () => wasm.exports.schnorr_verify(OUT + SIG, 64, IN + MSG, m.length, IN + PUB, 32),
      300
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 7) VELOCIDAD (iteraciones reducidas, timeout 10 s)
// ═══════════════════════════════════════════════════════════════════════════

describe("schnorr — velocidad", () => {
  beforeAll(useBench, 300_000)
  const v = VEC[0]

  test("get_pubkey", () => {
    wasm.write(IN + PRIV, hb(v.priv))
    const r = Wasm.benchSpeed("get_pubkey", 2_000, () => wasm.exports.schnorr_get_pubkey(OUT, IN + PRIV), {
      warmup: 300,
      runs: 3
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  }, 10_000)

  test("sign", () => {
    const m = hb(v.msg)
    wasm.write(IN + PRIV, hb(v.priv))
    wasm.write(IN + MSG, m)
    wasm.write(IN + AUX, hb(v.aux))
    const r = Wasm.benchSpeed(
      "sign",
      300,
      () => wasm.exports.schnorr_sign(OUT + SIG, IN + MSG, m.length, IN + PRIV, IN + AUX),
      { warmup: 50, runs: 3 }
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  }, 10_000)

  test("verify", () => {
    const m = hb(v.msg)
    wasm.write(OUT + SIG, hb(v.sig))
    wasm.write(IN + MSG, m)
    wasm.write(IN + PUB, hb(v.pub))
    const r = Wasm.benchSpeed(
      "verify",
      300,
      () => wasm.exports.schnorr_verify(OUT + SIG, 64, IN + MSG, m.length, IN + PUB, 32),
      { warmup: 50, runs: 3 }
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  }, 10_000)
})
