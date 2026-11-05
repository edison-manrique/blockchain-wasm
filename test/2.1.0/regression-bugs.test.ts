/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  regression-bugs.test.ts — Regresión de bugs corregidos en v2.1.0
 * ═══════════════════════════════════════════════════════════════════════════
 *  - FIX-1: bip32Fingerprint pasaba el xkey en vez de la pubkey
 *           (ancla: master BIP-32 TV1 → fingerprint 0x3442193e)
 *  - FIX-2: isValidPoint/compressRaw off-by-one en el último byte de Y (65 B)
 *  - FIX-3: Canonical S con >= en vez de >  (s ≤ floor(N/2))
 *  - FIX-7: normalizeSig valida longitudes de r/s
 *  - FIX-11: abort del runtime → WasmError [runtime] TRAP
 *
 *  El wrapper se carga con fromBuffer(readFileSync) porque load()/fetch
 *  falla en Windows/Bun (ENOENT).
 *
 *  Corre con:  bun test test/2.1.0/regression-bugs.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { readFileSync, existsSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { Wasm, type WasmInstance } from "../utils/wasm"
import { BlockchainWasm } from "../../src/blockchain-wasm"
import { Secp256k1 } from "../../src/secp256k1"
import { Ecdsa } from "../../src/ecdsa"
import { InvalidArgumentError, WasmError } from "../../src/errors"

const ENTRY = "assembly/index.ts"
const MASTER_FP_TV1 = 0x3442193e // fingerprint del master de BIP-32 Test Vector 1

let wasm: WasmInstance
let IN: number
let OUT: number

let _def: WasmInstance | null = null
async function defWasm(): Promise<WasmInstance> {
  if (!_def) _def = await Wasm.compileAndLoad(ENTRY)
  return _def
}
async function useDefault(): Promise<void> {
  wasm = await defWasm()
  IN = wasm.num("PARAM_IN_PTR")
  OUT = wasm.num("PARAM_OUT_PTR")
}

/** Binario precompilado para el wrapper (sin fetch). */
function wasmBytes(): Uint8Array {
  const here = dirname(fileURLToPath(import.meta.url))
  const candidates = [
    join(here, "..", "..", "build", "release.wasm"),
    join(here, "..", "..", "dist", "release.wasm"),
    join(here, "..", "..", "build", "blockchain-wasm.wasm"),
    join(here, "..", "..", "dist", "blockchain-wasm.wasm")
  ]
  for (const p of candidates) {
    if (existsSync(p)) return new Uint8Array(readFileSync(p))
  }
  throw new Error("Binario WASM no encontrado. Ajusta candidatos en wasmBytes().")
}

const N_HALF = new Uint8Array([
  0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
  0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0
])

/** a <= b big-endian byte a byte. */
function leqBE(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return true
    if (a[i] > b[i]) return false
  }
  return true
}

// ═══════════════════════════════════════════════════════════════════════════
// FIX-1: bip32Fingerprint (pubkey, no xkey)
// ═══════════════════════════════════════════════════════════════════════════

describe("regression — FIX-1: bip32Fingerprint", () => {
  beforeAll(useDefault, 300_000)

  test("raw: bip32_fingerprint(pub33) == 0x3442193e (master TV1)", () => {
    const seed = Wasm.hexToBytes("000102030405060708090a0b0c0d0e0f")
    wasm.write(IN, seed)
    expect(wasm.exports.bip32_from_seed(OUT, IN, 16)).toBe(0)
    const xkey = wasm.read(OUT, 88)

    // pubkey del master → OUT, y fingerprint SOBRE LA PUBKEY con >>> 0
    wasm.write(IN, xkey)
    wasm.exports.bip32_get_pubkey(OUT, IN)
    const fp = wasm.exports.bip32_fingerprint(OUT) >>> 0

    expect(fp).toBe(MASTER_FP_TV1)
  })

  test("wrapper: bip32Fingerprint(xkey) == 0x3442193e", async () => {
    await BlockchainWasm.fromBuffer(wasmBytes())
    const seed = Wasm.hexToBytes("000102030405060708090a0b0c0d0e0f")
    wasm.write(IN, seed)
    wasm.exports.bip32_from_seed(OUT, IN, 16)
    const xkey = wasm.read(OUT, 88)
    expect(BlockchainWasm.getInstance().bip32Fingerprint(xkey)).toBe(MASTER_FP_TV1)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// FIX-2: off-by-one del último byte de Y (65 B)
// ═══════════════════════════════════════════════════════════════════════════

describe("regression — FIX-2: isValidPoint off-by-one", () => {
  beforeAll(useDefault, 300_000)

  const G_UNCOMP =
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

  test("compressRaw valida el ÚLTIMO byte de Y (alterado → error)", () => {
    const bad = Wasm.hexToBytes(G_UNCOMP)
    bad[64] = bad[64] ^ 0x01
    wasm.write(IN, bad)
    expect(wasm.exports.compressRaw(OUT, IN, 65)).toBeLessThan(0)
  })

  test("compressRaw acepta Y íntegra válida", () => {
    wasm.write(IN, Wasm.hexToBytes(G_UNCOMP))
    expect(wasm.exports.compressRaw(OUT, IN, 65)).toBe(33)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// FIX-3: Canonical S (BIP-62)
// ═══════════════════════════════════════════════════════════════════════════

describe("regression — FIX-3: Canonical S", () => {
  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(wasmBytes())
  }, 300_000)

  test("toda firma cumple s <= floor(N/2)", () => {
    const priv = new Uint8Array(32)
    priv[31] = 0x01
    for (let i = 0; i < 8; i++) {
      const hash = new Uint8Array(32).fill(i + 1)
      const sig = Ecdsa.sign(hash, priv)
      expect(leqBE(sig.s, N_HALF)).toBe(true)
    }
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// FIX-7: normalizeSig
// ═══════════════════════════════════════════════════════════════════════════

describe("regression — FIX-7: normalizeSig", () => {
  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(wasmBytes())
  }, 300_000)

  const hash = new Uint8Array(32).fill(0x01)
  const pub = () => Secp256k1.getPublicKey(new Uint8Array(32).fill(0x01))

  test("rechaza signature.r ≠ 32 B", () => {
    const bad = { r: new Uint8Array(16), s: new Uint8Array(32), v: 0 }
    expect(() => Ecdsa.verify(hash, bad, pub())).toThrow(InvalidArgumentError)
    expect(() => Ecdsa.verify(hash, bad, pub())).toThrow(/signature\.r debe ser 32 bytes/)
  })

  test("rechaza signature.s ≠ 32 B", () => {
    const bad = { r: new Uint8Array(32), s: new Uint8Array(16), v: 0 }
    expect(() => Ecdsa.verify(hash, bad, pub())).toThrow(InvalidArgumentError)
    expect(() => Ecdsa.verify(hash, bad, pub())).toThrow(/signature\.s debe ser 32 bytes/)
  })

  test("rechaza Uint8Array ≠ 64 B", () => {
    expect(() => Ecdsa.verify(hash, new Uint8Array(32), pub())).toThrow(/signature debe ser 64 bytes/)
  })

  test("acepta Uint8Array(64) y retorna boolean", () => {
    expect(typeof Ecdsa.verify(hash, new Uint8Array(64).fill(0x02), pub())).toBe("boolean")
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// FIX-11: abort → WasmError TRAP
// ═══════════════════════════════════════════════════════════════════════════

describe("regression — FIX-11: abort handling", () => {
  test("WasmError soporta código TRAP del runtime", () => {
    const err = new WasmError("trap at 0:0:0", "runtime", "TRAP")
    expect(err.code).toBe("TRAP")
    expect(err.module).toBe("runtime")
  })
})