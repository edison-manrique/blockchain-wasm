/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  curve-validation.test.ts — Validación de curva (SEC-1, SEC-2)
 * ═══════════════════════════════════════════════════════════════════════════
 *  Pruebas de rechazo de puntos fuera de la curva en:
 *  - Secp256k1 uncompress/compress
 *  - ECDSA verify (33 y 65 B)
 *  - ECDH shared secret (33 y 65 B) + roundtrip positivo
 *  - BIP32 CKDpub (código -7)
 *  - Schnorr verify (x-only)
 *
 *  NOTA off-curve: X=1 ESTÁ en la curva (8 es residuo cuadrático mod P).
 *  Se usa X=5 (132 no es RC) como punto fuera de curva canónico.
 *
 *  Corre con:  bun test test/2.1.0/curve-validation.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance } from "../utils/wasm"

const ENTRY = "assembly/index.ts"
const OFF_CURVE_X = 0x05

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

const G_UNCOMP =
  "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

function offCurveCompressed(prefix: number): Uint8Array {
  const bad = new Uint8Array(33)
  bad[0] = prefix
  bad[32] = OFF_CURVE_X
  return bad
}

function offCurveUncompressed(): Uint8Array {
  const bad = Wasm.hexToBytes(G_UNCOMP)
  bad[64] = bad[64] ^ 0x01
  return bad
}

function privBytes(k: number): Uint8Array {
  const b = new Uint8Array(32)
  b[31] = k
  return b
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) SECP256K1 — UNCOMPRESS / COMPRESS
// ═══════════════════════════════════════════════════════════════════════════

describe("curve validation — Secp256k1", () => {
  beforeAll(useDefault, 300_000)

  test("uncompressRaw rechaza X sin raíz válida (X=5)", () => {
    wasm.write(IN, offCurveCompressed(0x02))
    expect(wasm.exports.uncompressRaw(OUT, IN, 33)).toBeLessThan(0)
  })

  test("uncompressRaw acepta X en la curva (G)", () => {
    wasm.write(IN, Wasm.hexToBytes("02" + G_UNCOMP.slice(2, 66)))
    expect(wasm.exports.uncompressRaw(OUT, IN, 33)).toBe(65)
  })

  test("compressRaw valida (X,Y) en uncompressed (65 B)", () => {
    wasm.write(IN, Wasm.hexToBytes(G_UNCOMP))
    expect(wasm.exports.compressRaw(OUT, IN, 65)).toBe(33)

    wasm.write(IN, offCurveUncompressed())
    expect(wasm.exports.compressRaw(OUT, IN, 65)).toBeLessThan(0)
  })

  test("compressRaw re-valida compressed con X fuera de curva", () => {
    wasm.write(IN, offCurveCompressed(0x03))
    expect(wasm.exports.compressRaw(OUT, IN, 33)).toBeLessThan(0)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) ECDSA VERIFY
// ═══════════════════════════════════════════════════════════════════════════

describe("curve validation — ECDSA", () => {
  beforeAll(useDefault, 300_000)

  test("verify retorna 0 para pubkey compressed fuera de curva", () => {
    const hash = new Uint8Array(32).fill(0x01)
    const sig = new Uint8Array(64).fill(0x02)
    wasm.write(IN, sig, 0)
    wasm.write(IN, offCurveCompressed(0x02), 64)
    wasm.write(IN, hash, 128)
    expect(wasm.exports.ecdsa_verify(IN + 128, IN, IN + 64, 33)).toBe(0)
  })

  test("verify retorna 0 para pubkey uncompressed fuera de curva", () => {
    const hash = new Uint8Array(32).fill(0x01)
    const sig = new Uint8Array(64).fill(0x02)
    wasm.write(IN, sig, 0)
    wasm.write(IN, offCurveUncompressed(), 64)
    wasm.write(IN, hash, 160)
    expect(wasm.exports.ecdsa_verify(IN + 160, IN, IN + 64, 65)).toBe(0)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) ECDH
// ═══════════════════════════════════════════════════════════════════════════

describe("curve validation — ECDH", () => {
  beforeAll(useDefault, 300_000)

  test("shared_secret retorna error para compressed fuera de curva", () => {
    wasm.write(IN, privBytes(1), 0)
    wasm.write(IN, offCurveCompressed(0x02), 64)
    expect(wasm.exports.ecdh_shared_secret(OUT, IN, IN + 64, 33)).toBeLessThan(0)
  })

  test("shared_secret retorna error para uncompressed fuera de curva", () => {
    wasm.write(IN, privBytes(1), 0)
    wasm.write(IN, offCurveUncompressed(), 64)
    expect(wasm.exports.ecdh_shared_secret(OUT, IN, IN + 64, 65)).toBeLessThan(0)
  })

  test("roundtrip positivo: ecdh(d1, pub2) == ecdh(d2, pub1) == compressed(2G)", () => {
    const G2_COMP = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    const d1 = new Uint8Array(32)
    d1[31] = 1
    const d2 = new Uint8Array(32)
    d2[31] = 2

    // pub1 = 1·G, pub2 = 2·G (ancladas a G)
    wasm.write(IN, d1)
    wasm.exports.pubkeyFromPrivkey(OUT, IN)
    const pub1 = wasm.read(OUT, 33)
    wasm.write(IN, d2)
    wasm.exports.pubkeyFromPrivkey(OUT, IN)
    const pub2 = wasm.read(OUT, 33)

    // shared(1, 2G) = 2G
    wasm.write(IN, d1)
    wasm.write(IN + 64, pub2)
    const rc1 = wasm.exports.ecdh_shared_secret(OUT, IN, IN + 64, 33)
    expect(rc1).toBe(33)
    const s1 = Wasm.bytesToHex(wasm.read(OUT, 33))

    // shared(2, 1G) = 2G
    wasm.write(IN, d2)
    wasm.write(IN + 64, pub1)
    const rc2 = wasm.exports.ecdh_shared_secret(OUT, IN, IN + 64, 33)
    expect(rc2).toBe(33)
    const s2 = Wasm.bytesToHex(wasm.read(OUT, 33))

    expect(s1).toBe(G2_COMP) // ancla absoluta
    expect(s2).toBe(G2_COMP) // simetría DH
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) BIP32 — CKDpub (código -7)
// ═══════════════════════════════════════════════════════════════════════════

describe("curve validation — BIP32 CKDpub", () => {
  beforeAll(useDefault, 300_000)

  /**
   * Construye un xkey PÚBLICO manual desde el master de BIP-32 TV1:
   * layout xkey: depth@0, fp@4, idx@8, isPrivate@12, chainCode@16..48, keyData@48..81.
   */
  function buildXpub(): Uint8Array {
    const seed = Wasm.hexToBytes("000102030405060708090a0b0c0d0e0f")
    wasm.write(IN, seed)
    expect(wasm.exports.bip32_from_seed(OUT, IN, 16)).toBe(0)
    const xprv = wasm.read(OUT, 88)

    wasm.write(IN, xprv)
    wasm.exports.bip32_get_pubkey(OUT, IN)
    const pub33 = wasm.read(OUT, 33)

    const xpub = new Uint8Array(xprv)
    xpub[12] = 0 // isPrivate = 0 → fuerza CKDpub
    xpub.set(pub33, 48) // keyData = pubkey compressed
    return xpub
  }

  test("CKDpub con xpub válido deriva OK (sanity del xpub manual)", () => {
    const xpub = buildXpub()
    wasm.write(IN, xpub)
    expect(wasm.exports.bip32_derive(OUT, IN, 0)).toBe(0)
  })

  test("CKDpub con X fuera de la curva retorna -7 (BIP32_ERR_PUBKEY_INVALID)", () => {
    const xpub = buildXpub()
    // Forzar X = 5 en keyData (keyData[0]=prefijo, keyData[1..33)=X)
    xpub[48] = 0x02
    for (let i = 49; i < 80; i++) xpub[i] = 0
    xpub[80] = OFF_CURVE_X
    wasm.write(IN, xpub)
    expect(wasm.exports.bip32_derive(OUT, IN, 0)).toBe(-7)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 5) SCHNORR (x-only)
// ═══════════════════════════════════════════════════════════════════════════

describe("curve validation — Schnorr", () => {
  beforeAll(useDefault, 300_000)

  test("verify retorna 0 para X x-only sin raíz válida (X=5)", () => {
    const sig = new Uint8Array(64).fill(0x02)
    const msg = new Uint8Array(32).fill(0x01)
    const badX = new Uint8Array(32)
    badX[31] = OFF_CURVE_X
    wasm.write(IN, sig, 0)
    wasm.write(IN, badX, 64)
    wasm.write(IN, msg, 128)
    expect(wasm.exports.schnorr_verify(IN, 64, IN + 128, 32, IN + 64, 32)).toBe(0)
  })
})
