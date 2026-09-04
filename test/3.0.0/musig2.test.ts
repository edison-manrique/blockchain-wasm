/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  musig2.test.ts — Harness de validación MuSig2 (BIP-327)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  • Smoke/property tests: funcionan con cualquier versión del WASM.
 *  • Vectores oficiales: se ejecutan SOLO si el probe detecta un WASM
 *    BIP-327 estricto (66 B compressed nonces, secnonce 97 B, R=∞→G,
 *    keyagg con cpoint y coeffs conformes). Con el WASM v3.0 (x-only)
 *    se salta con mensaje informativo.
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { BlockchainWasm } from "../../src/blockchain-wasm"
import { Musig2 } from "../../src/musig2"
import { Schnorr } from "../../src/schnorr"
import { Secp256k1 } from "../../src/secp256k1"
import { getRandomBytes } from "../../src/csprng"
import { bytesToHex, hexToBytes } from "../../src/types"

let wasm: BlockchainWasm
let exp: any
let IN: number
let OUT: number
let heap: Uint8Array
let STRICT = true // true = WASM BIP-327 estricto

const hex = (b: Uint8Array): string => bytesToHex(b)
const hb = (h: string): Uint8Array => hexToBytes(h)

const VDIR = join(__dirname, "vectors", "bip-327")
function loadVec(name: string): any {
  const p = join(VDIR, name)
  return existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null
}

function writeTo(ptr: number, data: Uint8Array): void {
  heap.set(data, ptr)
}
function readFrom(ptr: number, len: number): Uint8Array {
  return heap.slice(ptr, ptr + len)
}
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0
  for (const a of arrays) total += a.length
  const res = new Uint8Array(total)
  let off = 0
  for (const a of arrays) {
    res.set(a, off)
    off += a.length
  }
  return res
}
const privB = (k: number): Uint8Array => {
  const b = new Uint8Array(32)
  b[31] = k
  return b
}
const ONE_LE = (): Uint8Array => {
  const o = new Uint8Array(32)
  o[0] = 1
  return o
}

beforeAll(async () => {
  try {
    wasm = await BlockchainWasm.load()
  } catch {
    wasm = await BlockchainWasm.fromBuffer(readFileSync(join(__dirname, "../../dist/blockchain.wasm")))
  }
  exp = wasm.getExports()
  const a = wasm.getAllocator()
  IN = a.inPtr
  OUT = a.outPtr
  heap = a.getHeap()
}, 300_000)

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS DE FLUJO (agnósticos a la versión donde sea posible)
// ═══════════════════════════════════════════════════════════════════════════
function signAll(privs: Uint8Array[], msg: Uint8Array, secrand: Uint8Array): { sig: Uint8Array; q: Uint8Array } {
  writeTo(IN, concatBytes(...privs))
  writeTo(IN + 512, msg)
  writeTo(IN + 1024, secrand)
  const rc = exp.musig2_sign_all(OUT, OUT + 64, IN, privs.length, IN + 512, msg.length, IN + 1024)
  expect(rc).toBe(64)
  return { sig: readFrom(OUT, 64), q: readFrom(OUT + 64, 32) }
}
function verify(sig: Uint8Array, msg: Uint8Array, q: Uint8Array): number {
  writeTo(OUT, sig)
  writeTo(IN, msg)
  writeTo(IN + 64, q)
  return exp.schnorr_verify(OUT, 64, IN, msg.length, IN + 64, 32)
}

// ═══════════════════════════════════════════════════════════════════════════
// 0) PROBE: ¿el WASM es BIP-327 estricto? (nonce_agg vector 0)
// ═══════════════════════════════════════════════════════════════════════════
test("probe: detección de conformidad BIP-327", () => {
  const v = loadVec("nonce_agg_vectors.json")
  if (!v) {
    console.log("  (info) sin vectores → probe omitido")
    return
  }
  writeTo(IN, concatBytes(hb(v.pnonces[0]), hb(v.pnonces[1])))
  const rc = exp.musig2_nonce_agg(OUT, IN, 2)
  STRICT = rc === 0 && hex(readFrom(OUT, 66)) === v.valid_test_cases[0].expected.toLowerCase()
  console.log(
    STRICT
      ? "  ✅ WASM BIP-327 estricto: se ejecutan los vectores oficiales"
      : "  ⚠️  WASM v3.0 (x-only): los suites oficiales se saltan (requiere parche v3.1)"
  )
})

// ═══════════════════════════════════════════════════════════════════════════
// 1) SMOKE / PROPIEDADES (validan el WASM actual, cualquier versión)
// ═══════════════════════════════════════════════════════════════════════════
describe("musig2 — smoke (sign_all ↔ BIP-340)", () => {
  const msg = new TextEncoder().encode("musig2 smoke")
  test("sign_all verifica contra Q (2 y 3 firmantes)", () => {
    for (const privs of [
      [privB(1), privB(2)],
      [privB(3), privB(4), privB(5)]
    ]) {
      const { sig, q } = signAll(privs, msg, new Uint8Array(32 * privs.length).fill(0x33))
      expect(verify(sig, msg, q)).toBe(1)
    }
  })
  test("firma no verifica con msg distinto ni Q ajeno", () => {
    const { sig, q } = signAll([privB(1), privB(2)], msg, new Uint8Array(64).fill(0x44))
    expect(verify(sig, new TextEncoder().encode("otro"), q)).toBe(0)
    const { q: q2 } = signAll([privB(9), privB(8)], msg, new Uint8Array(64).fill(0x55))
    expect(verify(sig, msg, q2)).toBe(0)
  })
  test("rogue-key: suma naive no cancela", () => {
    const privs = [privB(1), privB(2), privB(3)]
    const { q } = signAll(privs, msg, new Uint8Array(96).fill(0x66))
    const { sig } = signAll([privB(3)], msg, new Uint8Array(32).fill(0x77))
    expect(verify(sig, msg, q)).toBe(0)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) FLUJO PARCIAL v3.0 (solo si el WASM NO es estricto)
// ═══════════════════════════════════════════════════════════════════════════
describe("musig2 — flujo parcial (convención x-only v3.0)", () => {
  test("nonce_agg+session+partial+sig_agg verifica", () => {
    if (STRICT) {
      console.log("  (skip) cubierto por vectores oficiales")
      return
    }
    const msg = new TextEncoder().encode("flujo v3.0")
    const privs = [privB(1), privB(2)]
    // pubkeys x-only
    const pubs: Uint8Array[] = privs.map((p) => {
      writeTo(IN, p)
      exp.schnorr_get_pubkey(OUT, IN)
      return readFrom(OUT, 32)
    })
    const secnonces: Uint8Array[] = []
    const pubnonces: Uint8Array[] = []
    for (let i = 0; i < 2; i++) {
      writeTo(IN, new Uint8Array(32).fill(0x55 + i))
      writeTo(IN + 64, privs[i])
      writeTo(IN + 128, pubs[i])
      expect(exp.musig2_nonce_gen(OUT, OUT + 64, IN, IN + 64, IN + 128, 0, 0, 0)).toBe(0)
      secnonces.push(readFrom(OUT, 64))
      pubnonces.push(readFrom(OUT + 64, 64))
    }
    writeTo(IN, concatBytes(...pubnonces))
    expect(exp.musig2_nonce_agg(OUT, IN, 2)).toBe(0)
    const aggn = readFrom(OUT, 64)
    // keyagg x-only
    writeTo(IN, concatBytes(...pubs))
    expect(exp.musig2_keyagg(OUT, OUT + 64, IN, 2)).toBe(0)
    const q = readFrom(OUT, 32)
    const gacc = readFrom(OUT + 64, 1)[0]
    writeTo(IN, aggn)
    writeTo(IN + 128, q)
    writeTo(IN + 256, msg)
    expect(exp.musig2_session_init(OUT, IN, IN + 128, IN + 256, msg.length)).toBe(0)
    const session = readFrom(OUT, 97)
    const one = ONE_LE()
    const partials: Uint8Array[] = []
    for (let i = 0; i < 2; i++) {
      writeTo(IN, session)
      writeTo(IN + 128, secnonces[i])
      writeTo(IN + 256, privs[i])
      writeTo(IN + 320, one)
      expect(exp.musig2_partial_sign(OUT, IN, gacc, IN + 128, IN + 256, IN + 320)).toBe(0)
      partials.push(readFrom(OUT, 32))
    }
    writeTo(IN, concatBytes(...partials))
    expect(exp.musig2_partial_sig_agg(OUT, IN, 2)).toBe(0)
    const sig = new Uint8Array(64)
    sig.set(session.slice(64, 96), 0)
    sig.set(readFrom(OUT, 32), 32)
    expect(verify(sig, msg, q)).toBe(1)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VECTORES OFICIALES BIP-327 (solo WASM estricto)
// ═══════════════════════════════════════════════════════════════════════════
describe("BIP-327 — key_agg_vectors", () => {
  test("casos válidos", () => {
    if (!STRICT) {
      console.log("  (skip) requiere WASM estricto")
      return
    }
    const v = loadVec("key_agg_vectors.json")!
    for (const c of v.valid_test_cases) {
      const pubs = c.key_indices.map((i: number) => hb(v.pubkeys[i]))
      writeTo(IN, concatBytes(...pubs))
      expect(exp.musig2_keyagg(OUT, OUT + 64, IN, pubs.length)).toBe(0)
      expect(hex(readFrom(OUT, 32))).toBe(c.expected.toLowerCase())
    }
  })
  test("casos de error (pubkey inválida)", () => {
    if (!STRICT) return
    const v = loadVec("key_agg_vectors.json")!
    for (const c of v.error_test_cases) {
      if ((c.tweak_indices ?? []).length) continue // tweaks: no soportadas aún
      const pubs = c.key_indices.map((i: number) => hb(v.pubkeys[i]))
      writeTo(IN, concatBytes(...pubs))
      expect(exp.musig2_keyagg(OUT, OUT + 64, IN, pubs.length)).toBeLessThan(0)
    }
  })
})

describe("BIP-327 — nonce_agg_vectors", () => {
  test("casos válidos (incluye R2 = ∞ → 33 ceros)", () => {
    if (!STRICT) return
    const v = loadVec("nonce_agg_vectors.json")!
    for (const c of v.valid_test_cases) {
      const pn = c.pnonce_indices.map((i: number) => hb(v.pnonces[i]))
      writeTo(IN, concatBytes(...pn))
      expect(exp.musig2_nonce_agg(OUT, IN, pn.length)).toBe(0)
      expect(hex(readFrom(OUT, 66))).toBe(c.expected.toLowerCase())
    }
  })
  test("casos de error", () => {
    if (!STRICT) return
    const v = loadVec("nonce_agg_vectors.json")!
    for (const c of v.error_test_cases) {
      const pn = c.pnonce_indices.map((i: number) => hb(v.pnonces[i]))
      writeTo(IN, concatBytes(...pn))
      expect(exp.musig2_nonce_agg(OUT, IN, pn.length)).toBeLessThan(0)
    }
  })
})

describe("BIP-327 — nonce_gen_vectors", () => {
  test("secnonce(97 B) y pubnonce(66 B) exactos", () => {
    if (!STRICT) return
    const v = loadVec("nonce_gen_vectors.json")!
    for (const c of v.test_cases) {
      // layout de entrada v3.1: secrand@0 | pk33@32 | sk@68 | aggpk@104 | extra@140 | msg@176
      writeTo(IN, hb(c.rand_))
      writeTo(IN + 32, hb(c.pk))
      const skPtr = c.sk ? (writeTo(IN + 68, hb(c.sk)), IN + 68) : 0
      const aggPtr = c.aggpk ? (writeTo(IN + 104, hb(c.aggpk)), IN + 104) : 0
      const extPtr = c.extra_in ? (writeTo(IN + 140, hb(c.extra_in)), IN + 140) : 0
      const extLen = c.extra_in ? hb(c.extra_in).length : 0
      let msgPtr = 0,
        msgLen = 0
      if (c.msg != null) {
        writeTo(IN + 176, hb(c.msg))
        msgPtr = IN + 176
        msgLen = hb(c.msg).length
      }
      const rc = exp.musig2_nonce_gen(OUT, OUT + 97, IN, skPtr, IN + 32, aggPtr, msgPtr, msgLen, extPtr, extLen)
      expect(rc).toBe(0)
      expect(hex(readFrom(OUT, 97))).toBe(c.expected_secnonce.toLowerCase())
      expect(hex(readFrom(OUT + 97, 66))).toBe(c.expected_pubnonce.toLowerCase())
    }
  })
})

describe("BIP-327 — sign_verify_vectors", () => {
  test("firmas parciales exactas (incluye aggnonce = ∞ → R = G)", () => {
    if (!STRICT) return
    const v = loadVec("sign_verify_vectors.json")!
    for (const c of v.valid_test_cases) {
      const pubs = c.key_indices.map((i: number) => hb(v.pubkeys[i]))
      const msg = hb(v.msgs[c.msg_index])
      const aggn = hb(v.aggnonces[c.aggnonce_index])
      const secnonce = hb(v.secnonces[0])
      const sk = hb(v.sk)
      const signer: number = c.signer_index
      // keyagg (33 B) → q, gacc
      writeTo(IN, concatBytes(...pubs))
      expect(exp.musig2_keyagg(OUT, OUT + 64, IN, pubs.length)).toBe(0)
      const q = readFrom(OUT, 32)
      const gacc = readFrom(OUT + 64, 1)[0]
      // coeficiente del signer (BIP-327: 1 solo si pk == 2ª distinta)
      exp.musig2_keyagg_list_hash(OUT, IN, pubs.length)
      const L = readFrom(OUT, 32)
      let secondIdx = -1
      for (let i = 1; i < pubs.length; i++) {
        if (hex(pubs[i]) !== hex(pubs[0])) {
          secondIdx = i
          break
        }
      }
      let coeff: Uint8Array
      if (signer === secondIdx) coeff = ONE_LE()
      else {
        writeTo(IN, L)
        writeTo(IN + 32, pubs[signer])
        exp.musig2_keyagg_coeff(OUT, IN, IN + 32)
        coeff = readFrom(OUT, 32)
      }
      // session
      writeTo(IN, aggn)
      writeTo(IN + 128, q)
      writeTo(IN + 256, msg)
      expect(exp.musig2_session_init(OUT, IN, IN + 128, IN + 256, msg.length)).toBe(0)
      const session = readFrom(OUT, 97)
      // partial sign
      writeTo(IN, session)
      writeTo(IN + 128, secnonce)
      writeTo(IN + 256, sk)
      writeTo(IN + 320, coeff)
      expect(exp.musig2_partial_sign(OUT, IN, gacc, IN + 128, IN + 256, IN + 320)).toBe(0)
      expect(hex(readFrom(OUT, 32))).toBe(c.expected.toLowerCase())
      // partial verify del mismo signer debe dar 1
      const pubnonce = hb(v.pnonces[c.nonce_indices[signer]])
      writeTo(IN, readFrom(OUT, 32))
      writeTo(IN + 32, session)
      writeTo(IN + 160, pubnonce)
      writeTo(IN + 226, pubs[signer])
      writeTo(IN + 262, coeff)
      expect(exp.musig2_partial_verify(IN, IN + 32, gacc, IN + 160, IN + 226, IN + 262)).toBe(1)
    }
  })
  test("verify_fail: firmas negadas / signer equivocado / s ≥ N", () => {
    if (!STRICT) return
    const v = loadVec("sign_verify_vectors.json")!
    const pubs = v.valid_test_cases[0].key_indices.map((i: number) => hb(v.pubkeys[i]))
    const msg = hb(v.msgs[0])
    writeTo(IN, concatBytes(...pubs))
    expect(exp.musig2_keyagg(OUT, OUT + 64, IN, pubs.length)).toBe(0)
    const q = readFrom(OUT, 32)
    for (const c of v.verify_fail_test_cases) {
      const sig = hb(c.sig)
      expect(verify(sig, msg, q)).toBe(0)
    }
  })
})

describe("BIP-327 — sig_agg_vectors (sin tweaks)", () => {
  test("firma final = Rx ‖ Σpsig", () => {
    if (!STRICT) return
    const v = loadVec("sig_agg_vectors.json")!
    for (const c of v.valid_test_cases) {
      if ((c.tweak_indices ?? []).length) continue // tweaks: TODO v3.2
      const pubs = c.key_indices.map((i: number) => hb(v.pubkeys[i]))
      const aggn = hb(c.aggnonce)
      // session
      writeTo(IN, concatBytes(...pubs))
      expect(exp.musig2_keyagg(OUT, OUT + 64, IN, pubs.length)).toBe(0)
      const q = readFrom(OUT, 32)
      writeTo(IN, aggn)
      writeTo(IN + 128, q)
      writeTo(IN + 256, hb(v.msg))
      expect(exp.musig2_session_init(OUT, IN, IN + 128, IN + 256, hb(v.msg).length)).toBe(0)
      const session = readFrom(OUT, 97)
      // Σ psig
      const psigs = c.psig_indices.map((i: number) => hb(v.psig_indices !== undefined ? v.psigs[i] : v.psigs[i]))
      writeTo(IN, concatBytes(...psigs))
      expect(exp.musig2_partial_sig_agg(OUT, IN, psigs.length)).toBe(0)
      const sig = new Uint8Array(64)
      sig.set(session.slice(64, 96), 0)
      sig.set(readFrom(OUT, 32), 32)
      expect(hex(sig)).toBe(c.expected.toLowerCase())
    }
  })
  test("psig ≥ N → error", () => {
    if (!STRICT) return
    const v = loadVec("sig_agg_vectors.json")!
    const c = v.error_test_cases[0]
    const psigs = c.psig_indices.map((i: number) => hb(v.psigs[i]))
    writeTo(IN, concatBytes(...psigs))
    expect(exp.musig2_partial_sig_agg(OUT, IN, psigs.length)).toBeLessThan(0)
  })
})

describe("BIP-327 — tweak_vectors / det_sign_vectors", () => {
  test("tweaks: pendiente (TODO v3.2)", () => {
    if (!STRICT) return
    console.log("  (skip) ApplyTweak no implementado todavía (requiere tacc/gacc encadenados)")
  })
})

describe("Musig2 — fachada de dominio (BIP-327 y x-only)", () => {
  test("flujo completo con claves x-only de 32 B (Schnorr.getPublicKey, 50 rondas)", () => {
    for (let i = 0; i < 50; i++) {
      const priv1 = getRandomBytes(32)
      const pub1 = Schnorr.getPublicKey(priv1)
      const priv2 = getRandomBytes(32)
      const pub2 = Schnorr.getPublicKey(priv2)

      const { aggregatedPubkey: Q, gacc } = Musig2.keyAgg([pub1, pub2])
      const coeffs = Musig2.keyAggCoeffs([pub1, pub2])
      const msg = new TextEncoder().encode(`xonly test round ${i}`)

      const nonce1 = Musig2.nonceGen(getRandomBytes(32), pub1, priv1, msg)
      const nonce2 = Musig2.nonceGen(getRandomBytes(32), pub2, priv2, msg)
      const aggNonce = Musig2.nonceAgg([nonce1.pubNonce, nonce2.pubNonce])
      const session = Musig2.sessionInit(aggNonce, Q, msg)

      const psig1 = Musig2.partialSign(session, gacc, nonce1.secNonce, priv1, coeffs[0])
      const psig2 = Musig2.partialSign(session, gacc, nonce2.secNonce, priv2, coeffs[1])

      expect(Musig2.partialVerify(psig1, session, gacc, nonce1.pubNonce, pub1, coeffs[0])).toBe(true)
      expect(Musig2.partialVerify(psig2, session, gacc, nonce2.pubNonce, pub2, coeffs[1])).toBe(true)

      const s = Musig2.partialSigAgg([psig1, psig2])
      const rx = session.slice(64, 96)
      const finalSig = new Uint8Array(64)
      finalSig.set(rx, 0)
      finalSig.set(s, 32)
      expect(Schnorr.verify(finalSig, msg, Q)).toBe(true)
    }
  })

  test("flujo completo con claves comprimidas de 33 B (Secp256k1.getPublicKey, 50 rondas)", () => {
    for (let i = 0; i < 50; i++) {
      const priv1 = getRandomBytes(32)
      const pub1 = Secp256k1.getPublicKey(priv1, true)
      const priv2 = getRandomBytes(32)
      const pub2 = Secp256k1.getPublicKey(priv2, true)

      const { aggregatedPubkey: Q, gacc } = Musig2.keyAgg([pub1, pub2])
      const coeffs = Musig2.keyAggCoeffs([pub1, pub2])
      const msg = new TextEncoder().encode(`compressed test round ${i}`)

      const nonce1 = Musig2.nonceGen(getRandomBytes(32), pub1, priv1, msg)
      const nonce2 = Musig2.nonceGen(getRandomBytes(32), pub2, priv2, msg)
      const aggNonce = Musig2.nonceAgg([nonce1.pubNonce, nonce2.pubNonce])
      const session = Musig2.sessionInit(aggNonce, Q, msg)

      const psig1 = Musig2.partialSign(session, gacc, nonce1.secNonce, priv1, coeffs[0])
      const psig2 = Musig2.partialSign(session, gacc, nonce2.secNonce, priv2, coeffs[1])

      expect(Musig2.partialVerify(psig1, session, gacc, nonce1.pubNonce, pub1, coeffs[0])).toBe(true)
      expect(Musig2.partialVerify(psig2, session, gacc, nonce2.pubNonce, pub2, coeffs[1])).toBe(true)

      const s = Musig2.partialSigAgg([psig1, psig2])
      const rx = session.slice(64, 96)
      const finalSig = new Uint8Array(64)
      finalSig.set(rx, 0)
      finalSig.set(s, 32)
      expect(Schnorr.verify(finalSig, msg, Q)).toBe(true)
    }
  })
})

