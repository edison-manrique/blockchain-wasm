import { describe, test, expect, beforeAll } from "bun:test"
import { BlockchainWasm } from "../../src/blockchain-wasm"
import { Ecdh } from "../../src/ecdh"
import { Schnorr } from "../../src/schnorr"
import { Secp256k1 } from "../../src/secp256k1"
import { hexToBytes, bytesToHex } from "../../src/types"
import { join } from "path"

const WASM_PATH = join(import.meta.dirname, "../../dist/blockchain.wasm")

const PRIV1 = "0000000000000000000000000000000000000000000000000000000000000001"
const PRIV2 = "0000000000000000000000000000000000000000000000000000000000000002"
const PRIV3 = "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9"
const G_COMP = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
const G_UNCOMP =
  "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
const XONLY_G = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
const XONLY_2G = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

// BIP-340 vector 0 (priv=3, aux=0, msg=0)
const V0_PUB = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
const V0_SIG =
  "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"

// priv del vector 0 (el que corresponde a V0_PUB / V0_SIG)
const PRIV0 = "0000000000000000000000000000000000000000000000000000000000000003"

// Vector 2 completo del BIP-340 (PRIV3 ya es su priv)
const V2_PUB = "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8"
const V2_AUX = "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906"
const V2_MSG = "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c"
const V2_SIG =
  "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"

const ZERO32 = new Uint8Array(32)

describe("wrapper ecdh + schnorr", () => {
  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(await Bun.file(WASM_PATH).arrayBuffer())
  })

  // ── ECDH ────────────────────────────────────────────────────────────────
  test("sharedSecret(1, G) == G compressed (ancla)", () => {
    expect(bytesToHex(Ecdh.sharedSecret(hexToBytes(PRIV1), hexToBytes(G_UNCOMP)))).toBe(G_COMP)
  })
  test("simetría DH: shared(a,B) == shared(b,A)", () => {
    const pub2 = Secp256k1.getPublicKey(hexToBytes(PRIV2))
    const pub3 = Secp256k1.getPublicKey(hexToBytes(PRIV3))
    expect(bytesToHex(Ecdh.sharedSecret(hexToBytes(PRIV2), pub3))).toBe(
      bytesToHex(Ecdh.sharedSecret(hexToBytes(PRIV3), pub2)),
    )
  })
  test("compressed == uncompressed (misma clave de entrada)", () => {
    const c = Secp256k1.getPublicKey(hexToBytes(PRIV3), true)
    const u = Secp256k1.getPublicKey(hexToBytes(PRIV3), false)
    expect(bytesToHex(Ecdh.sharedSecret(hexToBytes(PRIV2), c))).toBe(
      bytesToHex(Ecdh.sharedSecret(hexToBytes(PRIV2), u)),
    )
  })
  test("ECDH: priv/pub inválidos → lanza", () => {
    expect(() => Ecdh.sharedSecret(new Uint8Array(31), hexToBytes(G_COMP))).toThrow()
    expect(() => Ecdh.sharedSecret(hexToBytes(PRIV1), new Uint8Array(32))).toThrow()
  })

  // ── Schnorr ─────────────────────────────────────────────────────────────
  // ── Vector 0 (priv = …0003) ──
  test("getPublicKey(vector 0) == x-only oficial", () => {
    expect(bytesToHex(Schnorr.getPublicKey(hexToBytes(PRIV0)))).toBe(V0_PUB)
  })
  test("sign(vector 0: msg=0, aux=0) reproduce sig oficial", () => {
    expect(bytesToHex(Schnorr.sign(ZERO32, hexToBytes(PRIV0), ZERO32))).toBe(V0_SIG)
  })
  test("verify(vector 0) == true", () => {
    expect(Schnorr.verify(hexToBytes(V0_SIG), ZERO32, hexToBytes(V0_PUB))).toBe(true)
  })

  // ── Vector 2 (priv = c90fdaa2… = PRIV3): prueba bit-a-bit de sign ──
  test("getPublicKey(PRIV3) == x-only del vector 2", () => {
    expect(bytesToHex(Schnorr.getPublicKey(hexToBytes(PRIV3)))).toBe(V2_PUB)
  })
  test("sign(vector 2: msg/aux oficiales) reproduce sig oficial", () => {
    expect(bytesToHex(Schnorr.sign(hexToBytes(V2_MSG), hexToBytes(PRIV3), hexToBytes(V2_AUX)))).toBe(V2_SIG)
  })
  test("verify(vector 2) == true", () => {
    expect(Schnorr.verify(hexToBytes(V2_SIG), hexToBytes(V2_MSG), hexToBytes(V2_PUB))).toBe(true)
  })
  test("verify(vector 0) == true", () => {
    expect(Schnorr.verify(hexToBytes(V0_SIG), ZERO32, hexToBytes(V0_PUB))).toBe(true)
  })
  test("roundtrip con aux_rand del host (rng): sign→verify == true", () => {
    const msg = new Uint8Array(32).fill(0x07)
    const sig = Schnorr.sign(msg, hexToBytes(PRIV2)) // sin aux → entropía host
    const pub = Schnorr.getPublicKey(hexToBytes(PRIV2))
    expect(Schnorr.verify(sig, msg, pub)).toBe(true)
  })
  test("verify rechaza: sig corrupta / msg distinto / pub ajeno", () => {
    const msg = new Uint8Array(32).fill(0x07)
    const sig = Schnorr.sign(msg, hexToBytes(PRIV2), ZERO32)
    const pub = Schnorr.getPublicKey(hexToBytes(PRIV2))
    const bad = sig.slice()
    bad[3] ^= 0x40
    expect(Schnorr.verify(bad, msg, pub)).toBe(false)
    expect(Schnorr.verify(sig, new Uint8Array(32).fill(0x08), pub)).toBe(false)
    expect(Schnorr.verify(sig, msg, Schnorr.getPublicKey(hexToBytes(PRIV3)))).toBe(false)
  })
  test("agregación: getPub(aggPriv) == aggPub (propiedad)", () => {
    const aggPub = Schnorr.aggregatePublicKeys([hexToBytes(XONLY_G), hexToBytes(XONLY_2G)])
    const aggPriv = Schnorr.aggregatePrivateKeys([hexToBytes(PRIV1), hexToBytes(PRIV2)])
    expect(bytesToHex(Schnorr.getPublicKey(aggPriv))).toBe(bytesToHex(aggPub))
  })
  test("Schnorr: longitudes inválidas → lanza", () => {
    expect(() => Schnorr.sign(new Uint8Array(32), new Uint8Array(31))).toThrow()
    expect(() => Schnorr.verify(new Uint8Array(63), new Uint8Array(32), hexToBytes(V0_PUB))).toThrow()
    expect(() => Schnorr.aggregatePublicKeys([])).toThrow()
  })
})
