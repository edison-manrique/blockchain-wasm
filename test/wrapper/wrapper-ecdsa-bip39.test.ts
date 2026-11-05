import { describe, test, expect, beforeAll } from "bun:test"
import { BlockchainWasm } from "../../src/blockchain-wasm"
import { Ecdsa, SignatureFormat } from "../../src/ecdsa"
import { Bip39 } from "../../src/bip39"
import { Secp256k1 } from "../../src/secp256k1"
import { hexToBytes, bytesToHex, toUint8Array } from "../../src/types"
import { join } from "path"

const WASM_PATH = join(import.meta.dirname, "../../dist/blockchain-wasm.wasm")

const PRIV1 = "0000000000000000000000000000000000000000000000000000000000000001"
const PRIV2 = "0000000000000000000000000000000000000000000000000000000000000002"

// BIP39 vector oficial (entropy 16 ceros)
const ENTROPY_ZEROS = "00000000000000000000000000000000"
const MNEMONIC_ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const SEED_ABANDON =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

describe("wrapper ecdsa + bip39", () => {
  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(await Bun.file(WASM_PATH).arrayBuffer())
  })

  // ── ECDSA ───────────────────────────────────────────────────────────────
  test("sign/verify roundtrip (hash fijo)", () => {
    const hash = new Uint8Array(32).fill(0x01)
    const sig = Ecdsa.sign(hash, hexToBytes(PRIV1))
    expect(sig.r.length).toBe(32)
    expect(sig.s.length).toBe(32)
    expect([0, 1]).toContain(sig.v)
    const pub = Secp256k1.getPublicKey(hexToBytes(PRIV1))
    expect(Ecdsa.verify(hash, sig, pub)).toBe(true)
  })
  test("verify acepta firma compacta (r‖s, 64 B)", () => {
    const hash = new Uint8Array(32).fill(0x01)
    const sig = Ecdsa.sign(hash, hexToBytes(PRIV1))
    const compact = new Uint8Array(64)
    compact.set(sig.r, 0)
    compact.set(sig.s, 32)
    const pub = Secp256k1.getPublicKey(hexToBytes(PRIV1))
    expect(Ecdsa.verify(hash, compact, pub)).toBe(true)
  })
  test("verify rechaza: hash distinto / pub ajeno", () => {
    const hash = new Uint8Array(32).fill(0x01)
    const sig = Ecdsa.sign(hash, hexToBytes(PRIV1))
    const pub = Secp256k1.getPublicKey(hexToBytes(PRIV1))
    expect(Ecdsa.verify(new Uint8Array(32).fill(0x02), sig, pub)).toBe(false)
    expect(Ecdsa.verify(hash, sig, Secp256k1.getPublicKey(hexToBytes(PRIV2)))).toBe(false)
  })
  test("messageHash Universal == SHA-256 (ancla 'abc')", () => {
    expect(bytesToHex(Ecdsa.messageHash(toUint8Array("abc"), SignatureFormat.Universal))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
  })
  test("signMessage/verifyMessage roundtrip (formato Bitcoin)", () => {
    const msg = toUint8Array("hello blockchain")
    const pub = Secp256k1.getPublicKey(hexToBytes(PRIV1))
    const sig = Ecdsa.signMessage(msg, hexToBytes(PRIV1), SignatureFormat.Bitcoin)
    expect(Ecdsa.verifyMessage(msg, sig, pub, SignatureFormat.Bitcoin)).toBe(true)
    expect(Ecdsa.verifyMessage(toUint8Array("hello blockchaiN"), sig, pub, SignatureFormat.Bitcoin)).toBe(false)
  })
  test("ECDSA: longitudes inválidas → lanza", () => {
    expect(() => Ecdsa.sign(new Uint8Array(31), hexToBytes(PRIV1))).toThrow()
    expect(() =>
      Ecdsa.verify(new Uint8Array(32), new Uint8Array(63), Secp256k1.getPublicKey(hexToBytes(PRIV1))),
    ).toThrow()
  })

  // ── BIP39 ───────────────────────────────────────────────────────────────
  test("entropyToMnemonic(16 ceros) == abandon…about", () => {
    expect(Bip39.entropyToMnemonic(hexToBytes(ENTROPY_ZEROS))).toBe(MNEMONIC_ABANDON)
  })
  test("mnemonicToSeed(abandon…about, '') == seed oficial", () => {
    expect(bytesToHex(Bip39.mnemonicToSeed(MNEMONIC_ABANDON, ""))).toBe(SEED_ABANDON)
  })
  test("mnemonicToEntropy roundtrip", () => {
    expect(bytesToHex(Bip39.mnemonicToEntropy(MNEMONIC_ABANDON))).toBe(ENTROPY_ZEROS)
  })
  test("validate: válido true / checksum inválido false", () => {
    expect(Bip39.validate(MNEMONIC_ABANDON)).toBe(true)
    expect(
      Bip39.validate("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"),
    ).toBe(false)
  })
  test("generate(128) → 12 palabras y validate true (rng del host)", () => {
    const mn = Bip39.generate(128)
    expect(mn.split(" ").length).toBe(12)
    expect(Bip39.validate(mn)).toBe(true)
  })
  test("generate(256) → 24 palabras", () => {
    expect(Bip39.generate(256).split(" ").length).toBe(24)
  })
  test("generate con strength inválido → lanza", () => {
    expect(() => Bip39.generate(100)).toThrow()
  })
})
