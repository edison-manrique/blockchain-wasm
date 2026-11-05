import { describe, test, expect, beforeAll } from "bun:test"
import { BlockchainWasm } from "../../src/blockchain-wasm"
import { Bip32, HDKey } from "../../src/bip32"
import { Bip44 } from "../../src/bip44"
import { Secp256k1 } from "../../src/secp256k1"
import { hexToBytes, bytesToHex } from "../../src/types"
import { join } from "path"

const WASM_PATH = join(import.meta.dirname, "../../dist/blockchain-wasm.wasm")

// BIP32 Test Vector 1
const SEED_TV1 = "000102030405060708090a0b0c0d0e0f"
const TV1_MASTER_XPRV =
  "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
const TV1_MASTER_XPUB =
  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
const TV1_M0H_XPRV =
  "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"

// BIP39 seed de "abandon…about" (para BIP44)
const MNEMONIC_ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const SEED_ABANDON =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

describe("wrapper bip32 + bip44", () => {
  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(await Bun.file(WASM_PATH).arrayBuffer())
  })

  // ── BIP32 (vectores oficiales) ──────────────────────────────────────────
  test("fromSeed → master xprv/xpub (Test Vector 1)", () => {
    const master = Bip32.fromSeed(hexToBytes(SEED_TV1))
    expect(master.depth).toBe(0)
    expect(master.isPrivate).toBe(true)
    expect(master.toXprv()).toBe(TV1_MASTER_XPRV)
    expect(master.toXpub()).toBe(TV1_MASTER_XPUB)
  })
  test("derive(0') → xprv oficial (Test Vector 1)", () => {
    const master = Bip32.fromSeed(hexToBytes(SEED_TV1))
    const child = master.derive(0x80000000)
    expect(child.depth).toBe(1)
    expect(child.childIndex).toBe(0x80000000)
    expect(child.toXprv()).toBe(TV1_M0H_XPRV)
  })
  test("derivePath encadenable == derive manual", () => {
    const master = Bip32.fromSeed(hexToBytes(SEED_TV1))
    const a = master.derivePath("m/0'/1")
    const b = master.derive(0x80000000).derive(1)
    expect(a.toXprv()).toBe(b.toXprv())
  })
  test("neuter → xpub (isPrivate false) y toXprv lanza", () => {
    const master = Bip32.fromSeed(hexToBytes(SEED_TV1))
    const pub = master.neuter()
    expect(pub.isPrivate).toBe(false)
    expect(pub.toXpub()).toBe(master.toXpub())
    expect(() => pub.toXprv()).toThrow()
  })
  test("fromXpub roundtrip", () => {
    const master = Bip32.fromSeed(hexToBytes(SEED_TV1))
    const xpub = master.toXpub()
    const restored = Bip32.fromXpub(xpub)
    expect(restored.toXpub()).toBe(xpub)
    expect(restored.isPrivate).toBe(false)
  })
  test("getPublicKey == Secp256k1.getPublicKey(privateKey)", () => {
    const master = Bip32.fromSeed(hexToBytes(SEED_TV1))
    expect(bytesToHex(master.getPublicKey())).toBe(bytesToHex(Secp256k1.getPublicKey(master.privateKey)))
  })
  test("fingerprint es un número de 32 bits", () => {
    const master = Bip32.fromSeed(hexToBytes(SEED_TV1))
    const fp = master.fingerprint()
    expect(fp).toBeGreaterThanOrEqual(0)
    expect(fp).toBeLessThanOrEqual(0xffffffff)
  })

  // ── BIP44 (propiedades + anclas de formato) ─────────────────────────────
  test("deriveKeys: publicKey == getPublicKey(privateKey)", () => {
    const seed = hexToBytes(SEED_ABANDON)
    const leaf = Bip44.deriveKeys(seed, 44, 0, 0, 0, 0)
    expect(leaf.privateKey.length).toBe(32)
    expect(leaf.publicKey.length).toBe(33)
    expect(bytesToHex(leaf.publicKey)).toBe(bytesToHex(Secp256k1.getPublicKey(leaf.privateKey)))
  })
  test("derivePrivateKey == deriveKeys.privateKey", () => {
    const seed = hexToBytes(SEED_ABANDON)
    const priv = Bip44.derivePrivateKey(seed, 44, 0, 0, 0, 0)
    const leaf = Bip44.deriveKeys(seed, 44, 0, 0, 0, 0)
    expect(bytesToHex(priv)).toBe(bytesToHex(leaf.privateKey))
  })
  test("accountXpub/accountXprv: formato xpub/xprv", () => {
    const seed = hexToBytes(SEED_ABANDON)
    expect(Bip44.accountXpub(seed, 44, 0, 0).slice(0, 4)).toBe("xpub")
    expect(Bip44.accountXprv(seed, 44, 0, 0).slice(0, 4)).toBe("xprv")
  })
  test("fromMnemonicDerive == deriveKeys(seed) (consistencia)", () => {
    const seed = hexToBytes(SEED_ABANDON)
    const fromSeed = Bip44.deriveKeys(seed, 44, 0, 0, 0, 0)
    const fromMn = Bip44.fromMnemonicDerive(MNEMONIC_ABANDON, "", 44, 0, 0, 0, 0)
    expect(bytesToHex(fromMn.privateKey)).toBe(bytesToHex(fromSeed.privateKey))
    expect(bytesToHex(fromMn.publicKey)).toBe(bytesToHex(fromSeed.publicKey))
  })
  test("fromMnemonicXpub == accountXpub(seed) (consistencia)", () => {
    const seed = hexToBytes(SEED_ABANDON)
    expect(Bip44.fromMnemonicXpub(MNEMONIC_ABANDON, "", 44, 0, 0)).toBe(Bip44.accountXpub(seed, 44, 0, 0))
  })
  test("BIP44: seed inválido / mnemonic vacío → lanza", () => {
    expect(() => Bip44.derivePrivateKey(new Uint8Array(32), 44, 0, 0, 0, 0)).toThrow()
    expect(() => Bip44.fromMnemonicXpub("", "", 44, 0, 0)).toThrow()
  })
})
