import { describe, test, expect, beforeAll } from "bun:test"
import {
  BlockchainWasm,
  Secp256k1,
  Wif,
  Address,
  Ecdsa,
  Schnorr,
  Ecdh,
  Pbkdf2,
  Bip32,
  Bip39,
  Bip44,
  SignatureFormat,
  bytesToHex,
  toUint8Array,
} from "../../src/index"
import { join } from "path"

const WASM_PATH = join(import.meta.dirname, "../../dist/blockchain-wasm.wasm")

const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const SEED =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

describe("wrapper integración (barrel)", () => {
  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(await Bun.file(WASM_PATH).arrayBuffer())
  })

  test("smoke: todas las clases de dominio están exportadas", () => {
    expect(typeof BlockchainWasm.getInstance).toBe("function")
    expect(typeof Secp256k1.getPublicKey).toBe("function")
    expect(typeof Wif.encode).toBe("function")
    expect(typeof Address.p2pkh).toBe("function")
    expect(typeof Ecdsa.sign).toBe("function")
    expect(typeof Schnorr.sign).toBe("function")
    expect(typeof Ecdh.sharedSecret).toBe("function")
    expect(typeof Pbkdf2.sha512).toBe("function")
    expect(typeof Bip32.fromSeed).toBe("function")
    expect(typeof Bip39.mnemonicToSeed).toBe("function")
    expect(typeof Bip44.deriveKeys).toBe("function")
  })

  test("flujo end-to-end: mnemonic → seed → BIP44 → direcciones → firmas → WIF → BIP32", () => {
    // 1) Mnemonic → seed
    expect(Bip39.validate(MNEMONIC)).toBe(true)
    const seed = Bip39.mnemonicToSeed(MNEMONIC)
    expect(bytesToHex(seed)).toBe(SEED)

    // 2) BIP44 m/44'/0'/0'/0/0
    const leaf = Bip44.deriveKeys(seed, 44, 0, 0, 0, 0)
    expect(leaf.privateKey.length).toBe(32)
    expect(leaf.publicKey.length).toBe(33)
    expect(bytesToHex(leaf.publicKey)).toBe(bytesToHex(Secp256k1.getPublicKey(leaf.privateKey)))

    // 3) Direcciones desde la pubkey derivada
    expect(Address.p2pkh(leaf.publicKey)[0]).toBe("1")
    expect(Address.p2wpkh(leaf.publicKey).slice(0, 4)).toBe("bc1q")
    expect(Address.p2tr(leaf.publicKey).slice(0, 4)).toBe("bc1p")
    const eth = Address.eth(leaf.publicKey)
    expect(eth.slice(0, 2)).toBe("0x")
    expect(eth.length).toBe(42)

    // 4) WIF roundtrip
    const wif = Wif.encode(leaf.privateKey)
    expect(bytesToHex(Wif.decode(wif).privateKey)).toBe(bytesToHex(leaf.privateKey))

    // 5) ECDSA sign/verify de mensaje
    const msg = toUint8Array("integration test message")
    const esig = Ecdsa.signMessage(msg, leaf.privateKey, SignatureFormat.Bitcoin)
    expect(Ecdsa.verifyMessage(msg, esig, leaf.publicKey, SignatureFormat.Bitcoin)).toBe(true)

    // 6) Schnorr sign/verify
    const msg32 = new Uint8Array(32).fill(0x42)
    const ssig = Schnorr.sign(msg32, leaf.privateKey)
    const xonly = Schnorr.getPublicKey(leaf.privateKey)
    expect(Schnorr.verify(ssig, msg32, xonly)).toBe(true)

    // 7) ECDH con una segunda clave
    const leaf2 = Bip44.deriveKeys(seed, 44, 0, 0, 0, 1)
    const secret = Ecdh.sharedSecret(leaf.privateKey, leaf2.publicKey)
    expect(secret.length).toBe(33)
    expect(bytesToHex(Ecdh.sharedSecret(leaf2.privateKey, leaf.publicKey))).toBe(bytesToHex(secret))

    // 8) BIP32 derive path → xpub
    const master = Bip32.fromSeed(seed)
    const accountXpub = master.derivePath("m/44'/0'/0'").toXpub()
    expect(accountXpub.slice(0, 4)).toBe("xpub")
    expect(Bip44.accountXpub(seed, 44, 0, 0)).toBe(accountXpub)
  })

  test("Bip39.generate (rng del host) produce mnemónico válido", () => {
    const mn = Bip39.generate(128)
    expect(mn.split(" ").length).toBe(12)
    expect(Bip39.validate(mn)).toBe(true)
  })
})
