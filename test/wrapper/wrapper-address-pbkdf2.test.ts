import { describe, test, expect, beforeAll } from "bun:test"
import { BlockchainWasm } from "../../src/blockchain-wasm"
import { Address } from "../../src/address"
import { Pbkdf2 } from "../../src/pbkdf2"
import { bytesToHex, hexToBytes } from "../../src/types"

const WASM_PATH = "../../dist/blockchain.wasm" // ajusta
const PRIV1 = "0000000000000000000000000000000000000000000000000000000000000001"
const G_COMP = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
const G_UNCOMP =
  "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

describe("wrapper address + pbkdf2", () => {
  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(await Bun.file(WASM_PATH).arrayBuffer())
  })

  // ── Address (vectores de priv=1, anclas conocidas) ──────────────────────
  test("P2PKH compressed", () => {
    expect(Address.p2pkh(hexToBytes(G_COMP))).toBe("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
  })
  test("P2PKH uncompressed", () => {
    expect(Address.p2pkh(hexToBytes(G_UNCOMP))).toBe("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
  })
  test("P2WPKH (compressed)", () => {
    expect(Address.p2wpkh(hexToBytes(G_COMP))).toBe("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
  })
  test("ETH (EIP-55)", () => {
    expect(Address.eth(hexToBytes(G_COMP))).toBe("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
  })
  test("P2SH-P2WPKH: prefijo 3, longitud 34", () => {
    const addr = Address.p2shP2wpkh(hexToBytes(G_COMP))
    expect(addr[0]).toBe("3")
    expect(addr.length).toBe(34)
  })
  test("P2TR: prefijo bc1p, longitud 62", () => {
    const addr = Address.p2tr(hexToBytes(G_COMP))
    expect(addr.slice(0, 4)).toBe("bc1p")
    expect(addr.length).toBe(62)
  })
  test("fromPrivateKey(priv1, 'p2pkh')", () => {
    expect(Address.fromPrivateKey(hexToBytes(PRIV1), "p2pkh")).toBe("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
  })
  test("fromPrivateKey(priv1, 'eth')", () => {
    expect(Address.fromPrivateKey(hexToBytes(PRIV1), "eth")).toBe("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
  })
  test("pubkey inválida (longitud 32) → lanza", () => {
    expect(() => Address.p2pkh(new Uint8Array(32))).toThrow()
  })

  // ── Pbkdf2 ──────────────────────────────────────────────────────────────
  test("PBKDF2-SHA512 (vector BIP39: abandon…about, sin passphrase)", () => {
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    const seed = Pbkdf2.sha512(mnemonic, "mnemonic", 2048, 64)
    expect(bytesToHex(seed)).toBe(
      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    )
  })
  test("PBKDF2: dkLen menor es prefijo del mayor (consistencia)", () => {
    const a = Pbkdf2.sha512("password", "salt", 1, 32)
    const b = Pbkdf2.sha512("password", "salt", 1, 64)
    expect(a.length).toBe(32)
    expect(b.length).toBe(64)
    expect(bytesToHex(a)).toBe(bytesToHex(b.slice(0, 32)))
  })
  test("PBKDF2: iterations/dkLen inválidos → lanza", () => {
    expect(() => Pbkdf2.sha512("p", "s", 0, 32)).toThrow()
    expect(() => Pbkdf2.sha512("p", "s", 1, 0)).toThrow()
    expect(() => Pbkdf2.sha512("p", "s", 1, 4096)).toThrow()
  })
})