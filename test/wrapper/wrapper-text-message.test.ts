import { describe, test, expect, beforeAll } from "bun:test"
import { BlockchainWasm, Ecdsa, Schnorr, Secp256k1, SignatureFormat, hexToBytes } from "../../src/index"

const WASM_PATH = "../../dist/blockchain.wasm" // ajusta
const PRIV1 = "0000000000000000000000000000000000000000000000000000000000000001"
const TEXT = "Autorizo esta transacción"

describe("wrapper signTextMessage / verifyTextMessage", () => {
  let priv: Uint8Array
  let pub: Uint8Array
  let xonly: Uint8Array

  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(await Bun.file(WASM_PATH).arrayBuffer())
    priv = hexToBytes(PRIV1)
    pub = Secp256k1.getPublicKey(priv)
    xonly = Schnorr.getPublicKey(priv)
  })

  const formatos = [
    ["Universal", SignatureFormat.Universal],
    ["Bitcoin", SignatureFormat.Bitcoin],
    ["Ethereum", SignatureFormat.Ethereum]
  ] as const

  for (const [name, fmt] of formatos) {
    test(`ECDSA signTextMessage/verifyTextMessage (${name})`, () => {
      const sig = Ecdsa.signTextMessage(TEXT, priv, fmt)
      expect(Ecdsa.verifyTextMessage(TEXT, sig, pub, fmt)).toBe(true)
      // mensaje distinto → falla
      expect(Ecdsa.verifyTextMessage("otro mensaje", sig, pub, fmt)).toBe(false)
      // formato distinto al firmar → falla
      const otherFmt = fmt === SignatureFormat.Universal ? SignatureFormat.Bitcoin : SignatureFormat.Universal
      expect(Ecdsa.verifyTextMessage(TEXT, sig, pub, otherFmt)).toBe(false)
    })

    test(`Schnorr signTextMessage/verifyTextMessage (${name})`, () => {
      const sig = Schnorr.signTextMessage(TEXT, priv, fmt)
      expect(Schnorr.verifyTextMessage(TEXT, sig, xonly, fmt)).toBe(true)
      expect(Schnorr.verifyTextMessage("otro mensaje", sig, xonly, fmt)).toBe(false)
      const otherFmt = fmt === SignatureFormat.Universal ? SignatureFormat.Bitcoin : SignatureFormat.Universal
      expect(Schnorr.verifyTextMessage(TEXT, sig, xonly, otherFmt)).toBe(false)
    })
  }

  test("ECDSA acepta firma compacta (r‖s) en verifyTextMessage", () => {
    const sig = Ecdsa.signTextMessage(TEXT, priv, SignatureFormat.Ethereum)
    const compact = new Uint8Array(64)
    compact.set(sig.r, 0)
    compact.set(sig.s, 32)
    expect(Ecdsa.verifyTextMessage(TEXT, compact, pub, SignatureFormat.Ethereum)).toBe(true)
  })
})
