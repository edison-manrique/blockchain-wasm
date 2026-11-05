/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  wrapper-security-optin.test.ts — Seguridad explícita sin coste oculto
 * ═══════════════════════════════════════════════════════════════════════════
 *  Contrato v3.3:
 *   • `Secp256k1.isValid` (opt-in) valida pertenencia a la curva 33/64/65 B.
 *   • Las direcciones NO la ejecutan: solo rechazan lo que el algoritmo no
 *     puede procesar (P2TR/ETH/Tron con compressed necesitan descomprimir).
 *   • `wipeSecrets()` limpia el scratch WASM y es encadenable.
 *   • `zeroize(...)` limpia copias JS.
 *
 *  Usa el binario release ya compilado (dist/blockchain-wasm.wasm).
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { BlockchainWasm } from "../../src/blockchain-wasm"
import { Address } from "../../src/address"
import { Secp256k1 } from "../../src/secp256k1"
import { zeroize, hexToBytes } from "../../src/types"
import { join } from "path"

const WASM_PATH = join(import.meta.dirname, "../../dist/blockchain-wasm.wasm")

const G_COMP = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
const G_UNCOMP =
  "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

/** X = 5 → y² = 132 no es residuo cuadrático mod P. */
function offCurveCompressed(): Uint8Array {
  const bad = new Uint8Array(33)
  bad[0] = 0x02
  bad[32] = 0x05
  return bad
}
function offCurveUncompressed(): Uint8Array {
  const bad = hexToBytes(G_UNCOMP)
  bad[64] ^= 0x01
  return bad
}

describe("wrapper — validación de curva opt-in", () => {
  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(await Bun.file(WASM_PATH).arrayBuffer())
  })

  test("isValid acepta 33/64/65 B de la curva", () => {
    expect(Secp256k1.isValid(hexToBytes(G_COMP))).toBe(true)
    expect(Secp256k1.isValid(hexToBytes(G_UNCOMP))).toBe(true)
    expect(Secp256k1.isValid(hexToBytes(G_UNCOMP.slice(2)))).toBe(true)
  })

  test("isValid rechaza puntos fuera de la curva", () => {
    expect(Secp256k1.isValid(offCurveCompressed())).toBe(false)
    expect(Secp256k1.isValid(offCurveUncompressed())).toBe(false)
    expect(Secp256k1.isValid(offCurveUncompressed().subarray(1))).toBe(false)
  })

  test("isValid rechaza prefijo/longitud inválidos sin lanzar", () => {
    const badPrefix = new Uint8Array(33)
    badPrefix[0] = 0x05
    expect(Secp256k1.isValid(badPrefix)).toBe(false)
    expect(Secp256k1.isValid(new Uint8Array(32))).toBe(false)
    expect(Secp256k1.isValid(new Uint8Array(0))).toBe(false)
  })

  test("direcciones de hash directo NO validan la curva (65 B)", () => {
    const bad = offCurveUncompressed()
    expect(Address.p2pkhUncompressed(bad)[0]).toBe("1")
    expect(Address.eth(bad).slice(0, 2)).toBe("0x")
    expect(Address.tron(bad)[0]).toBe("T")
  })

  test("direcciones de hash directo NO validan la curva (compressed 33 B)", () => {
    const bad = offCurveCompressed()
    expect(Address.p2pkh(bad)[0]).toBe("1")
    expect(Address.p2wpkh(bad).slice(0, 4)).toBe("bc1q")
    expect(Address.p2shP2wpkh(bad)[0]).toBe("3")
  })

  test("P2TR/ETH/Tron compressed fallan si X no tiene raíz (necesitan Y)", () => {
    const bad = offCurveCompressed()
    expect(() => Address.p2tr(bad)).toThrow()
    expect(() => Address.eth(bad)).toThrow()
    expect(() => Address.tron(bad)).toThrow()
  })
})

describe("wrapper — borrado seguro opt-in", () => {
  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(await Bun.file(WASM_PATH).arrayBuffer())
  })

  test("wipeSecrets limpia PARAM_IN/OUT y es encadenable", () => {
    const wasm = BlockchainWasm.getInstance()
    const a = wasm.getAllocator()
    const priv = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    wasm.getPublicKey(priv, true)

    const heap = a.getHeap()
    expect(heap.slice(a.inPtr, a.inPtr + priv.length)).toEqual(priv)

    expect(wasm.wipeSecrets()).toBe(wasm)
    for (let i = 0; i < a.inSize + a.outSize; i++) {
      if (heap[a.inPtr + i] !== 0) throw new Error(`byte ${i} no se limpió`)
    }
  })

  test("zeroize limpia copias JS y tolera null/undefined", () => {
    const priv = new Uint8Array(32).fill(0xaa)
    const sig = new Uint8Array(65).fill(0xbb)
    zeroize(priv, null, undefined, sig)
    expect(priv.every((b) => b === 0)).toBe(true)
    expect(sig.every((b) => b === 0)).toBe(true)
  })

  test("wipeSecrets no rompe llamadas posteriores", () => {
    const wasm = BlockchainWasm.getInstance().wipeSecrets()
    expect(wasm.getPublicKey(hexToBytes("00".repeat(31) + "01"), true)).toEqual(hexToBytes(G_COMP))
    expect(Address.p2pkh(hexToBytes(G_COMP))).toBe("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
  })
})
