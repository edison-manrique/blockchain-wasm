/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  wrapper-utils.test.ts — utilidades puras de la frontera (sin WASM)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Cubre el contrato de `types.ts` que usa el hot path: decodificación hex,
 * validación de escalares y limpieza de copias JS.
 */
import { describe, expect, test } from "bun:test"
import {
  bytesToHex,
  hexToBytes,
  toUint8Array,
  concatBytes,
  zeroize,
  isValidPrivateKey,
} from "../../src/types"

const N = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
const N_MINUS_1 = N.slice(0, -2) + "40"
const ONE = "0000000000000000000000000000000000000000000000000000000000000001"

describe("utilidades puras (types.ts)", () => {
  test("hexToBytes: minúsculas, mayúsculas y longitud impar", () => {
    expect(Array.from(hexToBytes("00ff10"))).toEqual([0, 255, 16])
    expect(Array.from(hexToBytes("A0b1"))).toEqual([0xa0, 0xb1])
    expect(Array.from(hexToBytes("abc"))).toEqual([0x0a, 0xbc])
    expect(hexToBytes("").length).toBe(0)
  })

  test("bytesToHex ↔ hexToBytes: roundtrip de los 256 valores", () => {
    const all = new Uint8Array(256)
    for (let i = 0; i < 256; i++) all[i] = i
    expect(Array.from(hexToBytes(bytesToHex(all)))).toEqual(Array.from(all))
  })

  test("hexToBytes conserva el parseo laxo histórico", () => {
    expect(Array.from(hexToBytes("1g"))).toEqual([1])
    expect(Array.from(hexToBytes("g1"))).toEqual([0])
  })

  test("isValidPrivateKey: 0 y N inválidos; 1 y N−1 válidos", () => {
    expect(isValidPrivateKey(new Uint8Array(32))).toBe(false)
    expect(isValidPrivateKey(hexToBytes(N))).toBe(false)
    expect(isValidPrivateKey(hexToBytes(N_MINUS_1))).toBe(true)
    expect(isValidPrivateKey(hexToBytes(ONE))).toBe(true)
    expect(isValidPrivateKey(new Uint8Array(31))).toBe(false)
  })

  test("toUint8Array reutiliza Uint8Array y encodea strings UTF-8", () => {
    const same = new Uint8Array([9])
    expect(toUint8Array(same)).toBe(same)
    expect(Array.from(toUint8Array("abc"))).toEqual([97, 98, 99])
    expect(toUint8Array("ña").length).toBe(3)
  })

  test("concatBytes y zeroize no dejan residuos", () => {
    const joined = concatBytes(new Uint8Array([1, 2]), new Uint8Array([3]))
    expect(Array.from(joined)).toEqual([1, 2, 3])
    zeroize(joined, null, undefined)
    expect(Array.from(joined)).toEqual([0, 0, 0])
  })
})
