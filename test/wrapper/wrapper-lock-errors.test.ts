/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  wrapper-lock-errors.test.ts — Lock del scratch + error unificado
 * ═══════════════════════════════════════════════════════════════════════════
 *  Verifica:
 *   • `_enter/_leave` impiden reentrada sobre PARAM_IN/OUT (WasmBusyError).
 *   • El lock se libera siempre, incluso si la operación lanza.
 *   • `withScratch` da exclusividad a bloques de bajo nivel.
 *   • `runExclusive` serializa bloques async (orden FIFO).
 *   • `load/fromBuffer` concurrentes comparten instancia (single-flight).
 *   • Todos los errores heredan de `BlockchainWasmError`.
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { BlockchainWasm } from "../../src/blockchain-wasm"
import { Address } from "../../src/address"
import { Secp256k1 } from "../../src/secp256k1"
import {
  BlockchainWasmError,
  WasmError,
  InvalidArgumentError,
  WasmBusyError,
  RuntimeCode,
  toBlockchainWasmError
} from "../../src/errors"
import { hexToBytes } from "../../src/types"
import { join } from "path"

const WASM_PATH = join(import.meta.dirname, "../../dist/blockchain-wasm.wasm")
const G_COMP = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
const G_P2PKH = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

describe("lock del scratch compartido", () => {
  beforeAll(async () => {
    await BlockchainWasm.fromBuffer(await Bun.file(WASM_PATH).arrayBuffer())
  })

  test("libre por defecto", () => {
    const wasm = BlockchainWasm.getInstance()
    expect(wasm.isBusy()).toBe(false)
    expect(wasm.currentOperation).toBeNull()
  })

  test("withScratch bloquea la reentrada y libera al salir", () => {
    const wasm = BlockchainWasm.getInstance()
    wasm.withScratch((scope) => {
      expect(scope.isBusy()).toBe(true)
      expect(scope.currentOperation).toBe("withScratch")
      expect(() => Address.p2pkh(hexToBytes(G_COMP))).toThrow(WasmBusyError)
    })
    expect(wasm.isBusy()).toBe(false)
    expect(wasm.currentOperation).toBeNull()
    expect(Address.p2pkh(hexToBytes(G_COMP))).toBe(G_P2PKH)
  })

  test("el lock se libera aunque el bloque lance", () => {
    const wasm = BlockchainWasm.getInstance()
    expect(() =>
      wasm.withScratch(() => {
        throw new Error("boom")
      })
    ).toThrow("boom")
    expect(wasm.isBusy()).toBe(false)
    expect(Address.p2pkh(hexToBytes(G_COMP))).toBe(G_P2PKH)
  })

  test("un error del WASM no deja el lock tomado", () => {
    const wasm = BlockchainWasm.getInstance()
    const bad = new Uint8Array(33) // prefijo 0x00 → compressRaw devuelve -1
    expect(() => Secp256k1.compress(bad)).toThrow(WasmError)
    expect(wasm.isBusy()).toBe(false)
    expect(wasm.getPublicKey(hexToBytes("00".repeat(31) + "01"), true)).toHaveLength(33)
  })

  test("runExclusive serializa bloques async en orden FIFO", async () => {
    const wasm = BlockchainWasm.getInstance()
    const events: string[] = []
    const a = wasm.runExclusive(async () => {
      events.push("a1")
      await delay(25)
      events.push("a2")
    })
    const b = wasm.runExclusive(async () => {
      events.push("b1")
      await delay(1)
      events.push("b2")
    })
    await Promise.all([a, b])
    expect(events).toEqual(["a1", "a2", "b1", "b2"])
  })

  test("runExclusive sigue operativo tras un bloque rechazado", async () => {
    const wasm = BlockchainWasm.getInstance()
    await expect(
      wasm.runExclusive(() => {
        throw new Error("fallo controlado")
      })
    ).rejects.toThrow("fallo controlado")
    expect(await wasm.runExclusive(() => 42)).toBe(42)
  })

  test("fromBuffer concurrente comparte la misma instancia (single-flight)", async () => {
    const bytes = await Bun.file(WASM_PATH).arrayBuffer()
    const [a, b] = await Promise.all([BlockchainWasm.fromBuffer(bytes), BlockchainWasm.fromBuffer(bytes)])
    expect(a).toBe(b)
    expect(BlockchainWasm.getInstance()).toBe(a)
  })

  test("cargas distintas en vuelo → WasmBusyError (no devuelve el binario equivocado)", async () => {
    const b1 = await Bun.file(WASM_PATH).arrayBuffer()
    const b2 = await Bun.file(WASM_PATH).arrayBuffer()
    const first = BlockchainWasm.fromBuffer(b1)
    const second = BlockchainWasm.fromBuffer(b2)
    await expect(second).rejects.toThrow(WasmBusyError)
    const inst = await first
    expect(BlockchainWasm.getInstance()).toBe(inst)
  })
})

describe("error unificado de la librería", () => {
  test("toda la jerarquía es instanceof BlockchainWasmError", () => {
    expect(new InvalidArgumentError("x")).toBeInstanceOf(BlockchainWasmError)
    expect(new WasmBusyError("op", "owner")).toBeInstanceOf(WasmError)
    expect(new WasmBusyError("op", "owner")).toBeInstanceOf(BlockchainWasmError)
  })

  test("WasmBusyError expone code BUSY y el owner", () => {
    const err = new WasmBusyError("requested", "owner")
    expect(err.code).toBe(RuntimeCode.BUSY)
    expect(err.owner).toBe("owner")
    expect(err.message).toContain("requested")
    expect(err.message).toContain("runExclusive")
  })

  test("from() envuelve errores ajenos y conserva cause", () => {
    const cause = new RangeError("fuera de rango")
    const wrapped = BlockchainWasmError.from(cause, "address")
    expect(wrapped).toBeInstanceOf(BlockchainWasmError)
    expect(wrapped.cause).toBe(cause)
    expect(wrapped.module).toBe("address")
    expect(wrapped.code).toBe(RuntimeCode.INTERNAL)
  })

  test("from() devuelve el mismo error si ya es de la librería", () => {
    const original = new InvalidArgumentError("x", "wif")
    expect(BlockchainWasmError.from(original)).toBe(original)
    expect(toBlockchainWasmError(original)).toBe(original)
  })

  test("toJSON es serializable", () => {
    const json = new InvalidArgumentError("x", "address").toJSON()
    expect(json).toEqual({
      name: "InvalidArgumentError",
      message: "[address] x",
      code: RuntimeCode.INVALID_ARGUMENT,
      module: "address"
    })
  })

  test("BlockchainWasmError.is discrimina errores nativos", () => {
    expect(BlockchainWasmError.is(new InvalidArgumentError("x"))).toBe(true)
    expect(BlockchainWasmError.is(new Error("x"))).toBe(false)
  })
})
