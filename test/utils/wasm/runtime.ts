/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  test/utils/wasm/runtime.ts — Carga, ejecución y manejo optimizado de memoria
 * ═══════════════════════════════════════════════════════════════════════════
 */

import type { WasmInstance } from "./types.js"

const MASK64 = (1n << 64n) - 1n
const MASK256 = (1n << 256n) - 1n
const PAGE_SIZE = 65536

// ── Utilidades Hex Nativas Ultra-Rápidas ──

export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.replace(/\s+/g, "")
  return Uint8Array.from(Buffer.from(cleanHex, "hex"))
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("hex")
}

// ── Carga e Instanciación WASM ──

export async function load<T = Record<string, any>>(
  binary: Uint8Array,
  customImports: Record<string, any> = {}
): Promise<WasmInstance<T>> {
  const defaultImports = {
    env: {
      abort(_msg: number, _file: number, line: number, col: number): void {
        throw new Error(`WASM abort at ${line}:${col}`)
      }
    }
  }

  // Fusionar imports por defecto con customImports
  const imports = {
    ...defaultImports,
    ...customImports,
    env: {
      ...defaultImports.env,
      ...(customImports.env || {})
    }
  }

  const result: any = await WebAssembly.instantiate(binary, imports)
  const instance: WebAssembly.Instance = result.instance ?? result
  const exports = instance.exports as unknown as T
  const memory: WebAssembly.Memory | undefined = (exports as any).memory

  if (!memory) {
    throw new Error(
      "El módulo no exporta 'memory'. Si usaste noExportMemory=true, " +
      "debes proveer la memoria vía importMemory."
    )
  }

  // ── Gestión Optimizada de Vistas de Memoria ──
  let _lastByteLength = memory.buffer.byteLength
  let _view = new DataView(memory.buffer)
  let _u8 = new Uint8Array(memory.buffer)

  /**
   * OPTIMIZACIÓN GC: Solo re-crea vistas si la memoria de WASM creció (grow)
   * o si el buffer fue detached. Evita la creación continua de objetos en lecturas/escrituras.
   */
  const ensureViews = (): void => {
    const currentLength = memory.buffer.byteLength
    if (currentLength !== _lastByteLength || _u8.buffer !== memory.buffer) {
      _view = new DataView(memory.buffer)
      _u8 = new Uint8Array(memory.buffer)
      _lastByteLength = currentLength
    }
  }

  const syncViews = (): void => {
    _view = new DataView(memory.buffer)
    _u8 = new Uint8Array(memory.buffer)
    _lastByteLength = memory.buffer.byteLength
  }

  const num = (name: keyof T | string): number => {
    const g = (exports as any)[name]
    if (g == null) throw new Error(`Export '${String(name)}' no encontrado.`)
    if (typeof g === "number") return g
    if (typeof g === "object" && "value" in g) return Number(g.value)
    throw new Error(`Export '${String(name)}' no es numérico (tipo: ${typeof g})`)
  }

  const write = (ptr: number, bytes: Uint8Array): void => {
    ensureViews()
    _u8.set(bytes, ptr)
  }

  const read = (ptr: number, len: number): Uint8Array => {
    ensureViews()
    return _u8.slice(ptr, ptr + len)
  }

  const writeU256 = (ptr: number, value: bigint): void => {
    ensureViews()
    let v = value & MASK256
    _view.setBigUint64(ptr, v & MASK64, true)
    v >>= 64n
    _view.setBigUint64(ptr + 8, v & MASK64, true)
    v >>= 64n
    _view.setBigUint64(ptr + 16, v & MASK64, true)
    v >>= 64n
    _view.setBigUint64(ptr + 24, v, true)
  }

  const readU256 = (ptr: number): bigint => {
    ensureViews()
    return (
      _view.getBigUint64(ptr, true) |
      (_view.getBigUint64(ptr + 8, true) << 64n) |
      (_view.getBigUint64(ptr + 16, true) << 128n) |
      (_view.getBigUint64(ptr + 24, true) << 192n)
    )
  }

  const memoryPages = (): number => memory.buffer.byteLength / PAGE_SIZE
  const memoryBytes = (): number => memory.buffer.byteLength

  return {
    instance,
    exports,
    memory,
    get view() {
      ensureViews()
      return _view
    },
    get u8() {
      ensureViews()
      return _u8
    },
    syncViews,
    num,
    write,
    read,
    writeU256,
    readU256,
    memoryPages,
    memoryBytes
  }
}