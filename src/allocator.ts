/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  allocator.ts — Puente JS ↔ memoria lineal del WASM (I/O plano)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * El núcleo WASM opera 100 % sobre punteros a SU memoria lineal. Los
 * Uint8Array del usuario viven en el heap de JS; este allocator es la frontera
 * que los copia hacia/desde PARAM_IN / PARAM_OUT (reservados una vez al cargar).
 *
 * Zero‑overhead en el hot path:
 *  • Mantiene una ÚNICA vista del heap (`getHeap()`), cacheada y revalidada
 *    solo si la memoria crece (no crea un Uint8Array nuevo por operación).
 *  • `writeInput`/`readOutput` reusan las mismas regiones (memoria plana).
 */
export class WasmAllocator {
  private memory: WebAssembly.Memory
  private heap: Uint8Array | null = null

  /** Región de entrada (PARAM_IN). */
  readonly inPtr: number
  readonly inSize: number
  /** Región de salida (PARAM_OUT). */
  readonly outPtr: number
  readonly outSize: number

  /** Resultado del último `writeInput`. */
  lastPtr: number = 0
  lastLen: number = 0

  constructor(memory: WebAssembly.Memory, inPtr: number, inSize: number, outPtr: number, outSize: number) {
    this.memory = memory
    this.inPtr = inPtr
    this.inSize = inSize
    this.outPtr = outPtr
    this.outSize = outSize
  }

  /** Vista del heap cacheada; se regenera si `memory.buffer` cambia (memory.grow). */
  getHeap(): Uint8Array {
    if (!this.heap || this.heap.buffer !== this.memory.buffer) {
      this.heap = new Uint8Array(this.memory.buffer)
    }
    return this.heap
  }

  /** Escribe `data` en PARAM_IN + offset. @returns puntero absoluto. */
  writeInput(data: Uint8Array, offset: number = 0): number {
    if (offset + data.length > this.inSize) {
      throw new RangeError(`writeInput: ${data.length} B en offset ${offset} excede PARAM_IN (${this.inSize} B)`)
    }
    const ptr = this.inPtr + offset
    this.getHeap().set(data, ptr)
    this.lastPtr = ptr
    this.lastLen = data.length
    return ptr
  }

  /** Copia `len` bytes de PARAM_OUT + offset a un Uint8Array nuevo. */
  readOutput(len: number, offset: number = 0): Uint8Array {
    if (offset + len > this.outSize) {
      throw new RangeError(`readOutput: ${len} B en offset ${offset} excede PARAM_OUT (${this.outSize} B)`)
    }
    return this.getHeap().slice(this.outPtr + offset, this.outPtr + offset + len)
  }

  /** Copia `len` bytes desde un puntero absoluto cualquiera. */
  readBytes(ptr: number, len: number): Uint8Array {
    return this.getHeap().slice(ptr, ptr + len)
  }
}
