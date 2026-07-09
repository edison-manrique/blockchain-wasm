// =============================================================================
// 🧠 ARENA DE MEMORIA LOCAL (ZERO-DEPENDENCY)
// =============================================================================

export namespace LocalArena {
  // 64KB de memoria estática en la sección .data del binario WASM.
  // Evita llamadas al sistema y al Garbage Collector.
  const basePtr: usize = memory.data(65536)
  let currentPtr: usize = basePtr

  /**
   * Asigna memoria con alineación de 16 bytes.
   * Crítico para que WASM optimice lecturas/escrituras con load/store.
   */
  // @ts-ignore
  @inline
  export function alloc(size: usize): usize {
    let ptr = (currentPtr + 15) & ~15
    currentPtr = ptr + size
    return ptr
  }

  // @ts-ignore
  @inline
  export function save(): usize {
    return currentPtr
  }

  // @ts-ignore
  @inline
  export function restore(savedPtr: usize): void {
    currentPtr = savedPtr
  }
}