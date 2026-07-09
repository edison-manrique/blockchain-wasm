// @ts-ignore
@final
export class Memory {
  static basePtr: usize = 0
  static currentPtr: usize = 0
  static limitPtr: usize = 0

  static init(): void {
    if (Memory.basePtr == 0) {
      // Reservamos 64KB
      Memory.basePtr = heap.alloc(65536)
      Memory.currentPtr = Memory.basePtr
      Memory.limitPtr = Memory.basePtr + 65536
    }
  }

  @inline
  static alloc(size: usize): usize {
    // 2. ALINEACIÓN (CRÍTICO):
    // Muchos tipos de datos (f64, i64) funcionan más rápido o requieren
    // estar en direcciones múltiplos de 8.
    // Esto redondea currentPtr hacia arriba al múltiplo de 8 más cercano.
    let ptr = (Memory.currentPtr + 7) & ~7

    let nextPtr = ptr + size

    // 3. SEGURIDAD (Solo en debug si quieres rendimiento máximo en release):
    // Si te pasas de memoria, sin esto corromperás el heap principal.
    if (nextPtr > Memory.limitPtr) {
      unreachable() // O lanzar error, o expandir memoria
    }

    Memory.currentPtr = nextPtr
    return ptr
  }

  // Resetear todo (útil para limpiar entre frames de un juego)
  @inline
  static reset(): void {
    Memory.currentPtr = Memory.basePtr
  }

  @inline
  static save(): usize {
    return Memory.currentPtr
  }

  @inline
  static restore(savedPtr: usize): void {
    Memory.currentPtr = savedPtr
  }
}

Memory.init()
