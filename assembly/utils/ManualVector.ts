/**
 * =========================================================
 *  MANUAL VECTOR GENÉRICO <T>
 *  Gestiona memoria manualmente para cualquier tipo.
 * =========================================================
 */

@unmanaged
export class ManualVector<T> {
  ptr!: usize
  length!: i32
  capacity!: i32

  // Método estático para "instanciar" (Simula constructor)
  static create<T>(initialCap: i32): ManualVector<T> {
    // Alloc del struct del vector (cabecera)
    let vPtr = heap.alloc(offsetof<ManualVector<T>>())
    let v = changetype<ManualVector<T>>(vPtr)

    v.length = 0
    v.capacity = initialCap
    // Alloc del buffer de datos
    v.ptr = heap.alloc(usize(initialCap) * sizeof<T>())

    return v
  }

  // Método de instancia
  push(value: T): void {
    if (this.length >= this.capacity) {
      let newCap = this.capacity == 0 ? 4 : this.capacity * 2
      this.ptr = heap.realloc(this.ptr, usize(newCap) * sizeof<T>())
      this.capacity = newCap
    }

    // Cálculo de dirección genérico
    let offset = usize(this.length) * sizeof<T>()
    store<T>(this.ptr + offset, value)
    this.length++
  }

  get(index: i32): T {
    // En release mode, quitamos el check para velocidad máxima
    // if (index >= this.length) throw new Error("Index out of bounds");

    let offset = usize(index) * sizeof<T>()
    return load<T>(this.ptr + offset)
  }

  // Setter rápido
  set(index: i32, value: T): void {
    let offset = usize(index) * sizeof<T>()
    store<T>(this.ptr + offset, value)
  }

  destroy(): void {
    // Liberar buffer de datos
    heap.free(this.ptr)
    // Liberar el propio struct (this)
    heap.free(changetype<usize>(this))
  }
}
