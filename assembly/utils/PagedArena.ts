// @ts-ignore
@final
export class PagedArena {
  // Punteros de la página actual
  static currentPtr: usize = 0
  static limitPtr: usize = 0 // Final de la página actual

  // Punteros para la gestión de páginas
  static headPage: usize = 0 // La primera página (para el reset)
  static activePage: usize = 0 // La página donde estamos escribiendo ahora

  // Configuración
  static readonly PAGE_SIZE: usize = 65536 // 64KB por página
  // Offset reservado al inicio de cada página para guardar el puntero a la "siguiente página"
  static readonly HEADER_SIZE: usize = 4 // 4 bytes para el puntero 'next'

  static init(): void {
    if (PagedArena.headPage == 0) {
      PagedArena.allocateNewPage()
    }
  }

  // Crea una página nueva y la configura como activa
  private static allocateNewPage(): void {
    // 1. Pedir memoria al sistema (TLSF)
    let newPage = heap.alloc(PagedArena.PAGE_SIZE)

    // Inicializamos el header (next pointer) a 0 (null)
    store<usize>(newPage, 0)

    // 2. Enlazar: Si ya había una página activa, le decimos que su 'next' es esta nueva
    if (PagedArena.activePage != 0) {
      // Escribimos la dirección de la nueva página en el header de la vieja
      store<usize>(PagedArena.activePage, newPage)
    } else {
      // Si es la primera de todas, es la Head
      PagedArena.headPage = newPage
    }

    // 3. Actualizar estado
    PagedArena.activePage = newPage

    // El puntero de escritura empieza DESPUÉS del header
    PagedArena.currentPtr = newPage + PagedArena.HEADER_SIZE
    PagedArena.limitPtr = newPage + PagedArena.PAGE_SIZE

    trace("[Arena] New Page Allocated: " + newPage.toString(16))
  }

  @inline
  static alloc(size: usize): usize {
    // Alineación a 8 bytes
    let ptr = (PagedArena.currentPtr + 7) & ~7
    let nextPtr = ptr + size

    // ¿Nos salimos de la página actual?
    if (nextPtr > PagedArena.limitPtr) {
      // CASO DE CRECIMIENTO:

      // 1. Miramos si la página actual ya tiene una "siguiente página" enlazada
      // (Esto pasa si hicimos reset y estamos reutilizando memoria vieja)
      let nextPage = load<usize>(PagedArena.activePage)

      if (nextPage != 0) {
        // ¡GENIAL! Ya existe memoria reservada del frame anterior. Reutilizamos.
        PagedArena.activePage = nextPage
        PagedArena.currentPtr = nextPage + PagedArena.HEADER_SIZE
        PagedArena.limitPtr = nextPage + PagedArena.PAGE_SIZE
        trace("[Arena] Moving to existing next page")
      } else {
        // No hay espacio, hay que pedir RAM fresca al sistema
        PagedArena.allocateNewPage()
      }

      // Recalculamos punteros en la nueva página
      ptr = (PagedArena.currentPtr + 7) & ~7
      nextPtr = ptr + size
    }

    PagedArena.currentPtr = nextPtr
    return ptr
  }

  // Reset ULTRA RÁPIDO
  @inline
  static reset(): void {
    // Si la arena está vacía o fue destruida, la inicializamos automáticamente.
    if (PagedArena.headPage == 0) {
      PagedArena.init()
    }
    // No liberamos nada. Simplemente volvemos al principio de la primera página.
    // Así, en el siguiente frame, sobrescribiremos los datos viejos sin coste de alloc/free.
    PagedArena.activePage = PagedArena.headPage
    PagedArena.currentPtr = PagedArena.headPage + PagedArena.HEADER_SIZE
    PagedArena.limitPtr = PagedArena.headPage + PagedArena.PAGE_SIZE
  }

  // ==========================================
  // SCOPING DINÁMICO (SAVE / RESTORE)
  // ==========================================

  @inline
  static save(): usize {
    if (PagedArena.headPage == 0) {
      PagedArena.init()
    }
    return PagedArena.currentPtr
  }

  @inline
  static restore(savedPtr: usize): void {
    // 1. FAST PATH (Ruta Rápida):
    // ¿El puntero pertenece a la página actual? (Casi siempre es el caso en scopes pequeños)
    if (savedPtr >= PagedArena.activePage && savedPtr <= PagedArena.limitPtr) {
      PagedArena.currentPtr = savedPtr
      return
    }

    // 2. SLOW PATH (Ruta Lenta):
    // El puntero pertenece a una página anterior. Tenemos que buscar cuál es.
    let page = PagedArena.headPage
    while (page != 0) {
      let limit = page + PagedArena.PAGE_SIZE

      // Comprobamos si el puntero guardado cae dentro de esta página
      if (savedPtr >= page && savedPtr <= limit) {
        // ¡La encontramos! Restauramos toda la máquina de estado a esta página
        PagedArena.activePage = page
        PagedArena.currentPtr = savedPtr
        PagedArena.limitPtr = limit
        return
      }

      // Leer el puntero 'next' oculto en los primeros 4/8 bytes de la página
      page = load<usize>(page)
    }

    // Si llegamos aquí, se intentó restaurar un puntero corrupto o de otra arena
    trace("FATAL: PagedArena.restore() called with invalid pointer!", 0)
    unreachable()
  }

  // Destrucción total (Al cerrar el nivel/juego)
  static destroy(): void {
    let page = PagedArena.headPage
    while (page != 0) {
      let next = load<usize>(page)
      heap.free(page) // Devolvemos la memoria al sistema (TLSF)
      page = next
    }
    PagedArena.headPage = 0
    PagedArena.activePage = 0
    PagedArena.currentPtr = 0
    PagedArena.limitPtr = 0
  }
}
