/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  errors.ts — Error único de la librería + especializaciones
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  TODOS los errores que produce blockchain-wasm heredan de
 *  `BlockchainWasmError`, así que un consumidor puede capturarlos de una sola
 *  vez:
 *
 *  ```ts
 *  try {
 *    await BlockchainWasm.load()
 *    Address.p2pkh(pub)
 *  } catch (err) {
 *    if (err instanceof BlockchainWasmError) console.error(err.code, err.module)
 *    else throw err
 *  }
 *  ```
 *
 *  Jerarquía:
 *  • BlockchainWasmError  — base: `code`, `module`, `cause`, `toJSON()`.
 *  • WasmError            — error de dominio/WASM (compatibilidad v3.x).
 *  • NotInitializedError  — se usa BlockchainWasm antes de load/fromBuffer.
 *  • MissingExportError   — binario desincronizado (falta export/global).
 *  • InvalidArgumentError — validación de frontera en las fachadas.
 *  • WasmBusyError        — reentrada/concurrencia sobre el scratch compartido.
 *  • EntropyError         — CSPRNG ausente o generador inválido.
 *
 *  Los códigos numéricos de dominio (rc < 0 del WASM) viajan en `code`; el
 *  camino caliente no construye errores (solo se lanzan si rc < 0).
 */

// ═══════════════════════════════════════════════════════════════════════════
// CÓDIGOS
// ═══════════════════════════════════════════════════════════════════════════

export enum RuntimeCode {
  NOT_INITIALIZED = "NOT_INITIALIZED",
  MISSING_EXPORT = "MISSING_EXPORT",
  INVALID_ARGUMENT = "INVALID_ARGUMENT",
  BUSY = "BUSY",
  TRAP = "TRAP",
  ENTROPY_UNAVAILABLE = "ENTROPY_UNAVAILABLE",
  ENTROPY_INVALID = "ENTROPY_INVALID",
  INTERNAL = "INTERNAL"
}

export type BlockchainWasmErrorCode = RuntimeCode | number | string

export interface BlockchainWasmErrorOptions {
  /** Error original que provocó este (encadenado). */
  cause?: unknown
}

// ═══════════════════════════════════════════════════════════════════════════
// BASE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Error raíz de la librería. Cualquier fallo lanzado por el wrapper (incluidos
 * los rc < 0 del WASM) es `instanceof BlockchainWasmError`.
 */
export class BlockchainWasmError extends Error {
  /** Código de runtime (`RuntimeCode`) o rc numérico del WASM. */
  readonly code: BlockchainWasmErrorCode
  /** Módulo que originó el error: "runtime", "address", "bip32"… */
  readonly module: string
  /** Error original, si lo hubo. */
  override readonly cause?: unknown

  constructor(
    message: string,
    module: string,
    code: BlockchainWasmErrorCode,
    options?: BlockchainWasmErrorOptions
  ) {
    super(`[${module}] ${message}`)
    this.name = "BlockchainWasmError"
    this.module = module
    this.code = code
    if (options && "cause" in options) this.cause = options.cause
    // Mantiene `instanceof` correcto aunque el bundle transpile a ES5.
    Object.setPrototypeOf(this, new.target.prototype)
  }

  /** `true` si `err` pertenece a la jerarquía de la librería. */
  static is(err: unknown): err is BlockchainWasmError {
    return err instanceof BlockchainWasmError
  }

  /**
   * Normaliza CUALQUIER error al tipo de la librería.
   *
   * Útil en consumidores que quieren un único `catch` tipado: los `Error`
   * nativos (o rechazos de promesas) se envuelven conservando `cause`.
   */
  static from(err: unknown, module = "runtime", code: BlockchainWasmErrorCode = RuntimeCode.INTERNAL): BlockchainWasmError {
    if (err instanceof BlockchainWasmError) return err
    const message = err instanceof Error ? err.message : String(err)
    return new BlockchainWasmError(message, module, code, { cause: err })
  }

  /** Representación serializable (logs, IPC, telemetría). */
  toJSON(): { name: string; message: string; code: BlockchainWasmErrorCode; module: string } {
    return { name: this.name, message: this.message, code: this.code, module: this.module }
  }
}

/** Alias de compatibilidad: todos los errores de dominio eran `WasmError`. */
export class WasmError extends BlockchainWasmError {
  constructor(message: string, module: string, code: BlockchainWasmErrorCode, options?: BlockchainWasmErrorOptions) {
    super(message, module, code, options)
    this.name = "WasmError"
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ESPECIALIZACIONES
// ═══════════════════════════════════════════════════════════════════════════

export class NotInitializedError extends WasmError {
  constructor() {
    super(
      "WASM no inicializado. Llama a `await BlockchainWasm.fromBuffer(bytes)` / fromUrl() / load() antes de usar cualquier módulo.",
      "runtime",
      RuntimeCode.NOT_INITIALIZED
    )
    this.name = "NotInitializedError"
  }
}

export class MissingExportError extends WasmError {
  constructor(name: string) {
    super(
      `El binario WASM no exporta '${name}'. ¿Binario desincronizado? Recompila con 'bun run asbuild'.`,
      "runtime",
      RuntimeCode.MISSING_EXPORT
    )
    this.name = "MissingExportError"
  }
}

export class InvalidArgumentError extends WasmError {
  constructor(message: string, module = "runtime") {
    super(message, module, RuntimeCode.INVALID_ARGUMENT)
    this.name = "InvalidArgumentError"
  }
}

/**
 * El scratch del WASM (PARAM_IN/PARAM_OUT + work worlds) es único y compartido.
 * Esta bandera impide que una operación empiece mientras otra está en curso
 * (reentrada) y que dos cargas async compitan por el singleton.
 */
export class WasmBusyError extends WasmError {
  /** Operación que tenía el lock cuando se intentó entrar. */
  readonly owner: string

  constructor(requested: string, owner: string) {
    super(
      `WASM ocupado por '${owner}' mientras se intentaba '${requested}'. ` +
        "No compartas el singleton entre operaciones solapadas: usa `await wasm.runExclusive(fn)` " +
        "o serializa las llamadas.",
      "runtime",
      RuntimeCode.BUSY
    )
    this.name = "WasmBusyError"
    this.owner = owner
  }
}

/** Fallo de la fuente de entropía (Web Crypto ausente o generador inválido). */
export class EntropyError extends WasmError {
  constructor(message: string, code: RuntimeCode = RuntimeCode.ENTROPY_UNAVAILABLE, options?: BlockchainWasmErrorOptions) {
    super(message, "csprng", code, options)
    this.name = "EntropyError"
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER DE FRONTERA
// ═══════════════════════════════════════════════════════════════════════════

/** Envuelve errores ajenos en la jerarquía común (mantiene `instanceof`). */
export function toBlockchainWasmError(
  err: unknown,
  module = "runtime",
  code: BlockchainWasmErrorCode = RuntimeCode.INTERNAL
): BlockchainWasmError {
  return BlockchainWasmError.from(err, module, code)
}
