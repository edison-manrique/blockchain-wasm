/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  errors.ts — Jerarquía de errores del wrapper blockchain-wasm
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  • WasmError            — base (lleva `module` + `code`).
 *  • NotInitializedError  — se usa BlockchainWasm antes de fromBuffer/load.
 *  • MissingExportError   — binario desincronizado (falta export/global/memory).
 *  • InvalidArgumentError — validación de frontera en las fachadas.
 *
 * Los códigos numéricos de dominio (rc < 0 del WASM) se envuelven en WasmError
 * directamente desde blockchain-wasm.ts (camino frío), sin helper en el hot path.
 */

export const enum RuntimeCode {
  NOT_INITIALIZED = "NOT_INITIALIZED",
  MISSING_EXPORT = "MISSING_EXPORT",
  INVALID_ARGUMENT = "INVALID_ARGUMENT",
  TRAP = "TRAP"
}

export class WasmError extends Error {
  readonly code: number | string
  readonly module: string
  constructor(message: string, module: string, code: number | string) {
    super(`[${module}] ${message}`)
    this.name = "WasmError"
    this.module = module
    this.code = code
  }
}

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
