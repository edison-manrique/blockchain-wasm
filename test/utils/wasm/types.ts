/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  test/utils/wasm/types.ts — Tipos e interfaces del subsistema WASM
 * ═══════════════════════════════════════════════════════════════════════════
 */

export type Profile = "debug" | "test" | "bench" | "fast" | "small" | "safe"
export type RuntimeVariant = "stub" | "minimal" | "incremental"
export type UncheckedBehavior = "default" | "never" | "always"
export type TrapMode = "allow" | "clamp" | "js"
export type BindingsType = "esm" | "raw"
export type WasmFeature = "threads" | "simd" | "reference-types" | "gc" | "stringref" | "relaxed-simd"
export type DisableFeature = "mutable-globals" | "sign-extension" | "nontrapping-f2i" | "bulk-memory"

/** "memory" = cero disco (tests). "disk" = escribe .wasm/.wat + cache en R:\. */
export type CompileMode = "memory" | "disk"

export interface CompileOptions {
  // ── MODO ──
  mode?: CompileMode
  outFile?: string
  outDir?: string

  // ── Perfil / Optimización ──
  profile?: Profile
  optimizeLevel?: 0 | 1 | 2 | 3
  shrinkLevel?: 0 | 1 | 2
  converge?: boolean
  noAssert?: boolean
  uncheckedBehavior?: UncheckedBehavior

  // ── Runtime ──
  runtime?: RuntimeVariant
  exportRuntime?: boolean
  stackSize?: number

  // ── Memoria ──
  initialMemory?: number
  maximumMemory?: number
  fixedMemory?: number
  importMemory?: boolean
  noExportMemory?: boolean
  sharedMemory?: boolean
  zeroFilledMemory?: boolean
  lowMemoryLimit?: number
  memoryBase?: number

  // ── Tabla ──
  importTable?: boolean
  exportTable?: boolean
  tableBase?: number

  // ── Features WASM ──
  enable?: WasmFeature[]
  disable?: DisableFeature[]
  simd?: boolean
  relaxedSimd?: boolean
  threads?: boolean
  gc?: boolean
  referenceTypes?: boolean
  stringref?: boolean

  // ── Output ──
  bindings?: BindingsType
  emitWat?: boolean
  sourceMap?: boolean | string
  debug?: boolean
  exportStart?: string

  // ── Binaryen ──
  trapMode?: TrapMode
  runPasses?: string[]
  noValidate?: boolean

  // ── Aliases / Transforms ──
  use?: string[]
  transform?: string[]
  lib?: string[]
  resolvePath?: string[]

  // ── Misc ──
  noUnsafe?: boolean
  noColors?: boolean
  pedantic?: boolean
  stats?: boolean
  noEmit?: boolean
  disableWarning?: string[]
  extraFlags?: string[]

  // ── Control del Harness ──
  cache?: boolean
  forceRecompile?: boolean
  verbose?: boolean
  memCache?: boolean
}

export interface CompileResult {
  binary: Uint8Array
  stderr: string
  cached: boolean
  compileTimeMs: number
  sizeBytes: number
  outPath?: string
  mode: CompileMode
}

/**
 * Representa la instancia ejecutable de WASM.
 * Permite pasar un genérico `T` para tipar las funciones exportadas.
 */
export interface WasmInstance<T = Record<string, any>> {
  instance: WebAssembly.Instance
  exports: T
  memory: WebAssembly.Memory
  readonly view: DataView
  readonly u8: Uint8Array
  syncViews(): void
  num(name: keyof T | string): number
  write(ptr: number, bytes: Uint8Array, offset?: number): void
  read(ptr: number, len: number, offset?: number): Uint8Array
  writeU256(ptr: number, value: bigint): void
  readU256(ptr: number): bigint
  memoryPages(): number
  memoryBytes(): number
}

export interface BenchResult {
  name: string
  ops: number
  runs: number
  totalMs: number
  opsPerSec: number
  nsPerOp: number
  samples: number[]
  minNs: number
  maxNs: number
  meanNs: number
  medianNs: number
  stddevNs: number
  cvPct: number
}

export interface BenchOptions {
  warmup?: number
  runs?: number
}

export interface MemoryResult {
  name: string
  pagesBefore: number
  pagesAfter: number
  bytesBefore: number
  bytesAfter: number
  deltaBytes: number
  grew: boolean
}

export interface CompareResult {
  a: BenchResult
  b: BenchResult
  ratio: number
  winner: string
}

export interface CompileBenchSpec {
  label: string
  opts: CompileOptions | string
}

export interface CompileBenchResult {
  label: string
  compileTimeMs: number
  sizeBytes: number
  cached: boolean
  bench: BenchResult
}

export interface CompileCompareReport {
  entry: string
  a: CompileBenchResult
  b: CompileBenchResult
  speedRatio: number
  sizeRatio: number
  compileTimeRatio: number
  winner: string
}
