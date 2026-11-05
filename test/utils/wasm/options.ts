/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  test/utils/wasm/options.ts — Procesamiento de opciones y flags para asc
 * ═══════════════════════════════════════════════════════════════════════════
 */

import path from "node:path"
import { existsSync, mkdirSync, writeFileSync, unlinkSync } from "node:fs"
import { fileURLToPath } from "node:url"
import type { CompileOptions, Profile, UncheckedBehavior, BindingsType, TrapMode, WasmFeature, DisableFeature } from "./types.js"

// ── Determinación de Raíz y Rutas ──
const __dirname: string =
  typeof (import.meta as any).dir === "string"
    ? (import.meta as any).dir
    : path.dirname(fileURLToPath(import.meta.url))

export const ROOT = path.resolve(__dirname, "..", "..", "..")

function isWritableDir(dir: string): boolean {
  try {
    // `mkdirSync` sobre una raíz de unidad existente (`R:\`) lanza EPERM en
    // Windows: solo creamos el directorio si realmente no existe.
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    const probe = path.join(dir, `.probe-${process.pid}-${Date.now()}`)
    writeFileSync(probe, "1")
    unlinkSync(probe)
    return true
  } catch {
    return false
  }
}

/**
 * Raíz para caché de builds.
 * Prioriza:
 *  1) Variable de entorno `WASM_RAMDISK`
 *  2) Unidades / puntos de montaje en RAM habituales (`R:\` en Windows)
 *  3) Directorio local `.wasm-cache`
 *
 * Los artefactos viven SIEMPRE aquí; los tests no escriben en el repo.
 */
export const DISK_ROOT: string = (() => {
  const fromEnv = process.env.WASM_RAMDISK
  if (fromEnv && existsSync(fromEnv) && isWritableDir(fromEnv)) return fromEnv

  const candidates =
    process.platform === "win32"
      ? ["R:\\", "C:\\Temp\\wasm-ram"]
      : ["/dev/shm", "/mnt/ramdisk", "/tmp"]

  for (const c of candidates) {
    try {
      if (existsSync(c) && isWritableDir(c)) return c
    } catch { /* ignore */ }
  }
  return path.resolve(ROOT, ".wasm-cache")
})()

/** Directorio de caché L2 (binarios `.wasm` + metadatos `.json`). */
export const CACHE_DIR: string = path.resolve(
  process.env.WASM_CACHE_DIR || path.join(DISK_ROOT, ".wasm-cache-blockchain")
)

/** Máximo de bytes del caché L2 antes de podar los artefactos más antiguos. */
export const CACHE_MAX_BYTES: number = Number(process.env.WASM_CACHE_MAX_BYTES || 96 * 1024 * 1024)

/** Caché L2 deshabilitable por entorno (útil para medir builds en frío). */
export function isCacheEnabled(): boolean {
  const v = process.env.WASM_NO_CACHE
  return !(v === "1" || v === "true")
}

export const PROFILE_FLAGS: Record<Profile, string[]> = {
  // `release`: máxima optimización, solo para el binario publicado (`dist/`).
  // Es MUY lento (minutos en los barrels), por eso ningún test lo usa.
  release: ["-O3", "--shrinkLevel", "2", "--noAssert", "--converge", "--runtime", "stub"],
  // `bench`: build optimizado para medir velocidad en tests. -O1 compila 3–8×
  // más rápido que -O3 y el rendimiento medido es equivalente para las
  // comprobaciones de sanidad de la suite.
  bench: ["-O1", "--noAssert", "--runtime", "stub"],
  fast: ["-Ospeed", "--noAssert", "--converge", "--runtime", "stub"],
  small: ["-Osize", "--shrinkLevel", "2", "--noAssert", "--converge", "--runtime", "stub"],
  // Correctitud: -O0 compila 10–20× más rápido y no altera la semántica.
  test: ["-O0", "--noAssert", "--runtime", "stub"],
  // Variante -O1 (solo para comparativas de builds).
  test1: ["-O1", "--noAssert", "--runtime", "stub"],
  safe: ["-O0", "--debug", "--sourceMap", "--runtime", "stub"],
  debug: ["-O0", "--debug", "--sourceMap", "--runtime", "stub"]
}

export function resolveOpts(o: CompileOptions | string): CompileOptions {
  return typeof o === "string" ? parseShorthand(o) : o
}

export function resolveOutPath(entryRel: string, opts: CompileOptions): string {
  if (opts.outFile) {
    return path.isAbsolute(opts.outFile) ? opts.outFile : path.resolve(DISK_ROOT, opts.outFile)
  }
  const profile = opts.profile ?? "test"
  const rel = entryRel.replace(/^assembly[\\/]/, "")
  const stem = rel.replace(/\.ts$/, "").replace(/[\\/]/g, "_")
  const outDir = path.resolve(DISK_ROOT, opts.outDir ?? "build")
  return path.join(outDir, `${stem}_${profile}.wasm`)
}

export function parseShorthand(shorthand: string): CompileOptions {
  const opts: CompileOptions = {}
  const enable: WasmFeature[] = []
  const disable: DisableFeature[] = []

  for (const p of shorthand.toLowerCase().split("+")) {
    if (p === "mem" || p === "memory") { opts.mode = "memory"; continue }
    if (p === "disk") { opts.mode = "disk"; continue }
    if (p.startsWith("outdir=")) { opts.outDir = p.slice(7); continue }
    if (p.startsWith("out=")) { opts.outFile = p.slice(4); continue }

    switch (p) {
      case "bench": case "b": opts.profile = "bench"; continue
      case "release": case "r": opts.profile = "release"; continue
      case "fast": case "f": opts.profile = "fast"; continue
      case "small": case "s": opts.profile = "small"; continue
      case "test": case "t": opts.profile = "test"; continue
      case "safe": case "debug": case "d": opts.profile = "safe"; continue
    }
    if (p === "o0") { opts.optimizeLevel = 0; continue }
    if (p === "o1") { opts.optimizeLevel = 1; continue }
    if (p === "o2") { opts.optimizeLevel = 2; continue }
    if (p === "o3") { opts.optimizeLevel = 3; continue }
    if (p === "s0") { opts.shrinkLevel = 0; continue }
    if (p === "s1") { opts.shrinkLevel = 1; continue }
    if (p === "s2") { opts.shrinkLevel = 2; continue }
    if (p === "converge") { opts.converge = true; continue }
    if (p === "noassert") { opts.noAssert = true; continue }
    if (p.startsWith("unchecked=")) { opts.uncheckedBehavior = p.slice(10) as UncheckedBehavior; continue }
    if (p === "r1" || p === "stub") { opts.runtime = "stub"; continue }
    if (p === "r2" || p === "min" || p === "minimal") { opts.runtime = "minimal"; continue }
    if (p === "r3" || p === "inc" || p === "incremental") { opts.runtime = "incremental"; continue }
    if (p === "exportrt") { opts.exportRuntime = true; continue }
    if (p.startsWith("stack")) { opts.stackSize = parseInt(p.slice(5)); continue }
    if (p.startsWith("fm")) { const n = parseInt(p.slice(2)); if (!isNaN(n)) opts.fixedMemory = n; continue }
    if (p.startsWith("im")) { const n = parseInt(p.slice(2)); if (!isNaN(n)) opts.initialMemory = n; continue }
    if (p.startsWith("mm")) { const n = parseInt(p.slice(2)); if (!isNaN(n)) opts.maximumMemory = n; continue }
    if (p === "importmem") { opts.importMemory = true; continue }
    if (p === "noexportmem") { opts.noExportMemory = true; continue }
    if (p === "shared") { opts.sharedMemory = true; continue }
    if (p === "zerofilled") { opts.zeroFilledMemory = true; continue }
    if (p.startsWith("lowmem")) { opts.lowMemoryLimit = parseInt(p.slice(6)); continue }
    if (p.startsWith("membase")) { opts.memoryBase = parseInt(p.slice(7)); continue }
    if (p === "importtbl") { opts.importTable = true; continue }
    if (p === "exporttbl") { opts.exportTable = true; continue }
    if (p.startsWith("tblbase")) { opts.tableBase = parseInt(p.slice(7)); continue }
    if (p === "simd") { opts.simd = true; enable.push("simd"); continue }
    if (p === "rsimd") { opts.relaxedSimd = true; enable.push("relaxed-simd"); continue }
    if (p === "threads") { opts.threads = true; enable.push("threads"); continue }
    if (p === "gc") { opts.gc = true; enable.push("gc"); continue }
    if (p === "reftypes") { opts.referenceTypes = true; enable.push("reference-types"); continue }
    if (p === "stringref") { opts.stringref = true; enable.push("stringref"); continue }
    if (p === "nomutglob") { disable.push("mutable-globals"); continue }
    if (p === "nosignext") { disable.push("sign-extension"); continue }
    if (p === "notrapf2i") { disable.push("nontrapping-f2i"); continue }
    if (p === "nobulkmem") { disable.push("bulk-memory"); continue }
    if (p === "wat") { opts.emitWat = true; continue }
    if (p === "sourcemap") { opts.sourceMap = true; continue }
    if (p.startsWith("bindings=")) { opts.bindings = p.slice(9) as BindingsType; continue }
    if (p.startsWith("exportstart=")) { opts.exportStart = p.slice(12); continue }
    if (p.startsWith("trap=")) { opts.trapMode = p.slice(5) as TrapMode; continue }
    if (p === "novalidate") { opts.noValidate = true; continue }
    if (p.startsWith("passes=")) { opts.runPasses = p.slice(7).split(","); continue }
    if (p === "nounsafe") { opts.noUnsafe = true; continue }
    if (p === "nocolors") { opts.noColors = true; continue }
    if (p === "pedantic") { opts.pedantic = true; continue }
    if (p === "stats") { opts.stats = true; continue }
    if (p === "noemit") { opts.noEmit = true; continue }
    if (p === "v" || p === "verbose") { opts.verbose = true; continue }
    if (p === "cache") { opts.cache = true; continue }
    if (p === "nocache") { opts.cache = false; continue }
    if (p === "force") { opts.forceRecompile = true; continue }
  }

  if (enable.length) opts.enable = [...new Set(enable)]
  if (disable.length) opts.disable = [...new Set(disable)]
  return opts
}

export function buildAscArgs(entryAbs: string, opts: CompileOptions): string[] {
  const profile = opts.profile ?? "test"
  const args: string[] = [entryAbs]
  const flags = [...(PROFILE_FLAGS[profile] ?? PROFILE_FLAGS.test)]

  if (opts.optimizeLevel !== undefined) {
    for (let i = flags.length - 1; i >= 0; i--) if (/^-O/.test(flags[i])) flags.splice(i, 1)
    args.push(`-O${opts.optimizeLevel}`)
  }
  if (opts.shrinkLevel !== undefined) {
    const i = flags.indexOf("--shrinkLevel")
    if (i !== -1) flags.splice(i, 2)
    args.push("--shrinkLevel", String(opts.shrinkLevel))
  }
  if (opts.converge !== undefined) {
    const i = flags.indexOf("--converge")
    if (opts.converge && i === -1) args.push("--converge")
    if (!opts.converge && i !== -1) flags.splice(i, 1)
  }
  if (opts.noAssert !== undefined) {
    const i = flags.indexOf("--noAssert")
    if (opts.noAssert && i === -1) args.push("--noAssert")
    if (!opts.noAssert && i !== -1) flags.splice(i, 1)
  }
  if (opts.uncheckedBehavior) args.push("--uncheckedBehavior", opts.uncheckedBehavior)

  if (opts.runtime) {
    const i = flags.indexOf("--runtime")
    if (i !== -1) flags.splice(i, 2)
    args.push("--runtime", opts.runtime)
  }
  if (opts.exportRuntime) args.push("--exportRuntime")
  if (opts.stackSize !== undefined) args.push("--stackSize", String(opts.stackSize))

  args.push(...flags)

  if (opts.fixedMemory) {
    const m = String(Math.max(1, opts.fixedMemory))
    args.push("--initialMemory", m, "--maximumMemory", m)
  } else {
    if (opts.initialMemory) args.push("--initialMemory", String(Math.max(1, opts.initialMemory)))
    if (opts.maximumMemory) args.push("--maximumMemory", String(Math.max(1, opts.maximumMemory)))
  }
  if (opts.importMemory) args.push("--importMemory")
  if (opts.noExportMemory) args.push("--noExportMemory")
  if (opts.sharedMemory) args.push("--sharedMemory")
  if (opts.zeroFilledMemory) args.push("--zeroFilledMemory")
  if (opts.lowMemoryLimit) args.push("--lowMemoryLimit", String(opts.lowMemoryLimit))
  if (opts.memoryBase !== undefined) args.push("--memoryBase", String(opts.memoryBase))

  if (opts.importTable) args.push("--importTable")
  if (opts.exportTable) args.push("--exportTable")
  if (opts.tableBase !== undefined) args.push("--tableBase", String(opts.tableBase))

  const enableSet = new Set<WasmFeature>(opts.enable ?? [])
  if (opts.simd) enableSet.add("simd")
  if (opts.relaxedSimd) enableSet.add("relaxed-simd")
  if (opts.threads) enableSet.add("threads")
  if (opts.gc) enableSet.add("gc")
  if (opts.referenceTypes) enableSet.add("reference-types")
  if (opts.stringref) enableSet.add("stringref")
  for (const f of enableSet) args.push("--enable", f)
  if (opts.disable) for (const f of opts.disable) args.push("--disable", f)

  args.push("--outFile", "out.wasm")
  if (opts.emitWat) args.push("--textFile", "out.wat")
  if (opts.bindings) args.push("--bindings", opts.bindings)
  if (opts.sourceMap) {
    if (typeof opts.sourceMap === "string") {
      args.push("--sourceMap", opts.sourceMap)
    } else {
      args.push("--sourceMap")
    }
  }
  if (opts.debug) args.push("--debug")
  if (opts.exportStart) args.push("--exportStart", opts.exportStart)

  if (opts.trapMode) args.push("--trapMode", opts.trapMode)
  if (opts.runPasses) args.push("--runPasses", opts.runPasses.join(","))
  if (opts.noValidate) args.push("--noValidate")

  if (opts.use) for (const u of opts.use) args.push("--use", u)
  if (opts.transform) for (const t of opts.transform) args.push("--transform", t)
  if (opts.lib) for (const l of opts.lib) args.push("--lib", l)
  if (opts.resolvePath) for (const p of opts.resolvePath) args.push("--path", p)

  if (opts.noUnsafe) args.push("--noUnsafe")
  if (opts.noColors) args.push("--noColors")
  if (opts.pedantic) args.push("--pedantic")
  if (opts.stats) args.push("--stats")
  if (opts.noEmit) args.push("--noEmit")
  if (opts.disableWarning) for (const w of opts.disableWarning) args.push("--disableWarning", w)
  if (opts.extraFlags) args.push(...opts.extraFlags)

  return args
}