/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  test/utils/wasm/compiler.ts — Compilador AssemblyScript + Caché L1/L2
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Estrategia de velocidad (de más rápida a más lenta):
 *
 *   L1 · Map en memoria del proceso   →   ~0 ms
 *   L2 · R:\.wasm-cache-blockchain\   →   ~0,1 ms (lectura de RAM disk)
 *   Build · asc en proceso            →   0,15 s … varios s
 *
 * La clave de caché se deriva del **argv efectivo** de `asc` (no del objeto de
 * opciones), por lo que dos configuraciones equivalentes comparten artefacto
 * (p. ej. `bench` y `bench+o3`). El argv incluye el fingerprint de `assembly/`,
 * así que cualquier cambio de fuente invalida el caché automáticamente.
 *
 * Nada se escribe fuera de `CACHE_DIR` (RAM disk por defecto). `mode: "disk"`
 * sigue existiendo para quien quiera un `.wasm` inspeccionable en `outDir`.
 */

import { main } from "assemblyscript/asc"
import {
  readFileSync,
  readdirSync,
  existsSync,
  mkdirSync,
  writeFileSync,
  statSync,
  renameSync,
  unlinkSync
} from "node:fs"
import { createHash } from "node:crypto"
import path from "node:path"

import type { CompileOptions, CompileResult, CompileMode } from "./types.js"
import {
  ROOT,
  CACHE_DIR,
  CACHE_MAX_BYTES,
  resolveOpts,
  resolveOutPath,
  buildAscArgs,
  isCacheEnabled
} from "./options.js"

/** Incrementar si cambia el formato del artefacto o la lógica de la clave. */
const CACHE_VERSION = 2

interface CacheEntry {
  binary: Uint8Array
  compileTimeMs: number
  sizeBytes: number
}

interface CacheMeta {
  v: number
  entry: string
  profile: string
  sizeBytes: number
  compileTimeMs: number
  createdAt: number
}

const MEM_CACHE = new Map<string, CacheEntry>()
const IN_FLIGHT = new Map<string, Promise<CompileResult>>()

let _depFpCache = new Map<string, { key: string; ts: number }>()
const DIR_FP_TTL_MS = 2000
let _pruned = false

// ── API pública ───────────────────────────────────────────────────────────

export async function compile(
  entryRel: string,
  optsOrShorthand: CompileOptions | string = {}
): Promise<CompileResult> {
  const opts = resolveOpts(optsOrShorthand)
  const mode: CompileMode = opts.mode ?? "memory"
  const force = opts.forceRecompile === true
  const useCache = opts.cache !== false && isCacheEnabled()

  const args = buildAscArgs(path.resolve(ROOT, entryRel), opts)
  const key = cacheKeyFromArgs(entryRel, args)
  const { wasmPath, metaPath } = cachePathsFromKey(key)

  // ── L1 · RAM del proceso ──
  if (!force) {
    const hit = MEM_CACHE.get(key)
    if (hit) {
      return finishFromCache(hit, key, entryRel, opts, mode, "memory")
    }
  }

  // ── L2 · RAM disk ──
  if (useCache && !force && existsSync(wasmPath)) {
    try {
      const binary = new Uint8Array(readFileSync(wasmPath))
      const meta = readMeta(metaPath)
      const entry: CacheEntry = {
        binary,
        compileTimeMs: meta?.compileTimeMs ?? 0,
        sizeBytes: binary.byteLength
      }
      MEM_CACHE.set(key, entry)
      return finishFromCache(entry, key, entryRel, opts, mode, "disk-cache")
    } catch {
      /* artefacto corrupto → recompilar */
    }
  }

  // ── Deduplicación de compilaciones concurrentes ──
  if (!force) {
    const running = IN_FLIGHT.get(key)
    if (running) return running
  }

  const task = runCompile(entryRel, opts, args, key, mode, wasmPath, metaPath, useCache)
  IN_FLIGHT.set(key, task)
  try {
    return await task
  } finally {
    IN_FLIGHT.delete(key)
  }
}

/** Computa la clave de caché sin compilar (útil para el prebuild). */
export function cacheKeyOf(entryRel: string, optsOrShorthand: CompileOptions | string = {}): string {
  const opts = resolveOpts(optsOrShorthand)
  return cacheKeyFromArgs(entryRel, buildAscArgs(path.resolve(ROOT, entryRel), opts))
}

/** Ruta del artefacto `.wasm` cacheado para una entrada/opciones. */
export function cachedWasmPath(entryRel: string, optsOrShorthand: CompileOptions | string = {}): string {
  return cachePathsFromKey(cacheKeyOf(entryRel, optsOrShorthand)).wasmPath
}

/** true si el artefacto ya está en el caché L2. */
export function isCached(entryRel: string, optsOrShorthand: CompileOptions | string = {}): boolean {
  return existsSync(cachedWasmPath(entryRel, optsOrShorthand))
}

/** Limpia el caché L2 completo. Devuelve el número de archivos eliminados. */
export function clearDiskCache(): number {
  MEM_CACHE.clear()
  let removed = 0
  if (!existsSync(CACHE_DIR)) return removed
  for (const name of readdirSync(CACHE_DIR)) {
    try {
      unlinkSync(path.join(CACHE_DIR, name))
      removed++
    } catch { /* ignore */ }
  }
  return removed
}

/** Estadísticas del caché L2 (bytes y artefactos). */
export function cacheStats(): { dir: string; files: number; bytes: number } {
  if (!existsSync(CACHE_DIR)) return { dir: CACHE_DIR, files: 0, bytes: 0 }
  let files = 0
  let bytes = 0
  for (const name of readdirSync(CACHE_DIR)) {
    try {
      const st = statSync(path.join(CACHE_DIR, name))
      if (st.isFile()) {
        files++
        bytes += st.size
      }
    } catch { /* ignore */ }
  }
  return { dir: CACHE_DIR, files, bytes }
}

// ── Compilación real ──────────────────────────────────────────────────────

async function runCompile(
  entryRel: string,
  opts: CompileOptions,
  args: string[],
  key: string,
  mode: CompileMode,
  wasmPath: string,
  metaPath: string,
  useCache: boolean
): Promise<CompileResult> {
  if (opts.verbose) console.error(`\x1b[33m[asc]\x1b[0m ${args.join(" ")}`)

  const stderr: string[] = []
  const captured: {
    binary: Uint8Array | null
    wat: string | null
    bindings: string | null
    sourceMap: string | null
  } = { binary: null, wat: null, bindings: null, sourceMap: null }

  const t0 = performance.now()
  const { error } = await main(args, {
    readFile,
    writeFile: (filename: string, contents: Uint8Array | string): void => {
      if (filename.endsWith(".wasm") && contents instanceof Uint8Array) {
        captured.binary = contents
      } else if (filename.endsWith(".wat") && typeof contents === "string") {
        captured.wat = contents
      } else if ((filename.endsWith(".js") || filename.endsWith(".mjs")) && typeof contents === "string") {
        captured.bindings = contents
      } else if (filename.endsWith(".map") && typeof contents === "string") {
        captured.sourceMap = contents
      }
    },
    listFiles,
    stdout: { write(_: string) { /* silencioso */ } },
    stderr: { write(s: string) { stderr.push(s) } }
  })
  const compileTimeMs = performance.now() - t0

  if (error || captured.binary === null) {
    throw new Error(`Error compilando ${entryRel}:\n${stderr.join("")}`)
  }

  const binary: Uint8Array = captured.binary
  const entry: CacheEntry = { binary, compileTimeMs, sizeBytes: binary.byteLength }
  MEM_CACHE.set(key, entry)

  // ── Persistencia L2 (atómica) ──
  if (useCache) {
    ensureDir(CACHE_DIR)
    atomicWrite(wasmPath, binary)
    const meta: CacheMeta = {
      v: CACHE_VERSION,
      entry: entryRel,
      profile: opts.profile ?? "test",
      sizeBytes: binary.byteLength,
      compileTimeMs,
      createdAt: Date.now()
    }
    atomicWrite(metaPath, new TextEncoder().encode(JSON.stringify(meta)))
    if (!_pruned) {
      _pruned = true
      pruneCache()
    }
  }

  // ── Escritura explícita en modo "disk" ──
  let outPath: string | undefined
  if (mode === "disk") {
    outPath = resolveOutPath(entryRel, opts)
    ensureDir(path.dirname(outPath))
    writeFileSync(outPath, binary)
    if (captured.wat && opts.emitWat) writeFileSync(outPath.replace(/\.wasm$/, ".wat"), captured.wat)
    if (captured.bindings && opts.bindings) writeFileSync(outPath.replace(/\.wasm$/, ".js"), captured.bindings)
    if (captured.sourceMap && opts.sourceMap) writeFileSync(outPath + ".map", captured.sourceMap)
  }

  return {
    binary,
    stderr: stderr.join(""),
    cached: false,
    fresh: true,
    compileTimeMs,
    sizeBytes: binary.byteLength,
    outPath,
    mode,
    cacheKey: key,
    source: "compiled"
  }
}

function finishFromCache(
  entry: CacheEntry,
  key: string,
  entryRel: string,
  opts: CompileOptions,
  mode: CompileMode,
  source: "memory" | "disk-cache"
): CompileResult {
  let outPath: string | undefined
  if (mode === "disk") {
    outPath = resolveOutPath(entryRel, opts)
    if (!existsSync(outPath)) {
      ensureDir(path.dirname(outPath))
      writeFileSync(outPath, entry.binary)
    }
  }
  return {
    binary: entry.binary,
    stderr: "",
    cached: true,
    fresh: false,
    compileTimeMs: entry.compileTimeMs,
    sizeBytes: entry.binary.byteLength,
    outPath,
    mode,
    cacheKey: key,
    source
  }
}

// ── Clave de caché / fingerprints ──

function cacheKeyFromArgs(entryRel: string, args: string[]): string {
  const fingerprint = sourceFingerprint(path.resolve(ROOT, entryRel))
  return createHash("sha256")
    .update(`${CACHE_VERSION}\u0000${entryRel}\u0000${fingerprint}\u0000${args.join("\u0000")}`)
    .digest("hex")
    .slice(0, 24)
}

function cachePathsFromKey(key: string): { wasmPath: string; metaPath: string } {
  return {
    wasmPath: path.join(CACHE_DIR, `${key}.wasm`),
    metaPath: path.join(CACHE_DIR, `${key}.json`)
  }
}

function readMeta(metaPath: string): CacheMeta | null {
  try {
    return JSON.parse(readFileSync(metaPath, "utf8")) as CacheMeta
  } catch {
    return null
  }
}

function sourceFingerprint(entryAbs: string): string {
  const now = Date.now()
  const hit = _depFpCache.get(entryAbs)
  if (hit && now - hit.ts < DIR_FP_TTL_MS) return hit.key

  const seen = new Set<string>()
  const parts: string[] = []

  const visit = (spec: string, fromDir: string): void => {
    const abs = normalizeTsFile(spec, fromDir)
    if (!abs || seen.has(abs)) return
    seen.add(abs)

    let src: string
    try {
      src = readFileSync(abs, "utf8")
    } catch {
      return
    }
    parts.push(`${path.relative(ROOT, abs)}:${createHash("sha1").update(src).digest("hex")}`)

    // Cualquier literal relativo del archivo puede ser un import/export.
    const re = /["'](\.{1,2}\/[^"']+)["']/g
    const dir = path.dirname(abs)
    let m: RegExpExecArray | null
    while ((m = re.exec(src))) visit(m[1], dir)
  }

  visit(entryAbs, ROOT)
  parts.sort()
  const key = parts.join("|")
  _depFpCache.set(entryAbs, { key, ts: now })
  return key
}

/** Resuelve `x`, `x.ts` o `x/index.ts` a una ruta existente. */
function normalizeTsFile(spec: string, baseDir: string): string | null {
  const raw = path.isAbsolute(spec) ? spec : path.resolve(baseDir, spec)
  for (const c of [raw, `${raw}.ts`, path.join(raw, "index.ts")]) {
    try {
      if (statSync(c).isFile()) return c
    } catch { /* siguiente */ }
  }
  return null
}

// ── Utilidades de FS ──

function ensureDir(dir: string): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
}

function atomicWrite(file: string, data: Uint8Array): void {
  const tmp = `${file}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`
  writeFileSync(tmp, data)
  try {
    renameSync(tmp, file)
  } catch {
    // Windows: el destino puede existir y estar bloqueado → escribir directo.
    try {
      writeFileSync(file, data)
    } finally {
      try { unlinkSync(tmp) } catch { /* ignore */ }
    }
  }
}

function pruneCache(): void {
  try {
    const names = readdirSync(CACHE_DIR)
    const files = names
      .map((n) => {
        const p = path.join(CACHE_DIR, n)
        try {
          const st = statSync(p)
          return st.isFile() ? { p, size: st.size, mtime: st.mtimeMs } : null
        } catch {
          return null
        }
      })
      .filter((x): x is { p: string; size: number; mtime: number } => x !== null)

    let total = files.reduce((s, f) => s + f.size, 0)
    if (total <= CACHE_MAX_BYTES) return

    files.sort((a, b) => a.mtime - b.mtime)
    for (const f of files) {
      if (total <= CACHE_MAX_BYTES) break
      try {
        unlinkSync(f.p)
        total -= f.size
      } catch { /* ignore */ }
    }
  } catch { /* ignore */ }
}

function readFile(filename: string, baseDir: string): string | null {
  const base = path.isAbsolute(filename) ? path.dirname(filename) : baseDir || ROOT
  const name = path.isAbsolute(filename) ? path.basename(filename) : filename
  const abs = path.resolve(base, name)
  for (const c of [abs, abs + ".ts", path.join(abs, "index.ts")]) {
    try {
      return readFileSync(c, "utf8")
    } catch { /* siguiente */ }
  }
  return null
}

function listFiles(dirname: string, baseDir: string): string[] {
  const abs = path.isAbsolute(dirname) ? dirname : path.resolve(baseDir || ROOT, dirname)
  try {
    return readdirSync(abs)
  } catch {
    return []
  }
}
