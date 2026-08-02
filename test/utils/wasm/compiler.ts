/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  test/utils/wasm/compiler.ts — Compilador AssemblyScript + Sistema de Caché
 * ═══════════════════════════════════════════════════════════════════════════
 */

import { main } from "assemblyscript/asc"
import { readFileSync, readdirSync, existsSync, mkdirSync, writeFileSync, statSync } from "node:fs"
import { createHash } from "node:crypto"
import path from "node:path"

import type { CompileOptions, CompileResult, CompileMode } from "./types.js"
import { ROOT, CACHE_DIR, resolveOpts, resolveOutPath, buildAscArgs } from "./options.js"

const MEM_CACHE = new Map<string, Uint8Array>()

let _dirFpCache: { key: string; ts: number } | null = null
const DIR_FP_TTL_MS = 2000

export async function compile(
  entryRel: string,
  optsOrShorthand: CompileOptions | string = {}
): Promise<CompileResult> {
  const opts = resolveOpts(optsOrShorthand)
  const mode: CompileMode = opts.mode ?? "memory"
  const useMemCache = opts.memCache !== false
  const useCache = mode === "disk" && (opts.cache ?? (opts.profile === "bench" || opts.profile === "fast"))

  const key = cacheKey(entryRel, opts)
  const cachePath = path.join(CACHE_DIR, `${key}.wasm`)

  // ── 1) Cache en RAM (Cero Disco) ──
  if (useMemCache && !opts.forceRecompile && MEM_CACHE.has(key)) {
    const binary = MEM_CACHE.get(key)!
    let outPath: string | undefined
    if (mode === "disk") {
      outPath = resolveOutPath(entryRel, opts)
      if (!existsSync(outPath)) {
        ensureDir(path.dirname(outPath))
        writeFileSync(outPath, binary)
      }
    }
    return { binary, stderr: "", cached: true, compileTimeMs: 0, sizeBytes: binary.byteLength, outPath, mode }
  }

  // ── 2) Cache en Disco (Modo Disk) ──
  if (useCache && !opts.forceRecompile && existsSync(cachePath)) {
    const binary = new Uint8Array(readFileSync(cachePath))
    if (useMemCache) MEM_CACHE.set(key, binary)
    let outPath: string | undefined
    if (mode === "disk") {
      outPath = resolveOutPath(entryRel, opts)
      if (!existsSync(outPath)) {
        ensureDir(path.dirname(outPath))
        writeFileSync(outPath, binary)
      }
    }
    return { binary, stderr: "", cached: true, compileTimeMs: 0, sizeBytes: binary.byteLength, outPath, mode }
  }

  // ── 3) Proceso de Compilación en Memoria Virtual ──
  const entryAbs = path.resolve(ROOT, entryRel)
  const ascArgs = buildAscArgs(entryAbs, opts)
  if (opts.verbose) console.error(`\x1b[33m[asc]\x1b[0m ${ascArgs.join(" ")}`)

  const stderr: string[] = []
  const captured: {
    binary: Uint8Array | null
    wat: string | null
    bindings: string | null
    sourceMap: string | null
  } = {
    binary: null,
    wat: null,
    bindings: null,
    sourceMap: null
  }

  const t0 = performance.now()
  const { error } = await main(ascArgs, {
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
    stderr: {
      write(s: string) {
        stderr.push(s)
      }
    }
  })
  const compileTimeMs = performance.now() - t0

  if (error || captured.binary === null) {
    throw new Error(`Error compilando ${entryRel}:\n${stderr.join("")}`)
  }

  const binary: Uint8Array = captured.binary

  if (useMemCache) MEM_CACHE.set(key, binary)

  // ── 4) Escritura Física (Solo en modo "disk") ──
  let outPath: string | undefined
  if (mode === "disk") {
    outPath = resolveOutPath(entryRel, opts)
    ensureDir(path.dirname(outPath))
    writeFileSync(outPath, binary)

    if (captured.wat && opts.emitWat) {
      writeFileSync(outPath.replace(/\.wasm$/, ".wat"), captured.wat)
    }
    if (captured.bindings && opts.bindings) {
      writeFileSync(outPath.replace(/\.wasm$/, ".js"), captured.bindings)
    }
    if (captured.sourceMap && opts.sourceMap) {
      writeFileSync(outPath + ".map", captured.sourceMap)
    }

    if (useCache) {
      ensureDir(CACHE_DIR)
      writeFileSync(cachePath, binary)
      if (captured.wat && opts.emitWat) {
        writeFileSync(cachePath.replace(".wasm", ".wat"), captured.wat)
      }
    }
  }

  return {
    binary,
    stderr: stderr.join(""),
    cached: false,
    compileTimeMs,
    sizeBytes: binary.byteLength,
    outPath,
    mode
  }
}

// ── Métodos Auxiliares Privados ──

function ensureDir(dir: string): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
}

function cacheKey(entryRel: string, opts: CompileOptions): string {
  const srcFingerprint = dirFingerprintCached(path.resolve(ROOT, "assembly"))
  const { mode, cache, forceRecompile, memCache, verbose, outFile, outDir, ...compileOpts } = opts
  return createHash("sha256")
    .update(JSON.stringify({ e: entryRel, src: srcFingerprint, ...compileOpts }))
    .digest("hex")
    .slice(0, 16)
}

function dirFingerprintCached(dir: string): string {
  const now = Date.now()
  if (_dirFpCache && now - _dirFpCache.ts < DIR_FP_TTL_MS) {
    return _dirFpCache.key
  }
  const key = dirFingerprint(dir)
  _dirFpCache = { key, ts: now }
  return key
}

function dirFingerprint(dir: string): string {
  let acc = ""
  try {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name)
      acc += e.isDirectory() ? dirFingerprint(p) : `${p}:${statSync(p).mtimeMs}|`
    }
  } catch { /* ignorar */ }
  return acc
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