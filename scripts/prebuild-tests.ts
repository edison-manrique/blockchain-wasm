/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  scripts/prebuild-tests.ts — Prebuild paralelo del manifiesto de tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Compila todos los artefactos que la suite necesita y los deja en el caché L2
 * (RAM disk `R:\` por defecto). Después `bun test` arranca en caliente: solo
 * instancia binarios, no compila.
 *
 * Uso:
 *   bun run prebuild                # pool = núcleos lógicos disponibles
 *   bun run prebuild --jobs=4       # limitar workers
 *   bun run prebuild --force        # recompilar ignorando L1/L2
 *   bun run prebuild --list         # mostrar el manifiesto y salir
 *   bun run prebuild --only=sha2    # filtrar por entrada/etiqueta
 *   bun run prebuild --json         # salida máquina-legible
 */

import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { TEST_BUILDS, uniqueBuilds, buildLabel, type BuildSpec } from "../test/utils/wasm/manifest.js"
import { CACHE_DIR, isCacheEnabled } from "../test/utils/wasm/options.js"
import { cacheStats, clearDiskCache } from "../test/utils/wasm/compiler.js"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const WORKER = path.join(ROOT, "scripts", "prebuild-worker.ts")

interface JobResult {
  ok: boolean
  entry: string
  opts: string
  force: boolean
  cacheKey?: string
  compileTimeMs?: number
  sizeBytes?: number
  source?: "compiled" | "memory" | "disk-cache"
  error?: string
}

interface Job extends BuildSpec {
  label: string
}

// ── CLI ────────────────────────────────────────────────────────────────────

function flag(name: string): string | undefined {
  const prefix = `--${name}=`
  const hit = process.argv.find((a) => a.startsWith(prefix))
  return hit ? hit.slice(prefix.length) : undefined
}

const showList = process.argv.includes("--list")
const jsonOut = process.argv.includes("--json")
const force = process.argv.includes("--force")
const clearCache = process.argv.includes("--clear")
const only = flag("only")
const jobsArg = Number(flag("jobs") ?? os.availableParallelism?.() ?? os.cpus().length)
const CONCURRENCY = Math.max(1, Number.isFinite(jobsArg) ? jobsArg : 4)

function shorthandOf(opts: BuildSpec["opts"]): string {
  return typeof opts === "string" ? opts : JSON.stringify(opts)
}

function selectJobs(): Job[] {
  let list = uniqueBuilds(TEST_BUILDS)
  if (only) {
    const needle = only.toLowerCase()
    list = list.filter((b) => b.entry.toLowerCase().includes(needle) || b.label?.toLowerCase().includes(needle))
  }
  return list.map((b) => ({ ...b, label: buildLabel(b) }))
}

/**
 * Ordena los jobs costosos primero para que el pool no termine con una cola
 * dominada por un build `-O3` de 1 minuto.
 */
function priority(job: Job): number {
  const o = shorthandOf(job.opts)
  let score = 1
  if (o.includes("bench") || o.includes("o3")) score += 10
  if (o.includes("small") || o.includes("fast")) score += 3
  if (/secp256k1\/index|assembly\/index/.test(job.entry)) score += 5
  if (/point|generator|glv|wnaf/.test(job.entry)) score += 2
  return score
}

// ── Ejecución ──────────────────────────────────────────────────────────────

function fmtMs(ms: number): string {
  return ms < 1000 ? `${ms.toFixed(0)} ms` : `${(ms / 1000).toFixed(2)} s`
}

function fmtKB(bytes: number): string {
  return `${(bytes / 1024).toFixed(1)} KB`
}

async function runJob(job: Job): Promise<JobResult> {
  const args = [
    "run",
    WORKER,
    `--entry=${job.entry}`,
    `--opts=${shorthandOf(job.opts)}`,
    ...(force ? ["--force"] : [])
  ]
  const proc = Bun.spawn([process.execPath, ...args], {
    cwd: ROOT,
    stdout: "pipe",
    stderr: "pipe"
  })
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  await proc.exited

  const line = stdout.trim().split(/\r?\n/).filter(Boolean).pop()
  if (!line) {
    return { ok: false, entry: job.entry, opts: shorthandOf(job.opts), force, error: stderr.trim() || "sin salida" }
  }
  try {
    return JSON.parse(line) as JobResult
  } catch {
    return { ok: false, entry: job.entry, opts: shorthandOf(job.opts), force, error: line }
  }
}

async function main(): Promise<void> {
  const jobs = selectJobs().sort((a, b) => priority(b) - priority(a))

  if (showList) {
    console.log(`Manifiesto de builds (${jobs.length}):\n`)
    for (const j of jobs) console.log(`  ${j.entry}  [${shorthandOf(j.opts)}]`)
    console.log(`\nCaché L2: ${CACHE_DIR}`)
    return
  }

  if (!isCacheEnabled()) {
    console.warn("⚠  WASM_NO_CACHE=1: el prebuild compilará pero no persistirá artefactos.")
  }
  if (clearCache) {
    const n = clearDiskCache()
    console.log(`🧹 Caché L2 vaciado (${n} archivos).`)
  }

  console.log(
    `🔨 Prebuild ${jobs.length} builds · ${CONCURRENCY} worker(s) · ` +
      `caché L2 ${CACHE_DIR}${force ? " · --force" : ""}\n`
  )

  const t0 = performance.now()
  const results: JobResult[] = []
  let next = 0
  let done = 0

  const worker = async (): Promise<void> => {
    while (next < jobs.length) {
      const job = jobs[next++]
      const t = performance.now()
      const r = await runJob(job)
      const elapsed = performance.now() - t
      results.push(r)
      done++
      if (jsonOut) {
        console.log(JSON.stringify(r))
      } else if (r.ok) {
        const where = r.source === "compiled" ? "🔨" : r.source === "memory" ? "⚡ L1" : "♻️  L2"
        console.log(
          `[${String(done).padStart(2)}/${jobs.length}] ${where.padEnd(6)} ` +
            `${(r.compileTimeMs ?? 0).toFixed(0).padStart(6)} ms  ${fmtKB(r.sizeBytes ?? 0).padStart(9)}  ${job.label}  (${fmtMs(elapsed)})`
        )
      } else {
        console.log(`[${String(done).padStart(2)}/${jobs.length}] ❌ ${job.label}\n    ${r.error}`)
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, jobs.length) }, worker))

  const total = performance.now() - t0
  const failed = results.filter((r) => !r.ok)
  const compiled = results.filter((r) => r.source === "compiled")
  const hits = results.length - compiled.length
  const bytes = results.reduce((s, r) => s + (r.sizeBytes ?? 0), 0)

  if (jsonOut) {
    console.log(
      JSON.stringify({
        ok: failed.length === 0,
        totalMs: total,
        jobs: results.length,
        compiled: compiled.length,
        cached: hits,
        failed: failed.length,
        bytes
      })
    )
  } else {
    const stats = cacheStats()
    console.log(
      `\n${failed.length ? "❌" : "✅"} Prebuild ${failed.length ? "con errores" : "completo"} en ${fmtMs(total)} · ` +
        `${compiled.length} compilados · ${hits} desde caché · ${fmtKB(bytes)} totales`
    )
    console.log(`   Caché L2: ${stats.files} archivos · ${(stats.bytes / 1024 / 1024).toFixed(1)} MB`)
  }

  if (failed.length) process.exitCode = 1
}

await main()
