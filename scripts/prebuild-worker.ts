/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  scripts/prebuild-worker.ts — Compila UN build en un proceso aislado
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Uso interno de `scripts/prebuild-tests.ts`:
 *
 *   bun run scripts/prebuild-worker.ts --entry=assembly/... --opts=bench [--force]
 *
 * Escribe una única línea JSON por stdout. Cada job vive en su propio proceso
 * porque `assemblyscript/asc` mantiene estado global y no es seguro en paralelo
 * dentro de un mismo proceso.
 */

import { compile } from "../test/utils/wasm/compiler.js"
import type { CompileOptions } from "../test/utils/wasm/types.js"

function arg(name: string): string | undefined {
  const prefix = `--${name}=`
  const hit = process.argv.find((a) => a.startsWith(prefix))
  return hit ? hit.slice(prefix.length) : undefined
}

const entry = arg("entry")
const rawOpts = arg("opts") ?? "test"
const force = process.argv.includes("--force")

if (!entry) {
  console.error("prebuild-worker: falta --entry=<ruta relativa>")
  process.exit(2)
}

/** Los perfiles se pasan como shorthand; el resto como JSON. */
function parseOpts(raw: string): CompileOptions | string {
  if (raw.startsWith("{")) return JSON.parse(raw) as CompileOptions
  return raw
}

try {
  const opts = parseOpts(rawOpts)
  const result = await compile(entry, opts)
  const payload = {
    ok: true,
    entry,
    opts: rawOpts,
    force,
    cacheKey: result.cacheKey,
    compileTimeMs: result.compileTimeMs,
    sizeBytes: result.sizeBytes,
    source: result.source
  }
  console.log(JSON.stringify(payload))
} catch (err: any) {
  console.log(
    JSON.stringify({
      ok: false,
      entry,
      opts: rawOpts,
      force,
      error: String(err?.message ?? err)
    })
  )
  process.exitCode = 1
}
