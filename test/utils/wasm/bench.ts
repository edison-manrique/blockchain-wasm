/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  test/utils/wasm/bench.ts — Suite de pruebas, velocidad y medición de memoria
 * ═══════════════════════════════════════════════════════════════════════════
 */

import type {
  BenchResult,
  BenchOptions,
  MemoryResult,
  CompareResult,
  CompileBenchSpec,
  CompileBenchResult,
  CompileCompareReport,
  CompileResult,
  WasmInstance
} from "./types.js"
import { resolveOpts } from "./options.js"
import { compile } from "./compiler.js"
import { load } from "./runtime.js"

// ── Correctitud ──

export function assertCorrectness(name: string, fn: () => boolean): void {
  if (!fn()) throw new Error(`[CORRECTITUD FAIL] ${name}`)
}

export function runCorrectnessSuite(tests: [string, () => boolean][]): string[] {
  const failures: string[] = []
  for (const [name, fn] of tests) {
    try {
      if (!fn()) failures.push(name)
    } catch (e: any) {
      failures.push(`${name} (exception: ${e.message})`)
    }
  }
  return failures
}

// ── Mediciones de Velocidad ──

function resolveBenchOpts(o: number | BenchOptions): { warmup: number; runs: number } {
  return typeof o === "number" ? { warmup: o, runs: 1 } : { warmup: o.warmup ?? 1000, runs: o.runs ?? 1 }
}

export function benchSpeed(
  name: string,
  iterations: number,
  fn: () => void,
  opts: number | BenchOptions = 1000
): BenchResult {
  const { warmup, runs } = resolveBenchOpts(opts)
  for (let i = 0; i < warmup; i++) fn()

  const nRuns = Math.max(1, runs)
  const samples: number[] = []
  let bestTotalMs = Infinity

  for (let r = 0; r < nRuns; r++) {
    const t0 = performance.now()
    for (let i = 0; i < iterations; i++) fn()
    const totalMs = performance.now() - t0
    samples.push((totalMs * 1e6) / iterations)
    if (totalMs < bestTotalMs) bestTotalMs = totalMs
  }

  const sorted = [...samples].sort((a, b) => a - b)
  const minNs = sorted[0]
  const maxNs = sorted[sorted.length - 1]
  const meanNs = samples.reduce((s, x) => s + x, 0) / samples.length
  const medianNs = calcMedian(sorted)
  const stddevNs = calcStddev(samples, meanNs)
  const cvPct = meanNs > 0 ? (stddevNs / meanNs) * 100 : 0

  return {
    name,
    ops: iterations,
    runs: nRuns,
    totalMs: bestTotalMs,
    opsPerSec: (iterations / bestTotalMs) * 1000,
    nsPerOp: minNs,
    samples,
    minNs,
    maxNs,
    meanNs,
    medianNs,
    stddevNs,
    cvPct
  }
}

export function benchSuite(
  entries: { name: string; fn: () => void; iterations?: number }[],
  defaultIterations = 100_000,
  opts: number | BenchOptions = 1000
): BenchResult[] {
  return entries.map((e) => benchSpeed(e.name, e.iterations ?? defaultIterations, e.fn, opts))
}

// ── Mediciones de Memoria ──

export function benchMemory(name: string, wasm: WasmInstance, fn: () => void, iterations = 100): MemoryResult {
  const pagesBefore = wasm.memoryPages()
  const bytesBefore = wasm.memoryBytes()
  for (let i = 0; i < iterations; i++) fn()
  wasm.syncViews()
  const pagesAfter = wasm.memoryPages()
  const bytesAfter = wasm.memoryBytes()
  return {
    name,
    pagesBefore,
    pagesAfter,
    bytesBefore,
    bytesAfter,
    deltaBytes: bytesAfter - bytesBefore,
    grew: pagesAfter > pagesBefore
  }
}

export function assertZeroAlloc(name: string, wasm: WasmInstance, fn: () => void, iterations = 1000): void {
  const r = benchMemory(name, wasm, fn, iterations)
  if (r.grew) {
    throw new Error(
      `[MEMORY FAIL] ${name}: memoria creció ${r.deltaBytes} bytes ` +
        `(${r.pagesBefore} → ${r.pagesAfter} páginas) en ${iterations} iteraciones`
    )
  }
}

// ── Comparativas ──

export function benchCompare(
  nameA: string,
  fnA: () => void,
  nameB: string,
  fnB: () => void,
  iterations = 100_000,
  opts: number | BenchOptions = 1000
): CompareResult {
  const a = benchSpeed(nameA, iterations, fnA, opts)
  const b = benchSpeed(nameB, iterations, fnB, opts)
  const ratio = a.nsPerOp / b.nsPerOp
  const winner = ratio < 1 ? nameA : nameB
  return { a, b, ratio, winner }
}

export function benchRace(
  entries: { name: string; fn: () => void }[],
  iterations = 100_000,
  opts: number | BenchOptions = 1000
): BenchResult[] {
  const results = entries.map((e) => benchSpeed(e.name, iterations, e.fn, opts))
  results.sort((a, b) => a.nsPerOp - b.nsPerOp)
  return results
}

export async function benchCompileCompare(
  entryRel: string,
  specA: CompileBenchSpec,
  specB: CompileBenchSpec,
  benchFn: (wasm: WasmInstance) => () => void,
  iterations = 100_000,
  benchOpts: number | BenchOptions = 1000
): Promise<CompileCompareReport> {
  const runOne = async (spec: CompileBenchSpec): Promise<CompileBenchResult> => {
    const cr = await compile(entryRel, { ...resolveOpts(spec.opts), forceRecompile: true })
    const wasm = await load(cr.binary)
    const bench = benchSpeed(spec.label, iterations, benchFn(wasm), benchOpts)
    return { label: spec.label, compileTimeMs: cr.compileTimeMs, sizeBytes: cr.sizeBytes, cached: cr.cached, bench }
  }
  const a = await runOne(specA)
  const b = await runOne(specB)
  return {
    entry: entryRel,
    a,
    b,
    speedRatio: a.bench.nsPerOp / b.bench.nsPerOp,
    sizeRatio: a.sizeBytes / b.sizeBytes,
    compileTimeRatio: a.compileTimeMs / b.compileTimeMs,
    winner: a.bench.nsPerOp < b.bench.nsPerOp ? a.label : b.label
  }
}

// ── Formateadores e Impresión ──

export function printCompileCompare(r: CompileCompareReport): void {
  const ms = (x: number) => (x < 1 ? `${(x * 1000).toFixed(0)} µs` : `${x.toFixed(1)} ms`)
  const kb = (x: number) => `${(x / 1024).toFixed(2)} KB`
  console.log(`\n═══ Compile compare: ${r.entry} ═══`)
  const header =
    `${"Variant".padEnd(12)}  ${"compile".padStart(10)}  ${"size".padStart(10)}  ` +
    `${"ns/op".padStart(10)}  ${"mean±σ".padStart(18)}  ${"ops/s".padStart(14)}`
  console.log(header)
  console.log("─".repeat(header.length))
  for (const v of [r.a, r.b]) {
    const meanStd = `${v.bench.meanNs.toFixed(1)}±${v.bench.stddevNs.toFixed(1)}`
    console.log(
      `${v.label.padEnd(12)}  ${ms(v.compileTimeMs).padStart(10)}  ${kb(v.sizeBytes).padStart(10)}  ` +
        `${v.bench.nsPerOp.toFixed(1).padStart(10)}  ${meanStd.padStart(18)}  ${v.bench.opsPerSec.toFixed(0).padStart(14)}`
    )
  }
  console.log("─".repeat(header.length))
  console.log(`  speed   ${r.a.label}/${r.b.label} = ${r.speedRatio.toFixed(3)}x   (winner: ${r.winner})`)
  console.log(`  size    ${r.a.label}/${r.b.label} = ${r.sizeRatio.toFixed(3)}x`)
  console.log(`  compile ${r.a.label}/${r.b.label} = ${r.compileTimeRatio.toFixed(3)}x`)
  console.log("")
}

export function printCompileStats(cr: CompileResult, label = ""): void {
  const tag = label ? `[${label}] ` : ""
  console.log(
    `${tag}compile: ${cr.compileTimeMs.toFixed(1)} ms | ` +
      `size: ${(cr.sizeBytes / 1024).toFixed(2)} KB (${cr.sizeBytes} B)${cr.cached ? " | cached" : ""}`
  )
}

export function printResults(results: BenchResult[]): void {
  const maxName = Math.max(...results.map((r) => r.name.length), 4)
  const header =
    `${"Name".padEnd(maxName)}  ${"ns/op".padStart(10)}  ${"mean±σ".padStart(18)}  ` +
    `${"CV%".padStart(6)}  ${"ops/s".padStart(14)}  ${"runs".padStart(4)}`
  console.log(`\n${header}`)
  console.log("─".repeat(header.length))
  for (const r of results) {
    const meanStd = `${r.meanNs.toFixed(1)}±${r.stddevNs.toFixed(1)}`
    console.log(
      `${r.name.padEnd(maxName)}  ${r.nsPerOp.toFixed(1).padStart(10)}  ${meanStd.padStart(18)}  ` +
        `${r.cvPct.toFixed(1).padStart(6)}  ${r.opsPerSec.toFixed(0).padStart(14)}  ${String(r.runs).padStart(4)}`
    )
  }
  console.log("")
}

// ── Helpers Estadísticos ──

function calcMedian(sorted: number[]): number {
  const n = sorted.length
  if (n === 0) return 0
  const mid = n >> 1
  return n % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid]
}

function calcStddev(samples: number[], mean: number): number {
  if (samples.length < 2) return 0
  const variance = samples.reduce((s, x) => s + (x - mean) ** 2, 0) / (samples.length - 1)
  return Math.sqrt(variance)
}