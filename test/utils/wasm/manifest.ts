/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  test/utils/wasm/manifest.ts — Manifiesto de builds usados por la suite
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Cada entrada describe un artefacto que algún test necesita. El prebuild
 * paralelo (`scripts/prebuild-tests.ts`) compila esta lista en frío; después,
 * `bun test` solo instancia binarios desde el caché L2 (RAM disk).
 *
 * Regla: si un test compila algo que no está aquí, añadirlo. Y viceversa:
 * no mantener builds que ningún test usa.
 */

import type { CompileOptions } from "./types.js"

export interface BuildSpec {
  entry: string
  opts: CompileOptions | string
  /** Etiqueta legible para `--list` / progreso. */
  label?: string
}

/** Perfiles estándar por entrada. */
const CORRECTNESS: (CompileOptions | string)[] = ["test"]
const CORRECTNESS_AND_BENCH: (CompileOptions | string)[] = ["test", "bench"]

/** Expande `[entrada, perfiles]` a la lista plana de builds. */
function expand(entry: string, opts: (CompileOptions | string)[], label?: string): BuildSpec[] {
  return opts.map((o) => ({
    entry,
    opts: o,
    label: label ? `${label} · ${typeof o === "string" ? o : "?"}` : undefined
  }))
}

/**
 * Builds de correctitud y rendimiento.
 *
 * Los tests de campo/escalar/punto/generador/glv/wnaf comparan `-O1` vs `-O3`,
 * así que necesitan `test+o1` y `bench+o3` (equivalentes por argv a `test1` y
 * `bench`, el caché los deduplica).
 */
export const TEST_BUILDS: BuildSpec[] = [
  // ── secp256k1 · primitivas ──
  ...expand("assembly/secp256k1/field/index.ts", ["test", "test+o1"], "field"),
  ...expand("assembly/secp256k1/scalar/index.ts", ["test", "test+o1"], "scalar"),
  ...expand("assembly/secp256k1/point/index.ts", ["test", "test+o1"], "point"),
  ...expand("assembly/secp256k1/generator/index.ts", ["test", "test+o1"], "generator"),
  ...expand("assembly/secp256k1/glv/index.ts", ["test", "test+o1"], "glv"),
  ...expand("assembly/secp256k1/wnaf/index.ts", ["test", "test+o1"], "wnaf"),

  // ── barrels ──
  ...expand("assembly/secp256k1/index.ts", ["test", "bench"], "secp256k1"),
  ...expand("assembly/index.ts", ["test", "bench"], "barrel"),

  // ── hashes ──
  ...expand("assembly/hash/sha2/index.ts", ["test", "bench", "fast", "small"], "sha2"),
  ...expand("assembly/hash/keccak256.ts", CORRECTNESS_AND_BENCH, "keccak256"),
  ...expand("assembly/hash/ripemd160.ts", CORRECTNESS_AND_BENCH, "ripemd160"),

  // ── utilidades / direcciones ──
  ...expand("assembly/utils/base58.ts", CORRECTNESS_AND_BENCH, "base58"),
  ...expand("assembly/utils/bech32.ts", CORRECTNESS_AND_BENCH, "bech32"),
  ...expand("assembly/utils/wif.ts", CORRECTNESS_AND_BENCH, "wif"),
  ...expand("assembly/address/index.ts", CORRECTNESS_AND_BENCH, "address"),

  // ── bips ──
  ...expand("assembly/bips/bip32/index.ts", CORRECTNESS_AND_BENCH, "bip32"),
  ...expand("assembly/bips/bip39/index.ts", CORRECTNESS_AND_BENCH, "bip39"),
  ...expand("assembly/bips/bip44.ts", CORRECTNESS_AND_BENCH, "bip44"),

  // ── firmas / intercambio ──
  ...expand("assembly/signatures/ecdsa/index.ts", CORRECTNESS_AND_BENCH, "ecdsa"),
  ...expand("assembly/signatures/schnorr/index.ts", CORRECTNESS_AND_BENCH, "schnorr"),
  ...expand("assembly/ecdh/index.ts", CORRECTNESS_AND_BENCH, "ecdh")
]

/** Todos los builds, sin duplicados (misma entrada + mismas opciones). */
export function uniqueBuilds(list: BuildSpec[] = TEST_BUILDS): BuildSpec[] {
  const seen = new Set<string>()
  const out: BuildSpec[] = []
  for (const b of list) {
    const k = `${b.entry}\u0000${shorthandOf(b.opts)}`
    if (seen.has(k)) continue
    seen.add(k)
    out.push(b)
  }
  return out
}

function shorthandOf(opts: CompileOptions | string): string {
  return typeof opts === "string" ? opts : JSON.stringify(opts)
}

/** Etiqueta legible de un build. */
export function buildLabel(b: BuildSpec): string {
  return b.label ?? `${b.entry} [${shorthandOf(b.opts)}]`
}
