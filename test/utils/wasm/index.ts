/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  test/utils/wasm/index.ts — Punto de entrada unificado y fachada estática
 * ═══════════════════════════════════════════════════════════════════════════
 */

import type { CompileOptions, CompileResult, WasmInstance } from "./types.js"
import { compile, cacheKeyOf, cachedWasmPath, isCached, clearDiskCache, cacheStats } from "./compiler.js"
import { load, hexToBytes, bytesToHex } from "./runtime.js"
import { parseShorthand, CACHE_DIR, DISK_ROOT, PROFILE_FLAGS } from "./options.js"
import {
  assertCorrectness,
  runCorrectnessSuite,
  benchSpeed,
  benchSuite,
  benchMemory,
  assertZeroAlloc,
  benchCompare,
  benchRace,
  benchCompileCompare,
  printCompileCompare,
  printCompileStats,
  printResults
} from "./bench.js"

// Re-exportar todos los tipos
export * from "./types.js"

// Re-exportar funciones independientes para uso moderno
export { compile, cacheKeyOf, cachedWasmPath, isCached, clearDiskCache, cacheStats } from "./compiler.js"
export { CACHE_DIR, DISK_ROOT, PROFILE_FLAGS } from "./options.js"
export { load, hexToBytes, bytesToHex } from "./runtime.js"
export { parseShorthand } from "./options.js"
export * from "./bench.js"

/** Módulo cargado + métricas de compilación asociadas. */
export interface LoadedModule<T = Record<string, any>> {
  wasm: WasmInstance<T>
  info: CompileResult
}

/**
 * Compila (o sirve del caché) e instancia un módulo.
 * La instancia es SIEMPRE nueva (aislamiento entre suites); el binario se cachea.
 */
export async function getModule<T = Record<string, any>>(
  entryRel: string,
  optsOrShorthand: CompileOptions | string = {}
): Promise<WasmInstance<T>> {
  const { binary } = await compile(entryRel, optsOrShorthand)
  return load<T>(binary)
}

/** Igual que `getModule`, pero devuelve también las métricas de compilación. */
export async function loadModule<T = Record<string, any>>(
  entryRel: string,
  optsOrShorthand: CompileOptions | string = {}
): Promise<LoadedModule<T>> {
  const info = await compile(entryRel, optsOrShorthand)
  const wasm = await load<T>(info.binary)
  return { wasm, info }
}

/** Acceso directo al build `bench` (-O3) de una entrada. */
export async function benchModule<T = Record<string, any>>(entryRel: string): Promise<WasmInstance<T>> {
  return getModule<T>(entryRel, "bench")
}

/** Helper retrocompatible: compila e instancia en un solo paso. */
export async function compileAndLoad<T = Record<string, any>>(
  entryRel: string,
  optsOrShorthand: CompileOptions | string = {},
  customImports: Record<string, any> = {}
): Promise<WasmInstance<T>> {
  const { binary } = await compile(entryRel, optsOrShorthand)
  return load<T>(binary, customImports)
}

/**
 * Fachada Estática Retrocompatible.
 * Mantiene la compatibilidad 100% con tests existentes que usan Wasm.compileAndLoad(...).
 */
export class Wasm {
  private constructor() {}

  static compile = compile
  static load = load
  static compileAndLoad = compileAndLoad
  static module = loadModule
  static getModule = getModule
  static benchModule = benchModule

  // Testing & Correctitud
  static assertCorrectness = assertCorrectness
  static runCorrectnessSuite = runCorrectnessSuite

  // Benchmarks & Memoria
  static benchSpeed = benchSpeed
  static benchSuite = benchSuite
  static benchMemory = benchMemory
  static assertZeroAlloc = assertZeroAlloc
  static benchCompare = benchCompare
  static benchRace = benchRace
  static benchCompileCompare = benchCompileCompare

  // Formateadores
  static printCompileCompare = printCompileCompare
  static printCompileStats = printCompileStats
  static printResults = printResults

  // Caché
  static cacheKeyOf = cacheKeyOf
  static cachedWasmPath = cachedWasmPath
  static isCached = isCached
  static clearDiskCache = clearDiskCache
  static cacheStats = cacheStats

  // Utilidades
  static hexToBytes = hexToBytes
  static bytesToHex = bytesToHex
  static parseShorthand = parseShorthand
}
