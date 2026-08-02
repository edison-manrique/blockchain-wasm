/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  test/utils/wasm/index.ts — Punto de entrada unificado y fachada estática
 * ═══════════════════════════════════════════════════════════════════════════
 */

import type { CompileOptions, WasmInstance } from "./types.js"
import { compile } from "./compiler.js"
import { load, hexToBytes, bytesToHex } from "./runtime.js"
import { parseShorthand } from "./options.js"
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
export { compile } from "./compiler.js"
export { load, hexToBytes, bytesToHex } from "./runtime.js"
export { parseShorthand } from "./options.js"
export * from "./bench.js"

/**
 * Helper para compilar e instanciar en un solo paso
 */
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
 * Mantiene la compatibilidad 100% con tests existentes que usan Wasm.compileAndLoad(...)
 */
export class Wasm {
  private constructor() {}

  static compile = compile
  static load = load
  static compileAndLoad = compileAndLoad

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

  // Utilidades
  static hexToBytes = hexToBytes
  static bytesToHex = bytesToHex
  static parseShorthand = parseShorthand
}