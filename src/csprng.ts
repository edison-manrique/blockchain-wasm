/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  csprng.ts — Fuente de entropía host-side para blockchain-wasm
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * La entropía segura SOLO existe en el host (Web Crypto). Este módulo NO vive
 * en assembly/: el WASM nunca genera aleatoriedad (no tiene fuente). El wrapper
 * rellena la memoria lineal del WASM (zero-copia) ANTES de cada llamada.
 *
 * Refactorizado para el DOMINIO de esta lib:
 *   • privkey / scalar  → 32 B   (claves privadas, escalares)
 *   • entropy(n)        → n B    (BIP39: n ∈ {16,20,24,28,32}, validado)
 *   • auxRand           → 32 B   (aux_rand de Schnorr BIP-340)
 *   • bytes(n) / fill*  → genérico
 *
 * Inyección de generador (`generator?`): permite tests determinísticos y
 * fuentes externas (HSM / hardware RNG). Si NO se inyecta, se exige Web Crypto
 * y se falla rápido (en la construcción de EntropySource, la vía recomendada).
 *
 * Zero-copia: los métodos `*Into` crean una view sobre `memory.buffer` y la
 * pasan a getRandomValues; ningún byte se copia ni se aloca de más.
 *
 * Uso (preview del wrapper):
 *   const rng = new EntropySource(wasm.memory)
 *   rng.entropyInto(IN, 16)                       // 16 B de entropía en IN
 *   wasm.exports.bip39_entropy_to_mnemonic(OUT, IN, 16)
 *   rng.auxRandInto(IN + 256)                     // aux_rand para Schnorr
 *   wasm.exports.schnorr_sign(OUT, IN, msgLen, IN + 32, IN + 256)
 */

// ═══════════════════════════════════════════════════════════════════════════
// TIPOS Y CONSTANTES
// ═══════════════════════════════════════════════════════════════════════════

/** Generador inyectable: devuelve `size` bytes seguros (para tests / HSM). */
export type RandomBytesGenerator = (size: number) => Uint8Array

/** Rellenador interno (in-place, zero-alloc en el path por defecto). */
type RandomFiller = (buf: Uint8Array) => void

import { EntropyError, InvalidArgumentError, RuntimeCode } from "./errors"

/** Límite de bytes por llamada de la Web Crypto API (64 KB). */
const CHUNK = 65536

/** Longitudes válidas de entropía BIP39 (en bytes). */
const BIP39_ENTROPY_BYTES: ReadonlyArray<number> = [16, 20, 24, 28, 32]

/** Tamaño de clave privada / escalar / aux_rand (256 bits). */
const SCALAR_BYTES = 32

// ═══════════════════════════════════════════════════════════════════════════
// RESOLUCIÓN DEL FILLER (default lazy con fail-fast + adaptación de generador)
// ═══════════════════════════════════════════════════════════════════════════

let _defaultFiller: RandomFiller | null | undefined = undefined

/** Rellenador por defecto (Web Crypto). null = entorno sin crypto. */
function getDefaultFiller(): RandomFiller {
  if (_defaultFiller === undefined) {
    const c = typeof globalThis !== "undefined" ? globalThis.crypto : undefined
    if (!c || typeof c.getRandomValues !== "function") {
      _defaultFiller = null
    } else {
      _defaultFiller = (buf: Uint8Array): void => {
        // Cast aísla la restricción de SharedArrayBuffer (TS ≥5.7): nuestros
        // buffers SIEMPRE están respaldados por ArrayBuffer.
        c.getRandomValues(buf as Uint8Array<ArrayBuffer>)
      }
    }
  }
  if (_defaultFiller === null) {
    throw new EntropyError(
      "CRÍTICO: Criptografía segura (CSPRNG / Web Crypto) no disponible en este entorno. " +
        "Inyecta un `generator` o usa un runtime con crypto.getRandomValues.",
      RuntimeCode.ENTROPY_UNAVAILABLE
    )
  }
  return _defaultFiller
}

/** Normaliza un generador inyectado a un rellenador in-place (con copia). */
function adaptGenerator(gen: RandomBytesGenerator): RandomFiller {
  return (buf: Uint8Array): void => {
    const r = gen(buf.length)
    if (r.length !== buf.length) {
      throw new EntropyError(
        `generator devolvió ${r.length} bytes, se esperaban ${buf.length}`,
        RuntimeCode.ENTROPY_INVALID
      )
    }
    buf.set(r)
  }
}

function resolveFiller(gen?: RandomBytesGenerator): RandomFiller {
  return gen ? adaptGenerator(gen) : getDefaultFiller()
}

// ═══════════════════════════════════════════════════════════════════════════
// CHUNKING UNIFICADO (sirve para views de WASM y para Uint8Array normales)
// ═══════════════════════════════════════════════════════════════════════════

function fillView(view: Uint8Array, fill: RandomFiller): void {
  const size = view.length
  if (size <= CHUNK) {
    fill(view)
    return
  }
  for (let off = 0; off < size; off += CHUNK) {
    const n = off + CHUNK > size ? size - off : CHUNK
    fill(view.subarray(off, off + n)) // subarray de una view → misma backing store
  }
}

function assertBip39Entropy(n: number): void {
  // indexOf evita depender de Array.prototype.includes en targets mínimos
  let ok = false
  for (let i = 0; i < BIP39_ENTROPY_BYTES.length; i++) {
    if (BIP39_ENTROPY_BYTES[i] === n) {
      ok = true
      break
    }
  }
  if (!ok) {
    throw new InvalidArgumentError(`BIP39 entropy debe ser 16/20/24/28/32 bytes, recibido ${n}`, "csprng")
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// FUNCIONES PURAS DE BAJO NIVEL (sin clase)
// ═══════════════════════════════════════════════════════════════════════════

/** Genera `size` bytes seguros (nueva asignación). */
export function getRandomBytes(size: number, gen?: RandomBytesGenerator): Uint8Array {
  const buf = new Uint8Array(size)
  fillView(buf, resolveFiller(gen))
  return buf
}

/** Rellena un buffer EXISTENTE con entropía (zero-alloc). */
export function fillRandom(buf: Uint8Array, gen?: RandomBytesGenerator): Uint8Array {
  fillView(buf, resolveFiller(gen))
  return buf
}

/** Rellena [ptr, ptr+len) de la memoria lineal del WASM (zero-copia). */
export function fillRandomInto(memory: WebAssembly.Memory, ptr: number, len: number, gen?: RandomBytesGenerator): void {
  fillView(new Uint8Array(memory.buffer, ptr, len), resolveFiller(gen))
}

// ═══════════════════════════════════════════════════════════════════════════
// FUENTE DE ENTROPÍA (vía recomendada: el wrapper la instancia una vez)
// ═══════════════════════════════════════════════════════════════════════════

export interface EntropySourceOptions {
  /** Generador inyectable (tests determinísticos / HSM). Si se omite → Web Crypto. */
  generator?: RandomBytesGenerator
}

/**
 * Fuente de entropía reutilizable. Captura la memoria del WASM y el generador,
 * y expone helpers del dominio de esta lib. Constrúyela UNA vez en el wrapper.
 *
 * Fail-fast: si NO se inyecta `generator` y el entorno carece de Web Crypto,
 * la construcción lanza (no se puede usar el default sin entropía segura).
 */
export class EntropySource {
  private readonly _fill: RandomFiller
  private readonly _memory: WebAssembly.Memory | null

  constructor(memory?: WebAssembly.Memory, opts?: EntropySourceOptions) {
    // resolveFiller sin generador → getDefaultFiller() → fail-fast si no hay crypto
    this._fill = resolveFiller(opts?.generator)
    this._memory = memory ?? null
  }

  // ── Genérico ────────────────────────────────────────────────────────────

  /** `len` bytes seguros (nueva asignación). */
  bytes(len: number): Uint8Array {
    const buf = new Uint8Array(len)
    fillView(buf, this._fill)
    return buf
  }

  /** Rellena un buffer existente (zero-alloc). */
  fill(buf: Uint8Array): Uint8Array {
    fillView(buf, this._fill)
    return buf
  }

  /** Rellena [ptr, ptr+len) de la memoria WASM (zero-copia). */
  fillInto(ptr: number, len: number): void {
    this._requireMemory()
    fillView(new Uint8Array(this._memory!.buffer, ptr, len), this._fill)
  }

  // ── Dominio blockchain-wasm (variantes que devuelven Uint8Array) ────────

  /** Clave privada / escalar de 32 B. */
  privkey(): Uint8Array {
    return this.bytes(SCALAR_BYTES)
  }

  /** Entropía BIP39 de `n` bytes (valida n ∈ {16,20,24,28,32}). */
  entropy(n: number): Uint8Array {
    assertBip39Entropy(n)
    return this.bytes(n)
  }

  /** aux_rand de 32 B para Schnorr BIP-340. */
  auxRand(): Uint8Array {
    return this.bytes(SCALAR_BYTES)
  }

  // ── Dominio blockchain-wasm (variantes zero-copia en memoria WASM) ──────

  /** Clave privada / escalar de 32 B en `ptr`. */
  privkeyInto(ptr: number): void {
    this.fillInto(ptr, SCALAR_BYTES)
  }

  /** Entropía BIP39 de `n` bytes en `ptr` (valida n). */
  entropyInto(ptr: number, n: number): void {
    assertBip39Entropy(n)
    this.fillInto(ptr, n)
  }

  /** aux_rand de 32 B en `ptr`. */
  auxRandInto(ptr: number): void {
    this.fillInto(ptr, SCALAR_BYTES)
  }

  // ── Interno ─────────────────────────────────────────────────────────────

  private _requireMemory(): void {
    if (this._memory === null) {
      throw new InvalidArgumentError("EntropySource: métodos *Into requieren WebAssembly.Memory", "csprng")
    }
  }
}
