/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  keccak256/index.ts — Keccak-256 (Ethereum variant, 256-bit hash)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Keccak-256 con padding 0x01…0x80 (variante original de Keccak, NO SHA-3
 * que usa 0x06). Base de Ethereum: function selectors, address derivation,
 * Merkle Patricia Trie, solidity keccak256().
 *
 * ── ARQUITECTURA (alineada con SHA-2 / RIPEMD-160) ───────────────────────
 * • Contexto @unmanaged de 208 bytes sobre HASH_WORK_PTR (layout fijo).
 * • El estado sponge (200 B) ES el buffer (XOR directo, sin buffer separado).
 * • RC como StaticArray<u64> en el data segment (sin memory.data manual).
 * • CERO Memory.alloc / Memory.save / Memory.restore.
 * • CERO heap, CERO memory.grow.
 *
 * ── SPONGE CONSTRUCTION ───────────────────────────────────────────────────
 * rate = 136 bytes (1088 bits), capacity = 64 bytes (512 bits).
 * Absorb: XOR mensaje en el estado (rate words), luego keccakF1600.
 * Squeeze: primeros 32 bytes del estado post-permutación.
 *
 * ── API ───────────────────────────────────────────────────────────────────
 *   One-shot:  keccak256_hash_raw(outPtr, mPtr, len)
 *   Streaming: keccak256_create_ctx(ctxPtr)
 *              keccak256_update_raw(ctxPtr, mPtr, len)
 *              keccak256_final_raw(ctxPtr, outPtr)
 */
import { HASH_WORK_PTR, align8, PARAM_IN_PTR, PARAM_OUT_PTR } from "../utils/memory"
export { PARAM_IN_PTR, PARAM_OUT_PTR }

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTES
// ═══════════════════════════════════════════════════════════════════════════

export const KECCAK256_HASH: usize = 32
const RATE_BYTES: usize = 136 // rate de Keccak-256 (1088 bits)
const RATE_WORDS: usize = 17  // 136 / 8

/** Round constants (RC) — 24 rondas de iota. */
const RC: StaticArray<u64> = [
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

// ═══════════════════════════════════════════════════════════════════════════
// NÚCLEO: Keccak-f[1600] (24 rondas, completamente desenrollado)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Permutación Keccak-f[1600]. Opera sobre `s` (200 bytes = 25 × u64, LE).
 * Theta / Rho-Pi / Chi / Iota verificados contra el estándar NIST SP 800-185.
 */
// @ts-ignore
@inline
function keccakF1600(s: usize): void {
  let bc0: u64, bc1: u64, bc2: u64, bc3: u64, bc4: u64
  let d0: u64, d1: u64, d2: u64, d3: u64, d4: u64
  let t: u64, last: u64

  for (let round = 0; round < 24; round++) {
    // ── THETA ──
    bc0 = load<u64>(s) ^ load<u64>(s + 40) ^ load<u64>(s + 80) ^ load<u64>(s + 120) ^ load<u64>(s + 160)
    bc1 = load<u64>(s + 8) ^ load<u64>(s + 48) ^ load<u64>(s + 88) ^ load<u64>(s + 128) ^ load<u64>(s + 168)
    bc2 = load<u64>(s + 16) ^ load<u64>(s + 56) ^ load<u64>(s + 96) ^ load<u64>(s + 136) ^ load<u64>(s + 176)
    bc3 = load<u64>(s + 24) ^ load<u64>(s + 64) ^ load<u64>(s + 104) ^ load<u64>(s + 144) ^ load<u64>(s + 184)
    bc4 = load<u64>(s + 32) ^ load<u64>(s + 72) ^ load<u64>(s + 112) ^ load<u64>(s + 152) ^ load<u64>(s + 192)

    d0 = bc4 ^ rotl<u64>(bc1, 1)
    d1 = bc0 ^ rotl<u64>(bc2, 1)
    d2 = bc1 ^ rotl<u64>(bc3, 1)
    d3 = bc2 ^ rotl<u64>(bc4, 1)
    d4 = bc3 ^ rotl<u64>(bc0, 1)

    store<u64>(s,      load<u64>(s) ^ d0)
    store<u64>(s + 40, load<u64>(s + 40) ^ d0)
    store<u64>(s + 80, load<u64>(s + 80) ^ d0)
    store<u64>(s + 120, load<u64>(s + 120) ^ d0)
    store<u64>(s + 160, load<u64>(s + 160) ^ d0)
    store<u64>(s + 8,  load<u64>(s + 8) ^ d1)
    store<u64>(s + 48, load<u64>(s + 48) ^ d1)
    store<u64>(s + 88, load<u64>(s + 88) ^ d1)
    store<u64>(s + 128, load<u64>(s + 128) ^ d1)
    store<u64>(s + 168, load<u64>(s + 168) ^ d1)
    store<u64>(s + 16, load<u64>(s + 16) ^ d2)
    store<u64>(s + 56, load<u64>(s + 56) ^ d2)
    store<u64>(s + 96, load<u64>(s + 96) ^ d2)
    store<u64>(s + 136, load<u64>(s + 136) ^ d2)
    store<u64>(s + 176, load<u64>(s + 176) ^ d2)
    store<u64>(s + 24, load<u64>(s + 24) ^ d3)
    store<u64>(s + 64, load<u64>(s + 64) ^ d3)
    store<u64>(s + 104, load<u64>(s + 104) ^ d3)
    store<u64>(s + 144, load<u64>(s + 144) ^ d3)
    store<u64>(s + 184, load<u64>(s + 184) ^ d3)
    store<u64>(s + 32, load<u64>(s + 32) ^ d4)
    store<u64>(s + 72, load<u64>(s + 72) ^ d4)
    store<u64>(s + 112, load<u64>(s + 112) ^ d4)
    store<u64>(s + 152, load<u64>(s + 152) ^ d4)
    store<u64>(s + 192, load<u64>(s + 192) ^ d4)

    // ── RHO & PI (24 rotaciones encadenadas) ──
    last = load<u64>(s + 8)
    t = load<u64>(s + 80);  store<u64>(s + 80,  rotl<u64>(last, 1));  last = t
    t = load<u64>(s + 56);  store<u64>(s + 56,  rotl<u64>(last, 3));  last = t
    t = load<u64>(s + 88);  store<u64>(s + 88,  rotl<u64>(last, 6));  last = t
    t = load<u64>(s + 136); store<u64>(s + 136, rotl<u64>(last, 10)); last = t
    t = load<u64>(s + 144); store<u64>(s + 144, rotl<u64>(last, 15)); last = t
    t = load<u64>(s + 24);  store<u64>(s + 24,  rotl<u64>(last, 21)); last = t
    t = load<u64>(s + 40);  store<u64>(s + 40,  rotl<u64>(last, 28)); last = t
    t = load<u64>(s + 128); store<u64>(s + 128, rotl<u64>(last, 36)); last = t
    t = load<u64>(s + 64);  store<u64>(s + 64,  rotl<u64>(last, 45)); last = t
    t = load<u64>(s + 168); store<u64>(s + 168, rotl<u64>(last, 55)); last = t
    t = load<u64>(s + 192); store<u64>(s + 192, rotl<u64>(last, 2));  last = t
    t = load<u64>(s + 32);  store<u64>(s + 32,  rotl<u64>(last, 14)); last = t
    t = load<u64>(s + 120); store<u64>(s + 120, rotl<u64>(last, 27)); last = t
    t = load<u64>(s + 184); store<u64>(s + 184, rotl<u64>(last, 41)); last = t
    t = load<u64>(s + 152); store<u64>(s + 152, rotl<u64>(last, 56)); last = t
    t = load<u64>(s + 104); store<u64>(s + 104, rotl<u64>(last, 8));  last = t
    t = load<u64>(s + 96);  store<u64>(s + 96,  rotl<u64>(last, 25)); last = t
    t = load<u64>(s + 16);  store<u64>(s + 16,  rotl<u64>(last, 43)); last = t
    t = load<u64>(s + 160); store<u64>(s + 160, rotl<u64>(last, 62)); last = t
    t = load<u64>(s + 112); store<u64>(s + 112, rotl<u64>(last, 18)); last = t
    t = load<u64>(s + 176); store<u64>(s + 176, rotl<u64>(last, 39)); last = t
    t = load<u64>(s + 72);  store<u64>(s + 72,  rotl<u64>(last, 61)); last = t
    t = load<u64>(s + 48);  store<u64>(s + 48,  rotl<u64>(last, 20)); last = t
    store<u64>(s + 8, rotl<u64>(last, 44))

    // ── CHI (5 filas) ──
    bc0 = load<u64>(s); bc1 = load<u64>(s + 8); bc2 = load<u64>(s + 16); bc3 = load<u64>(s + 24); bc4 = load<u64>(s + 32)
    store<u64>(s, bc0 ^ (~bc1 & bc2)); store<u64>(s + 8, bc1 ^ (~bc2 & bc3)); store<u64>(s + 16, bc2 ^ (~bc3 & bc4))
    store<u64>(s + 24, bc3 ^ (~bc4 & bc0)); store<u64>(s + 32, bc4 ^ (~bc0 & bc1))

    bc0 = load<u64>(s + 40); bc1 = load<u64>(s + 48); bc2 = load<u64>(s + 56); bc3 = load<u64>(s + 64); bc4 = load<u64>(s + 72)
    store<u64>(s + 40, bc0 ^ (~bc1 & bc2)); store<u64>(s + 48, bc1 ^ (~bc2 & bc3)); store<u64>(s + 56, bc2 ^ (~bc3 & bc4))
    store<u64>(s + 64, bc3 ^ (~bc4 & bc0)); store<u64>(s + 72, bc4 ^ (~bc0 & bc1))

    bc0 = load<u64>(s + 80); bc1 = load<u64>(s + 88); bc2 = load<u64>(s + 96); bc3 = load<u64>(s + 104); bc4 = load<u64>(s + 112)
    store<u64>(s + 80, bc0 ^ (~bc1 & bc2)); store<u64>(s + 88, bc1 ^ (~bc2 & bc3)); store<u64>(s + 96, bc2 ^ (~bc3 & bc4))
    store<u64>(s + 104, bc3 ^ (~bc4 & bc0)); store<u64>(s + 112, bc4 ^ (~bc0 & bc1))

    bc0 = load<u64>(s + 120); bc1 = load<u64>(s + 128); bc2 = load<u64>(s + 136); bc3 = load<u64>(s + 144); bc4 = load<u64>(s + 152)
    store<u64>(s + 120, bc0 ^ (~bc1 & bc2)); store<u64>(s + 128, bc1 ^ (~bc2 & bc3)); store<u64>(s + 136, bc2 ^ (~bc3 & bc4))
    store<u64>(s + 144, bc3 ^ (~bc4 & bc0)); store<u64>(s + 152, bc4 ^ (~bc0 & bc1))

    bc0 = load<u64>(s + 160); bc1 = load<u64>(s + 168); bc2 = load<u64>(s + 176); bc3 = load<u64>(s + 184); bc4 = load<u64>(s + 192)
    store<u64>(s + 160, bc0 ^ (~bc1 & bc2)); store<u64>(s + 168, bc1 ^ (~bc2 & bc3)); store<u64>(s + 176, bc2 ^ (~bc3 & bc4))
    store<u64>(s + 184, bc3 ^ (~bc4 & bc0)); store<u64>(s + 192, bc4 ^ (~bc0 & bc1))

    // ── IOTA ──
    store<u64>(s, load<u64>(s) ^ unchecked(RC[round]))
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONTEXTO (208 bytes, @unmanaged)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Layout: [0..199] state (25×u64) | [200..203] r (u32) | [204..207] pad
 * El estado ES el buffer (sponge XOR directo). No necesita buffer separado.
 */
@unmanaged
class Keccak256Context {
  static readonly SIZE: usize = 208

  @inline get statePtr(): usize { return changetype<usize>(this) }

  @inline getR(): u32 { return load<u32>(changetype<usize>(this) + 200) }
  @inline setR(v: u32): void { store<u32>(changetype<usize>(this) + 200, v) }

  @inline
  init(): void {
    memory.fill(changetype<usize>(this), 0, 208)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CLASE PÚBLICA
// ═══════════════════════════════════════════════════════════════════════════
@final
class Keccak256 {
  /** Absorbe n bytes al contexto (streaming). */
  static update(ctx: Keccak256Context, mPtr: usize, n: isize): void {
    if (n <= 0) return
    let r = ctx.getR()
    const s = ctx.statePtr
    let ptr = mPtr
    let len = n

    // Completar el bloque actual (si hay residuo pendiente)
    if (r > 0) {
      let take = <u32>(<isize>RATE_BYTES - <isize>r)
      if (take > <u32>len) take = <u32>len
      for (let i: u32 = 0; i < take; i++) {
        const idx = r + i
        const wordOff = (idx >>> 3) << 3
        const bitShift = <u64>((idx & 7) << 3)
        store<u64>(s + wordOff, load<u64>(s + wordOff) ^ (<u64>load<u8>(ptr + i) << bitShift))
      }
      r += take
      ptr += take
      len -= <isize>take
      if (r == <u32>RATE_BYTES) {
        keccakF1600(s)
        r = 0
      }
    }

    // Absorber bloques completos de 136 B (por palabras u64, rápido)
    while (len >= <isize>RATE_BYTES) {
      for (let i: usize = 0; i < RATE_WORDS; i++) {
        const addr = s + (i << 3)
        store<u64>(addr, load<u64>(addr) ^ load<u64>(ptr + (i << 3)))
      }
      keccakF1600(s)
      ptr += RATE_BYTES
      len -= <isize>RATE_BYTES
    }

    // Guardar el residuo (< 136 B) byte a byte (XOR en estado)
    if (len > 0) {
      for (let i: u32 = 0; i < <u32>len; i++) {
        const wordOff = (i >>> 3) << 3
        const bitShift = <u64>((i & 7) << 3)
        store<u64>(s + wordOff, load<u64>(s + wordOff) ^ (<u64>load<u8>(ptr + i) << bitShift))
      }
      r = <u32>len
    }
    ctx.setR(r)
  }

  /**
   * Finaliza: padding Keccak (0x01…0x80) + permutación final + squeeze 32 B.
   * NO necesita paddedPtr externo (el padding se aplica directo al estado).
   */
  static final(ctx: Keccak256Context, outPtr: usize): void {
    const s = ctx.statePtr
    const r = ctx.getR()

    // Padding start: XOR 0x01 en la posición r (domain separation Keccak)
    const wordOff = (r >>> 3) << 3
    const bitShift = <u64>((r & 7) << 3)
    store<u64>(s + wordOff, load<u64>(s + wordOff) ^ (<u64>0x01 << bitShift))

    // Padding end: XOR 0x80 en el byte 135 (último byte del rate)
    // Byte 135 = word 16 (offset 128), bit 7 → shift 56
    store<u64>(s + 128, load<u64>(s + 128) ^ 0x8000000000000000)

    // Permutación final
    keccakF1600(s)

    // Squeeze: primeros 32 bytes del estado (4 palabras u64, little-endian)
    store<u64>(outPtr + 0, load<u64>(s + 0))
    store<u64>(outPtr + 8, load<u64>(s + 8))
    store<u64>(outPtr + 16, load<u64>(s + 16))
    store<u64>(outPtr + 24, load<u64>(s + 24))
  }

  /** One-shot: Keccak-256 de n bytes → 32 bytes en outPtr. Zero-alloc. */
  static hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
    const scratch = align8(HASH_WORK_PTR)
    const ctx = changetype<Keccak256Context>(scratch)
    ctx.init()
    Keccak256.update(ctx, mPtr, n)
    Keccak256.final(ctx, outPtr)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS (snake_case, solo punteros)
// ═══════════════════════════════════════════════════════════════════════════

export const KECCAK256_CTX_SIZE: usize = Keccak256Context.SIZE // 208

/** One-shot: Keccak-256(mPtr[0..len)) → outPtr (32 B). */
export function keccak256_hash_raw(outPtr: usize, mPtr: usize, len: isize): void {
  Keccak256.hash_raw(outPtr, mPtr, len)
}

/** Streaming: inicializa contexto en ctxPtr (≥ 208 B). */
export function keccak256_create_ctx(ctxPtr: usize): void {
  changetype<Keccak256Context>(ctxPtr).init()
}

/** Streaming: absorbe len bytes de mPtr al contexto. */
export function keccak256_update_raw(ctxPtr: usize, mPtr: usize, len: isize): void {
  Keccak256.update(changetype<Keccak256Context>(ctxPtr), mPtr, len)
}

/** Streaming: finaliza → 32 B en outPtr. No necesita paddedPtr. */
export function keccak256_final_raw(ctxPtr: usize, outPtr: usize): void {
  Keccak256.final(changetype<Keccak256Context>(ctxPtr), outPtr)
}