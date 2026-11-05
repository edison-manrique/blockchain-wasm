/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  arena.ts — Arena global zero-alloc (ÚNICA para toda la librería)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Reserva TODO en el DATA SEGMENT (`memory.data`): NUNCA heap.alloc, NUNCA
 * memory.grow. Cuatro "mundos" disjuntos que pueden anidarse por construcción:
 *
 *   1) CRYPTO_WORK  → arena bump save/restore (secp256k1: field/point/glv/…).
 *   2) HASH_WORK    → layout fijo SHA2/RIPEMD/Keccak (sin clase Arena).
 *   3) BIP32_WORK   → layout fijo BIP32 (xkeys, HMAC, IL/IR, pubkey, hash160).
 *   4) ADDRESS_WORK → layout fijo address (hash160, payload, bech32, taproot…).
 *
 * ── LAYOUT (offsets relativos a SCRATCH_BASE) ─────────────────────────────
 *   PARAM_IN     [0,4096)       I/O entrada  (0..2048 input | 2048..4096 aux)
 *   PARAM_OUT    [4096,8192)    I/O salida   (0..2048 out   | 2048..4096 out2)
 *   CRYPTO_WORK  [8192,73728)   arena bump secp256k1 (64 KB)
 *   HASH_WORK    [73728,77824)  layout fijo SHA2/RIPEMD/Keccak (4 KB)
 *   BIP32_WORK   [77824,78336)  layout fijo BIP32 (512 B)
 *   ADDRESS_WORK [78336,79360)  layout fijo address (1 KB)
 * CONVENCIÓN RAII (mundo 1): toda función que use Arena.alloc hace save() al
 * entrar y restore() al salir (también en returns tempranos).
 */

// ═══════════════════════════════════════════════════════════════════════════
// TAMAÑOS
// ═══════════════════════════════════════════════════════════════════════════

export const PARAM_IN_SIZE: usize = 4096   // ✅ era 512  (input + aux)
export const PARAM_OUT_SIZE: usize = 4096  // ✅ era 512  (output + out2)
export const WORK_SIZE: usize = 65536        // 64 KB  (arena secp256k1)
export const HASH_WORK_SIZE: usize = 4096    // 4 KB   (SHA2/RIPEMD/Keccak)
export const BIP32_WORK_SIZE: usize = 512    // 512 B  (BIP32)
export const ADDRESS_WORK_SIZE: usize = 1024 // 1 KB   (address BTC/ETH)

// ═══════════════════════════════════════════════════════════════════════════
// RESERVA ÚNICA
// ═══════════════════════════════════════════════════════════════════════════

export const SCRATCH_SIZE: usize =
  PARAM_IN_SIZE + PARAM_OUT_SIZE + WORK_SIZE + HASH_WORK_SIZE + BIP32_WORK_SIZE + ADDRESS_WORK_SIZE // 79360

const SCRATCH_BASE: usize = memory.data(<i32>SCRATCH_SIZE, 16)

// ═══════════════════════════════════════════════════════════════════════════
// PUNTEROS
// ═══════════════════════════════════════════════════════════════════════════

export const PARAM_IN_PTR: usize = SCRATCH_BASE
export const PARAM_OUT_PTR: usize = SCRATCH_BASE + PARAM_IN_SIZE
export const CRYPTO_WORK_PTR: usize = SCRATCH_BASE + PARAM_IN_SIZE + PARAM_OUT_SIZE
export const HASH_WORK_PTR: usize = SCRATCH_BASE + PARAM_IN_SIZE + PARAM_OUT_SIZE + WORK_SIZE
export const BIP32_WORK_PTR: usize = SCRATCH_BASE + PARAM_IN_SIZE + PARAM_OUT_SIZE + WORK_SIZE + HASH_WORK_SIZE
export const ADDRESS_WORK_PTR: usize = SCRATCH_BASE + PARAM_IN_SIZE + PARAM_OUT_SIZE + WORK_SIZE + HASH_WORK_SIZE + BIP32_WORK_SIZE

// @ts-ignore
@inline
export function align8(ptr: usize): usize {
  return (ptr + 7) & ~7
}

// ═══════════════════════════════════════════════════════════════════════════
// ARENA BUMP (mundo 1)
// ═══════════════════════════════════════════════════════════════════════════

// @ts-ignore
@final
export class Arena {
  static current: usize = CRYPTO_WORK_PTR

  // @ts-ignore
  @inline
  static alloc(size: usize): usize {
    const ptr = align8(Arena.current)
    const next = ptr + size
    if (next > CRYPTO_WORK_PTR + WORK_SIZE) unreachable()
    Arena.current = next
    return ptr
  }

  // @ts-ignore
  @inline
  static reset(): void {
    Arena.current = CRYPTO_WORK_PTR
  }

  // @ts-ignore
  @inline
  static save(): usize {
    return Arena.current
  }

  // @ts-ignore
  @inline
  static restore(savedPtr: usize): void {
    Arena.current = savedPtr
  }

  // @ts-ignore
  @inline
  static wipe(): void {
    memory.fill(SCRATCH_BASE, 0, SCRATCH_SIZE)
    Arena.current = CRYPTO_WORK_PTR
  }
}

/**
 * Borra TODO el scratch (PARAM_IN, PARAM_OUT y los cuatro work-worlds).
 *
 * Export OPT-IN: no se ejecuta automáticamente (coste O(79 KB) + pérdida de
 * cualquier estado temporal). El wrapper lo expone como `wipeSecrets()` para
 * encadenarlo cuando el proyecto quiera limpiar claves de la memoria lineal.
 */
export function secure_wipe(): void {
  Arena.wipe()
}