/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  field/convert.ts — Conversión bytes ↔ limbs (zero-alloc, punteros)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Convierte entre la representación interna (4 limbs u64 little-endian) y
 * bytes big-endian (el formato estándar de secp256k1 / Bitcoin: el byte más
 * significativo primero).
 *
 * Zero-alloc: opera solo con punteros (sin Uint8Array). El caller provee los
 * buffers de 32 bytes.
 *
 *   fromBytesPtr(res, ptr)  : bytes BE (32 B en ptr) → limbs LE (en res)
 *   toBytesPtr(a, outPtr)   : limbs LE (en a) → bytes BE (32 B en outPtr)
 */

/**
 * Carga 32 bytes big-endian desde `ptr` y los almacena como 4 limbs u64
 * little-endian en `res`.
 *
 * bytes[0..8]   (más significativo) → limb3
 * bytes[8..16]                      → limb2
 * bytes[16..24]                     → limb1
 * bytes[24..32] (menos significativo) → limb0
 */
// @ts-ignore
@inline
export function fromBytesPtr(res: usize, ptr: usize): void {
  store<u64>(res, bswap(load<u64>(ptr, 24)))
  store<u64>(res, bswap(load<u64>(ptr, 16)), 8)
  store<u64>(res, bswap(load<u64>(ptr, 8)), 16)
  store<u64>(res, bswap(load<u64>(ptr)), 24)
}

/**
 * Almacena los 4 limbs u64 little-endian de `a` como 32 bytes big-endian en
 * `outPtr`.
 *
 * limb3 → bytes[0..8]   (más significativo)
 * limb2 → bytes[8..16]
 * limb1 → bytes[16..24]
 * limb0 → bytes[24..32] (menos significativo)
 */
// @ts-ignore
@inline
export function toBytesPtr(a: usize, outPtr: usize): void {
  store<u64>(outPtr, bswap(load<u64>(a, 24)))
  store<u64>(outPtr, bswap(load<u64>(a, 16)), 8)
  store<u64>(outPtr, bswap(load<u64>(a, 8)), 16)
  store<u64>(outPtr, bswap(load<u64>(a)), 24)
}

