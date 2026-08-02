/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  sha2/common.ts — Endianness + funciones lógicas de SHA-2 (FIPS 180-4)
 * ═══════════════════════════════════════════════════════════════════════════
 *
//  * Todo // @inline: se traduce a operaciones WASM nativas con cero overhead.
 *
 * ── NOTA SOBRE ENDIANNESS (importante) ─────────────────────────────────────
 * Se usa `bswap` NATIVO del compilador tanto para u32 como para u64. Esta es
 * la versión que ya estaba validada al 100 % en el código SHA2 original
 * (SHA-256, SHA-512, HMAC y PBKDF2 pasaban todos los vectores con ella).
 *
 * NO se usa un byte-swap de 64 bits "a mano": además de ser más lento (emite
 * 8 AND + 7 SHIFT + 7 OR en vez de una única instrucción de swap de bytes),
 * es frágil por la inferencia de tipos de los literales en los shifts. El
 * `bswap<u64>` nativo es a la vez más rápido y correcto aquí.
 *
 * ── FUNCIONES LÓGICAS ──────────────────────────────────────────────────────
 * sigma*  = funciones de la expansión del schedule de mensaje (Wt).
 * Sigma*  = funciones de la compresión (sobre las variables de trabajo).
 * Ch/Maj  = elección / mayoría, idénticas en 32 y 64 bits (cambia el ancho).
 */

// ── Carga / almacenamiento big-endian ───────────────────────────────────────
// SHA-2 trabaja en big-endian; la memoria WASM es little-endian ⇒ bswap.

/**
 * sha2/common.ts — Endianness + funciones lógicas SHA-2 (FIPS 180-4). CANÓNICO.
//  * Todo // @inline → operaciones WASM nativas. bswap nativo (u32 y u64).
 */
// @ts-ignore
@inline
export function load32_be(ptr: usize): u32 {
  return bswap(load<u32>(ptr))
}
// @ts-ignore
@inline
export function store32_be(ptr: usize, u: u32): void {
  store<u32>(ptr, bswap(u))
}
// @ts-ignore
@inline
export function load64_be(ptr: usize): u64 {
  return bswap(load<u64>(ptr))
}
// @ts-ignore
@inline
export function store64_be(ptr: usize, u: u64): void {
  store<u64>(ptr, bswap(u))
}

// ── SHA-256 (u32) ──
// @ts-ignore
@inline
export function sigma0_256(x: u32): u32 {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}
// @ts-ignore
@inline
export function sigma1_256(x: u32): u32 {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}
// @ts-ignore
@inline
export function Sigma0_256(x: u32): u32 {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}
// @ts-ignore
@inline
export function Sigma1_256(x: u32): u32 {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}
// @ts-ignore
@inline
export function Ch32(x: u32, y: u32, z: u32): u32 {
  return z ^ (x & (y ^ z))
}
// @ts-ignore
@inline
export function Maj32(x: u32, y: u32, z: u32): u32 {
  return (x & y) ^ (z & (x ^ y))
}

// ── SHA-512 (u64) ──
// @ts-ignore
@inline
export function sigma0_512(x: u64): u64 {
  return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
}
// @ts-ignore
@inline
export function sigma1_512(x: u64): u64 {
  return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)
}
// @ts-ignore
@inline
export function Sigma0_512(x: u64): u64 {
  return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}
// @ts-ignore
@inline
export function Sigma1_512(x: u64): u64 {
  return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}
// @ts-ignore
@inline
export function Ch64(x: u64, y: u64, z: u64): u64 {
  return z ^ (x & (y ^ z))
}
// @ts-ignore
@inline
export function Maj64(x: u64, y: u64, z: u64): u64 {
  return (x & y) ^ (z & (x ^ y))
}
