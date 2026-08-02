/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  wnaf/wnaf.ts — Width-w Non-Adjacent Form de un escalar
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * compute: escribe los dígitos wNAF (i8, valor en [−2^(w−1), 2^(w−1)]) en
 * `result`, de menos a más significativo, y devuelve la longitud.
 *
 * Puro: trabaja solo con registros locales (5 limbs = 320 bits para absorber
 * el carry). Cero alloc, cero memoria global.
 */

/**
 * wNAF de un escalar de 256 bits.
 * @param result buffer de i8 (≥ 258 bytes)
 * @param k      escalar (32 B, little-endian limbs)
 * @param width  ventana w (típicamente 5)
 * @returns longitud del wNAF (nº de dígitos)
 */
export function compute(result: usize, k: usize, width: i32): i32 {
  let l0 = load<u64>(k)
  let l1 = load<u64>(k, 8)
  let l2 = load<u64>(k, 16)
  let l3 = load<u64>(k, 24)
  let l4: u64 = 0 // limb de guardia para el carry

  const width_mask = <u64>((1 << width) - 1)
  const limit = 1 << (width - 1) // 2^(w−1)
  const sub_val = 1 << width     // 2^w

  let len = 0
  let ptr = result

  while ((l0 | l1 | l2 | l3 | l4) != 0) {
    let digit: i32 = 0

    if ((l0 & 1) != 0) {
      // digit = k mod 2^w, re-centrado a [−limit, limit)
      const mod = <i32>(l0 & width_mask)
      digit = mod > limit ? mod - sub_val : mod

      // k ← k − digit  (digit puede ser negativo ⇒ suma de |digit|)
      // El carry es uniforme: −1 si digit>0 (resta), +1 si digit<0 (suma).
      const neg: u64 = digit < 0 ? 1 : 0 // +1
      const val: u64 = digit < 0 ? <u64>(-digit) : <u64>digit
      const carry: u64 = digit < 0 ? neg : 0 - neg // +1 o 0xFF..FF

      const o0 = l0
      l0 = digit < 0 ? l0 + val : l0 - val
      let c: u64 = digit < 0 ? u64(l0 < o0) : u64(l0 > o0)
      if (c != 0) {
        const o1 = l1
        l1 += carry
        c = digit < 0 ? u64(l1 < o1) : u64(l1 > o1)
        if (c != 0) {
          const o2 = l2
          l2 += carry
          c = digit < 0 ? u64(l2 < o2) : u64(l2 > o2)
          if (c != 0) {
            const o3 = l3
            l3 += carry
            c = digit < 0 ? u64(l3 < o3) : u64(l3 > o3)
            if (c != 0) l4 += carry
          }
        }
      }
    }

    store<i8>(ptr, <i8>digit)
    ptr++
    len++

    // shift right 1 (lógico, 320 bits)
    l0 = (l0 >> 1) | (l1 << 63)
    l1 = (l1 >> 1) | (l2 << 63)
    l2 = (l2 >> 1) | (l3 << 63)
    l3 = (l3 >> 1) | (l4 << 63)
    l4 = l4 >> 1
  }

  return len
}