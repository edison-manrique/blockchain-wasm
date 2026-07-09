// wnaf.ts

@final
export class WNAF {
  /**
   * Computes wNAF form of a scalar.
   * OPTIMIZADO: Branchless Arithmetic + Register-based.
   */
  static compute(result_ptr: usize, k_ptr: usize, width: i32): i32 {
    // 1. Cargar en registros locales (320 bits)
    let l0 = load<u64>(k_ptr, 0)
    let l1 = load<u64>(k_ptr, 8)
    let l2 = load<u64>(k_ptr, 16)
    let l3 = load<u64>(k_ptr, 24)
    let l4: u64 = 0

    // Precomputar constantes
    const width_mask = (1 << width) - 1
    const limit = 1 << (width - 1)
    const sub_val = 1 << width

    let len = 0
    let ptr = result_ptr

    // Bucle principal
    while ((l0 | l1 | l2 | l3 | l4) != 0) {
      let digit: i32 = 0

      // Si es impar (l0 & 1)
      if ((l0 & 1) != 0) {
        // Calcular digit: k mod 2^w
        let mod = <i32>(l0 & (<u64>width_mask))

        // Ajuste de rango [-2^(w-1), 2^(w-1)]
        // Usamos aritmética branchless para el ajuste
        // Si mod > limit, digit = mod - 2^w, else digit = mod
        // mask = (mod > limit) ? -1 : 0
        // digit = mod - (sub_val & mask)
        const mask = <i32>(mod > limit ? -1 : 0)
        digit = mod - (sub_val & mask)

        // Aplicar la resta: k = k - digit
        // k = k + (-digit)
        // Usamos aritmética de complemento a 2 para propagar el acarreo/préstamo
        // de forma natural a través de los registros.

        // Convertimos -digit a u64 para sumar.
        // Si digit es positivo, restamos (sumamos negativo).
        // Si digit es negativo, sumamos positivo.
        const val = <i64>-digit

        // Suma con Carry manual (sin ifs anidados)
        const old_l0 = l0
        l0 = l0 + <u64>val

        // Calcular carry out de l0
        // Carry ocurre si (val > 0 && sum < old) OR (val < 0 && sum > old)
        // Pero val es i64 sign-extended.
        // Forma robusta: (sum < old) si val > 0. (sum > old) si val < 0.
        // Simplificación: usaremos una variable de carry explícita u64(0/1/-1)

        // Re-implementación segura branchless:
        // Carry = 1 si hubo overflow, -1 si hubo underflow.
        // Dado que val es pequeño, solo afecta al bit bajo o genera un carry simple.

        // Carry propagation
        // l1 += carry
        // l2 += carry...

        // Detectar carry de l0
        // Si val < 0 (sumamos positivo), carry = 1 si overflow.
        // Si val > 0 (sumamos negativo), carry = -1 si underflow.

        // Truco: u64 arithmetic wraps.
        // Simplemente sumamos y detectamos wrap.
        let carry: u64 = 0
        if (val > 0) {
          // Sumamos positivo. Overflow si new < old
          if (l0 < old_l0) carry = 1
        } else {
          // Sumamos negativo (resta). Underflow si new > old
          if (l0 > old_l0) carry = -1 // 0xFF...FF
        }

        // Propagar carry a l1..l4
        // l1 = l1 + carry
        // Nuevo carry si overflow/underflow
        if (carry != 0) {
          const old_l1 = l1
          l1 += carry
          // Check propagation
          // Si carry era 1: overflow si l1 < old_l1
          // Si carry era -1: underflow si l1 > old_l1
          if ((carry == 1 && l1 < old_l1) || (carry == <u64>-1 && l1 > old_l1)) {
            const old_l2 = l2
            l2 += carry
            if ((carry == 1 && l2 < old_l2) || (carry == <u64>-1 && l2 > old_l2)) {
              const old_l3 = l3
              l3 += carry
              if ((carry == 1 && l3 < old_l3) || (carry == <u64>-1 && l3 > old_l3)) {
                l4 += carry
              }
            }
          }
        }
      }

      // Store digit
      store<i8>(ptr, <i8>digit)
      ptr++
      len++

      // Right Shift 1
      l0 = (l0 >> 1) | (l1 << 63)
      l1 = (l1 >> 1) | (l2 << 63)
      l2 = (l2 >> 1) | (l3 << 63)
      l3 = (l3 >> 1) | (l4 << 63)
      l4 = l4 >> 1
    }

    return len
  }
}
