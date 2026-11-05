/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  scalar/reduce.ts — Reducción 512 → 256 bits (mod N)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * A diferencia de field/reduce.ts (donde C_FIELD = 2^32+977 es pequeño y admite
 * el truco de registros), aquí C_SCALAR = 2^256 − N tiene 129 bits. Por eso la
 * reducción es ITERATIVA:
 *
 *   x = L + H·2^256  ≡  L + H·C  (mod N)
 *
 * Cada pasada reemplaza H por los limbs altos de H·C (que se van reduciendo:
 * 256→129→~2 bits). Con 3 pasadas converge siempre. Al final, si res ≥ N, se
 * resta N hasta normalizar (máx. unas pocas restas).
 *
 * Zero-alloc: usa la arena Arena (save/restore).
 */
import { CN0, CN1, CN2, CN3 } from "../constants"
import { mul } from "../field/mul"
import { addRaw, isZero } from "../field/raw"
import { subN, isGreaterOrEqualN } from "./addsub"
import { Arena } from "../../utils/arena"

/** reduce: res (32 B) = a (64 B, 512 bits) mod N. */
export function reduce(res: usize, a: usize): void {
  const ctx = Arena.save()
  const h = Arena.alloc(32) // limbs altos en reducción progresiva
  const c = Arena.alloc(32) // C_SCALAR
  const hc = Arena.alloc(64) // h · C (512 bits)

  // res = L (limbs bajos)
  store<u64>(res, load<u64>(a))
  store<u64>(res, load<u64>(a, 8), 8)
  store<u64>(res, load<u64>(a, 16), 16)
  store<u64>(res, load<u64>(a, 24), 24)

  // h = H (limbs altos)
  store<u64>(h, load<u64>(a, 32))
  store<u64>(h, load<u64>(a, 40), 8)
  store<u64>(h, load<u64>(a, 48), 16)
  store<u64>(h, load<u64>(a, 56), 24)

  // c = C_SCALAR
  store<u64>(c, CN0)
  store<u64>(c, CN1, 8)
  store<u64>(c, CN2, 16)
  store<u64>(c, CN3, 24)

  for (let i = 0; i < 3; i++) {
    if (isZero(h)) break
    mul(hc, h, c) // hc = h · C  (512 bits)
    const carry = addRaw(res, res, hc) // res += limbs bajos de hc
    // h ← limbs altos de hc + carry
    let hh0 = load<u64>(hc, 32)
    let hh1 = load<u64>(hc, 40)
    let hh2 = load<u64>(hc, 48)
    let hh3 = load<u64>(hc, 56)
    if (carry > 0) {
      hh0 += 1
      if (hh0 == 0) {
        hh1 += 1
        if (hh1 == 0) {
          hh2 += 1
          if (hh2 == 0) hh3 += 1
        }
      }
    }
    store<u64>(h, hh0)
    store<u64>(h, hh1, 8)
    store<u64>(h, hh2, 16)
    store<u64>(h, hh3, 24)
  }

  // Normalización final: res < N
  while (isGreaterOrEqualN(res)) subN(res, res)

  Arena.restore(ctx)
}
