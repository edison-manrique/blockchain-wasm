/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  scalar/mulmod.ts — Multiplicación / squaring mod N
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * mulMod / sqrMod = mul/sqr (256×256 → 512 bits, reusado de field/mul) seguido
 * de reduce mod N. NO es fused: C_SCALAR es grande (129 bits) y la reducción
 * necesita el producto completo en memoria. Scalar se usa poco (GLV, ECDSA),
 * así que prima la claridad/seguridad sobre el último ciclo.
 *
 * Zero-alloc: buffer de 512 bits en la arena (save/restore).
 */
import { mul, sqr } from "../field/mul"
import { reduce } from "./reduce"
import { Memory } from "../../utils/memory"

/** mulMod: res = (a · b) mod N. */
export function mulMod(res: usize, a: usize, b: usize): void {
  const ctx = Memory.save()
  const wide = Memory.alloc(64)
  mul(wide, a, b)
  reduce(res, wide)
  Memory.restore(ctx)
}

/** sqrMod: res = (a²) mod N. */
export function sqrMod(res: usize, a: usize): void {
  const ctx = Memory.save()
  const wide = Memory.alloc(64)
  sqr(wide, a)
  reduce(res, wide)
  Memory.restore(ctx)
}
