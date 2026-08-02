/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  scalar/inverse.ts — Inversa modular mod N (BEEA)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * modInverse: res = a⁻¹ mod N, vía Binary Extended Euclidean Algorithm.
 * Espejo de field/inverse.ts pero módulo N (usa addN_shr1 y sub mod N).
 *
 * ⚠️ SEGURIDAD: NO es constant-time (los while dependen de los datos). Adecuado
 * para inversas públicas. Para la inversa del nonce k en ECDSA hará falta una
 * versión constant-time (Bernstein–Yang). TODO(security).
 */
import { N0, N1, N2, N3 } from "../constants"
import { Memory } from "../../utils/memory"
import { isZero, shr1Raw, cmp, subRaw } from "../field/raw"
import { sub, addN_shr1 } from "./addsub"

/** modInverse: res = a⁻¹ mod N. res = 0 si a == 0. */
export function modInverse(res: usize, a: usize): void {
  if (isZero(a)) {
    store<u64>(res, 0)
    store<u64>(res, 0, 8)
    store<u64>(res, 0, 16)
    store<u64>(res, 0, 24)
    return
  }

  const ctx = Memory.save()
  const u = Memory.alloc(32)
  const v = Memory.alloc(32)
  const x1 = Memory.alloc(32)
  const x2 = Memory.alloc(32)

  memory.copy(u, a, 32)
  store<u64>(v, N0)
  store<u64>(v, N1, 8)
  store<u64>(v, N2, 16)
  store<u64>(v, N3, 24)

  store<u64>(x1, 1)
  store<u64>(x1, 0, 8)
  store<u64>(x1, 0, 16)
  store<u64>(x1, 0, 24)

  store<u64>(x2, 0)
  store<u64>(x2, 0, 8)
  store<u64>(x2, 0, 16)
  store<u64>(x2, 0, 24)

  while (!isZero(u)) {
    while ((load<u64>(u) & 1) == 0) {
      shr1Raw(u)
      if ((load<u64>(x1) & 1) == 0) {
        shr1Raw(x1)
      } else {
        addN_shr1(x1)
      }
    }
    while ((load<u64>(v) & 1) == 0) {
      shr1Raw(v)
      if ((load<u64>(x2) & 1) == 0) {
        shr1Raw(x2)
      } else {
        addN_shr1(x2)
      }
    }

    if (cmp(u, v) >= 0) {
      subRaw(u, u, v)
      sub(x1, x1, x2)
    } else {
      subRaw(v, v, u)
      sub(x2, x2, x1)
    }
  }

  memory.copy(res, x2, 32)
  Memory.restore(ctx)
}
