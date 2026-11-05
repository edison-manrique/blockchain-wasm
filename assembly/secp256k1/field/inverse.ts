/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  field/inverse.ts — Inversa modular mod P (BEEA)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * modInverse: res = a⁻¹ mod P, vía Binary Extended Euclidean Algorithm (BEEA).
 * Usa la arena `Arena` para los 4 buffers de trabajo (u, v, x1, x2) y los
 * libera con save/restore al terminar (zero-alloc en el heap).
 *
 * ⚠️ SEGURIDAD: este BEEA NO es constant-time (los while-loops dependen de los
 * datos: paridad y comparación u/v). Es adecuado para inversas de coordenadas
 * Z (toAffine, batchNormalize), que son públicas. NO debe usarse para la inversa
 * del nonce k en ECDSA (ahí hace falta Bernstein–Yang o un BEEA de iters fijas).
 * TODO(security): reemplazar por inversa constant-time cuando se use en firmas.
 *
 * Lógica EXACTA del BigInt256.modInverse original.
 */
import { P0, P1, P2, P3 } from "../constants"
import { Arena } from "../../utils/arena"
import { isZero, shr1Raw, cmp, subRaw } from "./raw"
import { sub, addP_shr1 } from "./addsub"

/**
 * modInverse: res = a⁻¹ mod P. res = 0 si a == 0.
 */
export function modInverse(res: usize, a: usize): void {
  if (isZero(a)) {
    store<u64>(res, 0)
    store<u64>(res, 0, 8)
    store<u64>(res, 0, 16)
    store<u64>(res, 0, 24)
    return
  }

  const ctx = Arena.save()
  const u = Arena.alloc(32)
  const v = Arena.alloc(32)
  const x1 = Arena.alloc(32)
  const x2 = Arena.alloc(32)

  memory.copy(u, a, 32)
  store<u64>(v, P0)
  store<u64>(v, P1, 8)
  store<u64>(v, P2, 16)
  store<u64>(v, P3, 24)

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
        addP_shr1(x1)
      }
    }
    while ((load<u64>(v) & 1) == 0) {
      shr1Raw(v)
      if ((load<u64>(x2) & 1) == 0) {
        shr1Raw(x2)
      } else {
        addP_shr1(x2)
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
  Arena.restore(ctx)
}
