import { Memory } from "../utils/Memory"
import { BigInt256, Scalar256 } from "./utils"

export class ECDH {
  /**
   * Compute shared secret from private key (32 bytes) and public key (65 bytes uncompressed).
   * Returns 33-byte compressed shared secret (02/03 + X).
   */
  static sharedSecret(privKey: Uint8Array, pubKey: Uint8Array): Uint8Array {
    if (privKey.length != 32) {
      assert(false, "Invalid private key length")
      return new Uint8Array(0)
    }
    if (pubKey.length != 65) {
      assert(false, "Public key must be uncompressed (65 bytes)")
      return new Uint8Array(0)
    }
    if (pubKey[0] != 0x04) {
      assert(false, "Invalid public key format")
      return new Uint8Array(0)
    }

    const ctx = Memory.save()

    // 1. Load Private Key (scalar)
    const d = Memory.alloc(32)
    BigInt256.fromBytes(d, privKey)

    // 2. Load Public Key (point)
    // pubKey[1..33] -> X, pubKey[33..65] -> Y
    const Q = Memory.alloc(96)
    const Q_x = Memory.alloc(32)
    const Q_y = Memory.alloc(32)
    const Q_z = Memory.alloc(32)

    // Parse X (bytes 1..33)
    // AS doesn't have slice on generic array in a way that BigInt256.fromBytes accepts?
    // BigInt256.fromBytes takes Uint8Array. subarray returns Uint8Array.
    const xBytes = pubKey.subarray(1, 33)
    const yBytes = pubKey.subarray(33, 65)

    BigInt256.fromBytes(Q_x, xBytes)
    BigInt256.fromBytes(Q_y, yBytes)

    // Set Z = 1
    store<u64>(Q_z, 1, 0)
    store<u64>(Q_z, 0, 8)
    store<u64>(Q_z, 0, 16)
    store<u64>(Q_z, 0, 24)

    memory.copy(Q, Q_x, 32)
    memory.copy(Q + 32, Q_y, 32)
    memory.copy(Q + 64, Q_z, 32)

    // 3. Compute P = d * Q
    const P = Memory.alloc(96)
    Scalar256.multiplyGLV(P, Q, d)

    // 4. Normalize P (Jacobian -> Affine)
    // P = (X, Y, Z). Affine x = X / Z^2 mod P.
    const z_ptr = P + 64

    if (BigInt256.isZero(z_ptr)) {
      Memory.restore(ctx)
      assert(false, "Result is infinity")
      return new Uint8Array(0)
    }

    // Check if Z=1 (optimization)
    const z_inv = Memory.alloc(32)
    if (
      load<u64>(z_ptr, 0) == 1 &&
      load<u64>(z_ptr, 8) == 0 &&
      load<u64>(z_ptr, 16) == 0 &&
      load<u64>(z_ptr, 24) == 0
    ) {
      // Z=1, Z^-1 = 1
      store<u64>(z_inv, 1, 0)
      store<u64>(z_inv, 0, 8)
      store<u64>(z_inv, 0, 16)
      store<u64>(z_inv, 0, 24)
    } else {
      BigInt256.modInverse(z_inv, z_ptr)
    }

    // z_inv_2 = z_inv^2
    const z_inv_2_red = Memory.alloc(32)
    BigInt256.sqrMod(z_inv_2_red, z_inv)

    // x_aff = X * z_inv^2
    const x_aff = Memory.alloc(32)
    BigInt256.mulMod(x_aff, P, z_inv_2_red) // P points to X

    // Need Y for parity byte. y_aff = Y * z_inv^3
    const z_inv_3 = Memory.alloc(32)
    BigInt256.mulMod(z_inv_3, z_inv_2_red, z_inv)

    const y_aff = Memory.alloc(32)
    BigInt256.mulMod(y_aff, P + 32, z_inv_3) // P+32 is Y

    // Serialize
    const out = new Uint8Array(33)
    // LSB of y_aff determines 0x02 or 0x03
    const y_lsb = load<u64>(y_aff, 0) & 1
    out[0] = y_lsb ? 0x03 : 0x02

    BigInt256.toBytes(x_aff, out.subarray(1, 33))

    Memory.restore(ctx)
    return out
  }
}
