import { Memory } from "../utils/Memory"
import { BigInt256, Scalar256, GeneratorTable, Point } from "./utils"
import { Sha256 } from "../sha2/sha256"
import { keccak256 } from "../keccak256"

export enum SignatureFormat {
  Universal = 0,
  Bitcoin = 1,
  Ethereum = 2
}

const BITCOIN_PREFIX = String.UTF8.encode("\x18Bitcoin Signed Message:\n")
const ETHEREUM_PREFIX = String.UTF8.encode("\x19Ethereum Signed Message:\n")

export class EcdsaSignature {
  r: Uint8Array
  s: Uint8Array
  v: i32

  constructor(r: Uint8Array, s: Uint8Array, v: i32) {
    this.r = r
    this.s = s
    this.v = v
  }
}

export class ECDSA {
  /**
   * Sign a 32-byte message hash using the provided 32-byte private key.
   * Uses RFC 6979 for deterministic nonce generation.
   */
  static sign(hash: Uint8Array, privateKey: Uint8Array): EcdsaSignature {
    if (hash.length != 32 || privateKey.length != 32) {
      assert(false, "Invalid input length")
      return new EcdsaSignature(new Uint8Array(0), new Uint8Array(0), 0)
    }

    const ctx = Memory.save()

    // Allocate bigints
    const z = Memory.alloc(32)
    const d = Memory.alloc(32)
    const k = Memory.alloc(32)
    const r = Memory.alloc(32)
    const s = Memory.alloc(32)
    const k_inv = Memory.alloc(32)
    const rd = Memory.alloc(32)
    const z_rd = Memory.alloc(32)
    const R = Memory.alloc(96) // Point

    // Load inputs
    BigInt256.fromBytes(z, hash)
    BigInt256.fromBytes(d, privateKey)

    // Reduce z mod n
    reduceScalar(z)

    // RFC 6979 Generate K
    generateK_RFC6979(k, hash, privateKey)

    // R = k * G
    GeneratorTable.multiply(R, k)

    // Convert R to Affine X
    const R_z_temp = R + 64
    if (BigInt256.isZero(R_z_temp)) {
      Memory.restore(ctx)
      assert(false, "k*G resulted in infinity (bad k)")
      return new EcdsaSignature(new Uint8Array(0), new Uint8Array(0), 0)
    }

    const temp_z_inv = Memory.alloc(32)
    BigInt256.modInverse(temp_z_inv, R_z_temp)

    const temp_z_inv_2_red = Memory.alloc(32)
    BigInt256.sqrMod(temp_z_inv_2_red, temp_z_inv)

    BigInt256.mulMod(r, R, temp_z_inv_2_red)

    // r = r mod n
    reduceScalar(r)

    if (Scalar256.isZero(r)) {
      Memory.restore(ctx)
      assert(false, "Signature r is zero")
      return new EcdsaSignature(new Uint8Array(0), new Uint8Array(0), 0)
    }

    // s = k^-1 * (z + r * d) mod n
    // k_inv = k^-1 mod N
    Scalar256.modInverse(k_inv, k)

    // rd = r * d mod n
    Scalar256.mul(rd, r, d)

    // z + rd
    Scalar256.add(z_rd, z, rd)

    // s = k_inv * (z + rd)
    Scalar256.mul(s, k_inv, z_rd)

    if (Scalar256.isZero(s)) {
      Memory.restore(ctx)
      assert(false, "Signature s is zero")
      return new EcdsaSignature(new Uint8Array(0), new Uint8Array(0), 0)
    }

    // Canonical S (BIP-62): if s > N/2, s = N - s
    // N_HALF = 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    const n_half = Memory.alloc(32)
    store<u64>(n_half, 0xdfe92f46681b20a0, 0)
    store<u64>(n_half, 0x5d576e7357a4501d, 8)
    store<u64>(n_half, 0xffffffffffffffff, 16)
    store<u64>(n_half, 0x7fffffffffffffff, 24)

    let recId = 0
    // Check parity of Y for recovery ID
    // We must normalize R to Affine to get RecId.

    // Normalize R.z
    const z_inv = Memory.alloc(32)
    const R_z = R + 64
    if (BigInt256.isZero(R_z)) {
      assert(false, "R is infinity")
      return new EcdsaSignature(new Uint8Array(0), new Uint8Array(0), 0)
    }

    // We only need parity of Y_aff.
    // Y_aff = Y * Z^-3.
    // Z^-1.
    BigInt256.modInverse(z_inv, R_z)

    // Z^-2
    const z_inv_2_red = Memory.alloc(32)
    BigInt256.sqrMod(z_inv_2_red, z_inv)

    // Z^-3
    const z_inv_3 = Memory.alloc(32)
    BigInt256.mulMod(z_inv_3, z_inv_2_red, z_inv)

    // Y_aff = Y * Z^-3
    const y_aff = Memory.alloc(32)
    BigInt256.mulMod(y_aff, R + 32, z_inv_3)

    // Check parity
    const isOddY = (load<u64>(y_aff, 0) & 1) != 0
    if (isOddY) {
      recId |= 1
    }

    if (Scalar256.isGreaterOrEqual(s, n_half)) {
      // s = N - s
      const n = Memory.alloc(32)
      store<u64>(n, Scalar256.N0, 0)
      store<u64>(n, Scalar256.N1, 8)
      store<u64>(n, Scalar256.N2, 16)
      store<u64>(n, Scalar256.N3, 24)
      Scalar256.subRaw(s, n, s)

      recId ^= 1
    }

    // Output
    const rBytes = new Uint8Array(32)
    const sBytes = new Uint8Array(32)
    BigInt256.toBytes(r, rBytes)
    BigInt256.toBytes(s, sBytes)

    Memory.restore(ctx)

    return new EcdsaSignature(rBytes, sBytes, recId)
  }

  static verify(hash: Uint8Array, signature: EcdsaSignature, publicKey: Uint8Array): bool {
    const ctx = Memory.save()

    // 1. Check input lengths
    if (hash.length != 32 || signature.r.length != 32 || signature.s.length != 32) {
      Memory.restore(ctx)
      return false
    }

    // 2. Load r, s
    const r = Memory.alloc(32)
    const s = Memory.alloc(32)
    const z = Memory.alloc(32)

    BigInt256.fromBytes(r, signature.r)
    BigInt256.fromBytes(s, signature.s)
    BigInt256.fromBytes(z, hash)

    reduceScalar(z) // z = hash mod N

    // Check r, s range [1, N-1]
    if (
      Scalar256.isZero(r) ||
      Scalar256.isGreaterOrEqualN(r) ||
      Scalar256.isZero(s) ||
      Scalar256.isGreaterOrEqualN(s)
    ) {
      Memory.restore(ctx)
      return false
    }

    // 3. Load Public Key (uncompressed only for now)
    if (publicKey.length != 65 || publicKey[0] != 0x04) {
      // TODO: Support compressed keys (needs sqrt mod P)
      Memory.restore(ctx)
      return false
    }

    const Q = Memory.alloc(96)
    const Q_x = Memory.alloc(32)
    const Q_y = Memory.alloc(32)
    const Q_z = Memory.alloc(32)

    BigInt256.fromBytes(Q_x, publicKey.subarray(1, 33))
    BigInt256.fromBytes(Q_y, publicKey.subarray(33, 65))

    // Set Z=1
    store<u64>(Q_z, 1, 0)
    store<u64>(Q_z, 0, 8)
    store<u64>(Q_z, 0, 16)
    store<u64>(Q_z, 0, 24)

    memory.copy(Q, Q_x, 32)
    memory.copy(Q + 32, Q_y, 32)
    memory.copy(Q + 64, Q_z, 32)

    // 4. Calculate s_inv = s^-1 mod N
    const s_inv = Memory.alloc(32)
    Scalar256.modInverse(s_inv, s)

    // 5. u1 = z * s_inv mod N
    const u1 = Memory.alloc(32)
    Scalar256.mul(u1, z, s_inv)

    // 6. u2 = r * s_inv mod N
    const u2 = Memory.alloc(32)
    Scalar256.mul(u2, r, s_inv)

    // 7. R = u1*G + u2*Q
    // We need simultaneous multiply or just two muls and add.
    // ScalarMul.multiply is k*P.

    const P1 = Memory.alloc(96)
    const P2 = Memory.alloc(96)

    // P1 = u1 * G
    GeneratorTable.multiply(P1, u1)

    // P2 = u2 * Q
    Scalar256.multiplyGLV(P2, Q, u2)

    // R = P1 + P2
    const R = Memory.alloc(96)
    Point.add(R, P1, P2)

    if (Point.isInfinity(R)) {
      Memory.restore(ctx)
      return false
    }

    // 8. v = R.x mod N
    // R is Jacobian (X, Y, Z). We need affine X.
    // X_aff = X / Z^2 mod P
    // ... same as in ECDH or sign ...
    // We use the same Z^-2 logic.

    const R_z = R + 64
    const z_inv = Memory.alloc(32)
    BigInt256.modInverse(z_inv, R_z) // mod P inversion

    const z_inv_2_red = Memory.alloc(32)
    BigInt256.sqrMod(z_inv_2_red, z_inv)

    const x_aff = Memory.alloc(32)
    BigInt256.mulMod(x_aff, R, z_inv_2_red) // R points to X

    // v = x_aff mod N
    // x_aff is mod P. P ~ N.
    // If x_aff >= N, sub N.
    reduceScalar(x_aff)

    // 9. compare v == r
    const equal = Scalar256.isGreaterOrEqual(x_aff, r) && Scalar256.isGreaterOrEqual(r, x_aff)

    Memory.restore(ctx)
    return equal
  }
}

// Helpers

function reduceScalar(a: usize): void {
  // Check if >= N
  while (Scalar256.isGreaterOrEqualN(a)) {
    Scalar256.subN(a, a)
  }
}

function generateK_RFC6979(k_out: usize, hash: Uint8Array, privKey: Uint8Array): void {
  // HMAC-DRBG using raw pointers for zero allocation 100%
  const K = Memory.alloc(32)
  const V = Memory.alloc(32)

  for (let i = 0; i < 32; i += 8) {
    store<u64>(V + i, 0x0101010101010101)
    store<u64>(K + i, 0)
  }

  // Input = V || 0x00 || privKey || hash
  const blob = Memory.alloc(97)
  memory.copy(blob, V, 32)
  store<u8>(blob + 32, 0x00)
  memory.copy(blob + 33, privKey.dataStart, 32)
  memory.copy(blob + 65, hash.dataStart, 32)

  // K = HMAC(blob, K)  -> Sha256.hmac_ptr(outPtr, kPtr, kLen, mPtr, mLen)
  Sha256.hmac_ptr(K, K, 32, blob, 97)
  // V = HMAC(V, K)
  Sha256.hmac_ptr(V, K, 32, V, 32)

  // Input = V || 0x01 || privKey || hash (already set)
  memory.copy(blob, V, 32)
  store<u8>(blob + 32, 0x01)

  Sha256.hmac_ptr(K, K, 32, blob, 97)
  Sha256.hmac_ptr(V, K, 32, V, 32)

  const blob2 = Memory.alloc(33)

  while (true) {
    // V = HMAC(V, K)
    Sha256.hmac_ptr(V, K, 32, V, 32)

    // Check if k valid (0 < k < N)
    // load to big endian for BigInt processing
    store<u64>(k_out, bswap(load<u64>(V + 24)), 0)
    store<u64>(k_out, bswap(load<u64>(V + 16)), 8)
    store<u64>(k_out, bswap(load<u64>(V + 8)), 16)
    store<u64>(k_out, bswap(load<u64>(V + 0)), 24)

    if (!Scalar256.isZero(k_out) && !Scalar256.isGreaterOrEqualN(k_out)) {
      return // Valid k found
    }

    // K = HMAC(V || 0x00, K)
    memory.copy(blob2, V, 32)
    store<u8>(blob2 + 32, 0x00)

    Sha256.hmac_ptr(K, K, 32, blob2, 33)
    Sha256.hmac_ptr(V, K, 32, V, 32)
  }
}

/**
 * Creates a message hash based on the given format.
 * - Universal: Single SHA-256 of the UTF-8 message.
 * - Bitcoin: Double SHA-256 of "\x18Bitcoin Signed Message:\n" + varint(len) + message.
 * - Ethereum: Keccak-256 of "\x19Ethereum Signed Message:\n" + len + message.
 */
export function getMessageHash(message: string, format: SignatureFormat = SignatureFormat.Universal): Uint8Array {
  const msgBytes = String.UTF8.encode(message)
  const msgLen = msgBytes.byteLength
  const mbuf = Uint8Array.wrap(msgBytes)

  if (format == SignatureFormat.Bitcoin) {
    let prefixLen = 1
    if (msgLen >= 0xfd && msgLen <= 0xffff) {
      prefixLen = 3
    } else if (msgLen > 0xffff) {
      prefixLen = 5
    }

    const pbuf = Uint8Array.wrap(BITCOIN_PREFIX)
    const buffer = new Uint8Array(pbuf.length + prefixLen + msgLen)

    let offset = 0
    memory.copy(buffer.dataStart, pbuf.dataStart, pbuf.length)
    offset += pbuf.length

    if (msgLen < 0xfd) {
      buffer[offset++] = <u8>msgLen
    } else if (msgLen <= 0xffff) {
      buffer[offset++] = 0xfd
      buffer[offset++] = <u8>(msgLen & 0xff)
      buffer[offset++] = <u8>((msgLen >> 8) & 0xff)
    } else {
      buffer[offset++] = 0xfe
      buffer[offset++] = <u8>(msgLen & 0xff)
      buffer[offset++] = <u8>((msgLen >> 8) & 0xff)
      buffer[offset++] = <u8>((msgLen >> 16) & 0xff)
      buffer[offset++] = <u8>((msgLen >> 24) & 0xff)
    }

    memory.copy(buffer.dataStart + offset, mbuf.dataStart, mbuf.length)

    const hash1 = Sha256.hash(buffer)
    return Sha256.hash(hash1)
  }

  if (format == SignatureFormat.Ethereum) {
    let temp = msgLen
    let lenStrLength = 0
    if (temp == 0) {
      lenStrLength = 1
    } else {
      while (temp > 0) {
        lenStrLength++
        temp /= 10
      }
    }

    const pbuf = Uint8Array.wrap(ETHEREUM_PREFIX)
    const buffer = new Uint8Array(pbuf.length + lenStrLength + mbuf.length)

    memory.copy(buffer.dataStart, pbuf.dataStart, pbuf.length)

    temp = msgLen
    let offset = pbuf.length + lenStrLength
    if (temp == 0) {
      buffer[offset - 1] = 48 // '0'
    } else {
      while (temp > 0) {
        buffer[--offset] = <u8>(48 + (temp % 10))
        temp /= 10
      }
    }

    memory.copy(buffer.dataStart + pbuf.length + lenStrLength, mbuf.dataStart, mbuf.length)

    return keccak256(buffer)
  }

  // Universal fallback
  return Sha256.hash(mbuf)
}

/**
 * Sign a text message using the specified message protocol format.
 */
export function signMessage(
  message: string,
  privateKey: Uint8Array,
  format: SignatureFormat = SignatureFormat.Universal
): EcdsaSignature {
  const hash = getMessageHash(message, format)
  return ECDSA.sign(hash, privateKey)
}

/**
 * Verify a text message using the specified message protocol format.
 */
export function verifyMessage(
  message: string,
  sig: EcdsaSignature,
  publicKey: Uint8Array,
  format: SignatureFormat = SignatureFormat.Universal
): bool {
  const hash = getMessageHash(message, format)
  return ECDSA.verify(hash, sig, publicKey)
}
