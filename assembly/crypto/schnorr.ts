import { BigInt256, Scalar256, Point } from "./utils"
import { Internal, Sha256 } from "../sha2/sha256"
import { Memory } from "../utils/Memory"

class TagHashes {
  static aux: Uint8Array | null = null
  static nonce: Uint8Array | null = null
  static challenge: Uint8Array | null = null
}

function getTagHash(tag: string): usize {
  if (tag == "aux") {
    if (TagHashes.aux == null) TagHashes.aux = Sha256.hash(Uint8Array.wrap(String.UTF8.encode("BIP0340/aux")))
    return TagHashes.aux!.dataStart
  } else if (tag == "nonce") {
    if (TagHashes.nonce == null) TagHashes.nonce = Sha256.hash(Uint8Array.wrap(String.UTF8.encode("BIP0340/nonce")))
    return TagHashes.nonce!.dataStart
  } else if (tag == "challenge") {
    if (TagHashes.challenge == null)
      TagHashes.challenge = Sha256.hash(Uint8Array.wrap(String.UTF8.encode("BIP0340/challenge")))
    return TagHashes.challenge!.dataStart
  }
  return 0
}

function taggedHashRaw(
  tag: string,
  out: usize,
  m1: usize,
  len1: isize,
  m2: usize = 0,
  len2: isize = 0,
  m3: usize = 0,
  len3: isize = 0
): void {
  const tagH = getTagHash(tag)
  const scratch = Sha256.__SCRATCH
  const st = scratch + 128
  const padded = scratch + 224

  Internal._hashInit_ptr(st)
  let r = Internal._hashUpdate_ptr(st, tagH, 32, 0)
  r = Internal._hashUpdate_ptr(st, tagH, 32, r)
  r = Internal._hashUpdate_ptr(st, m1, len1, r)
  if (len2 > 0) r = Internal._hashUpdate_ptr(st, m2, len2, r)
  if (len3 > 0) r = Internal._hashUpdate_ptr(st, m3, len3, r)
  Internal._hashFinal_ptr(st, padded, out, 32 + 32 + len1 + len2 + len3, r)
}

function bytesModN(res: usize, bytes: Uint8Array): void {
  BigInt256.fromBytes(res, bytes)
  while (Scalar256.isGreaterOrEqualN(res)) {
    Scalar256.subN(res, res)
  }
}

function ptrModN(res: usize, ptr: usize): void {
  store<u64>(res + 24, bswap(load<u64>(ptr)))
  store<u64>(res + 16, bswap(load<u64>(ptr + 8)))
  store<u64>(res + 8, bswap(load<u64>(ptr + 16)))
  store<u64>(res + 0, bswap(load<u64>(ptr + 24)))
  while (Scalar256.isGreaterOrEqualN(res)) {
    Scalar256.subN(res, res)
  }
}

class ExtPub {
  dBytes: Uint8Array
  pxBytes: Uint8Array
  constructor(dBytes: Uint8Array, pxBytes: Uint8Array) {
    this.dBytes = dBytes
    this.pxBytes = pxBytes
  }
}

/**
 * Lifts an X coordinate (32 bytes pointer) to a Point P.
 * Returns true if successful, false if the point is invalid.
 */
function liftX(P: usize, px: usize): bool {
  // c = x^3 + 7 mod P
  const c = Memory.alloc(32)
  BigInt256.sqrMod(c, px)
  BigInt256.mulMod(c, c, px)
  const seven = Memory.alloc(32)
  store<u64>(seven, 7, 0)
  store<u64>(seven, 0, 8)
  store<u64>(seven, 0, 16)
  store<u64>(seven, 0, 24)
  BigInt256.add(c, c, seven)

  // y = c^((p+1)/4) mod P
  const exp = Memory.alloc(32)
  store<u64>(exp, 0xffffffffbfffff0c, 0)
  store<u64>(exp, 0xffffffffffffffff, 8)
  store<u64>(exp, 0xffffffffffffffff, 16)
  store<u64>(exp, 0x3fffffffffffffff, 24)

  const base = Memory.alloc(32)
  memory.copy(base, c, 32)

  const py = Memory.alloc(32)
  store<u64>(py, 1, 0)
  store<u64>(py, 0, 8)
  store<u64>(py, 0, 16)
  store<u64>(py, 0, 24)

  for (let bit = 0; bit < 256; bit++) {
    const wordIdx = bit >> 6
    const bitIdx = bit & 63
    const word = load<u64>(exp + (wordIdx << 3))
    if ((word >> bitIdx) & 1) {
      BigInt256.mulMod(py, py, base)
    }
    BigInt256.sqrMod(base, base)
  }

  const ySq = Memory.alloc(32)
  BigInt256.sqrMod(ySq, py)
  if (memory.compare(ySq, c, 32) != 0) {
    return false // sqrt invalid
  }

  // If y mod 2 = 1, y = P - y
  if ((load<u64>(py, 0) & 1) != 0) {
    const pPrime = Memory.alloc(32)
    store<u64>(pPrime, BigInt256.P0, 0)
    store<u64>(pPrime, BigInt256.P1, 8)
    store<u64>(pPrime, BigInt256.P2, 16)
    store<u64>(pPrime, BigInt256.P3, 24)
    BigInt256.sub(py, pPrime, py)
  }

  memory.copy(P, px, 32)
  memory.copy(P + 32, py, 32)
  store<u64>(P + 64, 1, 0)
  store<u64>(P + 64, 0, 8)
  store<u64>(P + 64, 0, 16)
  store<u64>(P + 64, 0, 24)

  return true
}

function extpubSchnorr(priv: Uint8Array): ExtPub {
  const ctx = Memory.save()
  const d_ = Memory.alloc(32)
  BigInt256.fromBytes(d_, priv)

  const p = Memory.alloc(96)
  Scalar256.multiplyG(p, d_)
  Point.toAffine(p, p)

  const yIsEven = (load<u64>(p + 32, 0) & 1) == 0

  const d = Memory.alloc(32)
  if (yIsEven) {
    memory.copy(d, d_, 32)
  } else {
    store<u64>(d, Scalar256.N0, 0)
    store<u64>(d, Scalar256.N1, 8)
    store<u64>(d, Scalar256.N2, 16)
    store<u64>(d, Scalar256.N3, 24)
    Scalar256.sub(d, d, d_)
  }

  const px = new Uint8Array(32)
  BigInt256.toBytes(p, px)

  const dBytes = new Uint8Array(32)
  BigInt256.toBytes(d, dBytes)

  Memory.restore(ctx)
  return new ExtPub(dBytes, px)
}

/**
 * Schnorr public key wrapper
 */
export function getSchnorrPublicKey(privateKey: Uint8Array): Uint8Array {
  const ext = extpubSchnorr(privateKey)
  return ext.pxBytes
}

/**
 * Sign a message using Schnorr (BIP340).
 */
export function signSchnorr(message: Uint8Array, privateKey: Uint8Array, auxRand: Uint8Array): Uint8Array {
  const ctx = Memory.save()

  // 1. Get Public Key properties (dVal, pxBytes)
  const d_ = Memory.alloc(32)
  BigInt256.fromBytes(d_, privateKey)

  const Pub = Memory.alloc(96)
  Scalar256.multiplyG(Pub, d_)
  Point.toAffine(Pub, Pub)

  const yIsEven = (load<u64>(Pub + 32, 0) & 1) == 0

  const dVal = Memory.alloc(32)
  if (yIsEven) {
    memory.copy(dVal, d_, 32)
  } else {
    const N = Memory.alloc(32)
    store<u64>(N, Scalar256.N0, 0)
    store<u64>(N, Scalar256.N1, 8)
    store<u64>(N, Scalar256.N2, 16)
    store<u64>(N, Scalar256.N3, 24)
    Scalar256.sub(dVal, N, d_)
  }

  const pxPtr = Memory.alloc(32)
  store<u64>(pxPtr, bswap(load<u64>(Pub + 24)))
  store<u64>(pxPtr + 8, bswap(load<u64>(Pub + 16)))
  store<u64>(pxPtr + 16, bswap(load<u64>(Pub + 8)))
  store<u64>(pxPtr + 24, bswap(load<u64>(Pub + 0)))

  const dPtr = Memory.alloc(32)
  store<u64>(dPtr, bswap(load<u64>(dVal + 24)))
  store<u64>(dPtr + 8, bswap(load<u64>(dVal + 16)))
  store<u64>(dPtr + 16, bswap(load<u64>(dVal + 8)))
  store<u64>(dPtr + 24, bswap(load<u64>(dVal + 0)))

  // 2. Aux & Nonce
  const aux = Memory.alloc(32)
  taggedHashRaw("aux", aux, auxRand.dataStart, auxRand.byteLength)

  const tPtr = Memory.alloc(32)
  for (let i = 0; i < 32; i++) {
    store<u8>(tPtr + i, load<u8>(dPtr + i) ^ load<u8>(aux + i))
  }

  const rand = Memory.alloc(32)
  taggedHashRaw("nonce", rand, tPtr, 32, pxPtr, 32, message.dataStart, message.byteLength)

  const k_ = Memory.alloc(32)
  ptrModN(k_, rand)

  if (Scalar256.isZero(k_)) {
    Memory.restore(ctx)
    throw new Error("sign failed: k is zero")
  }

  // 3. R = k * G
  const R = Memory.alloc(96)
  Scalar256.multiplyG(R, k_)
  Point.toAffine(R, R)

  const ryIsEven = (load<u64>(R + 32, 0) & 1) == 0

  const kVal = Memory.alloc(32)
  if (ryIsEven) {
    memory.copy(kVal, k_, 32)
  } else {
    const N = Memory.alloc(32)
    store<u64>(N, Scalar256.N0, 0)
    store<u64>(N, Scalar256.N1, 8)
    store<u64>(N, Scalar256.N2, 16)
    store<u64>(N, Scalar256.N3, 24)
    Scalar256.sub(kVal, N, k_)
  }

  const rxPtr = Memory.alloc(32)
  store<u64>(rxPtr, bswap(load<u64>(R + 24)))
  store<u64>(rxPtr + 8, bswap(load<u64>(R + 16)))
  store<u64>(rxPtr + 16, bswap(load<u64>(R + 8)))
  store<u64>(rxPtr + 24, bswap(load<u64>(R + 0)))

  // 4. Challenge e
  const ePtr = Memory.alloc(32)
  taggedHashRaw("challenge", ePtr, rxPtr, 32, pxPtr, 32, message.dataStart, message.byteLength)

  const eVal = Memory.alloc(32)
  ptrModN(eVal, ePtr)

  // sig.s = (k + e * d) mod n
  const s = Memory.alloc(32)
  Scalar256.mul(s, eVal, dVal)
  Scalar256.add(s, kVal, s)

  const sigSBytes = new Uint8Array(32)
  BigInt256.toBytes(s, sigSBytes)

  const sig = new Uint8Array(64)
  for (let i = 0; i < 32; i++) sig[i] = load<u8>(rxPtr + i)
  sig.set(sigSBytes, 32)

  Memory.restore(ctx)
  return sig
}

/**
 * Verify a Schnorr signature (BIP340).
 */
export function verifySchnorr(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): bool {
  if (signature.length != 64) {
    return false
  }
  if (publicKey.length != 32) {
    return false
  }

  const rPtr = signature.dataStart
  const sPtr = signature.dataStart + 32
  const pubPtr = publicKey.dataStart

  const ctx = Memory.save()

  // P = lift_x(publicKey)
  const P = Memory.alloc(96)
  const px = Memory.alloc(32)
  store<u64>(px + 24, bswap(load<u64>(pubPtr)))
  store<u64>(px + 16, bswap(load<u64>(pubPtr + 8)))
  store<u64>(px + 8, bswap(load<u64>(pubPtr + 16)))
  store<u64>(px + 0, bswap(load<u64>(pubPtr + 24)))

  if (!liftX(P, px)) {
    Memory.restore(ctx)
    return false
  }

  // s >= N check
  const sNum = Memory.alloc(32)
  store<u64>(sNum + 24, bswap(load<u64>(sPtr)))
  store<u64>(sNum + 16, bswap(load<u64>(sPtr + 8)))
  store<u64>(sNum + 8, bswap(load<u64>(sPtr + 16)))
  store<u64>(sNum + 0, bswap(load<u64>(sPtr + 24)))
  if (Scalar256.isGreaterOrEqualN(sNum)) {
    Memory.restore(ctx)
    return false
  }

  // check r >= P
  const rNum = Memory.alloc(32)
  store<u64>(rNum + 24, bswap(load<u64>(rPtr)))
  store<u64>(rNum + 16, bswap(load<u64>(rPtr + 8)))
  store<u64>(rNum + 8, bswap(load<u64>(rPtr + 16)))
  store<u64>(rNum + 0, bswap(load<u64>(rPtr + 24)))

  if (BigInt256.isGreaterOrEqualP(rNum)) {
    Memory.restore(ctx)
    return false
  }

  const eHash = Memory.alloc(32)
  taggedHashRaw(
    "challenge",
    eHash,
    signature.dataStart,
    32,
    publicKey.dataStart,
    32,
    message.dataStart,
    message.byteLength
  )

  const eVal = Memory.alloc(32)
  ptrModN(eVal, eHash)

  // R = s*G - e*P
  // -e mod N:
  const nPrime = Memory.alloc(32)
  store<u64>(nPrime, Scalar256.N0, 0)
  store<u64>(nPrime, Scalar256.N1, 8)
  store<u64>(nPrime, Scalar256.N2, 16)
  store<u64>(nPrime, Scalar256.N3, 24)
  const minusE = Memory.alloc(32)
  Scalar256.sub(minusE, nPrime, eVal)

  const R = Memory.alloc(96)
  const tempP = Memory.alloc(96)

  // s*G
  Scalar256.multiplyG(R, sNum)

  // -e*P
  Scalar256.multiplyGLV(tempP, P, minusE)

  // s*G + (-e*P)
  Point.add(R, R, tempP)

  Point.toAffine(R, R)

  // Fail if R is infinite
  if (Point.isInfinity(R)) {
    Memory.restore(ctx)
    return false
  }

  // Fail if R.y is odd
  if ((load<u64>(R + 32, 0) & 1) != 0) {
    Memory.restore(ctx)
    return false
  }

  // Fail if R.x != r
  if (memory.compare(R, rNum, 32) != 0) {
    Memory.restore(ctx)
    return false
  }

  Memory.restore(ctx)
  return true
}

/**
 * Aggregates multiple 32-byte public keys into a single 32-byte public key.
 */
export function aggregatePublicKeys(pubKeys: Uint8Array[]): Uint8Array {
  const ctx = Memory.save()

  const P_agg = Memory.alloc(96)
  const tempP = Memory.alloc(96)
  const px = Memory.alloc(32)

  let first = true

  for (let i = 0; i < pubKeys.length; i++) {
    const pubPtr = pubKeys[i].dataStart
    store<u64>(px + 24, bswap(load<u64>(pubPtr)))
    store<u64>(px + 16, bswap(load<u64>(pubPtr + 8)))
    store<u64>(px + 8, bswap(load<u64>(pubPtr + 16)))
    store<u64>(px + 0, bswap(load<u64>(pubPtr + 24)))

    if (!liftX(tempP, px)) {
      Memory.restore(ctx)
      throw new Error("Invalid public key for aggregation")
    }

    if (first) {
      memory.copy(P_agg, tempP, 96)
      first = false
    } else {
      Point.add(P_agg, P_agg, tempP)
    }
  }

  if (first || Point.isInfinity(P_agg)) {
    Memory.restore(ctx)
    throw new Error("Aggregated public key is infinity")
  }

  Point.toAffine(P_agg, P_agg)
  const result = new Uint8Array(32)
  BigInt256.toBytes(P_agg, result)

  Memory.restore(ctx)
  return result
}

/**
 * Aggregates multiple 32-byte private keys into a single 32-byte private key.
 */
export function aggregatePrivateKeys(privKeys: Uint8Array[]): Uint8Array {
  const ctx = Memory.save()

  const sum = Memory.alloc(32)
  store<u64>(sum, 0, 0)
  store<u64>(sum, 0, 8)
  store<u64>(sum, 0, 16)
  store<u64>(sum, 0, 24)

  const d = Memory.alloc(32)
  const P = Memory.alloc(96)
  const N = Memory.alloc(32)
  store<u64>(N, Scalar256.N0, 0)
  store<u64>(N, Scalar256.N1, 8)
  store<u64>(N, Scalar256.N2, 16)
  store<u64>(N, Scalar256.N3, 24)

  for (let i = 0; i < privKeys.length; i++) {
    // Convert private key bytes to scalar (big-endian → little-endian mod N)
    BigInt256.fromBytes(d, privKeys[i])

    // Compute P_i = d_i * G and check Y parity
    Scalar256.multiplyG(P, d)
    Point.toAffine(P, P)

    // If P_i has odd Y, liftX will return -P_i, so use d_i = N - d_i
    if ((load<u64>(P + 32, 0) & 1) != 0) {
      Scalar256.sub(d, N, d)
    }

    Scalar256.add(sum, sum, d)
  }

  // Final check: sum*G should match the aggregated public key from aggregatePublicKeys.
  // If sum*G has odd Y, negate sum so signSchnorr produces a valid sig.
  Scalar256.multiplyG(P, sum)
  Point.toAffine(P, P)

  if ((load<u64>(P + 32, 0) & 1) != 0) {
    Scalar256.sub(sum, N, sum)
  }

  const result = new Uint8Array(32)
  BigInt256.toBytes(sum, result)

  Memory.restore(ctx)
  return result
}
