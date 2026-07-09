import { Point } from "../utils/point"
import { BigInt256, Scalar256 } from "../utils"
import { ECDSA } from "../ecdsa"
import { ECDH } from "../ecdh"
import { hexToBytes } from "../../utils"
import { signSchnorr, verifySchnorr, getSchnorrPublicKey, aggregatePublicKeys } from "../schnorr"
export * from "./core.test"

function allocBigInt256(): usize {
  return heap.alloc(32) as usize
}
function allocPoint(): usize {
  return heap.alloc(96) as usize
}

function setBigInt(ptr: usize, l0: u64, l1: u64, l2: u64, l3: u64): void {
  store<u64>(ptr, l0, 0)
  store<u64>(ptr, l1, 8)
  store<u64>(ptr, l2, 16)
  store<u64>(ptr, l3, 24)
}

function pointToBytesUncompressed(p: usize): Uint8Array {
  const bytes = new Uint8Array(65)
  bytes[0] = 0x04

  const z_ptr = p + 64
  const z_inv = allocBigInt256()
  BigInt256.modInverse(z_inv, z_ptr)

  const z_inv_2_red = allocBigInt256()
  BigInt256.mulMod(z_inv_2_red, z_inv, z_inv)

  const z_inv_3 = allocBigInt256()
  BigInt256.mulMod(z_inv_3, z_inv_2_red, z_inv)

  const x_aff = allocBigInt256()
  BigInt256.mulMod(x_aff, p, z_inv_2_red)

  const y_aff = allocBigInt256()
  BigInt256.mulMod(y_aff, p + 32, z_inv_3)

  BigInt256.toBytes(x_aff, bytes.subarray(1, 33))
  BigInt256.toBytes(y_aff, bytes.subarray(33, 65))

  return bytes
}

function utf8ToBytes(s: string): Uint8Array {
  return Uint8Array.wrap(String.UTF8.encode(s))
}

// ═══════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════

export function benchmark_bigint_add(count: i32): void {
  const a = allocBigInt256()
  const b = allocBigInt256()
  const res = allocBigInt256()
  setBigInt(a, 1, 2, 3, 4)
  setBigInt(b, 5, 6, 7, 8)
  for (let i = 0; i < count; i++) {
    BigInt256.add(res, a, b)
  }
}

export function benchmark_point_double(count: i32): void {
  const g = Point.generator()
  const res = allocPoint()
  for (let i = 0; i < count; i++) {
    Point.double(res, g)
  }
}

export function benchmark_point_add(count: i32): void {
  const g = Point.generator()
  const res = allocPoint()
  for (let i = 0; i < count; i++) {
    Point.add(res, g, g)
  }
}

export function benchmark_pubkey_gen(count: i32): void {
  benchmark_scalar_mul(count)
}

export function benchmark_scalar_mul(count: i32): void {
  const s = allocBigInt256()
  const res = allocPoint()
  setBigInt(s, 0x123456789, 0xabcdef, 0x1, 0)

  for (let i = 0; i < count; i++) {
    Scalar256.multiplyG(res, s)
  }
}

export function benchmark_ecdsa_sign(count: i32): void {
  const priv = new Uint8Array(32)
  for (let i = 0; i < 32; i++) priv[i] = <u8>(i + 1)
  const msg = new Uint8Array(32)
  msg[0] = 1
  for (let i = 0; i < count; i++) {
    ECDSA.sign(msg, priv)
  }
}

export function benchmark_ecdsa_verify(count: i32): void {
  const priv = new Uint8Array(32)
  for (let i = 0; i < 32; i++) priv[i] = <u8>(i + 1)
  const msg = new Uint8Array(32)
  msg[0] = 1
  const sig = ECDSA.sign(msg, priv)

  const privBig = allocBigInt256()
  BigInt256.fromBytes(privBig, priv)
  const pub = allocPoint()
  Scalar256.multiplyG(pub, privBig)
  const pubBytes = pointToBytesUncompressed(pub)

  for (let i = 0; i < count; i++) {
    ECDSA.verify(msg, sig, pubBytes)
  }
}

export function benchmark_ecdh(count: i32): void {
  const privA = new Uint8Array(32)
  for (let i = 0; i < 32; i++) privA[i] = <u8>(i + 1)
  const privB = new Uint8Array(32)
  for (let i = 0; i < 32; i++) privB[i] = <u8>(i + 2)

  const privBBig = allocBigInt256()
  BigInt256.fromBytes(privBBig, privB)
  const pubB = allocPoint()
  Scalar256.multiplyG(pubB, privBBig)
  const pubBBytes = pointToBytesUncompressed(pubB)

  for (let i = 0; i < count; i++) {
    ECDH.sharedSecret(privA, pubBBytes)
  }
}

export function benchmark_schnorr_sign(count: i32): void {
  const privHex = "0101010101010101010101010101010101010101010101010101010101010101"
  const msgHex = "0202020202020202020202020202020202020202020202020202020202020202"
  const auxHex = "0303030303030303030303030303030303030303030303030303030303030303"

  const priv = hexToBytes(privHex)
  const msg = hexToBytes(msgHex)
  const aux = hexToBytes(auxHex)

  for (let i = 0; i < count; i++) {
    signSchnorr(msg, priv, aux)
  }
}

export function benchmark_schnorr_verify(count: i32): void {
  const privHex = "0101010101010101010101010101010101010101010101010101010101010101"
  const expectedSigHex =
    "b070aafcea439a4f6f1bbfc2eb66d29d24b0cab74d6b745c3cfb009cc8fe4aa80e066c34819936549ff49b6fd4d41edfc401a367b87ddd59fee38177961c225f"
  const msgHex = "0202020202020202020202020202020202020202020202020202020202020202"

  const priv = hexToBytes(privHex)
  const msg = hexToBytes(msgHex)
  const sig = hexToBytes(expectedSigHex)
  const pub = getSchnorrPublicKey(priv)

  for (let i = 0; i < count; i++) {
    verifySchnorr(sig, msg, pub)
  }
}

export function benchmark_schnorr_multisig(count: i32): void {
  const priv1Hex = "0101010101010101010101010101010101010101010101010101010101010101"
  const priv2Hex = "0202020202020202020202020202020202020202020202020202020202020202"

  const priv1 = hexToBytes(priv1Hex)
  const priv2 = hexToBytes(priv2Hex)

  const reqPub1 = getSchnorrPublicKey(priv1)
  const reqPub2 = getSchnorrPublicKey(priv2)

  const pubArr = new Array<Uint8Array>(2)
  pubArr[0] = reqPub1
  pubArr[1] = reqPub2

  for (let i = 0; i < count; i++) {
    aggregatePublicKeys(pubArr)
  }
}
