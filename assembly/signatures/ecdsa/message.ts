/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ecdsa/message.ts — Hash de mensaje por formato + sign/verify de mensaje
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   ecdsa_message_hash(out32, msgPtr, msgLen, format) → 32
 *       Universal  = SHA-256(msg)
 *       Bitcoin    = SHA-256( SHA-256( prefix ‖ varint(len) ‖ msg ) )
 *       Ethereum   = Keccak-256( prefix ‖ decimal(len) ‖ msg )
 *
 *   ecdsa_sign_message(out65, msgPtr, msgLen, privPtr32, format) → 65 | <0
 *   ecdsa_verify_message(msgPtr, msgLen, sigPtr64, pubPtr, pubLen, format) → 1 | 0
 *
 * Zero-alloc: buffers en CRYPTO_WORK (Arena.save/restore); el hash temporal
 * se aloja ANTES del save interno de sign/verify, así sobrevive a la llamada.
 * Prefijos como StaticArray (sin String.UTF8.encode / sin heap).
 */
import { Arena } from "../../utils/arena"
import { sha256_hash_raw } from "../../hash/sha2"
import { keccak256_hash_raw } from "../../hash/keccak256"
import { SignatureFormat, BITCOIN_PREFIX, BITCOIN_PREFIX_LEN, ETHEREUM_PREFIX, ETHEREUM_PREFIX_LEN } from "./constants"
import { ecdsa_sign } from "./sign"
import { ecdsa_verify } from "./verify"

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE HASH
// ═══════════════════════════════════════════════════════════════════════════

export function ecdsa_message_hash(out32: usize, msgPtr: usize, msgLen: isize, format: i32): i32 {
  // Universal: SHA-256(msg) directo (sin buffer)
  if (format == <i32>SignatureFormat.Universal) {
    sha256_hash_raw(out32, msgPtr, msgLen)
    return 32
  }

  const ctx = Arena.save()

  if (format == <i32>SignatureFormat.Bitcoin) {
    const ml: u32 = <u32>msgLen
    let varintLen: usize = 1
    if (ml >= 0xfd && ml <= 0xffff) varintLen = 3
    else if (ml > 0xffff) varintLen = 5

    const total: usize = BITCOIN_PREFIX_LEN + varintLen + <usize>ml
    const buf = Arena.alloc(total)
    let off: usize = 0
    for (let i: usize = 0; i < BITCOIN_PREFIX_LEN; i++) {
      store<u8>(buf + off, unchecked(BITCOIN_PREFIX[<i32>i]))
      off++
    }
    if (ml < 0xfd) {
      store<u8>(buf + off, <u8>ml)
      off++
    } else if (ml <= 0xffff) {
      store<u8>(buf + off, 0xfd)
      off++
      store<u8>(buf + off, <u8>(ml & 0xff))
      off++
      store<u8>(buf + off, <u8>((ml >> 8) & 0xff))
      off++
    } else {
      store<u8>(buf + off, 0xfe)
      off++
      store<u8>(buf + off, <u8>(ml & 0xff))
      off++
      store<u8>(buf + off, <u8>((ml >> 8) & 0xff))
      off++
      store<u8>(buf + off, <u8>((ml >> 16) & 0xff))
      off++
      store<u8>(buf + off, <u8>((ml >> 24) & 0xff))
      off++
    }
    memory.copy(buf + off, msgPtr, <usize>ml)

    // double SHA-256 (hash intermedio en tmp → sin aliasing con msg)
    const tmp = Arena.alloc(32)
    sha256_hash_raw(tmp, buf, <isize>total)
    sha256_hash_raw(out32, tmp, 32)
    Arena.restore(ctx)
    return 32
  }

  // Ethereum: Keccak-256( prefix ‖ decimal(len) ‖ msg )
  const ml: u32 = <u32>msgLen
  let lenStrLen: usize = 0
  let t: u32 = ml
  if (t == 0) {
    lenStrLen = 1
  } else {
    while (t > 0) {
      lenStrLen++
      t /= 10
    }
  }

  const total: usize = ETHEREUM_PREFIX_LEN + lenStrLen + <usize>ml
  const buf = Arena.alloc(total)
  let off: usize = 0
  for (let i: usize = 0; i < ETHEREUM_PREFIX_LEN; i++) {
    store<u8>(buf + off, unchecked(ETHEREUM_PREFIX[<i32>i]))
    off++
  }
  // dígitos decimales de ml (escritos de atrás hacia adelante)
  let dpos: usize = off + lenStrLen
  if (ml == 0) {
    store<u8>(buf + off, 0x30) // '0'
  } else {
    t = ml
    while (t > 0) {
      dpos--
      store<u8>(buf + dpos, <u8>(0x30 + (t % 10)))
      t /= 10
    }
  }
  memory.copy(buf + off + lenStrLen, msgPtr, <usize>ml)

  keccak256_hash_raw(out32, buf, <isize>total)
  Arena.restore(ctx)
  return 32
}

// ═══════════════════════════════════════════════════════════════════════════
// SIGN / VERIFY DE MENSAJE (hash + firma)
// ═══════════════════════════════════════════════════════════════════════════

export function ecdsa_sign_message(out65: usize, msgPtr: usize, msgLen: isize, privPtr32: usize, format: i32): i32 {
  const ctx = Arena.save()
  const hashTmp = Arena.alloc(32)
  ecdsa_message_hash(hashTmp, msgPtr, msgLen, format)
  const rc = ecdsa_sign(out65, hashTmp, privPtr32)
  Arena.restore(ctx)
  return rc
}

export function ecdsa_verify_message(
  msgPtr: usize,
  msgLen: isize,
  sigPtr64: usize,
  pubPtr: usize,
  pubLen: u32,
  format: i32
): i32 {
  const ctx = Arena.save()
  const hashTmp = Arena.alloc(32)
  ecdsa_message_hash(hashTmp, msgPtr, msgLen, format)
  const rc = ecdsa_verify(hashTmp, sigPtr64, pubPtr, pubLen)
  Arena.restore(ctx)
  return rc
}
