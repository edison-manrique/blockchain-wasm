/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  boundary-validation.test.ts — Validación de fronteras (SEC-3, SEC-4)
 * ═══════════════════════════════════════════════════════════════════════════
 *  - SEC-3: privkeys fuera de rango (0, N, > N) rechazadas en todas las fachadas
 *  - SEC-4: passphrase BIP39 > 1888 bytes UTF-8 rechazada fail-fast
 *
 *  El wrapper se carga con fromBuffer(readFileSync) porque load()/fetch
 *  falla en Windows/Bun (ENOENT). NADA toca el WASM a nivel de módulo.
 *
 *  Corre con:  bun test test/2.1.0/boundary-validation.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { readFileSync, existsSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { BlockchainWasm } from "../../src/blockchain-wasm"
import { Secp256k1 } from "../../src/secp256k1"
import { Wif } from "../../src/wif"
import { Ecdsa } from "../../src/ecdsa"
import { Schnorr } from "../../src/schnorr"
import { Ecdh } from "../../src/ecdh"
import { Address } from "../../src/address"
import { Bip39 } from "../../src/bip39"
import { Bip44 } from "../../src/bip44"
import { InvalidArgumentError } from "../../src/errors"

function wasmBytes(): Uint8Array {
  const here = dirname(fileURLToPath(import.meta.url))
  const candidates = [
    join(here, "..", "..", "build", "release.wasm"),
    join(here, "..", "..", "dist", "release.wasm"),
    join(here, "..", "..", "build", "blockchain.wasm"),
    join(here, "..", "..", "dist", "blockchain.wasm")
  ]
  for (const p of candidates) {
    if (existsSync(p)) return new Uint8Array(readFileSync(p))
  }
  throw new Error("Binario WASM no encontrado. Ajusta candidatos en wasmBytes().")
}

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

const ZERO32 = new Uint8Array(32)
const N_BYTES = new Uint8Array([
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
  0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
  0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
])
const ALL_FF = new Uint8Array(32).fill(0xff)
const PRIV1 = new Uint8Array(32)
PRIV1[31] = 1

beforeAll(async () => {
  await BlockchainWasm.fromBuffer(wasmBytes())
}, 300_000)

// ═══════════════════════════════════════════════════════════════════════════
// 1) SEC-3 — RANGO DE PRIVKEY
// ═══════════════════════════════════════════════════════════════════════════

describe("boundary validation — privkey range (SEC-3)", () => {
  test("sanity: priv=1 es válida", () => {
    expect(Secp256k1.getPublicKey(PRIV1).length).toBe(33)
  })

  test("getPublicKey rechaza 0", () => {
    expect(() => Secp256k1.getPublicKey(ZERO32)).toThrow(InvalidArgumentError)
  })

  test("getPublicKey rechaza N", () => {
    expect(() => Secp256k1.getPublicKey(N_BYTES)).toThrow(InvalidArgumentError)
  })

  test("getPublicKey rechaza > N", () => {
    expect(() => Secp256k1.getPublicKey(ALL_FF)).toThrow(InvalidArgumentError)
  })

  test("Ecdsa.sign rechaza 0", () => {
    expect(() => Ecdsa.sign(new Uint8Array(32).fill(1), ZERO32)).toThrow(InvalidArgumentError)
  })

  test("Schnorr.sign rechaza 0", () => {
    expect(() => Schnorr.sign(new Uint8Array(32).fill(1), ZERO32)).toThrow(InvalidArgumentError)
  })

  test("Schnorr.getPublicKey rechaza N", () => {
    expect(() => Schnorr.getPublicKey(N_BYTES)).toThrow(InvalidArgumentError)
  })

  test("Ecdh.sharedSecret rechaza 0", () => {
    const pub = Secp256k1.getPublicKey(PRIV1)
    expect(() => Ecdh.sharedSecret(ZERO32, pub)).toThrow(InvalidArgumentError)
  })

  test("Wif.encode rechaza N", () => {
    expect(() => Wif.encode(N_BYTES)).toThrow(InvalidArgumentError)
  })

  test("Address.fromPrivateKey rechaza 0", () => {
    expect(() => Address.fromPrivateKey(ZERO32, "p2pkh")).toThrow(InvalidArgumentError)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) SEC-4 — PASSPHRASE BIP39 ≤ 1888 BYTES
// ═══════════════════════════════════════════════════════════════════════════

describe("boundary validation — passphrase BIP39 (SEC-4)", () => {
  test("acepta passphrase de exactamente 1888 bytes", () => {
    expect(Bip39.mnemonicToSeed(MNEMONIC, "x".repeat(1888)).length).toBe(64)
  })

  test("rechaza passphrase de 1889 bytes", () => {
    expect(() => Bip39.mnemonicToSeed(MNEMONIC, "x".repeat(1889))).toThrow(InvalidArgumentError)
    expect(() => Bip39.mnemonicToSeed(MNEMONIC, "x".repeat(1889))).toThrow(/1888/)
  })

  test("Bip44.fromMnemonicDerive rechaza > 1888", () => {
    expect(() => Bip44.fromMnemonicDerive(MNEMONIC, "x".repeat(1889), 44, 0, 0, 0, 0)).toThrow(InvalidArgumentError)
  })

  test("Bip44.fromMnemonicXpub rechaza > 1888", () => {
    expect(() => Bip44.fromMnemonicXpub(MNEMONIC, "x".repeat(1889), 44, 0, 0)).toThrow(InvalidArgumentError)
  })

  test("Bip44.fromMnemonicXprv rechaza > 1888", () => {
    expect(() => Bip44.fromMnemonicXprv(MNEMONIC, "x".repeat(1889), 44, 0, 0)).toThrow(InvalidArgumentError)
  })

  test("cuenta BYTES UTF-8, no caracteres (multibyte)", () => {
    // "é" = 2 bytes UTF-8 → 944 × 2 = 1888 OK; 945 × 2 = 1890 → error
    expect(Bip39.mnemonicToSeed(MNEMONIC, "é".repeat(944)).length).toBe(64)
    expect(() => Bip39.mnemonicToSeed(MNEMONIC, "é".repeat(945))).toThrow(InvalidArgumentError)
  })

  test("regresión: vector Trezor con passphrase 'TREZOR'", () => {
    const seed = Bip39.mnemonicToSeed(MNEMONIC, "TREZOR")
    expect(seed.length).toBe(64)
  })
})