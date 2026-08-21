/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bench.ts — Benchmark de rendimiento de wallet-crypto-wasm (solo ops/s)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  • Clave distinta por iteración: makeKeyStream() genera una base aleatoria
 *    y la incrementa de 1 en 1 (contador en los últimos 4 bytes).
 *  • End-to-end priv→address: mide priv → getPublicKey → Address.* compuesto.
 *  • Calibración adaptativa (bloque ~25 ms) y medición a tiempo fijo (~400 ms).
 *
 *  Corre con:  bun test/bench.ts
 */
import { readFileSync, statSync } from "node:fs"
import { fileURLToPath } from "node:url"
import {
  BlockchainWasm,
  Secp256k1,
  Address,
  Wif,
  Schnorr,
  Ecdsa,
  Ecdh,
  Pbkdf2,
  Bip39,
  Bip32,
  Bip44,
  SignatureFormat,
  hexToBytes,
  toUint8Array,
  getRandomBytes,
} from "../src/index"

// ── Resolución del binario (relativo a este archivo) ──────────────────────
const wasmPath = fileURLToPath(new URL("../dist/blockchain.wasm", import.meta.url))
const wasmBytes = readFileSync(wasmPath)
const binaryKB = (statSync(wasmPath).size / 1024).toFixed(1)

// ── Helpers de medición ───────────────────────────────────────────────────
const fmt = (n: number): string => n.toLocaleString("en-US")

function measureOps(fn: () => void, targetMs = 400): number {
  for (let i = 0; i < 5; i++) fn() // warmup
  const calStart = performance.now()
  for (let i = 0; i < 10; i++) fn()
  const perOpMs = (performance.now() - calStart) / 10
  const batchSize = Math.max(1, Math.round(25 / perOpMs)) // bloque ~25 ms

  let iters = 0
  let elapsed = 0
  const start = performance.now()
  do {
    for (let i = 0; i < batchSize; i++) fn()
    iters += batchSize
    elapsed = performance.now() - start
  } while (elapsed < targetMs)
  return Math.round(iters / (elapsed / 1000))
}

const rows: { label: string; ops: number }[] = []
function bench(label: string, fn: () => void, targetMs = 400): void {
  rows.push({ label, ops: measureOps(fn, targetMs) })
}
function printSection(title: string): void {
  console.log(`\n── ${title} ${"─".repeat(Math.max(0, 58 - title.length))}`)
  console.log(`  ${"Operación".padEnd(38)}${"ops/s".padStart(14)}`)
}
function printRows(): void {
  for (const r of rows) console.log(`  ${r.label.padEnd(38)}${fmt(r.ops).padStart(14)}`)
  rows.length = 0
}

/**
 * Stream de claves determinista y siempre válido para secp256k1.
 * Base fijada en (N - 1) / 2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
 * Incrementa un contador de 32 bits en los últimos 4 bytes por iteración.
 */
function makeKeyStream(): { next: () => Uint8Array } {
  // (N - 1) / 2 en secp256k1
  const buf = hexToBytes("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0")
  let counter = 0

  return {
    next: () => {
      counter = (counter + 1) >>> 0
      buf[28] = (counter >>> 24) & 0xff
      buf[29] = (counter >>> 16) & 0xff
      buf[30] = (counter >>> 8) & 0xff
      buf[31] = counter & 0xff
      return buf
    },
  }
}

// ── Datos fijos (precomputados, no se miden) ──────────────────────────────
const PRIV = hexToBytes("0000000000000000000000000000000000000000000000000000000000000001")
const PRIV2 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000002")
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const ENTROPY = new Uint8Array(16)
const MSG32 = new Uint8Array(32).fill(0x42)
const HASH = new Uint8Array(32).fill(0x01)
const MSG_TEXT = "Autorizo esta transacción"
const MSG_TEXT_BYTES = toUint8Array(MSG_TEXT)

// ── Main ──────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  await BlockchainWasm.fromBuffer(wasmBytes)

  const runtime = typeof Bun !== "undefined" ? `Bun ${Bun.version}` : `Node ${process.version}`
  console.log(`\n🔐 wallet-crypto-wasm — benchmark de rendimiento`)
  console.log(`   runtime  : ${runtime}`)
  console.log(`   binary   : ${binaryKB} KB`)
  console.log(`   platform : ${process.platform} ${process.arch}`)
  console.log(`   (clave distinta por iteración; camino público completo)`)

  // Precomputar entradas derivadas (no se mide)
  const PUB = Secp256k1.getPublicKey(PRIV)
  const PUB_UNCOMP = Secp256k1.uncompress(PUB)
  const PUB2 = Secp256k1.getPublicKey(PRIV2)
  const XONLY = Schnorr.getPublicKey(PRIV)
  const SEED = Bip39.mnemonicToSeed(MNEMONIC)
  const WIF_STR = Wif.encode(PRIV)
  const SCHNORR_SIG = Schnorr.sign(MSG32, PRIV)
  const ECDSA_SIG = Ecdsa.sign(HASH, PRIV)
  const ECDSA_MSG_SIG = Ecdsa.signMessage(MSG_TEXT_BYTES, PRIV, SignatureFormat.Bitcoin)
  const ECDSA_TEXT_SIG = Ecdsa.signTextMessage(MSG_TEXT, PRIV, SignatureFormat.Ethereum)
  const MASTER = Bip32.fromSeed(SEED)

  // ── Secp256k1 (claves) — clave distinta por iteración ──
  printSection("Secp256k1 (claves · clave distinta/iter)")
  {
    const ksC = makeKeyStream()
    bench("getPublicKey (compressed)", () => Secp256k1.getPublicKey(ksC.next()))
    const ksU = makeKeyStream()
    bench("getPublicKey (uncompressed)", () => Secp256k1.getPublicKey(ksU.next(), false))
  }
  bench("compress (65→33)", () => Secp256k1.compress(PUB_UNCOMP))
  bench("uncompress (33→65)", () => Secp256k1.uncompress(PUB))
  bench("isValid", () => Secp256k1.isValid(PUB))
  printRows()

  // ── Address (direcciones desde pubkey fija) ──
  printSection("Address (desde pubkey)")
  bench("p2pkh (1…)", () => Address.p2pkh(PUB))
  bench("p2shP2wpkh (3…)", () => Address.p2shP2wpkh(PUB))
  bench("p2wpkh (bc1q…)", () => Address.p2wpkh(PUB))
  bench("p2tr (bc1p…)", () => Address.p2tr(PUB))
  bench("eth (0x… EIP-55)", () => Address.eth(PUB))
  printRows()

  // ── End-to-end: priv → address (clave distinta por iteración) ──
  printSection("End-to-end (priv → address · direcciones/s)")
  {
    const ks1 = makeKeyStream()
    bench("priv → p2pkh", () => Address.p2pkh(Secp256k1.getPublicKey(ks1.next())))
    const ks2 = makeKeyStream()
    bench("priv → p2wpkh", () => Address.p2wpkh(Secp256k1.getPublicKey(ks2.next())))
    const ks3 = makeKeyStream()
    bench("priv → p2tr", () => Address.p2tr(Secp256k1.getPublicKey(ks3.next())))
    const ks4 = makeKeyStream()
    bench("priv → eth", () => Address.eth(Secp256k1.getPublicKey(ks4.next())))
  }
  printRows()

  // ── WIF ──
  printSection("WIF")
  bench("encode", () => Wif.encode(PRIV))
  bench("decode", () => Wif.decode(WIF_STR))
  printRows()

  // ── Schnorr (BIP-340) ──
  printSection("Schnorr (BIP-340)")
  bench("getPublicKey (x-only)", () => Schnorr.getPublicKey(PRIV))
  bench("sign", () => Schnorr.sign(MSG32, PRIV))
  bench("verify", () => Schnorr.verify(SCHNORR_SIG, MSG32, XONLY))
  printRows()

  // ── ECDSA ──
  printSection("ECDSA (secp256k1)")
  bench("sign (hash)", () => Ecdsa.sign(HASH, PRIV))
  bench("verify (hash)", () => Ecdsa.verify(HASH, ECDSA_SIG, PUB))
  bench("signMessage (Bitcoin)", () => Ecdsa.signMessage(MSG_TEXT_BYTES, PRIV, SignatureFormat.Bitcoin))
  bench("verifyMessage (Bitcoin)", () =>
    Ecdsa.verifyMessage(MSG_TEXT_BYTES, ECDSA_MSG_SIG, PUB, SignatureFormat.Bitcoin),
  )
  bench("signTextMessage (Ethereum)", () => Ecdsa.signTextMessage(MSG_TEXT, PRIV, SignatureFormat.Ethereum))
  bench("verifyTextMessage (Ethereum)", () =>
    Ecdsa.verifyTextMessage(MSG_TEXT, ECDSA_TEXT_SIG, PUB, SignatureFormat.Ethereum),
  )
  printRows()

  // ── ECDH ──
  printSection("ECDH")
  bench("sharedSecret", () => Ecdh.sharedSecret(PRIV, PUB2))
  printRows()

  // ── PBKDF2 ──
  printSection("PBKDF2-HMAC-SHA512")
  bench("sha512 (2048 iters, 64 B)", () => Pbkdf2.sha512("password", "salt", 2048, 64), 600)
  printRows()

  // ── BIP-39 ──
  printSection("BIP-39 (mnemónicos)")
  bench("mnemonicToSeed", () => Bip39.mnemonicToSeed(MNEMONIC), 600)
  bench("generate (128 bits)", () => Bip39.generate(128), 600)
  bench("validate", () => Bip39.validate(MNEMONIC))
  bench("entropyToMnemonic (16 B)", () => Bip39.entropyToMnemonic(ENTROPY))
  printRows()

  // ── BIP-32 / HDKey ──
  printSection("BIP-32 / HDKey")
  bench("fromSeed", () => Bip32.fromSeed(SEED))
  bench("derive (1 nivel hardened)", () => MASTER.derive(0x80000000))
  bench("derivePath (m/44'/0'/0')", () => MASTER.derivePath("m/44'/0'/0'"))
  bench("toXpub", () => MASTER.toXpub())
  bench("toXprv", () => MASTER.toXprv())
  bench("neuter", () => MASTER.neuter())
  printRows()

  // ── BIP-44 ──
  printSection("BIP-44")
  bench("deriveKeys (m/44'/0'/0'/0/0)", () => Bip44.deriveKeys(SEED, 44, 0, 0, 0, 0))
  bench("accountXpub (m/44'/0'/0')", () => Bip44.accountXpub(SEED, 44, 0, 0))
  printRows()

  console.log(`\n✅ benchmark completado\n`)
}

main().catch((err) => {
  console.error("❌ benchmark falló:", err)
  process.exit(1)
})
