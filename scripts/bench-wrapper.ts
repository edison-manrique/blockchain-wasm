/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bench-wrapper.ts — Velocidad del WRAPPER COMPILADO (dist/index.js)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Usa exclusivamente el bundle publicado `dist/index.js` y el binario
 * `dist/blockchain-wasm.wasm`, igual que lo haría un consumidor real.
 *
 * Mide dos capas para cada hot path:
 *   • API pública  → fachada (validaciones de frontera + getInstance)
 *   • API cruda    → singleton (solo marshalling WASM)
 * El delta cuantifica el coste del wrapper.
 *
 * Ejecutar:  bun run bench:wrapper
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
  bytesToHex,
  toUint8Array
} from "../dist/index.js"

// ── Binario liberado ──────────────────────────────────────────────────────
const wasmPath = fileURLToPath(new URL("../dist/blockchain-wasm.wasm", import.meta.url))
const wasmBytes = readFileSync(wasmPath)
const binaryKB = (statSync(wasmPath).size / 1024).toFixed(1)

const fmt = (n: number): string => n.toLocaleString("en-US")

// ── Motor de medición (mismo criterio que test/bench.ts) ──────────────────
function measureNs(fn: () => void, targetMs = 250): number {
  for (let i = 0; i < 5; i++) fn() // warmup
  const calStart = performance.now()
  for (let i = 0; i < 10; i++) fn()
  const perOpMs = (performance.now() - calStart) / 10
  const batch = Math.max(1, Math.round(20 / perOpMs))

  // 3 muestras; nos quedamos con la mejor para reducir ruido térmico/JIT.
  let best = Infinity
  for (let sample = 0; sample < 3; sample++) {
    let iters = 0
    let elapsed = 0
    const start = performance.now()
    do {
      for (let i = 0; i < batch; i++) fn()
      iters += batch
      elapsed = performance.now() - start
    } while (elapsed < targetMs)
    best = Math.min(best, (elapsed * 1e6) / iters)
  }
  return best
}

interface Row {
  label: string
  ns: number
}

/** Calibra un lote de ~10 ms para una función. */
function calibrateBatch(fn: () => void): number {
  for (let i = 0; i < 20; i++) fn()
  const t0 = performance.now()
  let n = 0
  while (performance.now() - t0 < 5 && n < 100000) {
    for (let i = 0; i < 100; i++) fn()
    n += 100
  }
  const perOpMs = (performance.now() - t0) / n
  return Math.max(1, Math.round(10 / perOpMs))
}

const rows: Row[] = []
function bench(label: string, fn: () => void, targetMs = 250): number {
  const ns = measureNs(fn, targetMs)
  rows.push({ label, ns })
  return ns
}

/**
 * A/B intercalado: mide fachada y singleton en bloques alternos para
 * cancelar deriva térmica/frecuencia. Sin esto, el delta del wrapper queda
 * dominado por el ruido del turbo-boost.
 */
function benchPair(label: string, apiFn: () => void, rawFn: () => void): void {
  const batch = Math.max(calibrateBatch(apiFn), calibrateBatch(rawFn), 1)
  // warmup
  for (let i = 0; i < 3; i++) {
    for (let k = 0; k < batch; k++) apiFn()
    for (let k = 0; k < batch; k++) rawFn()
  }

  let apiNs = 0
  let rawNs = 0
  for (let round = 0; round < 8; round++) {
    const apiFirst = (round & 1) === 0
    if (apiFirst) {
      let t = performance.now()
      for (let k = 0; k < batch; k++) apiFn()
      apiNs += (performance.now() - t) * 1e6
      t = performance.now()
      for (let k = 0; k < batch; k++) rawFn()
      rawNs += (performance.now() - t) * 1e6
    } else {
      let t = performance.now()
      for (let k = 0; k < batch; k++) rawFn()
      rawNs += (performance.now() - t) * 1e6
      t = performance.now()
      for (let k = 0; k < batch; k++) apiFn()
      apiNs += (performance.now() - t) * 1e6
    }
  }
  apiNs /= 8 * batch
  rawNs /= 8 * batch
  rows.push({ label: `${label} (api)`, ns: apiNs })
  rows.push({ label: `${label} (singleton)`, ns: rawNs })
  overhead(label, apiNs, rawNs)
}

function printRows(): void {
  console.log(`  ${"Operación".padEnd(48)}${"ns/op".padStart(11)}${"ops/s".padStart(14)}`)
  for (const r of rows) {
    console.log(
      `  ${r.label.padEnd(48)}${r.ns.toFixed(0).padStart(11)}${fmt(Math.round(1e9 / r.ns)).padStart(14)}`
    )
  }
  rows.length = 0
}

function section(title: string): void {
  console.log(`\n── ${title} ${"─".repeat(Math.max(0, 66 - title.length))}`)
}

/** Imprime el coste del wrapper comparando fachada vs singleton. */
function overhead(label: string, apiNs: number, rawNs: number): void {
  const overheadNs = apiNs - rawNs
  const pct = rawNs > 0 ? (overheadNs / rawNs) * 100 : 0
  console.log(
    `   ↳ ${label.padEnd(30)} wrapper +${overheadNs.toFixed(0)} ns/op (${pct >= 0 ? "+" : ""}${pct.toFixed(1)}%)`
  )
}

// ── Datos fijos ───────────────────────────────────────────────────────────
const PRIV_HEX = "0000000000000000000000000000000000000000000000000000000000000001"
const PRIV = hexToBytes(PRIV_HEX)
const PRIV2 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000002")
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const ENTROPY = new Uint8Array(16)
const MSG32 = new Uint8Array(32).fill(0x42)
const HASH = new Uint8Array(32).fill(0x01)
const MSG_TEXT = "Autorizo esta transacción"
const MSG_TEXT_BYTES = toUint8Array(MSG_TEXT)

async function main(): Promise<void> {
  const t0 = performance.now()
  const wasm = await BlockchainWasm.fromBuffer(wasmBytes)
  const bootMs = performance.now() - t0

  // Instancia única: la usan las llamadas "raw" para aislar el wrapper.
  const raw = BlockchainWasm.getInstance()

  const PUB = Secp256k1.getPublicKey(PRIV, true)
  const PUB_UNCOMP = Secp256k1.getPublicKey(PRIV, false)
  const PUB2 = Secp256k1.getPublicKey(PRIV2, true)
  const XONLY = Schnorr.getPublicKey(PRIV)
  const SEED = Bip39.mnemonicToSeed(MNEMONIC)
  const WIF_STR = Wif.encode(PRIV)
  const SCHNORR_SIG = Schnorr.sign(MSG32, PRIV)
  const ECDSA_SIG = Ecdsa.sign(HASH, PRIV)
  const ECDSA_MSG_SIG = Ecdsa.signMessage(MSG_TEXT_BYTES, PRIV, SignatureFormat.Bitcoin)
  const ECDSA_TEXT_SIG = Ecdsa.signTextMessage(MSG_TEXT, PRIV, SignatureFormat.Ethereum)
  const MASTER = Bip32.fromSeed(SEED)

  const runtime = typeof Bun !== "undefined" ? `Bun ${Bun.version}` : `Node ${process.version}`
  console.log(`\n⚡ blockchain-wasm — Benchmark del wrapper compilado`)
  console.log(`   runtime : ${runtime}`)
  console.log(`   wrapper : dist/index.js`)
  console.log(`   binary  : dist/blockchain-wasm.wasm (${binaryKB} KB)`)
  console.log(`   boot    : ${bootMs.toFixed(1)} ms (fetch-less, fromBuffer)`)

  // ── Secp256k1 ──
  section("Secp256k1 (fachada vs singleton)")
  benchPair("getPublicKey 33B", () => Secp256k1.getPublicKey(PRIV), () => raw.getPublicKey(PRIV, true))
  benchPair("getPublicKey 65B", () => Secp256k1.getPublicKey(PRIV, false), () => raw.getPublicKey(PRIV, false))
  bench("Secp256k1.isValid", () => Secp256k1.isValid(PUB))
  printRows()

  // ── Address ──
  section("Address (fachada vs singleton)")
  benchPair("p2pkh", () => Address.p2pkh(PUB), () => raw.btcP2pkh(PUB))
  benchPair("p2wpkh", () => Address.p2wpkh(PUB), () => raw.btcP2wpkh(PUB))
  benchPair("p2tr", () => Address.p2tr(PUB), () => raw.btcP2tr(PUB))
  benchPair("eth", () => Address.eth(PUB_UNCOMP), () => raw.ethAddress(PUB_UNCOMP))
  bench("Address.tron", () => Address.tron(PUB_UNCOMP))
  printRows()

  section("End-to-end priv → address (fachada)")
  bench("fromPrivateKey p2pkh", () => Address.fromPrivateKey(PRIV, "p2pkh"))
  bench("fromPrivateKey p2wpkh", () => Address.fromPrivateKey(PRIV, "p2wpkh"))
  bench("fromPrivateKey p2tr", () => Address.fromPrivateKey(PRIV, "p2tr"))
  bench("fromPrivateKey eth", () => Address.fromPrivateKey(PRIV, "eth"))
  printRows()

  // ── WIF ──
  section("WIF (fachada vs singleton)")
  benchPair("encode", () => Wif.encode(PRIV), () => raw.wifEncode(PRIV, true))
  benchPair("decode", () => Wif.decode(WIF_STR), () => raw.wifDecode(WIF_STR))
  printRows()

  // ── Schnorr ──
  section("Schnorr / BIP-340 (fachada vs singleton)")
  benchPair("sign", () => Schnorr.sign(MSG32, PRIV), () => raw.schnorrSign(MSG32, PRIV))
  benchPair("verify", () => Schnorr.verify(SCHNORR_SIG, MSG32, XONLY), () =>
    raw.schnorrVerify(SCHNORR_SIG, MSG32, XONLY)
  )
  printRows()

  // ── ECDSA ──
  section("ECDSA (fachada vs singleton)")
  benchPair("sign", () => Ecdsa.sign(HASH, PRIV), () => raw.ecdsaSign(HASH, PRIV))
  benchPair("verify", () => Ecdsa.verify(HASH, ECDSA_SIG, PUB), () => raw.ecdsaVerify(HASH, ECDSA_SIG, PUB))
  bench("Ecdsa.signMessage Bitcoin", () => Ecdsa.signMessage(MSG_TEXT_BYTES, PRIV, SignatureFormat.Bitcoin))
  bench("Ecdsa.verifyMessage Bitcoin", () =>
    Ecdsa.verifyMessage(MSG_TEXT_BYTES, ECDSA_MSG_SIG, PUB, SignatureFormat.Bitcoin)
  )
  bench("Ecdsa.signTextMessage Ethereum", () =>
    Ecdsa.signTextMessage(MSG_TEXT, PRIV, SignatureFormat.Ethereum)
  )
  bench("Ecdsa.verifyTextMessage Ethereum", () =>
    Ecdsa.verifyTextMessage(MSG_TEXT, ECDSA_TEXT_SIG, PUB_UNCOMP, SignatureFormat.Ethereum)
  )
  printRows()

  // ── ECDH ──
  section("ECDH (fachada vs singleton)")
  benchPair("sharedSecret", () => Ecdh.sharedSecret(PRIV, PUB2), () => raw.ecdhSharedSecret(PRIV, PUB2))
  printRows()

  // ── PBKDF2 / BIP-39 ──
  section("PBKDF2 / BIP-39")
  bench("Pbkdf2.sha512 (2048 it, 64B)", () => Pbkdf2.sha512("password", "salt", 2048, 64), 500)
  bench("Bip39.mnemonicToSeed", () => Bip39.mnemonicToSeed(MNEMONIC), 500)
  bench("Bip39.entropyToMnemonic (16B)", () => Bip39.entropyToMnemonic(ENTROPY))
  bench("Bip39.mnemonicToEntropy", () => Bip39.mnemonicToEntropy(MNEMONIC))
  bench("Bip39.validate", () => Bip39.validate(MNEMONIC))
  printRows()

  // ── BIP-32 / BIP-44 ──
  section("BIP-32 / BIP-44 (fachada vs singleton)")
  bench("Bip32.fromSeed", () => Bip32.fromSeed(SEED))
  benchPair("HDKey.derive", () => MASTER.derive(0x80000000), () => raw.bip32Derive(MASTER.raw, 0x80000000))
  benchPair("HDKey.depth (accessor)", () => MASTER.depth, () => raw.bip32XkeyDepth(MASTER.raw))
  bench("HDKey.derivePath (3 niveles)", () => MASTER.derivePath("m/44'/0'/0'"))
  bench("HDKey.toXpub", () => MASTER.toXpub())
  bench("HDKey.toXprv", () => MASTER.toXprv())
  bench("Bip32.fromXpub", () => Bip32.fromXpub(MASTER.toXpub()))
  bench("HDKey.neuter", () => MASTER.neuter())
  benchPair("Bip44.deriveLeaf", () => Bip44.deriveKeys(SEED, 44, 0, 0, 0, 0), () =>
    raw.bip44DeriveLeaf(SEED, 44, 0, 0, 0, 0)
  )
  benchPair("Bip44.accountXpub", () => Bip44.accountXpub(SEED, 44, 0, 0), () =>
    raw.bip44AccountXpub(SEED, 44, 0, 0)
  )
  bench("Bip44.fromMnemonicDerive", () => Bip44.fromMnemonicDerive(MNEMONIC, "", 44, 0, 0, 0, 0), 500)
  printRows()

  // ── Utilidades puras (sin WASM) ──
  section("Utilidades JS (sin WASM)")
  bench("hexToBytes (32 B)", () => hexToBytes(PRIV_HEX))
  bench("bytesToHex (32 B)", () => bytesToHex(PRIV))
  printRows()

  console.log(`\n✅ Benchmark completado.\n`)
}

main().catch((err) => {
  console.error("❌ Benchmark falló:", err)
  process.exit(1)
})
