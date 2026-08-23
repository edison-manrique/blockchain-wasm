/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bench.ts — Benchmark de rendimiento de blockchain-wasm v3.1.0
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  • Clave distinta por iteración: makeKeyStream() genera una base aleatoria
 *    y la incrementa de 1 en 1 (contador en los últimos 4 bytes).
 *  • End-to-end priv→address: mide priv → getPublicKey → Address.* compuesto.
 *  • MuSig2 (BIP-327): KeyAgg, NonceGen, NonceAgg, SessionInit, PartialSign,
 *    PartialVerify, SigAgg y SignAll.
 *  • Monitoreo de memoria WASM (zero-alloc / sin memory.grow) y heap JS de Bun.
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
  Musig2,
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

function measureOps(fn: () => void, targetMs = 300): number {
  for (let i = 0; i < 5; i++) fn() // warmup
  const calStart = performance.now()
  for (let i = 0; i < 10; i++) fn()
  const perOpMs = (performance.now() - calStart) / 10
  const batchSize = Math.max(1, Math.round(20 / perOpMs)) // bloque ~20 ms

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
function bench(label: string, fn: () => void, targetMs = 300): void {
  rows.push({ label, ops: measureOps(fn, targetMs) })
}
function printSection(title: string): void {
  console.log(`\n── ${title} ${"─".repeat(Math.max(0, 58 - title.length))}`)
  console.log(`  ${"Operación".padEnd(40)}${"ops/s".padStart(14)}`)
}
function printRows(): void {
  for (const r of rows) console.log(`  ${r.label.padEnd(40)}${fmt(r.ops).padStart(14)}`)
  rows.length = 0
}

/**
 * Stream de claves determinista y siempre válido para secp256k1.
 * Base fijada en (N - 1) / 2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
 * Incrementa un contador de 32 bits en los últimos 4 bytes por iteración.
 */
function makeKeyStream(): { next: () => Uint8Array } {
  const buf = new Uint8Array(32)
  buf[27] = 1 // Clave base: 2^32
  let counter = 0

  return {
    next: () => {
      counter = (counter + 1) >>> 0
      buf[28] = (counter >>> 24) & 0xff
      buf[29] = (counter >>> 16) & 0xff
      buf[30] = (counter >>> 8) & 0xff
      buf[31] = counter & 0xff
      return buf.slice()
    },
  }
}

// ── Datos fijos (precomputados) ───────────────────────────────────────────
const PRIV = hexToBytes("0000000000000000000000000000000000000000000000000000000000000001")
const PRIV2 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000002")
const PRIV3 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000003")
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const ENTROPY = new Uint8Array(16)
const MSG32 = new Uint8Array(32).fill(0x42)
const HASH = new Uint8Array(32).fill(0x01)
const MSG_TEXT = "Autorizo esta transacción"
const MSG_TEXT_BYTES = toUint8Array(MSG_TEXT)

// ── Main ──────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  const wasm = await BlockchainWasm.fromBuffer(wasmBytes)

  // Memoria inicial
  if (globalThis.gc) globalThis.gc()
  const initialHeap = process.memoryUsage().heapUsed
  const wasmMem = wasm.exp.memory as WebAssembly.Memory
  const initialWasmPages = wasmMem.buffer.byteLength / 65536
  const initialWasmBytes = wasmMem.buffer.byteLength

  const runtime = typeof Bun !== "undefined" ? `Bun ${Bun.version}` : `Node ${process.version}`
  console.log(`\n🔐 blockchain-wasm v3.1.0 — Benchmark de Rendimiento Criptográfico`)
  console.log(`   runtime  : ${runtime}`)
  console.log(`   binary   : ${binaryKB} KB (WebAssembly Zero-Alloc)`)
  console.log(`   platform : ${process.platform} ${process.arch}`)
  console.log(`   wasm mem : ${initialWasmPages} pages (${(initialWasmBytes / 1024).toFixed(0)} KB)`)
  console.log(`   (claves dinámicas por iteración en secp256k1; camino público completo)`)

  // Precomputar entradas derivadas (no se mide)
  const PUB = Secp256k1.getPublicKey(PRIV, true)
  const PUB_UNCOMP = Secp256k1.getPublicKey(PRIV, false)
  const PUB2 = Secp256k1.getPublicKey(PRIV2, true)
  const PUB3 = Secp256k1.getPublicKey(PRIV3, true)
  const XONLY = Schnorr.getPublicKey(PRIV)
  const SEED = Bip39.mnemonicToSeed(MNEMONIC)
  const WIF_STR = Wif.encode(PRIV)
  const SCHNORR_SIG = Schnorr.sign(MSG32, PRIV)
  const ECDSA_SIG = Ecdsa.sign(HASH, PRIV)
  const ECDSA_MSG_SIG = Ecdsa.signMessage(MSG_TEXT_BYTES, PRIV, SignatureFormat.Bitcoin)
  const ECDSA_TEXT_SIG = Ecdsa.signTextMessage(MSG_TEXT, PRIV, SignatureFormat.Ethereum)
  const MASTER = Bip32.fromSeed(SEED)

  // MuSig2 setup
  const musigPubs = [PUB, PUB2, PUB3]
  const musigPrivs = [PRIV, PRIV2, PRIV3]
  const musigSecrands = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), new Uint8Array(32).fill(3)]
  const { aggregatedPubkey: musigQ, gacc: musigGacc } = Musig2.keyAgg(musigPubs)
  const musigCoeffs = Musig2.keyAggCoeffs(musigPubs)
  const musigNonces = musigPrivs.map((sk, i) => Musig2.nonceGen(musigSecrands[i], musigPubs[i], sk, MSG32))
  const musigAggNonce = Musig2.nonceAgg(musigNonces.map(n => n.pubNonce))
  const musigSession = Musig2.sessionInit(musigAggNonce, musigQ, MSG32)
  const musigPsig1 = Musig2.partialSign(musigSession, musigGacc, musigNonces[0].secNonce, PRIV, musigCoeffs[0])
  const musigPsigs = musigPrivs.map((sk, i) => Musig2.partialSign(musigSession, musigGacc, musigNonces[i].secNonce, sk, musigCoeffs[i]))

  // ── Secp256k1 (claves) ──
  printSection("Secp256k1 (claves · clave distinta/iter)")
  {
    const ksC = makeKeyStream()
    bench("getPublicKey (compressed 33B)", () => Secp256k1.getPublicKey(ksC.next()))
    const ksU = makeKeyStream()
    bench("getPublicKey (uncompressed 65B)", () => Secp256k1.getPublicKey(ksU.next(), false))
  }
  bench("compress (65→33)", () => Secp256k1.compress(PUB_UNCOMP))
  bench("uncompress (33→65)", () => Secp256k1.uncompress(PUB))
  bench("isValid (pubkey check)", () => Secp256k1.isValid(PUB))
  printRows()

  // ── Address ──
  printSection("Address (desde pubkey)")
  bench("p2pkh (1… Legacy)", () => Address.p2pkh(PUB))
  bench("p2pkhUncompressed (1… Legacy 65B)", () => Address.p2pkhUncompressed(PUB_UNCOMP))
  bench("p2shP2wpkh (3… Nested SegWit)", () => Address.p2shP2wpkh(PUB))
  bench("p2wpkh (bc1q… Native SegWit)", () => Address.p2wpkh(PUB))
  bench("p2tr (bc1p… Taproot BIP-86)", () => Address.p2tr(PUB))
  bench("eth (0x… EIP-55)", () => Address.eth(PUB_UNCOMP))
  bench("tron (T… Base58Check)", () => Address.tron(PUB_UNCOMP))
  printRows()

  // ── End-to-end: priv → address ──
  printSection("End-to-end (priv → address · direcciones/s)")
  {
    const ks1 = makeKeyStream()
    bench("priv → p2pkh", () => Address.fromPrivateKey(ks1.next(), "p2pkh"))
    const ks2 = makeKeyStream()
    bench("priv → p2wpkh", () => Address.fromPrivateKey(ks2.next(), "p2wpkh"))
    const ks3 = makeKeyStream()
    bench("priv → p2tr", () => Address.fromPrivateKey(ks3.next(), "p2tr"))
    const ks4 = makeKeyStream()
    bench("priv → eth", () => Address.fromPrivateKey(ks4.next(), "eth"))
    const ks5 = makeKeyStream()
    bench("priv → tron", () => Address.fromPrivateKey(ks5.next(), "tron"))
  }
  printRows()

  // ── WIF ──
  printSection("WIF")
  bench("encode (priv → WIF)", () => Wif.encode(PRIV))
  bench("decode (WIF → priv)", () => Wif.decode(WIF_STR))
  printRows()

  // ── Schnorr (BIP-340) ──
  printSection("Schnorr (BIP-340)")
  bench("getPublicKey (x-only 32B)", () => Schnorr.getPublicKey(PRIV))
  bench("sign (64B signature)", () => Schnorr.sign(MSG32, PRIV))
  bench("verify (BIP-340 verify)", () => Schnorr.verify(SCHNORR_SIG, MSG32, XONLY))
  printRows()

  // ── MuSig2 (BIP-327) ──
  printSection("MuSig2 (BIP-327 Multi-Signature)")
  bench("keyAgg (3 signers → Q)", () => Musig2.keyAgg(musigPubs))
  bench("nonceGen (97B sec / 66B pub)", () => Musig2.nonceGen(musigSecrands[0], PUB, PRIV, MSG32))
  bench("nonceAgg (3 pubnonces → agg)", () => Musig2.nonceAgg(musigNonces.map(n => n.pubNonce)))
  bench("sessionInit (97B context)", () => Musig2.sessionInit(musigAggNonce, musigQ, MSG32))
  bench("partialSign (32B psig)", () => Musig2.partialSign(musigSession, musigGacc, musigNonces[0].secNonce, PRIV, musigCoeffs[0]))
  bench("partialVerify", () => Musig2.partialVerify(musigPsig1, musigSession, musigGacc, musigNonces[0].pubNonce, PUB, musigCoeffs[0]))
  bench("partialSigAgg (3 psigs → final)", () => Musig2.partialSigAgg(musigPsigs))
  bench("signAll (end-to-end 3 signers)", () => Musig2.signAll(musigPrivs, MSG32, musigSecrands))
  printRows()

  // ── ECDSA ──
  printSection("ECDSA (secp256k1)")
  bench("sign (deterministic RFC 6979)", () => Ecdsa.sign(HASH, PRIV))
  bench("verify (DER / Raw)", () => Ecdsa.verify(HASH, ECDSA_SIG, PUB))
  bench("signMessage (Bitcoin format)", () => Ecdsa.signMessage(MSG_TEXT_BYTES, PRIV, SignatureFormat.Bitcoin))
  bench("verifyMessage (Bitcoin format)", () =>
    Ecdsa.verifyMessage(MSG_TEXT_BYTES, ECDSA_MSG_SIG, PUB, SignatureFormat.Bitcoin),
  )
  bench("signTextMessage (Ethereum)", () => Ecdsa.signTextMessage(MSG_TEXT, PRIV, SignatureFormat.Ethereum))
  bench("verifyTextMessage (Ethereum)", () =>
    Ecdsa.verifyTextMessage(MSG_TEXT, ECDSA_TEXT_SIG, PUB_UNCOMP, SignatureFormat.Ethereum),
  )
  printRows()

  // ── ECDH ──
  printSection("ECDH")
  bench("sharedSecret", () => Ecdh.sharedSecret(PRIV, PUB2))
  printRows()

  // ── PBKDF2 ──
  printSection("PBKDF2-HMAC-SHA512")
  bench("sha512 (2048 iters, 64 B)", () => Pbkdf2.sha512("password", "salt", 2048, 64), 500)
  printRows()

  // ── BIP-39 ──
  printSection("BIP-39 (Mnemónicos)")
  bench("mnemonicToSeed (PBKDF2 2048)", () => Bip39.mnemonicToSeed(MNEMONIC), 500)
  bench("generate (128 bits / 12 palabras)", () => Bip39.generate(128), 500)
  bench("validate (checksum)", () => Bip39.validate(MNEMONIC))
  bench("entropyToMnemonic (16 B)", () => Bip39.entropyToMnemonic(ENTROPY))
  bench("mnemonicToEntropy", () => Bip39.mnemonicToEntropy(MNEMONIC))
  printRows()

  // ── BIP-32 / HDKey ──
  printSection("BIP-32 / HDKey")
  bench("fromSeed", () => Bip32.fromSeed(SEED))
  bench("derive (1 nivel hardened)", () => MASTER.derive(0x80000000))
  bench("derivePath (m/44'/0'/0')", () => MASTER.derivePath("m/44'/0'/0'"))
  bench("toXpub (serialize)", () => MASTER.toXpub())
  bench("toXprv (serialize)", () => MASTER.toXprv())
  bench("fromXpub (deserialize)", () => Bip32.fromXpub(MASTER.toXpub()))
  bench("neuter (xprv → xpub)", () => MASTER.neuter())
  printRows()

  // ── BIP-44 ──
  printSection("BIP-44 Multi-Coin")
  bench("deriveKeys (m/44'/0'/0'/0/0)", () => Bip44.deriveKeys(SEED, 44, 0, 0, 0, 0))
  bench("accountXpub (m/44'/0'/0')", () => Bip44.accountXpub(SEED, 44, 0, 0))
  bench("fromMnemonicDerive (full pipeline)", () => Bip44.fromMnemonicDerive(MNEMONIC, "", 44, 0, 0, 0, 0))
  printRows()

  // ── Monitoreo de Memoria ──
  const finalHeap = process.memoryUsage().heapUsed
  const finalWasmPages = wasmMem.buffer.byteLength / 65536
  const finalWasmBytes = wasmMem.buffer.byteLength
  const wasmPagesGrow = finalWasmPages - initialWasmPages
  const wasmBytesGrow = finalWasmBytes - initialWasmBytes
  const heapDeltaMB = ((finalHeap - initialHeap) / (1024 * 1024)).toFixed(2)

  printSection("Estadísticas de Memoria & Zero-Alloc")
  console.log(`  WASM Memory Inicial     : ${initialWasmPages} páginas (${(initialWasmBytes / 1024).toFixed(0)} KB)`)
  console.log(`  WASM Memory Final       : ${finalWasmPages} páginas (${(finalWasmBytes / 1024).toFixed(0)} KB)`)
  console.log(`  WASM memory.grow        : ${wasmPagesGrow} páginas (${wasmBytesGrow} bytes) — ${wasmPagesGrow === 0 ? "✅ ZERO-GROW (Static Scratchpad)" : "⚠️ Creció"}`)
  console.log(`  Bun JS Heap Δ           : ${heapDeltaMB} MB (recolectable por GC)`)

  console.log(`\n✅ Benchmark completado con éxito.\n`)
}

main().catch((err) => {
  console.error("❌ Benchmark falló:", err)
  process.exit(1)
})
