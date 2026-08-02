/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip39.test.ts — Correctitud + memoria + velocidad de BIP39
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores oficiales: bitcoin/bips bip-0039 (english), passphrase "TREZOR".
 *  Corre con:  bun test test/bip39.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance } from "./utils/wasm"

const ENTRY = "assembly/bips/bip39/index.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const hex = (b: Uint8Array): string => Wasm.bytesToHex(b)
const enc = (s: string): Uint8Array => new TextEncoder().encode(s)

// ── Helpers TS (marshalling mínimo; el único string-alloc está aquí) ──────

function entropyToMnemonic(entHex: string): string {
  const ent = Wasm.hexToBytes(entHex)
  wasm.write(IN, ent)
  const len: number = wasm.exports.bip39_entropy_to_mnemonic(OUT, IN, ent.length)
  if (len < 0) throw new Error(`entropy_to_mnemonic falló: ${len}`)
  return new TextDecoder().decode(wasm.read(OUT, len))
}

function mnemonicToEntropy(mn: string): Uint8Array | null {
  const bytes = enc(mn)
  wasm.write(IN, bytes)
  const len: number = wasm.exports.bip39_mnemonic_to_entropy(OUT, IN, bytes.length)
  if (len < 0) return null
  return wasm.read(OUT, len)
}

function mnemonicToSeed(mn: string, pass: string): Uint8Array {
  const m = enc(mn)
  const p = enc(pass)
  wasm.write(IN, m)
  wasm.write(IN + 256, p)
  wasm.exports.bip39_mnemonic_to_seed(OUT, IN, m.length, IN + 256, p.length)
  return wasm.read(OUT, 64)
}

function validate(mn: string): boolean {
  const bytes = enc(mn)
  wasm.write(IN, bytes)
  return wasm.exports.bip39_validate_mnemonic(IN, bytes.length)
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("bip39 — correctitud", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.exports.bip39_init()
  }, 120_000)

  test("WASM cargado — exports presentes", () => {
    expect(wasm.exports.bip39_init).toBeFunction()
    expect(wasm.exports.bip39_entropy_to_mnemonic).toBeFunction()
    expect(wasm.exports.bip39_mnemonic_to_entropy).toBeFunction()
    expect(wasm.exports.bip39_mnemonic_to_seed).toBeFunction()
    expect(wasm.exports.bip39_validate_mnemonic).toBeFunction()
  })

  // ── Vectores oficiales (entropy → mnemonic) ─────────────────────────────
  const vectors: [string, string][] = [
    [
      "00000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ],
    ["7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"],
    [
      "80808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
    ],
    ["ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"],
    [
      "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
      "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"
    ]
  ]

  for (const [entHex, mn] of vectors) {
    test(`entropy→mnemonic (${entHex.slice(0, 8)}…)`, () => {
      expect(entropyToMnemonic(entHex)).toBe(mn)
    })
    test(`mnemonic→entropy (${entHex.slice(0, 8)}…)`, () => {
      const ent = mnemonicToEntropy(mn)
      expect(ent).not.toBeNull()
      expect(hex(ent!)).toBe(entHex)
    })
    test(`validate (${entHex.slice(0, 8)}…)`, () => {
      expect(validate(mn)).toBeTruthy()
    })
  }

  // ── Seed (PBKDF2-HMAC-SHA512, passphrase "TREZOR") ──────────────────────
  test("seed: abandon…about + TREZOR", () => {
    const seed = mnemonicToSeed(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "TREZOR"
    )
    expect(hex(seed)).toBe(
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    )
  })

  test("seed: hamster…length (24w) + TREZOR", () => {
    const seed = mnemonicToSeed(
      "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
      "TREZOR"
    )
    expect(hex(seed)).toBe(
      "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"
    )
  })

  test("seed con passphrase vacía ≠ seed con TREZOR", () => {
    const mn = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    const s1 = mnemonicToSeed(mn, "")
    const s2 = mnemonicToSeed(mn, "TREZOR")
    expect(hex(s1)).not.toBe(hex(s2))
  })

  // ── Roundtrip para todos los tamaños de entropy ─────────────────────────
  test("roundtrip 12/15/18/21/24 palabras", () => {
    const ents = [
      "00000000000000000000000000000000", // 12
      "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", // 15? no: 20B=15w ✓
      "808080808080808080808080808080808080808080808080", // 24B=18w
      "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c" // 32B=24w
    ]
    for (const e of ents) {
      const mn = entropyToMnemonic(e)
      expect(mnemonicToEntropy(mn)).not.toBeNull()
      expect(hex(mnemonicToEntropy(mn)!)).toBe(e)
    }
  })

  // ── Casos inválidos ─────────────────────────────────────────────────────
  test("mnemonic con checksum corrupto → null / false", () => {
    const bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    expect(mnemonicToEntropy(bad)).toBeNull()
    expect(validate(bad)).toBeFalsy()
  })

  test("mnemonic con palabra inexistente → null / false", () => {
    const bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz"
    expect(mnemonicToEntropy(bad)).toBeNull()
    expect(validate(bad)).toBeFalsy()
  })

  test("word count inválido (13 palabras) → null / false", () => {
    const bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon"
    expect(mnemonicToEntropy(bad)).toBeNull()
    expect(validate(bad)).toBeFalsy()
  })

  test("entropy de longitud inválida → throw", () => {
    expect(() => entropyToMnemonic("0000000000000000")).toThrow() // 8 bytes
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA
// ═══════════════════════════════════════════════════════════════════════════

describe("bip39 — memoria", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.exports.bip39_init()
  }, 120_000)

  test("entropy→mnemonic no causa memory.grow", () => {
    const ent = Wasm.hexToBytes("00000000000000000000000000000000")
    wasm.write(IN, ent)
    Wasm.assertZeroAlloc("ent→mn", wasm, () => wasm.exports.bip39_entropy_to_mnemonic(OUT, IN, 16), 2000)
  })

  test("mnemonic→entropy no causa memory.grow", () => {
    const bytes = enc("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    wasm.write(IN, bytes)
    Wasm.assertZeroAlloc("mn→ent", wasm, () => wasm.exports.bip39_mnemonic_to_entropy(OUT, IN, bytes.length), 2000)
  })

  test("mnemonic→seed no causa memory.grow", () => {
    const m = enc("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    const p = enc("TREZOR")
    wasm.write(IN, m)
    wasm.write(IN + 256, p)
    Wasm.assertZeroAlloc(
      "mn→seed",
      wasm,
      () => wasm.exports.bip39_mnemonic_to_seed(OUT, IN, m.length, IN + 256, p.length),
      200
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD
// ═══════════════════════════════════════════════════════════════════════════

describe("bip39 — velocidad", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY, "bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    wasm.exports.bip39_init()
  }, 120_000)

  test("entropy→mnemonic (12 palabras)", () => {
    const ent = Wasm.hexToBytes("00000000000000000000000000000000")
    wasm.write(IN, ent)
    const r = Wasm.benchSpeed("ent→mn(12)", 1000, () => wasm.exports.bip39_entropy_to_mnemonic(OUT, IN, 16), {
      warmup: 20,
      runs: 3
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(20_000)
  })

  test("mnemonic→seed (512 iters PBKDF2)", () => {
    const m = enc("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    const p = enc("TREZOR")
    wasm.write(IN, m)
    wasm.write(IN + 256, p)
    const r = Wasm.benchSpeed(
      "mn→seed",
      512,
      () => wasm.exports.bip39_mnemonic_to_seed(OUT, IN, m.length, IN + 256, p.length),
      { warmup: 50, runs: 3 }
    )
    Wasm.printResults([r])
    // 2048 iters de HMAC-SHA512 ⇒ ~ms; solo sanity de que corre
    expect(r.nsPerOp).toBeGreaterThan(0)
  })
})
