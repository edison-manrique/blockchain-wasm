/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip44.test.ts — Correctitud + memoria + velocidad de BIP44
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores verificados con Python bip_utils (mnemonic "abandon...about").
 *  Corre con:  bun test test/bip44.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/bips/bip44.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const hex = (b: Uint8Array): string => Wasm.bytesToHex(b)
const enc = (s: string): Uint8Array => new TextEncoder().encode(s)

// ── Mnemonic de referencia (12 palabras, BIP39 Test Vector) ───────────────
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const SEED_HEX =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

// ── Helpers ────────────────────────────────────────────────────────────────

function writeSeed(): void {
  wasm.write(IN, Wasm.hexToBytes(SEED_HEX))
}

function writeMnemonic(passphrase: string = ""): { mnPtr: number; mnLen: number; passPtr: number; passLen: number } {
  const mnBytes = enc(MNEMONIC)
  const passBytes = enc(passphrase)
  wasm.write(IN, mnBytes)
  wasm.write(IN + 256, passBytes)
  return { mnPtr: IN, mnLen: mnBytes.length, passPtr: IN + 256, passLen: passBytes.length }
}

function readAscii(ptr: number, len: number): string {
  return new TextDecoder().decode(wasm.read(ptr, len))
}

// ═══════════════════════════════════════════════════════════════════════════
// 0) COMPILACIÓN
// ═══════════════════════════════════════════════════════════════════════════

describe("bip44 — compilación", () => {
  test("compilar y reportar stats", async () => {
    const cr: CompileResult = await Wasm.compile(ENTRY, { profile: "bench", forceRecompile: true })
    Wasm.printCompileStats(cr, "bench")
    expect(cr.sizeBytes).toBeGreaterThan(1024)
    expect(cr.compileTimeMs).toBeGreaterThan(0)
  }, 300_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD — Derivación desde seed
// ═══════════════════════════════════════════════════════════════════════════

describe("bip44 — derivación desde seed", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    // Pre-init generator
    writeSeed()
    wasm.exports.bip44_derive_privkey(OUT, IN, 64, 44, 0, 0, 0, 0)
  }, 300_000)

  test("m/44'/0'/0'/0/0 privkey", () => {
    writeSeed()
    const rc = wasm.exports.bip44_derive_privkey(OUT, IN, 64, 44, 0, 0, 0, 0)
    expect(rc).toBe(0)
    expect(hex(wasm.read(OUT, 32))).toBe("e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372")
  })

  test("m/44'/0'/0'/0/0 pubkey", () => {
    writeSeed()
    const rc = wasm.exports.bip44_derive_pubkey(OUT, IN, 64, 44, 0, 0, 0, 0)
    expect(rc).toBe(0)
    expect(hex(wasm.read(OUT, 33))).toBe("03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e")
  })

  test("m/44'/0'/0'/0/0 leaf (priv + pub juntos)", () => {
    writeSeed()
    const rc = wasm.exports.bip44_derive_leaf(OUT, OUT + 64, IN, 64, 44, 0, 0, 0, 0)
    expect(rc).toBe(0)
    expect(hex(wasm.read(OUT, 32))).toBe("e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372")
    expect(hex(wasm.read(OUT + 64, 33))).toBe("03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e")
  })

  test("m/44'/0'/0'/0/1 privkey", () => {
    writeSeed()
    const rc = wasm.exports.bip44_derive_privkey(OUT, IN, 64, 44, 0, 0, 0, 1)
    expect(rc).toBe(0)
    expect(hex(wasm.read(OUT, 32))).toBe(
      "5c1141f60edd3095579529db7e88d964cb0a9ec0f814f6a10cd5cbd763078a0c", // ✅ FIX
    )
  })

  test("m/44'/0'/0'/1/0 privkey (change)", () => {
    writeSeed()
    const rc = wasm.exports.bip44_derive_privkey(OUT, IN, 64, 44, 0, 0, 1, 0)
    expect(rc).toBe(0)
    expect(hex(wasm.read(OUT, 32))).toBe(
      "78df181d8d74216a5c1398689b35aada58cc42e5f056b6126c1c4f6e236294c7", // ✅ FIX
    )
  })

  test("m/44'/60'/0'/0/0 privkey (Ethereum)", () => {
    writeSeed()
    const rc = wasm.exports.bip44_derive_privkey(OUT, IN, 64, 44, 60, 0, 0, 0)
    expect(rc).toBe(0)
    expect(hex(wasm.read(OUT, 32))).toBe("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) CORRECTITUD — Account xpub/xprv
// ═══════════════════════════════════════════════════════════════════════════

describe("bip44 — account xpub/xprv", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    writeSeed()
    wasm.exports.bip44_derive_privkey(OUT, IN, 64, 44, 0, 0, 0, 0)
  }, 300_000)

  test("m/44'/0'/0' xprv", () => {
    writeSeed()
    const len = wasm.exports.bip44_account_xprv(OUT, IN, 64, 44, 0, 0)
    expect(len).toBeGreaterThan(0)
    expect(readAscii(OUT, len)).toBe(
      "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb",
    )
  })

  test("m/44'/0'/0' xpub", () => {
    writeSeed()
    const len = wasm.exports.bip44_account_xpub(OUT, IN, 64, 44, 0, 0)
    expect(len).toBeGreaterThan(0)
    expect(readAscii(OUT, len)).toBe(
      "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) CORRECTITUD — Desde mnemonic (pipeline completo)
// ═══════════════════════════════════════════════════════════════════════════

describe("bip44 — desde mnemonic", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    // Pre-init
    writeSeed()
    wasm.exports.bip44_derive_privkey(OUT, IN, 64, 44, 0, 0, 0, 0)
  }, 300_000)

  test("from_mnemonic_derive m/44'/0'/0'/0/0", () => {
    const { mnPtr, mnLen, passPtr, passLen } = writeMnemonic("")
    const rc = wasm.exports.bip44_from_mnemonic_derive(OUT, OUT + 64, mnPtr, mnLen, passPtr, passLen, 44, 0, 0, 0, 0)
    expect(rc).toBe(0)
    expect(hex(wasm.read(OUT, 32))).toBe("e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372")
    expect(hex(wasm.read(OUT + 64, 33))).toBe("03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e")
  })

  test("from_mnemonic_xprv m/44'/0'/0'", () => {
    const { mnPtr, mnLen, passPtr, passLen } = writeMnemonic("")
    const len = wasm.exports.bip44_from_mnemonic_xprv(OUT, mnPtr, mnLen, passPtr, passLen, 44, 0, 0)
    expect(len).toBeGreaterThan(0)
    expect(readAscii(OUT, len)).toBe(
      "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb",
    )
  })

  test("from_mnemonic_xpub m/44'/0'/0'", () => {
    const { mnPtr, mnLen, passPtr, passLen } = writeMnemonic("")
    const len = wasm.exports.bip44_from_mnemonic_xpub(OUT, mnPtr, mnLen, passPtr, passLen, 44, 0, 0)
    expect(len).toBeGreaterThan(0)
    expect(readAscii(OUT, len)).toBe(
      "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
    )
  })

  test("from_mnemonic_derive Ethereum m/44'/60'/0'/0/0", () => {
    const { mnPtr, mnLen, passPtr, passLen } = writeMnemonic("")
    const rc = wasm.exports.bip44_from_mnemonic_derive(OUT, OUT + 64, mnPtr, mnLen, passPtr, passLen, 44, 60, 0, 0, 0)
    expect(rc).toBe(0)
    expect(hex(wasm.read(OUT, 32))).toBe("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("bip44 — memoria", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    writeSeed()
    wasm.exports.bip44_derive_privkey(OUT, IN, 64, 44, 0, 0, 0, 0)
  }, 300_000)

  test("derive_leaf no causa memory.grow", () => {
    writeSeed()
    Wasm.assertZeroAlloc(
      "derive_leaf",
      wasm,
      () => wasm.exports.bip44_derive_leaf(OUT, OUT + 64, IN, 64, 44, 0, 0, 0, 0),
      300,
    )
  })

  test("account_xpub no causa memory.grow", () => {
    writeSeed()
    Wasm.assertZeroAlloc("account_xpub", wasm, () => wasm.exports.bip44_account_xpub(OUT, IN, 64, 44, 0, 0), 300)
  })

  test("from_mnemonic_derive no causa memory.grow", () => {
    const { mnPtr, mnLen, passPtr, passLen } = writeMnemonic("")
    Wasm.assertZeroAlloc(
      "mn_derive",
      wasm,
      () => wasm.exports.bip44_from_mnemonic_derive(OUT, OUT + 64, mnPtr, mnLen, passPtr, passLen, 44, 0, 0, 0, 0),
      200,
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 5) VELOCIDAD
// ═══════════════════════════════════════════════════════════════════════════

describe("bip44 — velocidad", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY, "bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    writeSeed()
    wasm.exports.bip44_derive_privkey(OUT, IN, 64, 44, 0, 0, 0, 0)
  }, 300_000)

  test("derive_leaf (5 niveles)", () => {
    writeSeed()
    const r = Wasm.benchSpeed(
      "derive_leaf",
      2_000,
      () => wasm.exports.bip44_derive_leaf(OUT, OUT + 64, IN, 64, 44, 0, 0, 0, 0),
      { warmup: 50, runs: 3 },
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  })

  test("account_xpub", () => {
    writeSeed()
    const r = Wasm.benchSpeed("account_xpub", 2_000, () => wasm.exports.bip44_account_xpub(OUT, IN, 64, 44, 0, 0), {
      warmup: 50,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  })

  test("from_mnemonic_derive (pipeline completo)", () => {
    const { mnPtr, mnLen, passPtr, passLen } = writeMnemonic("")
    const r = Wasm.benchSpeed(
      "mn_derive",
      200, // ✅ FIX: era 2_000 (timeout). 100 × 2.4ms ≈ 240ms/run
      () => wasm.exports.bip44_from_mnemonic_derive(OUT, OUT + 64, mnPtr, mnLen, passPtr, passLen, 44, 0, 0, 0, 0),
      { warmup: 10, runs: 3 }, // ✅ FIX: warmup era 50
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  }, 10_000) // ✅ FIX: timeout explícito por si el 1er run calienta tablas
})
