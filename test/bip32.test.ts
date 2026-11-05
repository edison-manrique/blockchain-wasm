/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bip32.test.ts — Correctitud + memoria + velocidad de BIP32
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores oficiales: BIP32 Test Vector 1, 2, 3 (bitcoin/bips/bip-0032).
 *  Corre con:  bun test test/bip32.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/bips/bip32/index.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const hex = (b: Uint8Array): string => Wasm.bytesToHex(b)

// ── Offsets del xkey (de constants.ts) ─────────────────────────────────────
const OFF_CHAIN = 16
const OFF_KEY = 48

// ── Helpers TS ─────────────────────────────────────────────────────────────

function readChain(xkeyPtr: number): string {
  return hex(wasm.read(xkeyPtr + OFF_CHAIN, 32))
}
function readPriv(xkeyPtr: number): string {
  return hex(wasm.read(xkeyPtr + OFF_KEY, 32))
}
function readPub(xkeyPtr: number): string {
  return hex(wasm.read(xkeyPtr + OFF_KEY, 33))
}

function fromSeed(seedHex: string, xkeyPtr: number): void {
  const seed = Wasm.hexToBytes(seedHex)
  wasm.write(IN, seed)
  const rc = wasm.exports.bip32_from_seed(xkeyPtr, IN, seed.length) // ✅ FIX: seed.length
  expect(rc).toBe(0)
}

function derive(childPtr: number, parentPtr: number, index: number): void {
  const rc = wasm.exports.bip32_derive(childPtr, parentPtr, index)
  expect(rc).toBe(0)
}

function derivePathStr(childPtr: number, parentPtr: number, path: string): void {
  const pathBytes = new TextEncoder().encode(path)
  wasm.write(IN + 128, pathBytes)
  const rc = wasm.exports.bip32_derive_path(childPtr, parentPtr, IN + 128, pathBytes.length)
  expect(rc).toBe(0)
}

function getPubkey(outPtr: number, xkeyPtr: number): void {
  const rc = wasm.exports.bip32_get_pubkey(outPtr, xkeyPtr)
  expect(rc).toBe(0)
}

// ═══════════════════════════════════════════════════════════════════════════
// 0) COMPILACIÓN
// ═══════════════════════════════════════════════════════════════════════════

describe("bip32 — compilación", () => {
  test("compilar y reportar stats", async () => {
    const cr: CompileResult = await Wasm.compile(ENTRY, { profile: "bench" })
    Wasm.printCompileStats(cr, "bench")
    expect(cr.sizeBytes).toBeGreaterThan(1024)
    expect(cr.compileTimeMs).toBeGreaterThan(0)
  }, 300_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD — BIP32 Test Vector 1
// ═══════════════════════════════════════════════════════════════════════════

describe("bip32 — Test Vector 1", () => {
  const SEED1 = "000102030405060708090a0b0c0d0e0f"
  const SEED1_LEN = 16
  // Xkeys en PARAM_IN (master) y PARAM_OUT (child), alternando
  const MASTER = 0 // relativo a IN
  const CHILD = 512 // relativo a OUT (wasm.num("PARAM_OUT_PTR"))

  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    // Pre-inicializar tablas del generator (absorbe el costo de init)
    const seed = Wasm.hexToBytes(SEED1)
    wasm.write(IN, seed)
    wasm.exports.bip32_from_seed(IN, IN, SEED1_LEN)
  }, 300_000)

  test("fromSeed → master", () => {
    fromSeed(SEED1, IN)
    expect(readChain(IN)).toBe("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
    expect(readPriv(IN)).toBe("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
    expect(wasm.exports.bip32_xkey_depth(IN)).toBe(0)
    expect(wasm.exports.bip32_xkey_is_private(IN)).toBe(1)
  })

  test("master pubkey", () => {
    fromSeed(SEED1, IN)
    getPubkey(OUT, IN)
    expect(hex(wasm.read(OUT, 33))).toBe("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
  })

  test("master fingerprint = 0x3442193e", () => {
    fromSeed(SEED1, IN)
    getPubkey(OUT, IN)
    const fp: number = wasm.exports.bip32_fingerprint(OUT)
    expect(fp).toBe(0x3442193e)
  })

  test("m/0' (hardened)", () => {
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000) // 0'
    expect(readChain(OUT)).toBe("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141")
    expect(readPriv(OUT)).toBe("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
    expect(wasm.exports.bip32_xkey_depth(OUT)).toBe(1)
    // ✅ FIX (>>> 0 convierte i32 signed → u32 unsigned):
    expect(wasm.exports.bip32_xkey_child_index(OUT) >>> 0).toBe(0x80000000)
    expect(wasm.exports.bip32_xkey_parent_fp(OUT)).toBe(0x3442193e)
  })

  test("m/0'/1 (non-hardened)", () => {
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000) // m/0'
    derive(IN, OUT, 1) // m/0'/1 (IN ahora es child, OUT es parent)
    // Resultado en IN
    expect(readChain(IN)).toBe("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19")
    expect(readPriv(IN)).toBe("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")
    expect(wasm.exports.bip32_xkey_depth(IN)).toBe(2)
  })

  test("m/0'/1 pubkey", () => {
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000)
    derive(IN, OUT, 1)
    getPubkey(OUT, IN)
    expect(hex(wasm.read(OUT, 33))).toBe("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")
  })

  test("m/0'/1/2' (hardened)", () => {
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000)
    derive(IN, OUT, 1)
    derive(OUT, IN, 2 + 0x80000000) // 2'
    expect(readChain(OUT)).toBe("04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f")
    expect(readPriv(OUT)).toBe("cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca")
  })

  test("m/0'/1/2'/2", () => {
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000)
    derive(IN, OUT, 1)
    derive(OUT, IN, 2 + 0x80000000)
    derive(IN, OUT, 2)
    expect(readChain(IN)).toBe("cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd")
    expect(readPriv(IN)).toBe("0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4")
  })

  test("m/0'/1/2'/2/1000000000", () => {
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000)
    derive(IN, OUT, 1)
    derive(OUT, IN, 2 + 0x80000000)
    derive(IN, OUT, 2)
    derive(OUT, IN, 1000000000)
    expect(readChain(OUT)).toBe("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e")
    expect(readPriv(OUT)).toBe("471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8")
  })

  test("derivePath 'm/0'/1/2'/2/1000000000'", () => {
    fromSeed(SEED1, IN)
    derivePathStr(OUT, IN, "m/0'/1/2'/2/1000000000")
    expect(readChain(OUT)).toBe("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e")
    expect(readPriv(OUT)).toBe("471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8")
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) CORRECTITUD — Test Vector 2 y 3 (master)
// ═══════════════════════════════════════════════════════════════════════════

describe("bip32 — Test Vectors 2 y 3", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    // Pre-init generator
    const seed = Wasm.hexToBytes("000102030405060708090a0b0c0d0e0f")
    wasm.write(IN, seed)
    wasm.exports.bip32_from_seed(IN, IN, seed.length)
  }, 300_000)

  test("Test Vector 2 — master", () => {
    fromSeed(
      "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
      IN,
    )
    expect(readChain(IN)).toBe("60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689")
    expect(readPriv(IN)).toBe("4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e")
  })

  test("Test Vector 3 — master", () => {
    fromSeed(
      "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
      IN,
    )
    expect(readChain(IN)).toBe("01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f")
    expect(readPriv(IN)).toBe("00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32")
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) CORRECTITUD — Neuter + derivación pública
// ═══════════════════════════════════════════════════════════════════════════

describe("bip32 — neuter y derivación pública", () => {
  const SEED1 = "000102030405060708090a0b0c0d0e0f"
  const SEED1_LEN = 16

  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    const seed = Wasm.hexToBytes(SEED1)
    wasm.write(IN, seed)
    wasm.exports.bip32_from_seed(IN, IN, SEED1_LEN)
  }, 300_000)

  test("neuter(master) → xpub", () => {
    fromSeed(SEED1, IN)
    const rc = wasm.exports.bip32_neuter(OUT, IN)
    expect(rc).toBe(0)
    expect(wasm.exports.bip32_xkey_is_private(OUT)).toBe(0)
    // chainCode debe ser el mismo
    expect(readChain(OUT)).toBe(readChain(IN))
    // keyData debe ser la pubkey (33 B)
    expect(readPub(OUT)).toBe("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
  })

  test("derivación pública conmuta con neuter (non-hardened)", () => {
    // Ruta: m/0' (hardened, desde priv) → m/0'/1 (non-hardened)
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000) // m/0' (priv)

    // Camino A: derivar m/0'/1 desde priv, luego neuter
    derive(IN, OUT, 1) // m/0'/1 (priv) en IN
    wasm.exports.bip32_neuter(OUT, IN) // neuter → xpub en OUT
    const pubA_chain = readChain(OUT)
    const pubA_key = readPub(OUT)

    // Camino B: neuter m/0', luego derivar m/0'/1 desde pub
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000) // m/0' (priv) en OUT
    wasm.exports.bip32_neuter(IN, OUT) // neuter m/0' → xpub en IN
    derive(OUT, IN, 1) // m/0'/1 desde xpub → en OUT

    // Ambos caminos deben dar el mismo resultado
    expect(readChain(OUT)).toBe(pubA_chain)
    expect(readPub(OUT)).toBe(pubA_key)
  })

  test("hardened desde xpub → error", () => {
    fromSeed(SEED1, IN)
    wasm.exports.bip32_neuter(OUT, IN) // xpub en OUT
    const rc = wasm.exports.bip32_derive(IN, OUT, 0x80000000) // 0' desde xpub
    expect(rc).toBe(-3) // BIP32_ERR_HARDENED_FROM_PUB
  })

  test("derivePath desde xpub (non-hardened path)", () => {
    // m/0' desde priv, neuter, luego derivar "0/1" desde xpub
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000)
    wasm.exports.bip32_neuter(IN, OUT) // xpub de m/0' en IN
    derivePathStr(OUT, IN, "0/1")
    expect(wasm.exports.bip32_xkey_is_private(OUT)).toBe(0)
    expect(wasm.exports.bip32_xkey_depth(OUT)).toBe(3) // m/0' + 0 + 1
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) CORRECTITUD — BIP44 helpers
// ═══════════════════════════════════════════════════════════════════════════

describe("bip32 — BIP44 helpers", () => {
  const SEED1 = "000102030405060708090a0b0c0d0e0f"
  const SEED1_LEN = 16

  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    const seed = Wasm.hexToBytes(SEED1)
    wasm.write(IN, seed)
    wasm.exports.bip32_from_seed(IN, IN, SEED1_LEN)
  }, 300_000)

  test("deriveAccount(44', 0', 0') == derivePath(\"m/44'/0'/0'\")", () => {
    fromSeed(SEED1, IN)
    wasm.exports.bip32_derive_account(OUT, IN, 44, 0, 0)
    const chainA = readChain(OUT)
    const privA = readPriv(OUT)

    fromSeed(SEED1, IN)
    derivePathStr(OUT, IN, "m/44'/0'/0'")
    expect(readChain(OUT)).toBe(chainA)
    expect(readPriv(OUT)).toBe(privA)
  })

  test("deriveAddress(44', 0', 0', 0, 0) == derivePath(\"m/44'/0'/0'/0/0\")", () => {
    fromSeed(SEED1, IN)
    wasm.exports.bip32_derive_address(OUT, IN, 44, 0, 0, 0, 0)
    const chainA = readChain(OUT)
    const privA = readPriv(OUT)

    fromSeed(SEED1, IN)
    derivePathStr(OUT, IN, "m/44'/0'/0'/0/0")
    expect(readChain(OUT)).toBe(chainA)
    expect(readPriv(OUT)).toBe(privA)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 7) SERIALIZACIÓN xpub/xprv
// ═══════════════════════════════════════════════════════════════════════════

describe("bip32 — serialización xpub/xprv", () => {
  const SEED1 = "000102030405060708090a0b0c0d0e0f"

  function readAscii(ptr: number, len: number): string {
    return new TextDecoder().decode(wasm.read(ptr, len))
  }

  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    const seed = Wasm.hexToBytes(SEED1)
    wasm.write(IN, seed)
    wasm.exports.bip32_from_seed(IN, IN, 16)
  }, 300_000)

  test("master xprv", () => {
    fromSeed(SEED1, IN)
    const len = wasm.exports.bip32_serialize_xprv(OUT, IN)
    expect(len).toBeGreaterThan(0)
    expect(readAscii(OUT, len)).toBe(
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
    )
  })

  test("master xpub", () => {
    fromSeed(SEED1, IN)
    const len = wasm.exports.bip32_serialize_xpub(OUT, IN)
    expect(len).toBeGreaterThan(0)
    expect(readAscii(OUT, len)).toBe(
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    )
  })

  test("m/0' xprv", () => {
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000)
    const len = wasm.exports.bip32_serialize_xprv(OUT, OUT)
    expect(readAscii(OUT, len)).toBe(
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
    )
  })

  test("m/0' xpub", () => {
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000)
    const len = wasm.exports.bip32_serialize_xpub(OUT, OUT)
    expect(readAscii(OUT, len)).toBe(
      "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    )
  })

  test("xprv desde clave pública → error", () => {
    fromSeed(SEED1, IN)
    wasm.exports.bip32_neuter(OUT, IN) // xpub en OUT
    const rc = wasm.exports.bip32_serialize_xprv(OUT, OUT)
    expect(rc).toBe(-6) // BIP32_ERR_NOT_PRIVATE
  })

  test("roundtrip: deserialize(serialize(master)) == master", () => {
    fromSeed(SEED1, IN) // master en IN
    const chainBefore = readChain(IN)
    const privBefore = readPriv(IN)

    // serialize → ASCII en OUT
    const len = wasm.exports.bip32_serialize_xprv(OUT, IN)
    expect(len).toBeGreaterThan(0)

    // deserialize → xkey en IN (sobreescribe master)
    const rc = wasm.exports.bip32_deserialize(IN, OUT, len)
    expect(rc).toBe(0)

    expect(readChain(IN)).toBe(chainBefore)
    expect(readPriv(IN)).toBe(privBefore)
    expect(wasm.exports.bip32_xkey_depth(IN)).toBe(0)
    expect(wasm.exports.bip32_xkey_is_private(IN)).toBe(1)
  })

  test("roundtrip xpub: deserialize(serialize(m/0')) == m/0' neutered", () => {
    fromSeed(SEED1, IN)
    derive(OUT, IN, 0x80000000) // m/0' priv en OUT

    // serialize xpub
    const len = wasm.exports.bip32_serialize_xpub(OUT, OUT)

    // deserialize → xkey en IN
    const rc = wasm.exports.bip32_deserialize(IN, OUT, len)
    expect(rc).toBe(0)
    expect(wasm.exports.bip32_xkey_is_private(IN)).toBe(0)
    expect(wasm.exports.bip32_xkey_depth(IN)).toBe(1)

    // pubkey debe coincidir con la de m/0'
    fromSeed(SEED1, IN + 128) // master temporal en IN+128
    derive(OUT, IN + 128, 0x80000000) // m/0' en OUT
    getPubkey(OUT + 128, OUT) // pubkey en OUT+128
    expect(hex(wasm.read(IN + 48, 33))).toBe(hex(wasm.read(OUT + 128, 33)))
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 5) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("bip32 — memoria", () => {
  const SEED1 = "000102030405060708090a0b0c0d0e0f"
  const SEED1_LEN = 16

  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    // Pre-init generator
    const seed = Wasm.hexToBytes(SEED1)
    wasm.write(IN, seed)
    wasm.exports.bip32_from_seed(IN, IN, SEED1_LEN)
  }, 300_000)

  test("fromSeed no causa memory.grow", () => {
    const seed = Wasm.hexToBytes(SEED1)
    wasm.write(IN, seed)
    Wasm.assertZeroAlloc("fromSeed", wasm, () => wasm.exports.bip32_from_seed(OUT, IN, SEED1_LEN), 1000)
  })

  test("derive (hardened) no causa memory.grow", () => {
    fromSeed(SEED1, IN)
    Wasm.assertZeroAlloc("ckdPriv-h", wasm, () => wasm.exports.bip32_derive(OUT, IN, 0x80000000), 500)
  })

  test("derive (non-hardened) no causa memory.grow", () => {
    fromSeed(SEED1, IN)
    wasm.exports.bip32_derive(OUT, IN, 0x80000000)
    Wasm.assertZeroAlloc("ckdPriv-nh", wasm, () => wasm.exports.bip32_derive(IN, OUT, 1), 500)
  })

  test("derivePath no causa memory.grow", () => {
    fromSeed(SEED1, IN)
    const pathBytes = new TextEncoder().encode("m/0'/1")
    wasm.write(IN + 128, pathBytes)
    Wasm.assertZeroAlloc(
      "derivePath",
      wasm,
      () => wasm.exports.bip32_derive_path(OUT, IN, IN + 128, pathBytes.length),
      300,
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 6) VELOCIDAD
// ═══════════════════════════════════════════════════════════════════════════

describe("bip32 — velocidad", () => {
  const SEED1 = "000102030405060708090a0b0c0d0e0f"
  const SEED1_LEN = 16

  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY, "bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
    // Pre-init generator
    const seed = Wasm.hexToBytes(SEED1)
    wasm.write(IN, seed)
    wasm.exports.bip32_from_seed(IN, IN, SEED1_LEN)
  }, 200_000)

  test("fromSeed", () => {
    const seed = Wasm.hexToBytes(SEED1)
    wasm.write(IN, seed)
    const r = Wasm.benchSpeed("fromSeed", 25_000, () => wasm.exports.bip32_from_seed(OUT, IN, SEED1_LEN), {
      warmup: 100,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(20_000)
  })

  test("derive non-hardened (incluye multiplyG)", () => {
    fromSeed(SEED1, IN)
    wasm.exports.bip32_derive(OUT, IN, 0x80000000) // m/0'
    const r = Wasm.benchSpeed("derive-nh", 5_000, () => wasm.exports.bip32_derive(IN, OUT, 1), {
      warmup: 50,
      runs: 3,
    })
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(500_000) // < 0.5 ms
  })

  test("derivePath m/44'/0'/0'/0/0", () => {
    fromSeed(SEED1, IN)
    const pathBytes = new TextEncoder().encode("m/44'/0'/0'/0/0")
    wasm.write(IN + 128, pathBytes)
    const r = Wasm.benchSpeed(
      "derivePath",
      2_000,
      () => wasm.exports.bip32_derive_path(OUT, IN, IN + 128, pathBytes.length),
      { warmup: 50, runs: 3 },
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeGreaterThan(0)
  })
})
