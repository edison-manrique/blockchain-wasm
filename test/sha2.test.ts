/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  sha2.test.ts — Suite completa: correctitud + memoria + velocidad + stats
 * ═══════════════════════════════════════════════════════════════════════════
 *  Vectores: NIST FIPS 180-4 (SHA-256/512), RFC 4231 (HMAC), RFC 7914 §11
 *            (PBKDF2-HMAC-SHA256), RFC 6070 extendido (PBKDF2-HMAC-SHA512).
 *
 *  Corre con:  bun test test/sha2.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { Wasm, type WasmInstance, type CompileResult } from "./utils/wasm"

const ENTRY = "assembly/hash/sha2/index.ts"
let wasm: WasmInstance
let IN: number
let OUT: number

const enc = (s: string): Uint8Array => new TextEncoder().encode(s)
const hex = (bytes: Uint8Array): string => Wasm.bytesToHex(bytes)

// ═══════════════════════════════════════════════════════════════════════════
// 0) COMPILACIÓN — tamaños y tiempos por perfil
// ═══════════════════════════════════════════════════════════════════════════

describe("sha2 — compilación", () => {
  const profiles = ["test", "bench", "fast", "small"] as const

  test("compilar en 4 perfiles y reportar stats", async () => {
    console.log("\n═══ SHA2 — Compilation stats ═══")
    console.log(
      `${"Profile".padEnd(10)}  ${"Time".padStart(10)}  ${"Size".padStart(10)}  ${"Bytes".padStart(8)}  ${"Cached".padStart(6)}`,
    )
    console.log("─".repeat(52))

    for (const profile of profiles) {
      const cr: CompileResult = await Wasm.compile(ENTRY, { profile })
      Wasm.printCompileStats(cr, profile)
      // Sanity: el binario debe ser razonable (> 1 KB, < 100 KB)
      expect(cr.sizeBytes).toBeGreaterThan(1024)
      expect(cr.sizeBytes).toBeLessThan(102400)
      expect(cr.compileTimeMs).toBeGreaterThan(0)
      expect(cr.binary).toBeInstanceOf(Uint8Array)
    }
    console.log("")
  }, 300_000)

  test("binario bench es válido (magic + version)", async () => {
    const { binary } = await Wasm.compile(ENTRY, "bench")
    // WASM magic: \0asm
    expect(binary[0]).toBe(0x00)
    expect(binary[1]).toBe(0x61)
    expect(binary[2]).toBe(0x73)
    expect(binary[3]).toBe(0x6d)
    // Version 1
    expect(binary[4]).toBe(0x01)
    expect(binary[5]).toBe(0x00)
    expect(binary[6]).toBe(0x00)
    expect(binary[7]).toBe(0x00)
  }, 120_000)
})

// ═══════════════════════════════════════════════════════════════════════════
// 1) CORRECTITUD
// ═══════════════════════════════════════════════════════════════════════════

describe("sha2 — correctitud", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("WASM cargado — exports presentes", () => {
    expect(wasm.exports.sha256_hash_raw).toBeFunction()
    expect(wasm.exports.sha512_hash_raw).toBeFunction()
    expect(wasm.exports.sha256_hmac_raw).toBeFunction()
    expect(wasm.exports.sha512_hmac_raw).toBeFunction()
    expect(wasm.exports.sha256_hmac_verify_raw).toBeFunction()
    expect(wasm.exports.sha512_hmac_verify_raw).toBeFunction()
    expect(wasm.exports.sha256_pbkdf2_raw).toBeFunction()
    expect(wasm.exports.sha512_pbkdf2_raw).toBeFunction()
    expect(wasm.exports.sha256_create_ctx).toBeFunction()
    expect(wasm.exports.sha256_update_raw).toBeFunction()
    expect(wasm.exports.sha256_final_raw).toBeFunction()
    expect(wasm.exports.sha512_create_ctx).toBeFunction()
    expect(wasm.exports.sha512_update_raw).toBeFunction()
    expect(wasm.exports.sha512_final_raw).toBeFunction()
  })

  // ── SHA-256 (NIST FIPS 180-4) ─────────────────────────────────────────────
  const sha256Cases: [string, string, string][] = [
    ["vacío", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    ["abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
    [
      "448 bits",
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ],
    [
      "896 bits",
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ],
  ]
  for (const [name, msg, want] of sha256Cases) {
    test(`SHA256(${name})`, () => {
      const m = enc(msg)
      wasm.write(IN, m)
      wasm.exports.sha256_hash_raw(OUT, IN, m.length)
      expect(hex(wasm.read(OUT, 32))).toBe(want)
    })
  }

  // ── SHA-512 (NIST FIPS 180-4) ─────────────────────────────────────────────
  const sha512Cases: [string, string, string][] = [
    [
      "vacío",
      "",
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ],
    [
      "abc",
      "abc",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ],
    [
      "896 bits",
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    ],
  ]
  for (const [name, msg, want] of sha512Cases) {
    test(`SHA512(${name})`, () => {
      const m = enc(msg)
      wasm.write(IN, m)
      wasm.exports.sha512_hash_raw(OUT, IN, m.length)
      expect(hex(wasm.read(OUT, 64))).toBe(want)
    })
  }

  // ── HMAC-SHA256 (RFC 4231 casos 1, 2, 3) ──────────────────────────────────
  test("HMAC-SHA256 RFC4231 caso 1", () => {
    const key = new Uint8Array(20).fill(0x0b)
    const msg = enc("Hi There")
    wasm.write(IN, key)
    wasm.write(IN + 64, msg)
    wasm.exports.sha256_hmac_raw(OUT, IN, key.length, IN + 64, msg.length)
    expect(hex(wasm.read(OUT, 32))).toBe("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
  })

  test("HMAC-SHA256 RFC4231 caso 2 (Jefe)", () => {
    const key = enc("Jefe")
    const msg = enc("what do ya want for nothing?")
    wasm.write(IN, key)
    wasm.write(IN + 64, msg)
    wasm.exports.sha256_hmac_raw(OUT, IN, key.length, IN + 64, msg.length)
    expect(hex(wasm.read(OUT, 32))).toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
  })

  test("HMAC-SHA256 RFC4231 caso 3 (key=0xaa*20, data=0xdd*50)", () => {
    const key = new Uint8Array(20).fill(0xaa)
    const msg = new Uint8Array(50).fill(0xdd)
    wasm.write(IN, key)
    wasm.write(IN + 64, msg)
    wasm.exports.sha256_hmac_raw(OUT, IN, key.length, IN + 64, msg.length)
    expect(hex(wasm.read(OUT, 32))).toBe("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
  })

  // ── HMAC-SHA512 (RFC 4231 casos 1, 2, 3) ──────────────────────────────────
  test("HMAC-SHA512 RFC4231 caso 1", () => {
    const key = new Uint8Array(20).fill(0x0b)
    const msg = enc("Hi There")
    wasm.write(IN, key)
    wasm.write(IN + 128, msg)
    wasm.exports.sha512_hmac_raw(OUT, IN, key.length, IN + 128, msg.length)
    expect(hex(wasm.read(OUT, 64))).toBe(
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    )
  })

  test("HMAC-SHA512 RFC4231 caso 2 (Jefe)", () => {
    const key = enc("Jefe")
    const msg = enc("what do ya want for nothing?")
    wasm.write(IN, key)
    wasm.write(IN + 128, msg)
    wasm.exports.sha512_hmac_raw(OUT, IN, key.length, IN + 128, msg.length)
    expect(hex(wasm.read(OUT, 64))).toBe(
      "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    )
  })

  test("HMAC-SHA512 RFC4231 caso 3 (key=0xaa*20, data=0xdd*50)", () => {
    const key = new Uint8Array(20).fill(0xaa)
    const msg = new Uint8Array(50).fill(0xdd)
    wasm.write(IN, key)
    wasm.write(IN + 128, msg)
    wasm.exports.sha512_hmac_raw(OUT, IN, key.length, IN + 128, msg.length)
    expect(hex(wasm.read(OUT, 64))).toBe(
      "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    )
  })

  // ── HMAC verify (constant-time) ────────────────────────────────────────────
  test("HMAC-SHA256 verify (válida e inválida)", () => {
    const key = new Uint8Array(20).fill(0x0b)
    const msg = enc("Hi There")
    wasm.write(IN, key)
    wasm.write(IN + 64, msg)
    wasm.exports.sha256_hmac_raw(OUT, IN, key.length, IN + 64, msg.length)
    const mac = wasm.read(OUT, 32)
    wasm.write(IN + 128, mac)
    expect(wasm.exports.sha256_hmac_verify_raw(IN, key.length, IN + 64, msg.length, IN + 128, 32)).toBeTruthy()
    // MAC corrupto (flip primer byte)
    wasm.write(IN + 128, mac)
    wasm.u8[IN + 128] ^= 0xff
    wasm.syncViews()
    expect(wasm.exports.sha256_hmac_verify_raw(IN, key.length, IN + 64, msg.length, IN + 128, 32)).toBeFalsy()
  })

  test("HMAC-SHA512 verify (válida e inválida)", () => {
    const key = new Uint8Array(20).fill(0x0b)
    const msg = enc("Hi There")
    wasm.write(IN, key)
    wasm.write(IN + 128, msg)
    wasm.exports.sha512_hmac_raw(OUT, IN, key.length, IN + 128, msg.length)
    const mac = wasm.read(OUT, 64)
    wasm.write(IN + 256, mac)
    expect(wasm.exports.sha512_hmac_verify_raw(IN, key.length, IN + 128, msg.length, IN + 256, 64)).toBeTruthy()
    // MAC corrupto (flip último byte)
    wasm.write(IN + 256, mac)
    wasm.u8[IN + 256 + 63] ^= 0x01
    wasm.syncViews()
    expect(wasm.exports.sha512_hmac_verify_raw(IN, key.length, IN + 128, msg.length, IN + 256, 64)).toBeFalsy()
  })

  // ── PBKDF2-HMAC-SHA256 (RFC 7914 §11) ─────────────────────────────────────
  const pbkdf2Sha256Cases: [string, string, string, number, number, string][] = [
    [
      "c=1, dkLen=64",
      "passwd",
      "salt",
      1,
      64,
      "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
    ],
    [
      "c=2, dkLen=64",
      "passwd",
      "salt",
      2,
      64,
      "2d412f896e76685e30df569f0a740634e31f031f749d607d9e44210bffb91a6ab670f500c78862001959f7d7b9f96afb3605700298acb14427e0239463c66f20",
    ],
    [
      "c=4096, dkLen=32",
      "password",
      "salt",
      4096,
      32,
      "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
    ],
  ]
  for (const [name, pass, salt, iters, dkLen, want] of pbkdf2Sha256Cases) {
    test(`PBKDF2-SHA256 (${name})`, () => {
      const p = enc(pass)
      const s = enc(salt)
      wasm.write(IN, p)
      wasm.write(IN + 64, s)
      wasm.exports.sha256_pbkdf2_raw(OUT, IN, p.length, IN + 64, s.length, iters, dkLen)
      expect(hex(wasm.read(OUT, dkLen))).toBe(want)
    })
  }

  // ── PBKDF2-HMAC-SHA512 (RFC 6070 extendido) ───────────────────────────────
  const pbkdf2Sha512Cases: [string, string, string, number, number, string][] = [
    [
      "c=1, dkLen=64",
      "password",
      "salt",
      1,
      64,
      "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
    ],
    [
      "c=2, dkLen=64",
      "passwd",
      "salt",
      2,
      64,
      "422a2c609b7e035e154ad40236dc0d73983c6c7a46aa6136466e216b3be22896cf65c59be9216fc659736f14d29a7472862c7c261e8a2dd53cf2a67a73dcd275",
    ],
    [
      "c=4096, dkLen=64",
      "password",
      "salt",
      4096,
      64,
      "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5",
    ],
  ]
  for (const [name, pass, salt, iters, dkLen, want] of pbkdf2Sha512Cases) {
    test(`PBKDF2-SHA512 (${name})`, () => {
      const p = enc(pass)
      const s = enc(salt)
      wasm.write(IN, p)
      wasm.write(IN + 128, s)
      wasm.exports.sha512_pbkdf2_raw(OUT, IN, p.length, IN + 128, s.length, iters, dkLen)
      expect(hex(wasm.read(OUT, dkLen))).toBe(want)
    })
  }

  // ── Streaming SHA-256 == one-shot ─────────────────────────────────────────
  test("SHA256 streaming (3 fragmentos) == one-shot", () => {
    const msg = enc("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    // one-shot
    wasm.write(IN, msg)
    wasm.exports.sha256_hash_raw(OUT, IN, msg.length)
    const oneshot = hex(wasm.read(OUT, 32))
    // streaming: ctx en IN+256, padded en IN+256+112
    const ctx = IN + 256
    const padded = ctx + 112
    wasm.exports.sha256_create_ctx(ctx)
    wasm.exports.sha256_update_raw(ctx, IN, 20)
    wasm.exports.sha256_update_raw(ctx, IN + 20, 20)
    wasm.exports.sha256_update_raw(ctx, IN + 40, msg.length - 40)
    wasm.exports.sha256_final_raw(ctx, padded, OUT)
    expect(hex(wasm.read(OUT, 32))).toBe(oneshot)
  })

  // ── Streaming SHA-512 == one-shot ─────────────────────────────────────────
  test("SHA512 streaming (4 fragmentos) == one-shot", () => {
    const msg = enc(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    )
    // one-shot
    wasm.write(IN, msg)
    wasm.exports.sha512_hash_raw(OUT, IN, msg.length)
    const oneshot = hex(wasm.read(OUT, 64))
    // streaming: ctx en IN+256, padded en IN+256+208
    const ctx = IN + 256
    const padded = ctx + 208
    wasm.exports.sha512_create_ctx(ctx)
    wasm.exports.sha512_update_raw(ctx, IN, 30)
    wasm.exports.sha512_update_raw(ctx, IN + 30, 30)
    wasm.exports.sha512_update_raw(ctx, IN + 60, 30)
    wasm.exports.sha512_update_raw(ctx, IN + 90, msg.length - 90)
    wasm.exports.sha512_final_raw(ctx, padded, OUT)
    expect(hex(wasm.read(OUT, 64))).toBe(oneshot)
  })

  // ── Edge case: mensaje de exactamente 1 bloque ────────────────────────────
  test("SHA256(64 bytes = 1 bloque exacto)", () => {
    const msg = new Uint8Array(64).fill(0x61) // 64 × 'a'
    wasm.write(IN, msg)
    wasm.exports.sha256_hash_raw(OUT, IN, msg.length)
    // Vector precalculado con Node.js crypto
    expect(hex(wasm.read(OUT, 32))).toBe("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb")
  })

  test("SHA256(55 bytes = padding en mismo bloque)", () => {
    const msg = new Uint8Array(55).fill(0x62) // 55 × 'b'
    wasm.write(IN, msg)
    wasm.exports.sha256_hash_raw(OUT, IN, msg.length)
    expect(hex(wasm.read(OUT, 32))).toBe("eb2c86e932179f4ba13fe8715a26124b77d6bad290b9b4c1cc140cf633300c19")
  })

  test("SHA256(56 bytes = padding fuerza 2 bloques)", () => {
    const msg = new Uint8Array(56).fill(0x63) // 56 × 'c'
    wasm.write(IN, msg)
    wasm.exports.sha256_hash_raw(OUT, IN, msg.length)
    expect(hex(wasm.read(OUT, 32))).toBe("f6c7b87acd114115d66897c8cb138c16a8b886673d1b93737f4918be472ea878")
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 2) MEMORIA (zero-alloc)
// ═══════════════════════════════════════════════════════════════════════════

describe("sha2 — memoria", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY)
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("sha256/sha512 no causan memory.grow", () => {
    const msg = enc("abc")
    wasm.write(IN, msg)
    Wasm.assertZeroAlloc("sha256", wasm, () => wasm.exports.sha256_hash_raw(OUT, IN, msg.length), 2000)
    Wasm.assertZeroAlloc("sha512", wasm, () => wasm.exports.sha512_hash_raw(OUT, IN, msg.length), 2000)
  })

  test("hmac256/hmac512 no causan memory.grow", () => {
    const key = new Uint8Array(20).fill(0x0b)
    const msg = enc("Hi There")
    wasm.write(IN, key)
    wasm.write(IN + 64, msg)
    Wasm.assertZeroAlloc("hmac256", wasm, () => wasm.exports.sha256_hmac_raw(OUT, IN, 20, IN + 64, msg.length), 1000)
    wasm.write(IN + 128, msg)
    Wasm.assertZeroAlloc("hmac512", wasm, () => wasm.exports.sha512_hmac_raw(OUT, IN, 20, IN + 128, msg.length), 1000)
  })

  test("pbkdf2-sha256 no causa memory.grow", () => {
    const pass = enc("passwd")
    const salt = enc("salt")
    wasm.write(IN, pass)
    wasm.write(IN + 64, salt)
    Wasm.assertZeroAlloc(
      "pbkdf2-256",
      wasm,
      () => wasm.exports.sha256_pbkdf2_raw(OUT, IN, pass.length, IN + 64, salt.length, 4, 32),
      200,
    )
  })

  test("pbkdf2-sha512 no causa memory.grow", () => {
    const pass = enc("password")
    const salt = enc("salt")
    wasm.write(IN, pass)
    wasm.write(IN + 128, salt)
    Wasm.assertZeroAlloc(
      "pbkdf2-512",
      wasm,
      () => wasm.exports.sha512_pbkdf2_raw(OUT, IN, pass.length, IN + 128, salt.length, 4, 64),
      200,
    )
  })

  test("streaming sha256 no causa memory.grow", () => {
    const ctx = IN + 256
    const padded = ctx + 112
    const msg = new Uint8Array(100).fill(0x42)
    wasm.write(IN, msg)
    Wasm.assertZeroAlloc(
      "stream256",
      wasm,
      () => {
        wasm.exports.sha256_create_ctx(ctx)
        wasm.exports.sha256_update_raw(ctx, IN, 100)
        wasm.exports.sha256_final_raw(ctx, padded, OUT)
      },
      500,
    )
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 3) VELOCIDAD (throughput + latencia)
// ═══════════════════════════════════════════════════════════════════════════

describe("sha2 — velocidad", () => {
  beforeAll(async () => {
    wasm = await Wasm.compileAndLoad(ENTRY, "bench")
    IN = wasm.num("PARAM_IN_PTR")
    OUT = wasm.num("PARAM_OUT_PTR")
  }, 120_000)

  test("throughput hash (1 KB)", () => {
    const msg = new Uint8Array(1024).fill(0x61)
    wasm.write(IN, msg)
    const results = Wasm.benchSuite(
      [
        { name: "sha256(1KB)", fn: () => wasm.exports.sha256_hash_raw(OUT, IN, msg.length), iterations: 50_000 },
        { name: "sha512(1KB)", fn: () => wasm.exports.sha512_hash_raw(OUT, IN, msg.length), iterations: 50_000 },
      ],
      10_000,
      { warmup: 1000, runs: 3 },
    )
    Wasm.printResults(results)
    const s256 = results.find((r) => r.name === "sha256(1KB)")!
    const s512 = results.find((r) => r.name === "sha512(1KB)")!
    expect(s256.nsPerOp).toBeLessThan(50_000)
    expect(s512.nsPerOp).toBeLessThan(50_000)
    expect(s256.cvPct).toBeLessThan(15)
    expect(s512.cvPct).toBeLessThan(15)
  })

  test("throughput hash (64 B = 1 bloque)", () => {
    const msg = new Uint8Array(64).fill(0x62)
    wasm.write(IN, msg)
    const results = Wasm.benchSuite(
      [
        { name: "sha256(64B)", fn: () => wasm.exports.sha256_hash_raw(OUT, IN, 64), iterations: 200_000 },
        { name: "sha512(128B)", fn: () => wasm.exports.sha512_hash_raw(OUT, IN, 128), iterations: 200_000 },
      ],
      50_000,
      { warmup: 2000, runs: 3 },
    )
    Wasm.printResults(results)
    const s256 = results.find((r) => r.name === "sha256(64B)")!
    expect(s256.nsPerOp).toBeLessThan(5_000) // < 5 µs por bloque
  })

  test("latencia HMAC-SHA256 (msg corto)", () => {
    const key = new Uint8Array(32).fill(0x0b)
    const msg = enc("attack at dawn")
    wasm.write(IN, key)
    wasm.write(IN + 64, msg)
    const r = Wasm.benchSpeed(
      "hmac256(short)",
      100_000,
      () => wasm.exports.sha256_hmac_raw(OUT, IN, 32, IN + 64, msg.length),
      { warmup: 2000, runs: 3 },
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(20_000) // < 20 µs
  })

  test("latencia PBKDF2-SHA256 (c=1)", () => {
    const pass = enc("passwd")
    const salt = enc("salt")
    wasm.write(IN, pass)
    wasm.write(IN + 64, salt)
    const r = Wasm.benchSpeed(
      "pbkdf2-256(c=1)",
      50_000,
      () => wasm.exports.sha256_pbkdf2_raw(OUT, IN, pass.length, IN + 64, salt.length, 1, 64),
      { warmup: 1000, runs: 3 },
    )
    Wasm.printResults([r])
    expect(r.nsPerOp).toBeLessThan(50_000) // < 50 µs por iteración única
  })

  test("comparativa: sha256 vs sha512 (1 KB)", () => {
    const msg = new Uint8Array(1024).fill(0x63)
    wasm.write(IN, msg)
    const cmp = Wasm.benchCompare(
      "sha256",
      () => wasm.exports.sha256_hash_raw(OUT, IN, 1024),
      "sha512",
      () => wasm.exports.sha512_hash_raw(OUT, IN, 1024),
      50_000,
      { warmup: 1000, runs: 3 },
    )
    console.log(`\n  sha256/sha512 ratio: ${cmp.ratio.toFixed(3)}x → winner: ${cmp.winner}\n`)
    // SHA-512 usa registros de 64 bits → suele ser más rápido en WASM64 o igual
    expect(cmp.ratio).toBeGreaterThan(0.3) // sanity: no más de 3x más lento
    expect(cmp.ratio).toBeLessThan(3.0)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// 4) COMPILACIÓN COMPARADA (bench vs small)
// ═══════════════════════════════════════════════════════════════════════════

describe("sha2 — compile compare", () => {
  test("bench vs small: tamaño y velocidad", async () => {
    const report = await Wasm.benchCompileCompare(
      ENTRY,
      { label: "bench", opts: "bench" },
      { label: "small", opts: "small" },
      (w) => {
        const inPtr = w.num("PARAM_IN_PTR")
        const outPtr = w.num("PARAM_OUT_PTR")
        const msg = new Uint8Array(256).fill(0x61)
        w.write(inPtr, msg)
        return () => w.exports.sha256_hash_raw(outPtr, inPtr, 256)
      },
      100_000,
      { warmup: 1000, runs: 3 },
    )
    Wasm.printCompileCompare(report)
    // Sanity: ambos compilan y producen binarios válidos
    expect(report.a.sizeBytes).toBeGreaterThan(1024)
    expect(report.b.sizeBytes).toBeGreaterThan(1024)
    expect(report.speedRatio).toBeGreaterThan(0.5)
    expect(report.speedRatio).toBeLessThan(2.0)
  }, 300_000)
})
