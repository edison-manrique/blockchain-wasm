/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  encoding-worker.js — Bench WASM vs JS + fuzz de roundtrips (off-thread)
 * ═══════════════════════════════════════════════════════════════════════════
 *  Comandos:
 *    { command:"bench" }            → { type:"result", row, opsPerSec } ×5 + done
 *    { command:"fuzz", count }      → progress + { type:"fuzz-done", mismatches }
 *
 *  Fuzz cross-valida: Base58 WASM ≡ JS BigInt, Base58Check roundtrip WASM,
 *  Bech32/Bech32m roundtrip JS. Carga su propia instancia WASM.
 */
import { BlockchainWasm } from "../../dist/index.js";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

// ── JS de referencia ──
function jsB58Enc(bytes) {
  let z = 0; while (z < bytes.length && bytes[z] === 0) z++;
  let n = 0n; for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  return "1".repeat(z) + s;
}
function jsB58Dec(str) {
  let z = 0; while (z < str.length && str[z] === "1") z++;
  let n = 0n;
  for (const c of str) n = n * 58n + BigInt(B58.indexOf(c));
  const out = [];
  while (n > 0n) { out.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (let i = 0; i < z; i++) out.unshift(0);
  return new Uint8Array(out);
}
function polymod(v) {
  let chk = 1;
  for (const x of v) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ x;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
function hrpExpand(hrp) {
  const o = [];
  for (const c of hrp) o.push(c.charCodeAt(0) >>> 5);
  o.push(0);
  for (const c of hrp) o.push(c.charCodeAt(0) & 31);
  return o;
}
function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0; const out = []; const maxv = (1 << to) - 1;
  for (const b of data) {
    acc = (acc << from) | b; bits += from;
    while (bits >= to) { bits -= to; out.push((acc >>> bits) & maxv); }
  }
  if (pad && bits > 0) out.push((acc << (to - bits)) & maxv);
  return out;
}
function bechEnc(hrp, ver, prog, spec) {
  const target = spec === "bech32m" ? 0x2bc830a3 : 1;
  const d5 = [ver, ...convertBits(prog, 8, 5, true)];
  const mod = (polymod([...hrpExpand(hrp), ...d5, 0, 0, 0, 0, 0, 0]) ^ target) >>> 0;
  const chk = []; for (let i = 0; i < 6; i++) chk.push((mod >>> (5 * (5 - i))) & 31);
  return hrp + "1" + [...d5, ...chk].map((v) => CHARSET[v]).join("");
}
function bechDec(s) {
  const pos = s.lastIndexOf("1");
  const hrp = s.slice(0, pos);
  const data = [...s.slice(pos + 1)].map((c) => CHARSET.indexOf(c));
  if (data.some((v) => v < 0) || data.length < 6) return null;
  const pm = polymod([...hrpExpand(hrp), ...data]);
  if (pm !== 1 && pm !== 0x2bc830a3) return null;
  const d5 = data.slice(0, -6);
  return { hrp, ver: d5[0], prog: new Uint8Array(convertBits(d5.slice(1), 5, 8, false)) };
}
const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

// ── WASM ──
let ctx = null;
async function ensure() {
  if (!ctx) {
    await BlockchainWasm.fromUrl("../../dist/blockchain.wasm");
    const bw = BlockchainWasm.getInstance();
    ctx = { a: bw.getAllocator(), exp: bw.getExports(), dec: new TextDecoder() };
  }
  return ctx;
}
function wasmB58Str(a, exp, n) {
  exp.base58_indices_to_ascii(a.outPtr, n);
  return ctx.dec.decode(a.readOutput(n));
}

function measure(name, row, fn) {
  for (let i = 0; i < 300; i++) fn();
  let iters = 0;
  const t0 = performance.now();
  while (performance.now() - t0 < 300) { for (let i = 0; i < 50; i++) fn(); iters += 50; }
  const ms = performance.now() - t0;
  self.postMessage({ type: "result", row, opsPerSec: Math.round(iters / (ms / 1000)) });
}

async function runBench() {
  const { a, exp } = await ensure();
  const p32 = new Uint8Array(32).fill(0x61);
  const p21 = new Uint8Array(21).fill(0x11); p21[0] = 0x00;
  const addr = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";

  // preparar decode: ascii→indices en inPtr (una vez)
  const sBytes = new TextEncoder().encode(addr);
  a.writeInput(sBytes, 0);
  exp.base58_ascii_to_indices(a.inPtr, sBytes.length);

  a.writeInput(p32, 0);
  measure("b58-enc(32B) WASM", 0, () => exp.base58_encode_raw(a.outPtr, a.inPtr, 32));
  measure("b58-dec(34ch) WASM", 1, () => exp.base58_decode_raw(a.outPtr, a.inPtr, sBytes.length));
  a.writeInput(p21, 0);
  measure("b58check-enc(21B) WASM", 2, () => exp.base58check_encode_raw(a.outPtr, a.inPtr, 21));
  measure("b58-enc(32B) JS BigInt", 3, () => jsB58Enc(p32));
  measure("bech32m(32B) JS", 4, () => bechEnc("bc", 1, p32, "bech32m"));
}

async function runFuzz(count) {
  const { a, exp } = await ensure();
  let mismatches = 0;
  for (let i = 0; i < count; i++) {
    const r = crypto.getRandomValues(new Uint8Array(32));

    // 1) Base58: WASM ≡ JS
    a.writeInput(r, 0);
    const n = exp.base58_encode_raw(a.outPtr, a.inPtr, 32);
    const wStr = wasmB58Str(a, exp, n);
    if (wStr !== jsB58Enc(r)) mismatches++;

    // 2) Base58 decode roundtrip WASM ≡ original
    const back = jsB58Dec(wStr);
    if (!eq(back, r)) mismatches++;

    // 3) Base58Check roundtrip WASM (payload 21 B)
    const p21 = new Uint8Array(21); p21.set(r.slice(0, 20), 1);
    a.writeInput(p21, 0);
    const nc = exp.base58check_encode_raw(a.outPtr, a.inPtr, 21);
    const cStr = wasmB58Str(a, exp, nc);
    const sB = new TextEncoder().encode(cStr);
    a.writeInput(sB, 0);
    exp.base58_ascii_to_indices(a.inPtr, sB.length);
    const pl = exp.base58check_decode_raw(a.outPtr, a.inPtr, sB.length);
    if (pl !== 21 || !eq(a.readOutput(21), p21)) mismatches++;

    // 4) Bech32 + Bech32m roundtrip JS
    for (const spec of ["bech32", "bech32m"]) {
      const s = bechEnc("bc", spec === "bech32" ? 0 : 1, r.slice(0, 20), spec);
      const d = bechDec(s);
      if (!d || !eq(d.prog, r.slice(0, 20))) mismatches++;
    }

    if (i % 250 === 0) self.postMessage({ type: "progress", done: i, total: count });
  }
  self.postMessage({ type: "fuzz-done", total: count, mismatches });
}

self.onmessage = async (e) => {
  const { command } = e.data;
  if (command === "bench") await runBench();
  else if (command === "fuzz") await runFuzz(e.data.count || 2000);
  self.postMessage({ type: "done" });
};