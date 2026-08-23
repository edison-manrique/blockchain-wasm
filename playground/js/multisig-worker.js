/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  multisig-worker.js — Rogue-key attack (BigInt EC) + bench de agregación
 * ═══════════════════════════════════════════════════════════════════════════
 *  cmds:
 *    { cmd:"rogue", d1, da }  → { type:"rogue", dr, da }
 *        Fabrica d_rogue tal que liftX(P1)+liftX(P_rogue) == lift(da·G),
 *        usando aritmética de escalares en BigInt (negación de puntos = N−d).
 *    { cmd:"bench", n }       → { type:"bench", text }
 */
import { BlockchainWasm, Schnorr, getRandomBytes } from "../../dist/index.js";

// ── secp256k1 en BigInt (solo para la demo rogue-key) ─────────────────────
const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const G = { x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
            y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n };
const mod = (a, m = P) => ((a % m) + m) % m;
function modpow(b, e, m) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
const inv = (a) => modpow(a, P - 2n, P);
function pDbl(p) { const l = mod(3n * p.x * p.x * inv(2n * p.y)); const x = mod(l * l - 2n * p.x); return { x, y: mod(l * (p.x - x) - p.y) }; }
function pAdd(p, q) {
  if (!p) return q; if (!q) return p;
  if (p.x === q.x) return mod(p.y - q.y) === 0n ? null : pDbl(p);
  const l = mod((q.y - p.y) * inv(mod(q.x - p.x)));
  const x = mod(l * l - p.x - q.x);
  return { x, y: mod(l * (p.x - x) - p.y) };
}
function pMul(k, p) { let r = null, a = p; k = mod(k, N); while (k > 0n) { if (k & 1n) r = pAdd(r, a); a = pDbl(a); k >>= 1n; } return r; }
/** Escalar cuya punto tiene Y par (el que liftX usaría). */
const liftScalar = (d) => { const pt = pMul(d, G); return (pt.y & 1n) === 0n ? mod(d, N) : mod(-d, N); };
const hex32 = (n) => mod(n, N).toString(16).padStart(64, "0");

let wasmReady = null;
async function ensureWasm() {
  if (!wasmReady) wasmReady = BlockchainWasm.fromUrl("../../dist/blockchain.wasm");
  await wasmReady;
}

self.onmessage = async (e) => {
  const { cmd } = e.data;
  if (cmd === "rogue") {
    const d1 = BigInt("0x" + e.data.d1), da = BigInt("0x" + e.data.da);
    const l1 = liftScalar(d1), la = liftScalar(da);
    let dr = mod(la - l1, N);
    if (dr === 0n) dr = 1n;
    // liftX(P_rogue) debe ser dr·G con Y par; si no, negar el escalar
    const pr = pMul(dr, G);
    if ((pr.y & 1n) === 1n) dr = mod(-dr, N);
    self.postMessage({ type: "rogue", dr: hex32(dr), da: e.data.da });
  } else if (cmd === "bench") {
    await ensureWasm();
    const n = e.data.n || 16;
    const keys = [], pubs = [];
    for (let i = 0; i < n; i++) { const k = getRandomBytes(32); keys.push(k); pubs.push(Schnorr.getPublicKey(k)); }
    let it = 0; const t0 = performance.now();
    do { Schnorr.aggregatePublicKeys(pubs); it++; } while (performance.now() - t0 < 500);
    const aggOps = Math.round(it / ((performance.now() - t0) / 1000));
    const aggPriv = Schnorr.aggregatePrivateKeys(keys);
    const msg = new Uint8Array(32).fill(7);
    let it2 = 0; const t1 = performance.now();
    do { Schnorr.sign(msg, aggPriv); it2++; } while (performance.now() - t1 < 500);
    const signOps = Math.round(it2 / ((performance.now() - t1) / 1000));
    self.postMessage({ type: "bench", text: `agg(${n} keys): ${aggOps.toLocaleString()} agg/s · sign(aggPriv): ${signOps.toLocaleString()} sig/s` });
  }
};