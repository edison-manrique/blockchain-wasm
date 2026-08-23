/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  hash-worker.js — Worker de benchmark hashing (no bloquea el UI)
 * ═══════════════════════════════════════════════════════════════════════════
 *  Recibe { command:"bench", bytes } y responde:
 *    { type:"result", name, opsPerSec } por algoritmo + { type:"done" } al final.
 *  Carga su propia instancia WASM (singleton dentro del worker).
 */
import { BlockchainWasm } from "../../dist/index.js";

let ctx = null;
async function ensure() {
  if (!ctx) {
    await BlockchainWasm.fromUrl("../../dist/blockchain.wasm");
    const bw = BlockchainWasm.getInstance();
    ctx = { a: bw.getAllocator(), exp: bw.getExports() };
  }
  return ctx;
}

self.onmessage = async (e) => {
  const { command, bytes } = e.data;
  if (command !== "bench") return;
  const { a, exp } = await ensure();
  const data = new Uint8Array(bytes);
  a.writeInput(data, 0);
  const n = data.length;

  const jobs = [
    ["sha256",    () => exp.sha256_hash_raw(a.outPtr, a.inPtr, n)],
    ["sha512",    () => exp.sha512_hash_raw(a.outPtr, a.inPtr, n)],
    ["keccak256", () => exp.keccak256_hash_raw(a.outPtr, a.inPtr, n)],
    ["ripemd160", () => exp.ripemd160_hash_raw(a.outPtr, a.inPtr, n)]
  ];

  for (const [name, fn] of jobs) {
    for (let i = 0; i < 300; i++) fn(); // warmup
    let iters = 0;
    const t0 = performance.now();
    while (performance.now() - t0 < 300) { // ventana fija de 300 ms por algoritmo
      for (let i = 0; i < 100; i++) fn();
      iters += 100;
    }
    const ms = performance.now() - t0;
    self.postMessage({ type: "result", name, opsPerSec: Math.round(iters / (ms / 1000)) });
  }
  self.postMessage({ type: "done" });
};