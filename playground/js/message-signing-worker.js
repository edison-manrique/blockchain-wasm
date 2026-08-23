/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  message-signing-worker.js — Batch signing multi-formato (off-main-thread)
 * ═══════════════════════════════════════════════════════════════════════════
 *  Por cada mensaje: 3 firmas ECDSA (Universal/Bitcoin/Ethereum) + verify,
 *  y 1 firma Schnorr (Universal) + verify. Reporta progreso y throughput.
 *
 *  Protocolo:
 *    → { command:"start", data:{ messages:string[], privHex:string } }
 *    → { command:"stop" }
 *    ← { type:"progress", done, total }
 *    ← { type:"done", total, ecdsaOk, schnorrOk, ms, rate }
 *    ← { type:"error", error }
 */
import { BlockchainWasm, Ecdsa, Schnorr, Secp256k1, hexToBytes } from "../../dist/index.js";

let running = false;

self.onmessage = async (e) => {
  const { command, data } = e.data;
  if (command === "stop") { running = false; return; }
  if (command !== "start") return;
  running = true;
  try {
    await BlockchainWasm.fromUrl("../../dist/blockchain.wasm");
    runBatch(data);
  } catch (err) {
    self.postMessage({ type: "error", error: err.message });
  }
};

function runBatch({ messages, privHex }) {
  const priv = hexToBytes(privHex);
  if (priv.length !== 32) { self.postMessage({ type: "error", error: "privkey ≠ 32 B" }); return; }
  const pub = Secp256k1.getPublicKey(priv, true);
  const xonly = Schnorr.getPublicKey(priv);

  const total = messages.length * 3; // firmas ECDSA
  let ecdsaOk = 0, schnorrOk = 0, done = 0;
  const t0 = performance.now();
  const REPORT_EVERY = 20; // mensajes

  for (let mi = 0; mi < messages.length; mi++) {
    if (!running) break;
    const msg = messages[mi];
    for (let f = 0; f < 3; f++) {
      const sig = Ecdsa.signTextMessage(msg, priv, f);
      if (Ecdsa.verifyTextMessage(msg, sig, pub, f)) ecdsaOk++;
      done++;
    }
    const ss = Schnorr.signTextMessage(msg, priv, 0);
    if (Schnorr.verifyTextMessage(msg, ss, xonly, 0)) schnorrOk++;

    if ((mi + 1) % REPORT_EVERY === 0) {
      self.postMessage({ type: "progress", done: mi + 1, total: messages.length });
    }
  }
  const ms = performance.now() - t0;
  self.postMessage({
    type: "done",
    total: done,
    ecdsaOk,
    schnorrOk,
    ms,
    rate: ms > 0 ? Math.round((done + messages.length) / (ms / 1000)) : 0
  });
}