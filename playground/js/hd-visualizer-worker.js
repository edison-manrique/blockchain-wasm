/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  hd-visualizer-worker.js — Derivación BIP-32 batch fuera del hilo principal
 * ═══════════════════════════════════════════════════════════════════════════
 *  Comandos:
 *    { command:"master",   id, seedHex }                  → { type:"master", id, node }
 *    { command:"children", id, parentRaw, indices, basePath } → { type:"children", id, children:[{index,hardened,label,node}] }
 *    { command:"path",     id, seedHex, path }            → { type:"path", id, node }
 *    Errores: { type:"error", id, error }
 *
 *  `node` = { raw, path, depth, childIndex, parentFp, fp, isPrivate,
 *             chainCode, pubHex, privHex, xpub, xprv }
 */
import { BlockchainWasm, Bip32, HDKey, bytesToHex, hexToBytes } from "../../dist/index.js";

const HARD = 0x80000000;
let ready = false;

async function ensure() {
  if (!ready) {
    await BlockchainWasm.fromUrl("../../dist/blockchain.wasm");
    ready = true;
  }
}

/** Extrae metadatos serializables de una HDKey. */
function nodeMeta(key, path) {
  return {
    raw: key.raw,
    path,
    depth: key.depth,
    childIndex: key.childIndex >>> 0,
    parentFp: key.parentFingerprint >>> 0,
    fp: key.fingerprint() >>> 0,
    isPrivate: key.isPrivate,
    chainCode: bytesToHex(key.chainCode),
    pubHex: bytesToHex(key.publicKey),
    privHex: key.isPrivate ? bytesToHex(key.privateKey) : null,
    xpub: key.toXpub(),
    xprv: key.isPrivate ? key.toXprv() : null
  };
}

self.onmessage = async (e) => {
  const { command, id } = e.data;
  try {
    await ensure();
    if (command === "master") {
      const master = Bip32.fromSeed(hexToBytes(e.data.seedHex));
      self.postMessage({ type: "master", id, node: nodeMeta(master, "m") });
    } else if (command === "children") {
      const parent = new HDKey(new Uint8Array(e.data.parentRaw));
      const children = e.data.indices.map((idx0) => {
        const idx = idx0 >>> 0;
        const hardened = idx >= HARD;
        const label = hardened ? `${idx - HARD}'` : String(idx);
        const child = parent.derive(idx);
        return { index: idx, hardened, label, node: nodeMeta(child, e.data.basePath + "/" + label) };
      });
      self.postMessage({ type: "children", id, children });
    } else if (command === "path") {
      const master = Bip32.fromSeed(hexToBytes(e.data.seedHex));
      const p = e.data.path;
      const key = p === "m" || p === "" ? master : master.derivePath(p);
      self.postMessage({ type: "path", id, node: nodeMeta(key, p || "m") });
    }
  } catch (err) {
    self.postMessage({ type: "error", id, error: err.message });
  }
};