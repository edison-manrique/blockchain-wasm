/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  vanity-worker.js — Web Worker de Alta Velocidad con Evaluación Multi-Regla
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { BlockchainWasm, Address, Secp256k1, Wif, bytesToHex } from "../lib/index.js";

let isRunning = false;
let workerId = 0;

self.onmessage = async (e) => {
  const { command, data } = e.data;

  if (command === "stop") {
    isRunning = false;
    return;
  }

  if (command === "start") {
    workerId = data.workerId;
    isRunning = true;

    try {
      // Carga e inicialización de WebAssembly desde playground/lib/
      await BlockchainWasm.fromUrl("../lib/blockchain.wasm");
      runSearchLoop(data);
    } catch (err) {
      self.postMessage({ type: "error", error: err.message, workerId });
    }
  }
};

function extractSearchPart(address, addrType) {
  if (addrType === "p2pkh" || addrType === "p2sh-p2wpkh") return address.slice(1);
  if (addrType === "p2wpkh" || addrType === "p2tr") return address.slice(4);
  if (addrType === "eth") return address.slice(2);
  return address;
}

function runSearchLoop(config) {
  const { addrType, rules, isCaseSensitive } = config;
  const privBytes = new Uint8Array(32);

  let localAttempts = 0;
  const reportBatch = 2500; // Informar a la UI cada 2500 intentos para acelerar procesamiento IPC

  // Pre-procesar los términos para evitar conversión en caliente dentro del bucle
  const processedRules = rules.map(rule => {
    return {
      ...rule,
      termLower: rule.term ? rule.term.toLowerCase() : "",
      prefixLower: rule.prefixTerm ? rule.prefixTerm.toLowerCase() : "",
      suffixLower: rule.suffixTerm ? rule.suffixTerm.toLowerCase() : ""
    };
  });

  while (isRunning) {
    // Generar entropía CSPRNG de 32 bytes
    crypto.getRandomValues(privBytes);
    localAttempts++;

    // Obtener claves públicas y dirección
    const pubComp = Secp256k1.getPublicKey(privBytes, true);
    const pubUncomp = Secp256k1.getPublicKey(privBytes, false);

    let address = "";
    if (addrType === "p2pkh") address = Address.p2pkh(pubComp);
    else if (addrType === "p2sh-p2wpkh") address = Address.p2shP2wpkh(pubComp);
    else if (addrType === "p2wpkh") address = Address.p2wpkh(pubComp);
    else if (addrType === "p2tr") address = Address.p2tr(pubComp);
    else if (addrType === "eth") address = Address.eth(pubUncomp);

    const searchPart = extractSearchPart(address, addrType);
    const subjectExact = searchPart;
    const subjectLower = searchPart.toLowerCase();

    // Evaluar cada una de las reglas sobre LA MISMA dirección generada (Evaluación Multi-Regla)
    for (let i = 0; i < processedRules.length; i++) {
      const r = processedRules[i];
      const subject = isCaseSensitive ? subjectExact : subjectLower;
      let matched = false;

      if (r.mode === "prefix") {
        const target = isCaseSensitive ? r.term : r.termLower;
        if (subject.startsWith(target)) matched = true;
      } else if (r.mode === "suffix") {
        const target = isCaseSensitive ? r.term : r.termLower;
        if (subject.endsWith(target)) matched = true;
      } else if (r.mode === "contains") {
        const target = isCaseSensitive ? r.term : r.termLower;
        if (subject.includes(target)) matched = true;
      } else if (r.mode === "both") {
        const prefix = isCaseSensitive ? r.prefixTerm : r.prefixLower;
        const suffix = isCaseSensitive ? r.suffixTerm : r.suffixLower;
        if (subject.startsWith(prefix) && subject.endsWith(suffix)) matched = true;
      }

      if (matched) {
        const wifStr = Wif.encode(privBytes, true);
        const privHex = bytesToHex(privBytes);

        self.postMessage({
          type: "match",
          workerId,
          match: {
            address,
            wifStr,
            privHex,
            matchedTarget: r.label,
            attempts: localAttempts
          }
        });
        break; // Coincidencia encontrada para esta clave
      }
    }

    if (localAttempts % reportBatch === 0) {
      self.postMessage({
        type: "progress",
        workerId,
        attempts: reportBatch
      });
    }
  }
}
