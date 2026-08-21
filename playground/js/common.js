/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  common.js — Utilidades compartidas y cargador de BlockchainWasm
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { BlockchainWasm, bytesToHex, hexToBytes } from "../../dist/index.js";

let wasmInstance = null;

/**
 * Inicializa el singleton global de BlockchainWasm desde /playground/lib/blockchain.wasm
 */
export async function initWasm() {
  if (wasmInstance) return wasmInstance;
  
  const statusDot = document.getElementById("wasm-status-dot");
  const statusText = document.getElementById("wasm-status-text");

  try {
    if (statusText) statusText.innerText = "Cargando WASM...";
    // Carga desde el directorio local lib/
    wasmInstance = await BlockchainWasm.fromUrl("../../dist/blockchain.wasm");
    
    if (statusDot) statusDot.classList.add("active");
    if (statusText) statusText.innerText = "WASM Listo (Zero-Alloc)";
    console.log("BlockchainWasm inicializado con éxito");
    return wasmInstance;
  } catch (err) {
    console.error("Error al cargar BlockchainWasm:", err);
    if (statusText) statusText.innerText = "Error WASM: " + err.message;
    if (statusDot) statusDot.style.background = "#F6465D";
    throw err;
  }
}

/**
 * Copia texto al portapapeles y muestra una notificación flotante (toast)
 */
export function copyToClipboard(text, label = "Texto") {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast(`✓ ${label} copiado al portapapeles`);
  }).catch(() => {
    showToast(`❌ Error al copiar ${label}`);
  });
}

/**
 * Muestra una notificación toast elegante
 */
export function showToast(message) {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }
  
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerText = message;
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(20px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}

/**
 * Genera una clave privada aleatoria de 32 bytes en formato Hexadecimal
 */
export function getRandomHexKey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Valida si un string es hexadecimal válido de la longitud especificada en bytes
 */
export function isValidHex(hexStr, expectedBytes = null) {
  if (typeof hexStr !== "string") return false;
  const clean = hexStr.startsWith("0x") ? hexStr.slice(2) : hexStr;
  if (!/^[0-9a-fA-F]*$/.test(clean)) return false;
  if (expectedBytes !== null && clean.length !== expectedBytes * 2) return false;
  return true;
}

/**
 * Convierte hex seguro (remueve prefijo 0x si existe)
 */
export function parseHexInput(str) {
  if (!str) return new Uint8Array(0);
  const clean = str.trim().startsWith("0x") ? str.trim().slice(2) : str.trim();
  return hexToBytes(clean);
}

export { bytesToHex, hexToBytes };
