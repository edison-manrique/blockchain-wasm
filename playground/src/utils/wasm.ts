/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  wasm.ts — Utilidades compartidas y cargador de BlockchainWasm (SolidJS)
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { BlockchainWasm, bytesToHex, hexToBytes } from 'blockchain-wasm';
import wasmUrl from '../../../dist/blockchain-wasm.wasm?url';

let wasmInstance: BlockchainWasm | null = null;

/**
 * Inicializa el singleton global de BlockchainWasm desde /dist/blockchain.wasm
 */
export async function initWasm(): Promise<BlockchainWasm> {
  if (wasmInstance) return wasmInstance;

  try {
    wasmInstance = await BlockchainWasm.fromUrl(wasmUrl);
    console.log('BlockchainWasm inicializado con éxito');
    return wasmInstance;
  } catch (err) {
    console.error('Error al cargar BlockchainWasm:', err);
    throw err;
  }
}

export function getWasmInstance(): BlockchainWasm | null {
  return wasmInstance;
}

/**
 * Copia texto al portapapeles y muestra una notificación flotante (toast)
 */
export function copyToClipboard(text: string, label = 'Texto'): void {
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
export function showToast(message: string): void {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerText = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(20px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}

/**
 * Genera una clave privada aleatoria de 32 bytes en formato Hexadecimal
 */
export function getRandomHexKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Valida si un string es hexadecimal válido de la longitud especificada en bytes
 */
export function isValidHex(hexStr: string, expectedBytes: number | null = null): boolean {
  if (typeof hexStr !== 'string') return false;
  const clean = hexStr.startsWith('0x') ? hexStr.slice(2) : hexStr;
  if (!/^[0-9a-fA-F]*$/.test(clean)) return false;
  if (expectedBytes !== null && clean.length !== expectedBytes * 2) return false;
  return true;
}

/**
 * Convierte hex seguro (remueve prefijo 0x si existe)
 */
export function parseHexInput(str: string): Uint8Array {
  if (!str) return new Uint8Array(0);
  const clean = str.trim().startsWith('0x') ? str.trim().slice(2) : str.trim();
  return hexToBytes(clean);
}

export { bytesToHex, hexToBytes };