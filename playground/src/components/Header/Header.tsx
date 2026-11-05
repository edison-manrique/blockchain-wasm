/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  Header.tsx — Cabecera superior con estado WASM
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { initWasm } from '../../utils/wasm';
import styles from './Header.module.css';

export const Header: Component = () => {
  const navigate = useNavigate();
  const [wasmReady, setWasmReady] = createSignal(false);
  const [wasmStatus, setWasmStatus] = createSignal<string>('Inicializando WASM...');

  onMount(async () => {
    try {
      setWasmStatus('Cargando WASM...');
      await initWasm();
      setWasmReady(true);
      setWasmStatus('WASM Listo (Zero-Alloc)');
    } catch (err) {
      setWasmStatus(`Error WASM: ${(err as Error).message}`);
    }
  });

  const navigateHome = () => {
    navigate('/');
  };

  return (
    <header class={styles.header}>
      <button class={styles.brandContainer} onClick={navigateHome}>
        <div class={styles.brandLogo}>⚡</div>
        <div class={styles.brandTitle}>
          BlockchainWasm <span class={styles.tag}>Zero-Alloc v3.2</span>
        </div>
      </button>
      <div class={styles.headerStatus}>
        <div class={styles.wasmBadge}>
          <span class={`${styles.statusDot} ${wasmReady() ? styles.active : ''}`}></span>
          <span id="wasm-status-text">{wasmStatus()}</span>
        </div>
      </div>
    </header>
  );
};