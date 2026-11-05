/**
 * ════════════════════════════════════════════════════════════════════════════
 *  Dashboard.tsx — Panel central con grid de módulos
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { initWasm, getRandomHexKey } from '../../utils/wasm';
import styles from './Dashboard.module.css';

interface ModuleCard {
  path: string;
  icon: string;
  title: string;
  description: string;
  badge?: string;
  border?: string;
}

const MODULES: ModuleCard[] = [
  { path: '/vanity', icon: '✨', title: 'Vanity Search', description: 'Buscador multihilo de direcciones personalizadas BTC/ETH.', badge: 'MULTI-THREAD', border: 'rgba(240, 185, 11, 0.3)' },
  { path: '/address', icon: '📫', title: 'Address', description: 'P2PKH, P2SH, SegWit, Taproot y Ethereum EIP-55.' },
  { path: '/bip39', icon: '🌱', title: 'BIP-39', description: 'Mnemónicos, entropía hex y seed PBKDF2 de 512 bits.', badge: 'BIP39' },
  { path: '/bip32', icon: '🌳', title: 'BIP-32 HD', description: 'Derivación jerárquica, xprv/xpub y neutering.', badge: 'BIP32' },
  { path: '/bip44', icon: '💼', title: 'BIP-44', description: 'Matriz multi-moneda de cuentas y direcciones HD.', badge: 'BIP44' },
  { path: '/ecdsa', icon: '✍️', title: 'ECDSA', description: 'Firmas r|s|v en formatos Raw, Bitcoin y Ethereum.', badge: 'ECDSA' },
  { path: '/schnorr', icon: '⚡', title: 'Schnorr', description: 'BIP-340 de 64 bytes y claves x-only.', badge: 'BIP340' },
  { path: '/ecdh', icon: '🔐', title: 'ECDH', description: 'Intercambio Diffie-Hellman (Alice & Bob).', badge: 'ECDH' },
  { path: '/secp256k1', icon: '📈', title: 'Curve', description: 'Compresión 33B ↔ 65B y validación matemática.', badge: 'SECP' },
  { path: '/pbkdf2', icon: '🔑', title: 'PBKDF2', description: 'KDF HMAC-SHA-512 con benchmark de rendimiento.', badge: 'KDF' },
  { path: '/wif', icon: '🎫', title: 'WIF', description: 'Wallet Import Format (Base58Check) encode/decode.', badge: 'WIF' },
  { path: '/hash', icon: '🧪', title: 'Hash Lab', description: 'SHA-256, RIPEMD-160, Keccak-256 y Hash160.' },
  { path: '/encoding', icon: '🔤', title: 'Encoding', description: 'Base58, Base58Check, Bech32, Bech32m, Hex.' },
  { path: '/hd-visualizer', icon: '🌲', title: 'HD Visualizer', description: 'Árbol HD interactivo con derivación visual.' },
  { path: '/message-signing', icon: '🖋️', title: 'Msg Signing', description: 'Firma y verificación de mensajes BTC/ETH.' },
  { path: '/anvil', icon: '🔨', title: 'Anvil EVM Wallet', description: 'Wallet EVM integrada con Anvil local.', badge: 'TESTNET', border: 'rgba(240, 185, 11, 0.3)' },
];

export const Dashboard: Component = () => {
  const navigate = useNavigate();
  const runtime = 'Bun / Browser';

  return (
    <div class={styles.dashboard}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>Suite de Pruebas & Playground Criptográfico</h1>
          <p class={styles.pageDescription}>
            Motor criptográfico zero-alloc WebAssembly (AssemblyScript) para carteras Bitcoin y Ethereum.
          </p>
        </div>
      </div>

      <div class={styles.metricsGrid}>
        <div class={`${styles.metricCard} ${styles.card}`}>
          <div>
            <div class={styles.metricLabel}>Rendimiento WASM</div>
            <div class={styles.metricValue}>Zero Heap</div>
          </div>
          <span class={styles.metricIcon}>⚡</span>
        </div>
        <div class={`${styles.metricCard} ${styles.card}`}>
          <div>
            <div class={styles.metricLabel}>Algoritmos</div>
            <div class={styles.metricValueSuccess}>15 Módulos</div>
          </div>
          <span class={styles.metricIcon}>📦</span>
        </div>
        <div class={`${styles.metricCard} ${styles.card}`}>
          <div>
            <div class={styles.metricLabel}>Entorno</div>
            <div class={styles.metricValueGold} id="runtime-name">{runtime}</div>
          </div>
          <span class={styles.metricIcon}>🌐</span>
        </div>
      </div>

      <h2 class={styles.modulesTitle}>Módulos Disponibles</h2>
      <div class={styles.modulesGrid}>
        {MODULES.map(module => (
          <div
            class={`${styles.moduleCard} ${styles.card}`}
            style={module.border ? { border: module.border } : {}}
            onClick={() => navigate(module.path)}
          >
            <div class={styles.cardHeader}>
              <span class={styles.cardTitle}><span class={styles.icon}>{module.icon}</span> {module.title}</span>
              {module.badge && <span class={`${styles.badge} ${styles.btnPrimary}`}>{module.badge}</span>}
            </div>
            <p class={styles.cardDescription}>{module.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
};