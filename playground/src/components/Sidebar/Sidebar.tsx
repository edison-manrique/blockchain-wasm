/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  Sidebar.tsx — Navegación lateral compartida
 * ═══════════════════════════════════════════════════════════════════════════
 */
/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  Sidebar.tsx — Navegación lateral compartida
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component } from 'solid-js';
import { useLocation, useNavigate } from '@solidjs/router';
import styles from './Sidebar.module.css';

interface SidebarItem {
  path: string;
  icon: string;
  label: string;
  badge?: string;
  badgeColor?: string;
}

const SIDEBAR_ITEMS: SidebarItem[] = [
  { path: '/', icon: '⚡', label: 'Dashboard Central', badge: 'HUB' },
  { path: '/anvil', icon: '🔨', label: 'Anvil EVM Wallet', badge: 'TESTNET', badgeColor: 'var(--gold-primary)' },
  { path: '/address', icon: '📫', label: 'Address (BTC/ETH)' },
  { path: '/hash', icon: '🧪', label: 'Hash Lab' },
  { path: '/encoding', icon: '🔤', label: 'Encoding' },
  { path: '/hd-visualizer', icon: '🌲', label: 'HD Visualizer' },
  { path: '/message-signing', icon: '🖋️', label: 'Msg Signing' },
  { path: '/vanity', icon: '✨', label: 'Vanity Search' },
  { path: '/bip39', icon: '🌱', label: 'BIP-39 Mnemonic', badge: 'BIP39' },
  { path: '/bip32', icon: '🌳', label: 'BIP-32 HD Tree', badge: 'BIP32' },
  { path: '/bip44', icon: '💼', label: 'BIP-44 Wallet', badge: 'BIP44' },
  { path: '/ecdsa', icon: '✍️', label: 'ECDSA Secp256k1', badge: 'ECDSA' },
  { path: '/schnorr', icon: '⚡', label: 'Schnorr Taproot', badge: 'BIP340' },
  { path: '/ecdh', icon: '🔐', label: 'ECDH Secret', badge: 'ECDH' },
  { path: '/secp256k1', icon: '📈', label: 'Curve Secp256k1', badge: 'SECP' },
  { path: '/pbkdf2', icon: '🔑', label: 'PBKDF2 SHA-512', badge: 'KDF' },
  { path: '/wif', icon: '🎫', label: 'WIF Format', badge: 'WIF' },
];

export const Sidebar: Component = () => {
  const location = useLocation();
  const navigate = useNavigate();

  return (
    <nav class={styles.sidebar}>
      <div class={styles.sidebarTitle}>Módulos Criptográficos</div>
      {SIDEBAR_ITEMS.map(item => (
        <button
          class={`${styles.sidebarItem} ${location.pathname === item.path ? styles.active : styles.inactive}`}
          onClick={() => navigate(item.path)}
        >
          <span>{item.icon} {item.label}</span>
          {item.badge && (
            <span
              class={styles.itemBadge}
              style={item.badgeColor ? { background: item.badgeColor.replace('var(--gold-muted)', 'var(--gold-muted)'), color: item.badgeColor } : {}}
            >
              {item.badge}
            </span>
          )}
        </button>
      ))}
    </nav>
  );
};