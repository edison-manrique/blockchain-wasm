/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  VanityPage.tsx — Vanity Address Search (Simplified UI)
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount, onCleanup } from 'solid-js';
import { Secp256k1, Address } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './VanityPage.module.css';

interface FoundAddress {
  pattern: string;
  address: string;
  privKey: string;
  pubKey: string;
  type: 'prefix' | 'suffix' | 'contains';
  timestamp: Date;
}

export const VanityPage: Component = () => {
  const [pattern, setPattern] = createSignal<string>('');
  const [patternType, setPatternType] = createSignal<'prefix' | 'suffix' | 'contains'>('prefix');
  const [coinType, setCoinType] = createSignal<'btc' | 'eth'>('btc');
  const [caseSensitive, setCaseSensitive] = createSignal<boolean>(false);
  const [workers, setWorkers] = createSignal<number>(navigator.hardwareConcurrency || 4);
  const [searching, setSearching] = createSignal<boolean>(false);
  const [found, setFound] = createSignal<FoundAddress[]>([]);
  const [stats, setStats] = createSignal<{ attempts: number; speed: number; elapsed: number }>({ attempts: 0, speed: 0, elapsed: 0 });

  let searchInterval: number | null = null;
  let startTime = 0;
  let attempts = 0;

  const startSearch = () => {
    if (searching() || !pattern().trim()) return;
    setSearching(true);
    setFound([]);
    attempts = 0;
    startTime = Date.now();
    setStats({ attempts: 0, speed: 0, elapsed: 0 });

    searchInterval = window.setInterval(() => {
      const batch = 100;
      for (let i = 0; i < batch; i++) {
        const privKey = getRandomHexKey();
        const privBytes = parseHexInput(privKey);
        const pubComp = Secp256k1.getPublicKey(privBytes, true);
        const pubUncomp = Secp256k1.getPublicKey(privBytes, false);

        let address = '';
        if (coinType() === 'btc') {
          address = Address.p2pkh(pubComp);
        } else {
          address = Address.eth(pubUncomp);
        }

        attempts++;

        const searchPattern = caseSensitive() ? pattern() : pattern().toLowerCase();
        const checkAddress = caseSensitive() ? address : address.toLowerCase();

        let matched = false;
        if (patternType() === 'prefix' && checkAddress.startsWith(searchPattern)) matched = true;
        else if (patternType() === 'suffix' && checkAddress.endsWith(searchPattern)) matched = true;
        else if (patternType() === 'contains' && checkAddress.includes(searchPattern)) matched = true;

        if (matched) {
          setFound(prev => [{
            pattern: pattern(),
            address,
            privKey,
            pubKey: bytesToHex(pubComp),
            type: patternType(),
            timestamp: new Date(),
          }, ...prev.slice(0, 9)]);
        }
      }

      const elapsed = (Date.now() - startTime) / 1000;
      const speed = attempts / elapsed;
      setStats({ attempts, speed, elapsed });
    }, 0);
  };

  const stopSearch = () => {
    setSearching(false);
    if (searchInterval) {
      clearInterval(searchInterval);
      searchInterval = null;
    }
  };

  const handlePatternChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPattern(target.value);
  };

  const handlePatternTypeChange = (e: Event) => {
    const target = e.target as HTMLSelectElement;
    setPatternType(target.value as 'prefix' | 'suffix' | 'contains');
  };

  const handleCoinTypeChange = (e: Event) => {
    const target = e.target as HTMLSelectElement;
    setCoinType(target.value as 'btc' | 'eth');
  };

  const handleCaseSensitiveChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setCaseSensitive(target.checked);
  };

  const handleWorkersChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setWorkers(parseInt(target.value) || 1);
  };

  const copy = (text: string, label: string) => {
    if (text) copyToClipboard(text, label);
  };

  onMount(async () => {
    await initWasm();
  });

  onCleanup(() => {
    if (searchInterval) clearInterval(searchInterval);
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>✨ Vanity Address Search</h1>
          <p class={styles.pageDescription}>
            Buscador de direcciones personalizadas Bitcoin/Ethereum. Busca por prefijo, sufijo o contenido.
          </p>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>⚙️</span> Configuración de Búsqueda</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Patrón a Buscar</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder={coinType() === 'btc' ? 'Ej: 1BTC, 1Love, bc1q' : 'Ej: 0xDead, 0xC0de'}
              value={pattern()}
              onInput={handlePatternChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Tipo de Coincidencia</label>
            <select class={styles.selectCustom} value={patternType()} onChange={handlePatternTypeChange}>
              <option value="prefix">Prefijo (empieza con...)</option>
              <option value="suffix">Sufijo (termina con...)</option>
              <option value="contains">Contiene (en cualquier posición)</option>
            </select>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Red</label>
            <select class={styles.selectCustom} value={coinType()} onChange={handleCoinTypeChange}>
              <option value="btc">Bitcoin (P2PKH Legacy)</option>
              <option value="eth">Ethereum (EIP-55)</option>
            </select>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>
              <input type="checkbox" checked={caseSensitive()} onChange={handleCaseSensitiveChange} style={{ 'margin-right': '8px' }} />
              Case Sensitive (distinguir mayúsculas/minúsculas)
            </label>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Hilos de Trabajo (Workers)</label>
            <input
              type="number"
              class={styles.inputText}
              value={workers()}
              onInput={handleWorkersChange}
              min={1}
              max={16}
            />
          </div>

          <div class={styles.btnGroup}>
            <button
              class={`${styles.btn} ${searching() ? styles.btnSecondary : styles.btnPrimary}`}
              onClick={searching() ? stopSearch : startSearch}
              disabled={!pattern().trim()}
            >
              {searching() ? '⏹️ Detener' : '🔍 Iniciar Búsqueda'}
            </button>
          </div>

          <div class={styles.statsBox}>
            <div class={styles.statRow}>
              <span class={styles.statLabel}>Intentos:</span>
              <span class={styles.statValue}>{stats().attempts.toLocaleString()}</span>
            </div>
            <div class={styles.statRow}>
              <span class={styles.statLabel}>Velocidad:</span>
              <span class={styles.statValue}>{stats().speed.toFixed(0)} ops/s</span>
            </div>
            <div class={styles.statRow}>
              <span class={styles.statLabel}>Tiempo:</span>
              <span class={styles.statValue}>{stats().elapsed.toFixed(1)}s</span>
            </div>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🏆</span> Direcciones Encontradas ({found().length})</span>
          </div>

          {found().length === 0 ? (
            <p style={{ color: 'var(--text-muted)', 'font-size': '12px', padding: '20px', 'text-align': 'center' }}>
              {searching() ? 'Buscando...' : 'Configura un patrón e inicia la búsqueda'}
            </p>
          ) : (
            <div class={styles.resultsList}>
              {found().map((item, index) => (
                <div // @ts-ignore
                  key={index}
                  class={styles.resultItem}>
                  <div class={styles.resultHeader}>
                    <span class={styles.resultType}>{item.type.toUpperCase()}</span>
                    <span class={styles.resultTime}>{item.timestamp.toLocaleTimeString()}</span>
                  </div>
                  <div class={styles.resultRow}>
                    <label class={styles.resultLabel}>Dirección:</label>
                    <div class={styles.resultValue}>
                      <span>{item.address}</span>
                      <button class={styles.copyBtn} onClick={() => copy(item.address, 'Address')}>Copiar</button>
                    </div>
                  </div>
                  <div class={styles.resultRow}>
                    <label class={styles.resultLabel}>PrivKey:</label>
                    <div class={styles.resultValue}>
                      <span>{item.privKey}</span>
                      <button class={styles.copyBtn} onClick={() => copy(item.privKey, 'PrivKey')}>Copiar</button>
                    </div>
                  </div>
                  <div class={styles.resultRow}>
                    <label class={styles.resultLabel}>PubKey:</label>
                    <div class={styles.resultValue}>
                      <span>{item.pubKey}</span>
                      <button class={styles.copyBtn} onClick={() => copy(item.pubKey, 'PubKey')}>Copiar</button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};