/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  Pbkdf2Page.tsx — PBKDF2-HMAC-SHA512 Key Derivation with Benchmark
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Pbkdf2 } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './Pbkdf2Page.module.css';

export const Pbkdf2Page: Component = () => {
  const [password, setPassword] = createSignal<string>('');
  const [salt, setSalt] = createSignal<string>('');
  const [iterations, setIterations] = createSignal<number>(2048);
  const [dkLen, setDkLen] = createSignal<number>(64);
  const [derivedKey, setDerivedKey] = createSignal<string>('-');
  const [benchResult, setBenchResult] = createSignal<string>('');

  const generateRandom = () => {
    setPassword(getRandomHexKey());
    setSalt(getRandomHexKey().slice(0, 32)); // 16 bytes salt
  };

  const derive = () => {
    try {
      const pwd = password() ? parseHexInput(password()) : new TextEncoder().encode('test password');
      const slt = salt() ? parseHexInput(salt()) : new TextEncoder().encode('test salt');
      const dk = Pbkdf2.sha512(pwd, slt, iterations(), dkLen());
      setDerivedKey(bytesToHex(dk));
    } catch (err) {
      console.error(err);
    }
  };

  const benchmark = () => {
    try {
      const pwd = new TextEncoder().encode('benchmark password');
      const slt = new TextEncoder().encode('benchmark salt');
      const iter = iterations();
      const len = dkLen();

      const start = performance.now();
      for (let i = 0; i < 10; i++) {
        Pbkdf2.sha512(pwd, slt, iter, len);
      }
      const end = performance.now();
      const avg = (end - start) / 10;
      setBenchResult(`10 ejecuciones: ${(end - start).toFixed(2)}ms total, ${avg.toFixed(2)}ms/op (${iter} iteraciones, ${len} bytes)`);
    } catch (err) {
      console.error(err);
    }
  };

  const handlePasswordChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPassword(target.value);
  };

  const handleSaltChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setSalt(target.value);
  };

  const handleIterationsChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setIterations(parseInt(target.value) || 2048);
  };

  const handleDkLenChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setDkLen(parseInt(target.value) || 64);
  };

  const copy = (text: string, label: string) => {
    if (text && text !== '-') copyToClipboard(text, label);
  };

  onMount(async () => {
    await initWasm();
    generateRandom();
    derive();
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>🔑 PBKDF2-HMAC-SHA512 Laboratory</h1>
          <p class={styles.pageDescription}>
            Derivación de claves PBKDF2 con HMAC-SHA512. Iteraciones configurables y benchmark de rendimiento WASM.
          </p>
        </div>
        <div class={styles.btnGroup}>
          <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateRandom}>🎲 Valores Aleatorios</button>
          <button class={`${styles.btn} ${styles.btnSecondary}`} onClick={benchmark}>⚡ Benchmark (10 ops)</button>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>⚙️</span> Parámetros</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Password (Hex o texto)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Password en hex (64 chars) o déjalo vacío para 'test password'"
              value={password()}
              onInput={handlePasswordChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Salt (Hex o texto)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Salt en hex (32 chars = 16 bytes) o déjalo vacío para 'test salt'"
              value={salt()}
              onInput={handleSaltChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Iteraciones</label>
            <input
              type="number"
              class={styles.inputText}
              value={iterations()}
              onInput={handleIterationsChange}
              min={1}
              max={10000000}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Longitud Derivada (dkLen) en bytes</label>
            <input
              type="number"
              class={styles.inputText}
              value={dkLen()}
              onInput={handleDkLenChange}
              min={1}
              max={512}
            />
          </div>

          <div class={styles.btnGroup}>
            <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={derive}>🔐 Derivar Clave</button>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>📤</span> Resultado</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Derivada (dkLen bytes Hex)</label>
            <div class={styles.outputBox} style={{ 'min-height': '80px' }}>
              <span>{derivedKey()}</span>
              <button class={styles.copyBtn} onClick={() => copy(derivedKey(), 'Derived Key')}>Copiar</button>
            </div>
          </div>

          {benchResult() && (
            <div class={`${styles.alert} ${styles.alertSuccess}`} style={{ 'margin-top': '8px' }}>
              📊 {benchResult()}
            </div>
          )}

          <p style={{ 'font-size': '11px', color: 'var(--text-muted)', 'margin-top': '8px' }}>
            PBKDF2-HMAC-SHA512: Pseudorandom Function = HMAC-SHA512.
            Usado en BIP-39 (2048 iteraciones por defecto) y BIP-32.
          </p>
        </div>
      </div>
    </div>
  );
};