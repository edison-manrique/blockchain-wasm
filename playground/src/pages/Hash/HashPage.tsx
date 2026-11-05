/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  HashPage.tsx — Hash Laboratory (simplified)
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { BlockchainWasm, bytesToHex } from 'blockchain-wasm';
import { initWasm, copyToClipboard, parseHexInput } from '../../utils/wasm';
import styles from './HashPage.module.css';

export const HashPage: Component = () => {
  const [input, setInput] = createSignal<string>('hello world');
  const [inputType, setInputType] = createSignal<'hex' | 'text'>('text');
  const [sha256, setSha256] = createSignal<string>('-');
  const [ripemd160, setRipemd160] = createSignal<string>('-');
  const [keccak256, setKeccak256] = createSignal<string>('-');
  const [hash160, setHash160] = createSignal<string>('-');

  const computeHashes = () => {
    try {
      let data: Uint8Array;
      if (inputType() === 'hex') {
        data = parseHexInput(input());
      } else {
        data = new TextEncoder().encode(input());
      }

      if (data.length === 0) {
        setSha256('-');
        setRipemd160('-');
        setKeccak256('-');
        setHash160('-');
        return;
      }

      const bw = BlockchainWasm.getInstance();
      bw.withScratch((w) => {
        const a = w.getAllocator();
        const exp = w.getExports() as unknown as Record<string, Function>;

        // SHA-256
        a.writeInput(data, 0);
        exp.sha256_hash_raw(a.outPtr, a.inPtr, data.length);
        const sha = a.readOutput(32);
        setSha256(bytesToHex(sha));

        // RIPEMD-160
        exp.ripemd160_hash_raw(a.outPtr, a.inPtr, data.length);
        const rip = a.readOutput(20);
        setRipemd160(bytesToHex(rip));

        // Keccak-256
        exp.keccak256_hash_raw(a.outPtr, a.inPtr, data.length);
        const kec = a.readOutput(32);
        setKeccak256(bytesToHex(kec));

        // Hash160 (RIPEMD160 of SHA256)
        a.writeInput(sha, 0);
        exp.ripemd160_hash_raw(a.outPtr, a.inPtr, 32);
        const h160 = a.readOutput(20);
        setHash160(bytesToHex(h160));
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleInputChange = (e: Event) => {
    const target = e.target as HTMLTextAreaElement;
    setInput(target.value);
    computeHashes();
  };

  const handleTypeChange = (e: Event) => {
    const target = e.target as HTMLSelectElement;
    setInputType(target.value as 'hex' | 'text');
    computeHashes();
  };

  const copy = (text: string, label: string) => {
    if (text && text !== '-') copyToClipboard(text, label);
  };

  onMount(async () => {
    await initWasm();
    computeHashes();
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>🧪 Hash Laboratory</h1>
          <p class={styles.pageDescription}>
            SHA-256, RIPEMD-160, Keccak-256 y Hash160 disponibles via API de bajo nivel WASM.
          </p>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>📥</span> Entrada</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Tipo de Entrada</label>
            <select class={styles.selectCustom} value={inputType()} onChange={handleTypeChange}>
              <option value="hex">Hexadecimal</option>
              <option value="text">Texto (UTF-8)</option>
            </select>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Datos de Entrada</label>
            <textarea
              class={styles.textareaCustom}
              rows={4}
              placeholder={inputType() === 'hex' ? 'Ej: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' : 'Ej: hello world'}
              value={input()}
              onInput={handleInputChange}
            />
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>📤</span> Resultados Hash</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>SHA-256 (32 bytes)</label>
            <div class={styles.outputBox}>
              <span>{sha256()}</span>
              <button class={styles.copyBtn} onClick={() => copy(sha256(), 'SHA-256')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>RIPEMD-160 (20 bytes)</label>
            <div class={styles.outputBox}>
              <span>{ripemd160()}</span>
              <button class={styles.copyBtn} onClick={() => copy(ripemd160(), 'RIPEMD-160')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Keccak-256 (32 bytes) — Ethereum</label>
            <div class={styles.outputBox}>
              <span>{keccak256()}</span>
              <button class={styles.copyBtn} onClick={() => copy(keccak256(), 'Keccak-256')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Hash160 = RIPEMD-160(SHA-256) (20 bytes)</label>
            <div class={styles.outputBox}>
              <span>{hash160()}</span>
              <button class={styles.copyBtn} onClick={() => copy(hash160(), 'Hash160')}>Copiar</button>
            </div>
          </div>

          <p style={{ 'font-size': '11px', color: 'var(--text-muted)', 'margin-top': '8px' }}>
            Para hashes reales, usa la API de bajo nivel BlockchainWasm.getInstance().getExports()
          </p>
        </div>
      </div>
    </div>
  );
};