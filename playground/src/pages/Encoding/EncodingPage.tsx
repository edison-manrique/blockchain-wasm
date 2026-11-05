/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  EncodingPage.tsx — Hex encoding/decoding (simplified)
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { BlockchainWasm, bytesToHex } from 'blockchain-wasm';
import { initWasm, copyToClipboard, parseHexInput } from '../../utils/wasm';
import styles from './EncodingPage.module.css';

export const EncodingPage: Component = () => {
  const [input, setInput] = createSignal<string>('hello world');
  const [inputType, setInputType] = createSignal<'hex' | 'text'>('text');
  const [hex, setHex] = createSignal<string>('-');
  const [base58, setBase58] = createSignal<string>('-');
  const [base58Check, setBase58Check] = createSignal<string>('-');

  const computeEncodings = () => {
    try {
      let data: Uint8Array;
      if (inputType() === 'hex') {
        data = parseHexInput(input());
      } else {
        data = new TextEncoder().encode(input());
      }

      if (data.length === 0) {
        setHex('-');
        setBase58('-');
        setBase58Check('-');
        return;
      }

      // Hex
      setHex(bytesToHex(data));

      // Base58 and Base58Check via WASM
      const bw = BlockchainWasm.getInstance();
      bw.withScratch((w) => {
        const a = w.getAllocator();
        const exp = w.getExports() as unknown as Record<string, Function>;

        a.writeInput(data, 0);
        const len = exp.base58_encode_raw(a.outPtr, a.inPtr, data.length);
        if (len > 0) {
          exp.base58_indices_to_ascii(a.outPtr, len);
          setBase58(new TextDecoder().decode(a.readOutput(len)));
        } else {
          setBase58('-');
        }

        const lenCheck = exp.base58check_encode_raw(a.outPtr, a.inPtr, data.length);
        if (lenCheck > 0) {
          exp.base58_indices_to_ascii(a.outPtr, lenCheck);
          setBase58Check(new TextDecoder().decode(a.readOutput(lenCheck)));
        } else {
          setBase58Check('-');
        }
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleInputChange = (e: Event) => {
    const target = e.target as HTMLTextAreaElement;
    setInput(target.value);
    computeEncodings();
  };

  const handleTypeChange = (e: Event) => {
    const target = e.target as HTMLSelectElement;
    setInputType(target.value as 'hex' | 'text');
    computeEncodings();
  };

  const copy = (text: string, label: string) => {
    if (text && text !== '-') copyToClipboard(text, label);
  };

  onMount(async () => {
    await initWasm();
    computeEncodings();
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>🔤 Encoding Laboratory</h1>
          <p class={styles.pageDescription}>
            Codificación y decodificación Hexadecimal, Base58 y Base58Check procesados en WASM.
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
              placeholder={inputType() === 'hex' ? 'Ej: 0014751e76e8199196d454941c45d1b3a323f1433bd6' : 'Ej: hello world'}
              value={input()}
              onInput={handleInputChange}
            />
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>📤</span> Resultados Encoding</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Hexadecimal</label>
            <div class={styles.outputBox}>
              <span>{hex()}</span>
              <button class={styles.copyBtn} onClick={() => copy(hex(), 'Hex')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Base58</label>
            <div class={styles.outputBox}>
              <span>{base58()}</span>
              <button class={styles.copyBtn} onClick={() => copy(base58(), 'Base58')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Base58Check (con checksum SHA256d)</label>
            <div class={styles.outputBox}>
              <span>{base58Check()}</span>
              <button class={styles.copyBtn} onClick={() => copy(base58Check(), 'Base58Check')}>Copiar</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};