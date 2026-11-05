/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  Bip39Page.tsx — BIP-39 Mnemonic & Entropy Laboratory
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Bip39 } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput } from '../../utils/wasm';
import styles from './Bip39Page.module.css';

const VALID_HEX_LENS: Record<number, string> = {
  32: '128 bits (12 palabras)',
  40: '160 bits (15 palabras)',
  48: '192 bits (18 palabras)',
  56: '224 bits (21 palabras)',
  64: '256 bits (24 palabras)',
};

export const Bip39Page: Component = () => {
  const [strength, setStrength] = createSignal<number>(256);
  const [mnemonic, setMnemonic] = createSignal<string>('');
  const [entropy, setEntropy] = createSignal<string>('');
  const [passphrase, setPassphrase] = createSignal<string>('');
  const [seed, setSeed] = createSignal<string>('-');
  const [entropyStatus, setEntropyStatus] = createSignal<{ text: string; class: string }>({ text: '0 caracteres (0 bits)', class: 'invalid' });
  const [validationStatus, setValidationStatus] = createSignal<{ text: string; class: string; show: boolean }>({ text: '', class: '', show: false });

  const updateEntropyCounter = () => {
    const hex = entropy().trim().replace(/^0x/i, '');
    const len = hex.length;
    const bits = len * 4;

    if (VALID_HEX_LENS[len]) {
      setEntropyStatus({ text: `${len} hex chars (${VALID_HEX_LENS[len]}) ✓`, class: 'valid' });
    } else {
      setEntropyStatus({ text: `${len} hex chars (${bits} bits) — Necesita 32, 40, 48, 56 o 64`, class: 'invalid' });
    }
  };

  const processMnemonic = () => {
    const mn = mnemonic().trim();
    if (!mn) {
      setValidationStatus({ text: '', class: '', show: false });
      setEntropy('');
      updateEntropyCounter();
      setSeed('-');
      return;
    }

    try {
      const isValid = Bip39.validate(mn);
      if (isValid) {
        setValidationStatus({ text: '✓ Frase Mnemónica BIP-39 Válida', class: 'alert-success', show: true });

        const ent = Bip39.mnemonicToEntropy(mn);
        setEntropy(bytesToHex(ent));
        updateEntropyCounter();

        const pass = passphrase() || '';
        const sd = Bip39.mnemonicToSeed(mn, pass);
        setSeed(bytesToHex(sd));
      } else {
        setValidationStatus({ text: '❌ Frase Mnemónica Inválida o Checksum Incorrecto', class: 'alert-error', show: true });
        setSeed('-');
      }
    } catch (err) {
      setValidationStatus({ text: `❌ Error: ${(err as Error).message}`, class: 'alert-error', show: true });
    }
  };

  const processEntropyInput = () => {
    updateEntropyCounter();
    const hex = entropy().trim().replace(/^0x/i, '');
    if (!VALID_HEX_LENS[hex.length]) return;

    try {
      const entropyBytes = hexToBytes(hex);
      const mn = Bip39.entropyToMnemonic(entropyBytes);
      setMnemonic(mn);
      processMnemonic();
    } catch (err) {
      setValidationStatus({ text: `❌ Error en entropía: ${(err as Error).message}`, class: 'alert-error', show: true });
    }
  };

  const generateMnemonic = () => {
    const mn = Bip39.generate(strength());
    setMnemonic(mn);
    processMnemonic();
  };

  const handleStrengthChange = (e: Event) => {
    const target = e.target as HTMLSelectElement;
    setStrength(parseInt(target.value));
  };

  const handleMnemonicChange = (e: Event) => {
    const target = e.target as HTMLTextAreaElement;
    setMnemonic(target.value);
    processMnemonic();
  };

  const handleEntropyChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setEntropy(target.value);
    processEntropyInput();
  };

  const handlePassphraseChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPassphrase(target.value);
    processMnemonic();
  };

  const copy = (text: string, label: string) => {
    if (text && text !== '-') copyToClipboard(text, label);
  };

  onMount(async () => {
    await initWasm();
    const mn = Bip39.generate(256);
    setMnemonic(mn);
    processMnemonic();
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>🌱 BIP-39 Mnemonic & Entropy Laboratory</h1>
          <p class={styles.pageDescription}>
            Generación bidireccional de frases mnemónicas, conversión desde entropía hexadecimal personalizada
            (128–256 bits) y derivación PBKDF2-HMAC-SHA512 de la seed.
          </p>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🎲</span> Frase Mnemónica (Wordlist)</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Longitud de Entropía</label>
            <select class={styles.selectCustom} value={strength()} onChange={handleStrengthChange}>
              <option value={128}>128 bits (16 B / 32 hex) — 12 palabras</option>
              <option value={160}>160 bits (20 B / 40 hex) — 15 palabras</option>
              <option value={192}>192 bits (24 B / 48 hex) — 18 palabras</option>
              <option value={224}>224 bits (28 B / 56 hex) — 21 palabras</option>
              <option value={256}>256 bits (32 B / 64 hex) — 24 palabras</option>
            </select>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Frase Mnemónica (BIP-39 English)</label>
            <textarea
              class={styles.textareaCustom}
              rows={3}
              placeholder="Ingresa o genera una frase de 12 a 24 palabras..."
              value={mnemonic()}
              onInput={handleMnemonicChange}
            />
          </div>

          <div class={styles.btnGroup}>
            <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateMnemonic}>🎲 Generar Mnemónico</button>
            <button class={`${styles.btn} ${styles.btnSecondary}`} onClick={() => copy(mnemonic(), 'Frase Mnemónica')}>📋 Copiar Frase</button>
          </div>

          <div class={`${styles.alert} ${validationStatus().class}`} style={{ display: validationStatus().show ? 'flex' : 'none' }}>
            {validationStatus().text}
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>⚙️</span> Entropía Hexadecimal Raw & Seed</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>
              Entropía Hexadecimal Raw (16, 20, 24, 28 o 32 Bytes)
              <span class={`${styles.charCounter} ${entropyStatus().class}`}>{entropyStatus().text}</span>
            </label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Ej. 00000000000000000000000000000000 (32 chars = 12 palabras)"
              spellcheck="false"
              value={entropy()}
              onInput={handleEntropyChange}
            />
            <div class={styles.btnGroup} style={{ 'margin-top': '6px' }}>
              <button class={`${styles.btn} ${styles.btnSm} ${styles.btnSecondary}`} onClick={processEntropyInput}>
                ⚡ Derivar Mnemónico desde Entropía
              </button>
              <button class={`${styles.btn} ${styles.btnSm} ${styles.btnSecondary}`} onClick={() => copy(entropy(), 'Entropía')}>
                Copiar Hex
              </button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Passphrase Opcional (Salt para PBKDF2)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Passphrase opcional (2FA / 13th word)"
              value={passphrase()}
              onInput={handlePassphraseChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>BIP-39 Seed (512-bit / 64 bytes Hex)</label>
            <div class={styles.outputBox} style={{ 'min-height': '60px' }}>
              <span>{seed()}</span>
              <button class={styles.copyBtn} onClick={() => copy(seed(), 'BIP-39 Seed')}>Copiar</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};