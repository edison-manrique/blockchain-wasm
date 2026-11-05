/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  Secp256k1Page.tsx — Curve Operations: Compress/Decompress/Validate
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Secp256k1 } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './Secp256k1Page.module.css';

export const Secp256k1Page: Component = () => {
  const [privKey, setPrivKey] = createSignal<string>('');
  const [pubKeyInput, setPubKeyInput] = createSignal<string>('');

  const [pubComp, setPubComp] = createSignal<string>('-');
  const [pubUncomp, setPubUncomp] = createSignal<string>('-');
  const [compressed, setCompressed] = createSignal<string>('-');
  const [decompressed, setDecompressed] = createSignal<string>('-');
  const [isValid, setIsValid] = createSignal<boolean | null>(null);

  const generateKey = () => {
    const key = getRandomHexKey();
    setPrivKey(key);
    updateFromPrivKey();
  };

  const updateFromPrivKey = () => {
    try {
      const pk = parseHexInput(privKey());
      if (pk.length !== 32) return;
      const comp = Secp256k1.getPublicKey(pk, true);
      const uncomp = Secp256k1.getPublicKey(pk, false);
      setPubComp(bytesToHex(comp));
      setPubUncomp(bytesToHex(uncomp));
      setPubKeyInput(bytesToHex(comp));
      validateKey(bytesToHex(comp));
    } catch (err) { console.error(err); }
  }

  const compressKey = () => {
    try {
      const pk = parseHexInput(pubKeyInput());
      if (pk.length !== 65) return;
      const comp = Secp256k1.compress(pk);
      setCompressed(bytesToHex(comp));
      setPubKeyInput(bytesToHex(comp));
      validateKey(bytesToHex(comp));
    } catch (err) { console.error(err); }
  }

  const decompressKey = () => {
    try {
      const pk = parseHexInput(pubKeyInput());
      if (pk.length !== 33) return;
      const uncomp = Secp256k1.uncompress(pk);
      setDecompressed(bytesToHex(uncomp));
      setPubKeyInput(bytesToHex(uncomp));
      validateKey(bytesToHex(uncomp));
    } catch (err) { console.error(err); }
  }

  const validateKey = (key: string) => {
    try {
      const pk = parseHexInput(key);
      const valid = Secp256k1.isValid(pk);
      setIsValid(valid);
    } catch (err) {
      setIsValid(false);
    }
  }

  const handlePrivKeyChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPrivKey(target.value);
    updateFromPrivKey();
  };

  const handlePubKeyInputChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPubKeyInput(target.value);
    validateKey(target.value);
  };

  const copy = (text: string, label: string) => {
    if (text && text !== '-') copyToClipboard(text, label);
  };

  onMount(async () => {
    await initWasm();
    generateKey();
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>📈 Curve Secp256k1 Laboratory</h1>
          <p class={styles.pageDescription}>
            Compresión/descompresión de claves públicas (33B ↔ 65B), validación matemática de puntos en curva.
          </p>
        </div>
        <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateKey}>🎲 Nueva Clave Aleatoria</button>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔑</span> Desde Clave Privada</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Privada (32 bytes Hex)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Clave privada hexadecimal de 64 caracteres"
              value={privKey()}
              onInput={handlePrivKeyChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública Comprimida (33 bytes = 0x02/0x03 + X)</label>
            <div class={styles.outputBox}>
              <span>{pubComp()}</span>
              <button class={styles.copyBtn} onClick={() => copy(pubComp(), 'PubKey Comprimida')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública Descomprimida (65 bytes = 0x04 + X + Y)</label>
            <div class={styles.outputBox}>
              <span>{pubUncomp()}</span>
              <button class={styles.copyBtn} onClick={() => copy(pubUncomp(), 'PubKey Descomprimida')}>Copiar</button>
            </div>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔄</span> Comprimir / Descomprimir</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública de Entrada (33 o 65 bytes Hex)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Clave pública hexadecimal (33 o 65 bytes)"
              value={pubKeyInput()}
              onInput={handlePubKeyInputChange}
            />
          </div>

          <div class={styles.btnGroup}>
            <button class={`${styles.btn} ${styles.btnSecondary}`} onClick={compressKey} disabled={pubKeyInput().length !== 130}>
              📦 Comprimir (65B → 33B)
            </button>
            <button class={`${styles.btn} ${styles.btnSecondary}`} onClick={decompressKey} disabled={pubKeyInput().length !== 66}>
              📤 Descomprimir (33B → 65B)
            </button>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Resultado Comprimido (33 bytes)</label>
            <div class={styles.outputBox}>
              <span>{compressed()}</span>
              <button class={styles.copyBtn} onClick={() => copy(compressed(), 'Compressed')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Resultado Descomprimido (65 bytes)</label>
            <div class={styles.outputBox}>
              <span>{decompressed()}</span>
              <button class={styles.copyBtn} onClick={() => copy(decompressed(), 'Decompressed')}>Copiar</button>
            </div>
          </div>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>✅</span> Validación de Punto en Curva</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Estado de Validación</label>
            <div class={styles.outputBox} style={{ 'justify-content': 'flex-start', color: isValid() === true ? 'var(--green-success)' : isValid() === false ? 'var(--red-error)' : 'var(--text-muted)' }}>
              <span>{isValid() === null ? 'Ingresa una clave pública para validar' : isValid() ? '✓ Punto VÁLIDO en secp256k1' : '❌ Punto INVÁLIDO (fuera de curva o formato incorrecto)'}</span>
            </div>
          </div>

          <p style={{ 'font-size': '11px', color: 'var(--text-muted)', 'margin-top': '8px' }}>
            Valida: formato correcto (0x02/0x03 para 33B, 0x04 para 65B) + coordenadas satisfacen y² = x³ + 7 (mod p)
          </p>
        </div>
      </div>
    </div>
  );
};