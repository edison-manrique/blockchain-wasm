/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  WifPage.tsx — WIF (Wallet Import Format) Encode/Decode
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Wif } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './WifPage.module.css';

export const WifPage: Component = () => {
  const [privKey, setPrivKey] = createSignal<string>('');
  const [compressed, setCompressed] = createSignal<boolean>(true);
  const [wifEncoded, setWifEncoded] = createSignal<string>('-');
  const [wifInput, setWifInput] = createSignal<string>('');
  const [wifDecoded, setWifDecoded] = createSignal<{ privateKey: string; compressed: boolean } | null>(null);

  const generateKey = () => {
    const key = getRandomHexKey();
    setPrivKey(key);
    encodeWif();
  };

  const encodeWif = () => {
    try {
      const pk = parseHexInput(privKey());
      if (pk.length !== 32) return;
      const wif = Wif.encode(pk, compressed());
      setWifEncoded(wif);
    } catch (err) {
      console.error(err);
    }
  };

  const decodeWif = () => {
    try {
      const wif = wifInput().trim();
      if (!wif) return;
      const decoded = Wif.decode(wif);
      setWifDecoded({
        privateKey: bytesToHex(decoded.privateKey),
        compressed: decoded.compressed
      });
    } catch (err) {
      console.error(err);
      setWifDecoded(null);
    }
  };

  const handlePrivKeyChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPrivKey(target.value);
    encodeWif();
  };

  const handleCompressedChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setCompressed(target.checked);
    encodeWif();
  };

  const handleWifInputChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setWifInput(target.value);
    decodeWif();
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
          <h1 class={styles.pageTitle}>🎫 WIF Format Laboratory</h1>
          <p class={styles.pageDescription}>
            Wallet Import Format (Base58Check) encode/decode. Compressed (K/L) y Uncompressed (5) prefixes.
          </p>
        </div>
        <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateKey}>🎲 Nueva Clave Aleatoria</button>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔐</span> WIF Encode (PrivKey → WIF)</span>
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
            <label class={styles.formLabel}>
              <input type="checkbox" checked={compressed()} onChange={handleCompressedChange} style={{ 'margin-right': '8px' }} />
              Clave Pública Comprimida (true = K/L prefix, false = 5 prefix)
            </label>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>WIF Encoded (Base58Check)</label>
            <div class={styles.outputBox}>
              <span>{wifEncoded()}</span>
              <button class={styles.copyBtn} onClick={() => copy(wifEncoded(), 'WIF Encoded')}>Copiar</button>
            </div>
          </div>

          <p style={{ 'font-size': '11px', color: 'var(--text-muted)', 'margin-top': '8px' }}>
            Comprimido (true): Prefijo <strong>K</strong> (mainnet) / <strong>L</strong> (testnet)<br/>
            Descomprimido (false): Prefijo <strong>5</strong> (mainnet) / <strong>9</strong> (testnet)
          </p>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔓</span> WIF Decode (WIF → PrivKey)</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>WIF String (Base58Check)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Ej: Kx... o Lx... o 5x..."
              value={wifInput()}
              onInput={handleWifInputChange}
            />
          </div>

          {wifDecoded() && (
            <>
              <div class={styles.formGroup}>
                <label class={styles.formLabel}>Clave Privada Decodificada (32 bytes Hex)</label>
                <div class={styles.outputBox}>
                  <span>{wifDecoded()!.privateKey}</span>
                  <button class={styles.copyBtn} onClick={() => copy(wifDecoded()!.privateKey, 'WIF Decoded PrivKey')}>Copiar</button>
                </div>
              </div>

              <div class={styles.formGroup}>
                <label class={styles.formLabel}>¿Estaba Comprimida?</label>
                <div class={styles.outputBox} style={{ 'justify-content': 'flex-start' }}>
                  <span>{wifDecoded()!.compressed ? 'Sí (comprimida - 33 bytes pubkey)' : 'No (descomprimida - 65 bytes pubkey)'}</span>
                </div>
              </div>
            </>
          )}

          <p style={{ 'font-size': '11px', color: 'var(--text-muted)', 'margin-top': '8px' }}>
            WIF = Base58Check(version byte + private key + compression flag + checksum 4 bytes)
          </p>
        </div>
      </div>
    </div>
  );
};