/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  EcdsaPage.tsx — ECDSA Secp256k1 Signing & Verification
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Secp256k1, Ecdsa } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './EcdsaPage.module.css';

const SignatureFormat = { Universal: 0, Bitcoin: 1, Ethereum: 2 } as const;
type SignatureFormat = typeof SignatureFormat[keyof typeof SignatureFormat];

export const EcdsaPage: Component = () => {
  const [privKey, setPrivKey] = createSignal<string>('');
  const [message, setMessage] = createSignal<string>('');
  const [hash, setHash] = createSignal<string>('');
  const [format, setFormat] = createSignal<SignatureFormat>(SignatureFormat.Bitcoin);

  const [pubKey, setPubKey] = createSignal<string>('-');
  const [signature, setSignature] = createSignal<string>('-');
  const [sigR, setSigR] = createSignal<string>('-');
  const [sigS, setSigS] = createSignal<string>('-');
  const [sigV, setSigV] = createSignal<number>(0);
  const [verifyResult, setVerifyResult] = createSignal<{ valid: boolean; message: string } | null>(null);
  const [verifyHashResult, setVerifyHashResult] = createSignal<{ valid: boolean; message: string } | null>(null);

  const generateKey = () => {
    const newKey = getRandomHexKey();
    setPrivKey(newKey);
    updatePubKey();
  };

  const updatePubKey = () => {
    try {
      const pk = parseHexInput(privKey());
      if (pk.length !== 32) return;
      const pub = Secp256k1.getPublicKey(pk, true);
      setPubKey(bytesToHex(pub));
    } catch (err) {
      console.error(err);
    }
  };

  const signMessage = () => {
    try {
      const pk = parseHexInput(privKey());
      if (pk.length !== 32) return;
      const msg = new TextEncoder().encode(message());

      const sig = Ecdsa.signMessage(msg, pk, format());
      const sigBytes = new Uint8Array(65);
      sigBytes.set(sig.r, 0);
      sigBytes.set(sig.s, 32);
      sigBytes[64] = sig.v;

      setSignature(bytesToHex(sigBytes));
      setSigR(bytesToHex(sig.r));
      setSigS(bytesToHex(sig.s));
      setSigV(sig.v);

      // Verify
      const pub = Secp256k1.getPublicKey(pk, false);
      const valid = Ecdsa.verifyMessage(msg, sig, pub, format());
      setVerifyResult({ valid, message: valid ? '✓ Firma VÁLIDA' : '❌ Firma INVÁLIDA' });
    } catch (err) {
      console.error(err);
      setVerifyResult({ valid: false, message: `❌ Error: ${(err as Error).message}` });
    }
  };

  const signHash = () => {
    try {
      const pk = parseHexInput(privKey());
      if (pk.length !== 32) return;
      const h = parseHexInput(hash());
      if (h.length !== 32) return;

      const sig = Ecdsa.sign(h, pk);
      const sigBytes = new Uint8Array(65);
      sigBytes.set(sig.r, 0);
      sigBytes.set(sig.s, 32);
      sigBytes[64] = sig.v;

      setSignature(bytesToHex(sigBytes));
      setSigR(bytesToHex(sig.r));
      setSigS(bytesToHex(sig.s));
      setSigV(sig.v);

      // Verify
      const pub = Secp256k1.getPublicKey(pk, false);
      const valid = Ecdsa.verify(h, sig, pub);
      setVerifyHashResult({ valid, message: valid ? '✓ Firma VÁLIDA' : '❌ Firma INVÁLIDA' });
    } catch (err) {
      console.error(err);
      setVerifyHashResult({ valid: false, message: `❌ Error: ${(err as Error).message}` });
    }
  };

  const verifySignature = () => {
    try {
      const sigHex = signature();
      const sigBytes = parseHexInput(sigHex);
      if (sigBytes.length !== 65) return;

      const sig = { r: sigBytes.slice(0, 32), s: sigBytes.slice(32, 64), v: sigBytes[64] };
      const pub = parseHexInput(pubKey());
      if (pub.length !== 65 && pub.length !== 33) return;

      const pubUncomp = pub.length === 33 ? Secp256k1.uncompress(pub) : pub;
      const msg = new TextEncoder().encode(message());

      const valid = Ecdsa.verifyMessage(msg, sig, pubUncomp, format());
      setVerifyResult({ valid, message: valid ? '✓ Firma VÁLIDA' : '❌ Firma INVÁLIDA' });
    } catch (err) {
      console.error(err);
      setVerifyResult({ valid: false, message: `❌ Error: ${(err as Error).message}` });
    }
  };

  const handlePrivKeyChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPrivKey(target.value);
    updatePubKey();
  };

  const handleMessageChange = (e: Event) => {
    const target = e.target as HTMLTextAreaElement;
    setMessage(target.value);
  };

  const handleHashChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setHash(target.value);
  };

  const handleFormatChange = (e: Event) => {
    const target = e.target as HTMLSelectElement;
    setFormat(parseInt(target.value) as SignatureFormat);
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
          <h1 class={styles.pageTitle}>✍️ ECDSA Secp256k1 Laboratory</h1>
          <p class={styles.pageDescription}>
            Firmas y verificación ECDSA con formatos Raw (r|s|v), Bitcoin (Low-S + DER) y Ethereum (v=27/28).
          </p>
        </div>
        <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateKey}>🎲 Nueva Clave Aleatoria</button>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔑</span> Claves</span>
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
            <label class={styles.formLabel}>Clave Pública Comprimida (33 bytes)</label>
            <div class={styles.outputBox}>
              <span>{pubKey()}</span>
              <button class={styles.copyBtn} onClick={() => copy(pubKey(), 'PubKey')}>Copiar</button>
            </div>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>📝</span> Firmar Mensaje</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Formato de Firma</label>
            <select class={styles.selectCustom} value={format()} onChange={handleFormatChange}>
              <option value={0}>Raw (r||s||v) — 65 bytes</option>
              <option value={1}>Bitcoin (Low-S + DER)</option>
              <option value={2}>Ethereum (v=27/28)</option>
            </select>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Mensaje (UTF-8)</label>
            <textarea
              class={styles.textareaCustom}
              rows={3}
              placeholder="Mensaje a firmar..."
              value={message()}
              onInput={handleMessageChange}
            />
          </div>

          <div class={styles.btnGroup}>
            <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={signMessage}>✍️ Firmar Mensaje</button>
            <button class={`${styles.btn} ${styles.btnSecondary}`} onClick={verifySignature}>🔍 Verificar Firma</button>
          </div>

          {verifyResult() && (
            <div class={`${styles.alert} ${verifyResult()!.valid ? styles.alertSuccess : styles.alertError}`}>
              {verifyResult()!.message}
            </div>
          )}
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔐</span> Firmar Hash (32 bytes)</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Hash (32 bytes Hex)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Hash hexadecimal de 64 caracteres (32 bytes)"
              value={hash()}
              onInput={handleHashChange}
            />
          </div>

          <div class={styles.btnGroup}>
            <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={signHash}>✍️ Firmar Hash</button>
          </div>

          {verifyHashResult() && (
            <div class={`${styles.alert} ${verifyHashResult()!.valid ? styles.alertSuccess : styles.alertError}`}>
              {verifyHashResult()!.message}
            </div>
          )}
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>📋</span> Resultado de Firma</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Firma Completa (65 bytes Hex)</label>
            <div class={styles.outputBox}>
              <span>{signature()}</span>
              <button class={styles.copyBtn} onClick={() => copy(signature(), 'Signature')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>R (32 bytes)</label>
            <div class={styles.outputBox}>
              <span>{sigR()}</span>
              <button class={styles.copyBtn} onClick={() => copy(sigR(), 'R')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>S (32 bytes)</label>
            <div class={styles.outputBox}>
              <span>{sigS()}</span>
              <button class={styles.copyBtn} onClick={() => copy(sigS(), 'S')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>V (1 byte)</label>
            <div class={styles.outputBox} style={{ 'justify-content': 'flex-start' }}>
              <span>{sigV()}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};