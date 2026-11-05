/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  SchnorrPage.tsx — Schnorr BIP-340 Taproot Signing
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Schnorr, Secp256k1 } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './SchnorrPage.module.css';

export const SchnorrPage: Component = () => {
  const [privKey, setPrivKey] = createSignal<string>('');
  const [message, setMessage] = createSignal<string>('');
  const [auxRand, setAuxRand] = createSignal<string>('');
  const [pubKey, setPubKey] = createSignal<string>('-');
  const [signature, setSignature] = createSignal<string>('-');
  const [verifyResult, setVerifyResult] = createSignal<{ valid: boolean; message: string } | null>(null);
  const [verifyPubKey, setVerifyPubKey] = createSignal<string>('');
  const [verifyMsg, setVerifyMsg] = createSignal<string>('');
  const [verifySig, setVerifySig] = createSignal<string>('');
  const [verifySigResult, setVerifySigResult] = createSignal<{ valid: boolean; message: string } | null>(null);

  const generateKey = () => {
    const newKey = getRandomHexKey();
    setPrivKey(newKey);
    updatePubKey();
  };

  const updatePubKey = () => {
    try {
      const pk = parseHexInput(privKey());
      if (pk.length !== 32) return;
      const pub = Schnorr.getPublicKey(pk);
      setPubKey(bytesToHex(pub));
      setVerifyPubKey(bytesToHex(pub));
    } catch (err) {
      console.error(err);
    }
  };

  const signMessage = () => {
    try {
      const pk = parseHexInput(privKey());
      if (pk.length !== 32) return;
      const msg = new TextEncoder().encode(message());
      const aux = auxRand() ? parseHexInput(auxRand()) : undefined;

      const sig = Schnorr.sign(msg, pk, aux);
      setSignature(bytesToHex(sig));
      setVerifySig(bytesToHex(sig));
      setVerifyMsg(message());

      // Verify
      const valid = Schnorr.verify(sig, msg, Schnorr.getPublicKey(pk));
      setVerifyResult({ valid, message: valid ? '✓ Firma Schnorr VÁLIDA (BIP-340)' : '❌ Firma INVÁLIDA' });
    } catch (err) {
      console.error(err);
      setVerifyResult({ valid: false, message: `❌ Error: ${(err as Error).message}` });
    }
  };

  const verifySignature = () => {
    try {
      const sigBytes = parseHexInput(verifySig());
      if (sigBytes.length !== 64) return;
      const pubBytes = parseHexInput(verifyPubKey());
      if (pubBytes.length !== 32) return;
      const msg = new TextEncoder().encode(verifyMsg());

      const valid = Schnorr.verify(sigBytes, msg, pubBytes);
      setVerifySigResult({ valid, message: valid ? '✓ Firma Schnorr VÁLIDA (BIP-340)' : '❌ Firma INVÁLIDA' });
    } catch (err) {
      console.error(err);
      setVerifySigResult({ valid: false, message: `❌ Error: ${(err as Error).message}` });
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

  const handleAuxRandChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setAuxRand(target.value);
  };

  const handleVerifyPubKeyChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setVerifyPubKey(target.value);
  };

  const handleVerifyMsgChange = (e: Event) => {
    const target = e.target as HTMLTextAreaElement;
    setVerifyMsg(target.value);
  };

  const handleVerifySigChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setVerifySig(target.value);
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
          <h1 class={styles.pageTitle}>⚡ Schnorr BIP-340 Taproot Laboratory</h1>
          <p class={styles.pageDescription}>
            Firmas Schnorr de 64 bytes (r||s) con claves x-only de 32 bytes. Soporte para aux_rand (RFC 6979).
          </p>
        </div>
        <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateKey}>🎲 Nueva Clave Aleatoria</button>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔑</span> Claves x-only</span>
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
            <label class={styles.formLabel}>Aux Rand Opcional (32 bytes Hex)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Entropía auxiliar para firma determinística (opcional)"
              value={auxRand()}
              onInput={handleAuxRandChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública x-only (32 bytes)</label>
            <div class={styles.outputBox}>
              <span>{pubKey()}</span>
              <button class={styles.copyBtn} onClick={() => copy(pubKey(), 'PubKey x-only')}>Copiar</button>
            </div>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>✍️</span> Firmar Mensaje (BIP-340)</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Mensaje (UTF-8)</label>
            <textarea
              class={styles.textareaCustom}
              rows={3}
              placeholder="Mensaje a firmar con Schnorr..."
              value={message()}
              onInput={handleMessageChange}
            />
          </div>

          <div class={styles.btnGroup}>
            <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={signMessage}>⚡ Firmar Schnorr</button>
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
            <span class={styles.cardTitle}><span class={styles.icon}>📋</span> Firma Resultante</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Firma Schnorr (64 bytes = r||s)</label>
            <div class={styles.outputBox}>
              <span>{signature()}</span>
              <button class={styles.copyBtn} onClick={() => copy(signature(), 'Schnorr Signature')}>Copiar</button>
            </div>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔍</span> Verificar Firma Schnorr</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública x-only (32 bytes Hex)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Clave pública x-only de 64 caracteres hex"
              value={verifyPubKey()}
              onInput={handleVerifyPubKeyChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Mensaje (UTF-8)</label>
            <textarea
              class={styles.textareaCustom}
              rows={2}
              placeholder="Mensaje original firmado"
              value={verifyMsg()}
              onInput={handleVerifyMsgChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Firma (64 bytes Hex)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Firma Schnorr de 128 caracteres hex"
              value={verifySig()}
              onInput={handleVerifySigChange}
            />
          </div>

          <div class={styles.btnGroup}>
            <button class={`${styles.btn} ${styles.btnSecondary}`} onClick={verifySignature}>🔍 Verificar</button>
          </div>

          {verifySigResult() && (
            <div class={`${styles.alert} ${verifySigResult()!.valid ? styles.alertSuccess : styles.alertError}`}>
              {verifySigResult()!.message}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};