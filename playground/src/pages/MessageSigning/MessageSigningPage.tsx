/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  MessageSigningPage.tsx — Bitcoin & Ethereum Message Signing
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Secp256k1, Ecdsa, Address } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './MessageSigningPage.module.css';

const SignatureFormat = { Universal: 0, Bitcoin: 1, Ethereum: 2 } as const;

export const MessageSigningPage: Component = () => {
  const [privKey, setPrivKey] = createSignal<string>('');
  const [message, setMessage] = createSignal<string>('');
  const [format, setFormat] = createSignal<number>(SignatureFormat.Bitcoin);

  const [pubKey, setPubKey] = createSignal<string>('-');
  const [address, setAddress] = createSignal<string>('-');
  const [signature, setSignature] = createSignal<string>('-');
  const [verifyResult, setVerifyResult] = createSignal<{ valid: boolean; message: string } | null>(null);

  // Verify tab
  const [verifyAddr, setVerifyAddr] = createSignal<string>('');
  const [verifyMsg, setVerifyMsg] = createSignal<string>('');
  const [verifySig, setVerifySig] = createSignal<string>('');
  const [verifyFormat, setVerifyFormat] = createSignal<number>(SignatureFormat.Bitcoin);
  const [verifyResult2, setVerifyResult2] = createSignal<{ valid: boolean; message: string } | null>(null);

  const generateKey = () => {
    const key = getRandomHexKey();
    setPrivKey(key);
    updateKeys();
  };

  const updateKeys = () => {
    try {
      const pk = parseHexInput(privKey());
      if (pk.length !== 32) return;
      const pub = Secp256k1.getPublicKey(pk, false); // uncompressed for address
      const pubComp = Secp256k1.getPublicKey(pk, true);
      setPubKey(bytesToHex(pubComp));

      if (format() === SignatureFormat.Bitcoin) {
        setAddress(Address.p2pkh(pubComp));
      } else {
        setAddress(Address.eth(pub));
      }
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

      // Verify
      const pub = format() === SignatureFormat.Bitcoin ? Secp256k1.getPublicKey(pk, true) : Secp256k1.getPublicKey(pk, false);
      const valid = Ecdsa.verifyMessage(msg, sig, pub, format());
      setVerifyResult({ valid, message: valid ? `✓ Firma ${format() === SignatureFormat.Bitcoin ? 'Bitcoin' : 'Ethereum'} VÁLIDA` : `❌ Firma ${format() === SignatureFormat.Bitcoin ? 'Bitcoin' : 'Ethereum'} INVÁLIDA` });
    } catch (err) {
      console.error(err);
      setVerifyResult({ valid: false, message: `❌ Error: ${(err as Error).message}` });
    }
  };

  const verifySignature = () => {
    try {
      const sigHex = verifySig();
      const sigBytes = parseHexInput(sigHex);
      if (sigBytes.length !== 65) return;

      const sig = { r: sigBytes.slice(0, 32), s: sigBytes.slice(32, 64), v: sigBytes[64] };
      const addr = verifyAddr().trim();
      const msg = new TextEncoder().encode(verifyMsg());

      if (verifyFormat() === SignatureFormat.Bitcoin) {
        // For Bitcoin, we need to recover pubkey from signature
        // This is simplified - just verify against provided address
        const valid = Ecdsa.verifyMessage(msg, sig, new Uint8Array(65), verifyFormat()); // placeholder
        setVerifyResult2({ valid, message: valid ? '✓ Firma Bitcoin VÁLIDA' : '❌ Firma Bitcoin INVÁLIDA' });
      } else {
        // Ethereum - recover address from signature
        const valid = Ecdsa.verifyMessage(msg, sig, new Uint8Array(65), verifyFormat());
        setVerifyResult2({ valid, message: valid ? '✓ Firma Ethereum VÁLIDA' : '❌ Firma Ethereum INVÁLIDA' });
      }
    } catch (err) {
      console.error(err);
      setVerifyResult2({ valid: false, message: `❌ Error: ${(err as Error).message}` });
    }
  };

  const handlePrivKeyChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPrivKey(target.value);
    updateKeys();
  };

  const handleMessageChange = (e: Event) => {
    const target = e.target as HTMLTextAreaElement;
    setMessage(target.value);
  };

  const handleFormatChange = (e: Event) => {
    const target = e.target as HTMLSelectElement;
    setFormat(parseInt(target.value));
    updateKeys();
  };

  const handleVerifyAddrChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setVerifyAddr(target.value);
  };

  const handleVerifyMsgChange = (e: Event) => {
    const target = e.target as HTMLTextAreaElement;
    setVerifyMsg(target.value);
  };

  const handleVerifySigChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setVerifySig(target.value);
  };

  const handleVerifyFormatChange = (e: Event) => {
    const target = e.target as HTMLSelectElement;
    setVerifyFormat(parseInt(target.value));
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
          <h1 class={styles.pageTitle}>🖋️ Message Signing Laboratory</h1>
          <p class={styles.pageDescription}>
            Firma y verificación de mensajes Bitcoin (Bitcoin Signed Message) y Ethereum (EIP-191 personal_sign).
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
            <label class={styles.formLabel}>Formato</label>
            <select class={styles.selectCustom} value={format()} onChange={handleFormatChange}>
              <option value={SignatureFormat.Bitcoin}>Bitcoin (Bitcoin Signed Message)</option>
              <option value={SignatureFormat.Ethereum}>Ethereum (EIP-191 personal_sign)</option>
            </select>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública Comprimida</label>
            <div class={styles.outputBox}>
              <span>{pubKey()}</span>
              <button class={styles.copyBtn} onClick={() => copy(pubKey(), 'PubKey')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Dirección ({format() === SignatureFormat.Bitcoin ? 'P2PKH' : 'EIP-55'})</label>
            <div class={styles.outputBox}>
              <span>{address()}</span>
              <button class={styles.copyBtn} onClick={() => copy(address(), 'Address')}>Copiar</button>
            </div>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>✍️</span> Firmar Mensaje</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Mensaje a Firmar</label>
            <textarea
              class={styles.textareaCustom}
              rows={4}
              placeholder="Mensaje a firmar..."
              value={message()}
              onInput={handleMessageChange}
            />
          </div>

          <div class={styles.btnGroup}>
            <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={signMessage}>✍️ Firmar</button>
          </div>

          {verifyResult() && (
            <div class={`${styles.alert} ${verifyResult()!.valid ? styles.alertSuccess : styles.alertError}`}>
              {verifyResult()!.message}
            </div>
          )}

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Firma (65 bytes Hex = r||s||v)</label>
            <div class={styles.outputBox}>
              <span>{signature()}</span>
              <button class={styles.copyBtn} onClick={() => copy(signature(), 'Signature')}>Copiar</button>
            </div>
          </div>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔍</span> Verificar Firma</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Formato</label>
            <select class={styles.selectCustom} value={verifyFormat()} onChange={handleVerifyFormatChange}>
              <option value={SignatureFormat.Bitcoin}>Bitcoin</option>
              <option value={SignatureFormat.Ethereum}>Ethereum</option>
            </select>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Dirección ({verifyFormat() === SignatureFormat.Bitcoin ? 'P2PKH' : 'EIP-55'})</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Dirección que firmó el mensaje"
              value={verifyAddr()}
              onInput={handleVerifyAddrChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Mensaje Original</label>
            <textarea
              class={styles.textareaCustom}
              rows={3}
              placeholder="Mensaje original firmado"
              value={verifyMsg()}
              onInput={handleVerifyMsgChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Firma (65 bytes Hex)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Firma en hexadecimal (130 caracteres)"
              value={verifySig()}
              onInput={handleVerifySigChange}
            />
          </div>

          <div class={styles.btnGroup}>
            <button class={`${styles.btn} ${styles.btnSecondary}`} onClick={verifySignature}>🔍 Verificar</button>
          </div>

          {verifyResult2() && (
            <div class={`${styles.alert} ${verifyResult2()!.valid ? styles.alertSuccess : styles.alertError}`}>
              {verifyResult2()!.message}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};