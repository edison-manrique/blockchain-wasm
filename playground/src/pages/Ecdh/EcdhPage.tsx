/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  EcdhPage.tsx — ECDH Key Exchange (Alice & Bob)
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Ecdh, Secp256k1 } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './EcdhPage.module.css';

export const EcdhPage: Component = () => {
  // Alice
  const [alicePriv, setAlicePriv] = createSignal<string>('');
  const [alicePub, setAlicePub] = createSignal<string>('-');
  // Bob
  const [bobPriv, setBobPriv] = createSignal<string>('');
  const [bobPub, setBobPub] = createSignal<string>('-');
  // Shared secrets
  const [aliceShared, setAliceShared] = createSignal<string>('-');
  const [bobShared, setBobShared] = createSignal<string>('-');
  const [match, setMatch] = createSignal<boolean | null>(null);

  const generateAlice = () => {
    const key = getRandomHexKey();
    setAlicePriv(key);
    updateAlicePub();
  };

  const generateBob = () => {
    const key = getRandomHexKey();
    setBobPriv(key);
    updateBobPub();
  };

  const updateAlicePub = () => {
    try {
      const pk = parseHexInput(alicePriv());
      if (pk.length !== 32) return;
      const pub = Secp256k1.getPublicKey(pk, true);
      setAlicePub(bytesToHex(pub));
      computeShared();
    } catch (err) { console.error(err); }
  };

  const updateBobPub = () => {
    try {
      const pk = parseHexInput(bobPriv());
      if (pk.length !== 32) return;
      const pub = Secp256k1.getPublicKey(pk, true);
      setBobPub(bytesToHex(pub));
      computeShared();
    } catch (err) { console.error(err); }
  };

  const computeShared = () => {
    try {
      if (alicePriv() && bobPub()) {
        const aPriv = parseHexInput(alicePriv());
        const bPub = parseHexInput(bobPub());
        if (aPriv.length === 32 && (bPub.length === 33 || bPub.length === 65)) {
          const shared = Ecdh.sharedSecret(aPriv, bPub);
          setAliceShared(bytesToHex(shared));
        }
      }
      if (bobPriv() && alicePub()) {
        const bPriv = parseHexInput(bobPriv());
        const aPub = parseHexInput(alicePub());
        if (bPriv.length === 32 && (aPub.length === 33 || aPub.length === 65)) {
          const shared = Ecdh.sharedSecret(bPriv, aPub);
          setBobShared(bytesToHex(shared));
        }
      }
      if (aliceShared() !== '-' && bobShared() !== '-') {
        setMatch(aliceShared() === bobShared());
      }
    } catch (err) { console.error(err); }
  };

  const handleAlicePrivChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setAlicePriv(target.value);
    updateAlicePub();
  };

  const handleBobPrivChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setBobPriv(target.value);
    updateBobPub();
  };

  const copy = (text: string, label: string) => {
    if (text && text !== '-') copyToClipboard(text, label);
  };

  onMount(async () => {
    await initWasm();
    generateAlice();
    generateBob();
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>🔐 ECDH Key Exchange Laboratory</h1>
          <p class={styles.pageDescription}>
            Intercambio Diffie-Hellman sobre secp256k1: Alice y Bob derivan el mismo secreto compartido.
          </p>
        </div>
        <div class={styles.btnGroup}>
          <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateAlice}>🎲 Nueva Clave Alice</button>
          <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateBob}>🎲 Nueva Clave Bob</button>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>👩</span> Alice</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Privada Alice (32 bytes Hex)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Clave privada de Alice"
              value={alicePriv()}
              onInput={handleAlicePrivChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública Alice (33 bytes comprimida)</label>
            <div class={styles.outputBox}>
              <span>{alicePub()}</span>
              <button class={styles.copyBtn} onClick={() => copy(alicePub(), 'Alice PubKey')}>Copiar</button>
            </div>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>👨</span> Bob</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Privada Bob (32 bytes Hex)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Clave privada de Bob"
              value={bobPriv()}
              onInput={handleBobPrivChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública Bob (33 bytes comprimida)</label>
            <div class={styles.outputBox}>
              <span>{bobPub()}</span>
              <button class={styles.copyBtn} onClick={() => copy(bobPub(), 'Bob PubKey')}>Copiar</button>
            </div>
          </div>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔐</span> Secreto Compartido (Alice → Bob)</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>ECDH Shared Secret (33 bytes = clave pública del punto compartido)</label>
            <div class={styles.outputBox}>
              <span>{aliceShared()}</span>
              <button class={styles.copyBtn} onClick={() => copy(aliceShared(), 'Alice Shared Secret')}>Copiar</button>
            </div>
          </div>

          {match() !== null && (
            <div class={`${styles.alert} ${match() ? styles.alertSuccess : styles.alertError}`}>
              {match() ? '✓ Secretos coinciden — Intercambio ECDH exitoso' : '❌ Secretos NO coinciden — Error en intercambio'}
            </div>
          )}
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔐</span> Secreto Compartido (Bob → Alice)</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>ECDH Shared Secret (33 bytes = clave pública del punto compartido)</label>
            <div class={styles.outputBox}>
              <span>{bobShared()}</span>
              <button class={styles.copyBtn} onClick={() => copy(bobShared(), 'Bob Shared Secret')}>Copiar</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};