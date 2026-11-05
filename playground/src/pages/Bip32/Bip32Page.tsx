/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  Bip32Page.tsx — BIP-32 HD Tree Laboratory
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Bip32 } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './Bip32Page.module.css';

export const Bip32Page: Component = () => {
  const [seed, setSeed] = createSignal<string>('');
  const [path, setPath] = createSignal<string>("m/44'/0'/0'/0/0");
  const [masterXprv, setMasterXprv] = createSignal<string>('-');
  const [masterXpub, setMasterXpub] = createSignal<string>('-');
  const [derivedXprv, setDerivedXprv] = createSignal<string>('-');
  const [derivedXpub, setDerivedXpub] = createSignal<string>('-');
  const [derivedPrivKey, setDerivedPrivKey] = createSignal<string>('-');
  const [derivedPubKey, setDerivedPubKey] = createSignal<string>('-');
  const [depth, setDepth] = createSignal<number>(0);
  const [parentFp, setParentFp] = createSignal<string>('-');
  const [childIndex, setChildIndex] = createSignal<number>(0);
  const [isPrivate, setIsPrivate] = createSignal<boolean>(false);
  const [chainCode, setChainCode] = createSignal<string>('-');
  const [fingerprint, setFingerprint] = createSignal<string>('-');

  const generateSeed = () => {
    const newSeed = getRandomHexKey() + getRandomHexKey();
    setSeed(newSeed);
    processSeed();
  };

  const processSeed = () => {
    try {
      if (!seed().trim()) return;

      const seedBytes = parseHexInput(seed());
      if (seedBytes.length < 16 || seedBytes.length > 64) return;

      const master = Bip32.fromSeed(seedBytes);
      setMasterXprv(master.toXprv());
      setMasterXpub(master.toXpub());

      const pubKey = master.getPublicKey();
      setDerivedPubKey(bytesToHex(pubKey));
      setDerivedPrivKey('-');
      updateKeyInfo(master);
      derivePath();
    } catch (err) {
      console.error(err);
    }
  };

  const derivePath = () => {
    try {
      if (!masterXprv() || masterXprv() === '-') return;

      const master = Bip32.fromXprv(masterXprv());
      const derived = master.derivePath(path());

      setDerivedXprv(derived.toXprv());
      setDerivedXpub(derived.neuter().toXpub());

      const privKey = derived.privateKey;
      const pubKey = derived.publicKey;

      setDerivedPrivKey(bytesToHex(privKey));
      setDerivedPubKey(bytesToHex(pubKey));
      updateKeyInfo(derived);
    } catch (err) {
      console.error(err);
    }
  };

  const updateKeyInfo = (key: any) => {
    try {
      setDepth(key.depth);
      setParentFp('0x' + key.parentFingerprint.toString(16).padStart(8, '0'));
      setChildIndex(key.childIndex);
      setIsPrivate(key.isPrivate);
      setChainCode(bytesToHex(key.chainCode));
      setFingerprint('0x' + key.fingerprint().toString(16).padStart(8, '0'));
    } catch (err) {
      console.error(err);
    }
  };

  const handleSeedChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setSeed(target.value);
    processSeed();
  };

  const handlePathChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPath(target.value);
    derivePath();
  };

  const copy = (text: string, label: string) => {
    if (text && text !== '-') copyToClipboard(text, label);
  };

  onMount(async () => {
    await initWasm();
    generateSeed();
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>🌳 BIP-32 HD Tree Laboratory</h1>
          <p class={styles.pageDescription}>
            Derivación jerárquica determinista: master key → xprv/xpub → derivación por path → claves hijas.
          </p>
        </div>
        <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateSeed}>🎲 Nueva Seed Aleatoria</button>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🌱</span> Master Key (Seed)</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Seed (64 bytes / 128 hex chars)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Seed hexadecimal de 64 bytes (generada desde BIP-39)"
              value={seed()}
              onInput={handleSeedChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Master XPRV (clave privada extendida)</label>
            <div class={styles.outputBox}>
              <span>{masterXprv()}</span>
              <button class={styles.copyBtn} onClick={() => copy(masterXprv(), 'Master XPRV')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Master XPUB (clave pública extendida)</label>
            <div class={styles.outputBox}>
              <span>{masterXpub()}</span>
              <button class={styles.copyBtn} onClick={() => copy(masterXpub(), 'Master XPUB')}>Copiar</button>
            </div>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔍</span> Derivación por Path</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Ruta de Derivación BIP-32</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="m/44'/0'/0'/0/0"
              value={path()}
              onInput={handlePathChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Derived XPRV</label>
            <div class={styles.outputBox}>
              <span>{derivedXprv()}</span>
              <button class={styles.copyBtn} onClick={() => copy(derivedXprv(), 'Derived XPRV')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Derived XPUB</label>
            <div class={styles.outputBox}>
              <span>{derivedXpub()}</span>
              <button class={styles.copyBtn} onClick={() => copy(derivedXpub(), 'Derived XPUB')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Privada Derivada (32 bytes)</label>
            <div class={styles.outputBox}>
              <span>{derivedPrivKey()}</span>
              <button class={styles.copyBtn} onClick={() => copy(derivedPrivKey(), 'Derived PrivKey')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública Derivada (33 bytes comprimida)</label>
            <div class={styles.outputBox}>
              <span>{derivedPubKey()}</span>
              <button class={styles.copyBtn} onClick={() => copy(derivedPubKey(), 'Derived PubKey')}>Copiar</button>
            </div>
          </div>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>📊</span> Metadatos de la Clave (XKey)</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Profundidad (Depth)</label>
            <div class={styles.outputBox} style={{ 'justify-content': 'flex-start' }}>
              <span>{depth()}</span>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Parent Fingerprint</label>
            <div class={styles.outputBox} style={{ 'justify-content': 'flex-start' }}>
              <span>{parentFp()}</span>
              <button class={styles.copyBtn} onClick={() => copy(parentFp(), 'Parent FP')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Child Index</label>
            <div class={styles.outputBox} style={{ 'justify-content': 'flex-start' }}>
              <span>{childIndex()}</span>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>¿Es Privada?</label>
            <div class={styles.outputBox} style={{ 'justify-content': 'flex-start' }}>
              <span>{isPrivate() ? 'Sí (xprv)' : 'No (xpub)'}</span>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Chain Code (32 bytes)</label>
            <div class={styles.outputBox}>
              <span>{chainCode()}</span>
              <button class={styles.copyBtn} onClick={() => copy(chainCode(), 'Chain Code')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Fingerprint (4 bytes)</label>
            <div class={styles.outputBox} style={{ 'justify-content': 'flex-start' }}>
              <span>{fingerprint()}</span>
              <button class={styles.copyBtn} onClick={() => copy(fingerprint(), 'Fingerprint')}>Copiar</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};