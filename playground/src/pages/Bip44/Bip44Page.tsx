/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  Bip44Page.tsx — BIP-44 Multi-coin Wallet Laboratory
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Bip44 } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './Bip44Page.module.css';

interface Bip44Leaf {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export const Bip44Page: Component = () => {
  const [seed, setSeed] = createSignal<string>('');
  const [mnemonic, setMnemonic] = createSignal<string>('');
  const [passphrase, setPassphrase] = createSignal<string>('');
  const [purpose, setPurpose] = createSignal<number>(44);
  const [coinType, setCoinType] = createSignal<number>(0); // 0 = BTC, 60 = ETH
  const [account, setAccount] = createSignal<number>(0);
  const [change, setChange] = createSignal<number>(0);
  const [addressIndex, setAddressIndex] = createSignal<number>(0);

  const [accountXprv, setAccountXprv] = createSignal<string>('-');
  const [accountXpub, setAccountXpub] = createSignal<string>('-');
  const [leaf, setLeaf] = createSignal<Bip44Leaf | null>(null);

  const coinTypes = [
    { value: 0, label: 'Bitcoin (BTC)' },
    { value: 60, label: 'Ethereum (ETH)' },
    { value: 195, label: 'Tron (TRX)' },
    { value: 2, label: 'Litecoin (LTC)' },
    { value: 145, label: 'Dogecoin (DOGE)' },
    { value: 1815, label: 'Cardano (ADA)' },
  ];

  const purposes = [
    { value: 44, label: "BIP-44 (44')" },
    { value: 49, label: "BIP-49 (49') - Nested SegWit" },
    { value: 84, label: "BIP-84 (84') - Native SegWit" },
    { value: 86, label: "BIP-86 (86') - Taproot" },
  ];

  const generateSeed = () => {
    const newSeed = getRandomHexKey() + getRandomHexKey(); // 64 bytes
    setSeed(newSeed);
    deriveFromSeed();
  };

  const deriveFromSeed = () => {
    try {
      if (!seed().trim()) return;
      const seedBytes = parseHexInput(seed());
      if (seedBytes.length !== 64) return;

      const xprv = Bip44.accountXprv(seedBytes, purpose(), coinType(), account());
      const xpub = Bip44.accountXpub(seedBytes, purpose(), coinType(), account());

      setAccountXprv(xprv);
      setAccountXpub(xpub);
      deriveLeaf();
    } catch (err) {
      console.error(err);
    }
  };

  const deriveFromMnemonic = () => {
    try {
      if (!mnemonic().trim()) return;

      const xprv = Bip44.fromMnemonicXprv(mnemonic(), passphrase(), purpose(), coinType(), account());
      const xpub = Bip44.fromMnemonicXpub(mnemonic(), passphrase(), purpose(), coinType(), account());

      setAccountXprv(xprv);
      setAccountXpub(xpub);
      deriveLeafFromMnemonic();
    } catch (err) {
      console.error(err);
    }
  };

  const deriveLeaf = () => {
    try {
      if (!seed().trim()) return;
      const seedBytes = parseHexInput(seed());
      if (seedBytes.length !== 64) return;

      const result = Bip44.deriveKeys(seedBytes, purpose(), coinType(), account(), change(), addressIndex());
      setLeaf(result);
    } catch (err) {
      console.error(err);
    }
  };

  const deriveLeafFromMnemonic = () => {
    try {
      if (!mnemonic().trim()) return;
      const result = Bip44.fromMnemonicDerive(mnemonic(), passphrase(), purpose(), coinType(), account(), change(), addressIndex());
      setLeaf(result);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSeedChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setSeed(target.value);
    deriveFromSeed();
  };

  const handleMnemonicChange = (e: Event) => {
    const target = e.target as HTMLTextAreaElement;
    setMnemonic(target.value);
    deriveFromMnemonic();
  };

  const handlePassphraseChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPassphrase(target.value);
    deriveFromMnemonic();
  };

  const handleChange = (setter: (v: number) => void) => (e: Event) => {
    const target = e.target as HTMLInputElement;
    setter(parseInt(target.value) || 0);
    deriveFromSeed();
    deriveFromMnemonic();
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
          <h1 class={styles.pageTitle}>💼 BIP-44 Multi-Coin Wallet Laboratory</h1>
          <p class={styles.pageDescription}>
            Matriz HD multi-moneda: purpose → coin_type → account → change → address_index.
            Soporta BIP-44 (Legacy), BIP-49 (Nested SegWit), BIP-84 (Native SegWit), BIP-86 (Taproot).
          </p>
        </div>
        <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateSeed}>🎲 Nueva Seed Aleatoria</button>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🌱</span> Entrada: Seed o Mnemónico</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Seed (64 bytes / 128 hex chars)</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Seed hexadecimal de 64 bytes"
              value={seed()}
              onInput={handleSeedChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Mnemónico BIP-39 (alternativa a seed)</label>
            <textarea
              class={styles.textareaCustom}
              rows={2}
              placeholder="Ingresa frase mnemónica de 12-24 palabras"
              value={mnemonic()}
              onInput={handleMnemonicChange}
            />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Passphrase Opcional</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="Passphrase (25th word)"
              value={passphrase()}
              onInput={handlePassphraseChange}
            />
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>⚙️</span> Parámetros BIP-44</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Purpose</label>
            <select class={styles.selectCustom} value={purpose()} onChange={(e) => { setPurpose(parseInt((e.target as HTMLSelectElement).value)); deriveFromSeed(); deriveFromMnemonic(); }}>
              {purposes.map(p => <option value={p.value}>{p.label}</option>)}
            </select>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Coin Type</label>
            <select class={styles.selectCustom} value={coinType()} onChange={(e) => { setCoinType(parseInt((e.target as HTMLSelectElement).value)); deriveFromSeed(); deriveFromMnemonic(); }}>
              {coinTypes.map(c => <option value={c.value}>{c.label}</option>)}
            </select>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Account Index</label>
            <input type="number" class={styles.inputText} value={account()} onChange={handleChange(setAccount)} min={0} max={2147483647} />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Change (0=external, 1=internal)</label>
            <input type="number" class={styles.inputText} value={change()} onChange={handleChange(setChange)} min={0} max={1} />
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Address Index</label>
            <input type="number" class={styles.inputText} value={addressIndex()} onChange={handleChange(setAddressIndex)} min={0} max={2147483647} />
          </div>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔑</span> Account Extended Keys</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Account XPRV</label>
            <div class={styles.outputBox}>
              <span>{accountXprv()}</span>
              <button class={styles.copyBtn} onClick={() => copy(accountXprv(), 'Account XPRV')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Account XPUB</label>
            <div class={styles.outputBox}>
              <span>{accountXpub()}</span>
              <button class={styles.copyBtn} onClick={() => copy(accountXpub(), 'Account XPUB')}>Copiar</button>
            </div>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🍃</span> Derived Leaf (address_index: {addressIndex()})</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Private Key (32 bytes)</label>
            <div class={styles.outputBox}>
              <span>{leaf() ? bytesToHex(leaf()!.privateKey) : '-'}</span>
              <button class={styles.copyBtn} onClick={() => leaf() && copy(bytesToHex(leaf()!.privateKey), 'Leaf PrivKey')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Public Key (33 bytes compressed)</label>
            <div class={styles.outputBox}>
              <span>{leaf() ? bytesToHex(leaf()!.publicKey) : '-'}</span>
              <button class={styles.copyBtn} onClick={() => leaf() && copy(bytesToHex(leaf()!.publicKey), 'Leaf PubKey')}>Copiar</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};