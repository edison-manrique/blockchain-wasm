/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  AddressPage.tsx — Generación de direcciones BTC/ETH/TRX desde Privkey o Pubkey
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount, Show } from 'solid-js';
import { Secp256k1, Address } from 'blockchain-wasm';
import { initWasm, getRandomHexKey, parseHexInput, bytesToHex, copyToClipboard } from '../../utils/wasm';
import styles from './AddressPage.module.css';

export const AddressPage: Component = () => {
  const [mode, setMode] = createSignal<'privkey' | 'pubkey'>('privkey');
  const [privKey, setPrivKey] = createSignal<string>('');
  const [pubKeyInput, setPubKeyInput] = createSignal<string>('');

  const [pubComp, setPubComp] = createSignal<string>('-');
  const [pubUncomp, setPubUncomp] = createSignal<string>('-');
  const [pubStatus, setPubStatus] = createSignal<{ valid: boolean; text: string } | null>(null);

  const [addrP2pkh, setAddrP2pkh] = createSignal<string>('-');
  const [addrP2pkhUncomp, setAddrP2pkhUncomp] = createSignal<string>('-');
  const [addrP2sh, setAddrP2sh] = createSignal<string>('-');
  const [addrP2wpkh, setAddrP2wpkh] = createSignal<string>('-');
  const [addrP2tr, setAddrP2tr] = createSignal<string>('-');
  const [addrEth, setAddrEth] = createSignal<string>('-');
  const [addrTron, setAddrTron] = createSignal<string>('-');

  const resetAddresses = () => {
    setAddrP2pkh('-');
    setAddrP2pkhUncomp('-');
    setAddrP2sh('-');
    setAddrP2wpkh('-');
    setAddrP2tr('-');
    setAddrEth('-');
    setAddrTron('-');
  };

  const deriveFromPubkeys = (compBytes: Uint8Array, uncompBytes: Uint8Array) => {
    setAddrP2pkh(Address.p2pkh(compBytes));
    setAddrP2pkhUncomp(Address.p2pkhUncompressed(uncompBytes));
    setAddrP2sh(Address.p2shP2wpkh(compBytes));
    setAddrP2wpkh(Address.p2wpkh(compBytes));
    setAddrP2tr(Address.p2tr(compBytes));
    setAddrEth(Address.eth(uncompBytes));
    setAddrTron(Address.tron(uncompBytes));
  };

  const updateFromPrivKey = () => {
    try {
      const hex = privKey().trim();
      const privBytes = parseHexInput(hex);
      if (privBytes.length !== 32) {
        setPubComp('-');
        setPubUncomp('-');
        resetAddresses();
        return;
      }

      const compBytes = Secp256k1.getPublicKey(privBytes, true);
      const uncompBytes = Secp256k1.getPublicKey(privBytes, false);

      setPubComp(bytesToHex(compBytes));
      setPubUncomp(bytesToHex(uncompBytes));
      deriveFromPubkeys(compBytes, uncompBytes);
    } catch (err) {
      console.error(err);
      resetAddresses();
    }
  };

  const updateFromPubKey = () => {
    try {
      const hex = pubKeyInput().trim();
      const pubBytes = parseHexInput(hex);

      if (pubBytes.length !== 33 && pubBytes.length !== 65) {
        if (hex.length > 0) {
          setPubStatus({ valid: false, text: `Longitud inválida (${pubBytes.length} bytes): se requiere 33B (comprimida) o 65B (descomprimida)` });
        } else {
          setPubStatus(null);
        }
        setPubComp('-');
        setPubUncomp('-');
        resetAddresses();
        return;
      }

      if (!Secp256k1.isValid(pubBytes)) {
        setPubStatus({ valid: false, text: 'Clave pública inválida: no está sobre la curva secp256k1' });
        setPubComp('-');
        setPubUncomp('-');
        resetAddresses();
        return;
      }

      let compBytes: Uint8Array;
      let uncompBytes: Uint8Array;

      if (pubBytes.length === 33) {
        compBytes = pubBytes;
        uncompBytes = Secp256k1.uncompress(pubBytes);
        setPubStatus({ valid: true, text: '✓ Clave pública válida (33 bytes comprimida)' });
      } else {
        uncompBytes = pubBytes;
        compBytes = Secp256k1.compress(pubBytes);
        setPubStatus({ valid: true, text: '✓ Clave pública válida (65 bytes descomprimida)' });
      }

      setPubComp(bytesToHex(compBytes));
      setPubUncomp(bytesToHex(uncompBytes));
      deriveFromPubkeys(compBytes, uncompBytes);
    } catch (err) {
      console.error(err);
      setPubStatus({ valid: false, text: `Error: ${(err as Error).message}` });
      resetAddresses();
    }
  };

  const handleRandom = () => {
    if (mode() === 'privkey') {
      const newKey = getRandomHexKey();
      setPrivKey(newKey);
      updateFromPrivKey();
    } else {
      const randPriv = parseHexInput(getRandomHexKey());
      // Randomly choose compressed (33B) or uncompressed (65B)
      const compressed = Math.random() > 0.5;
      const pub = Secp256k1.getPublicKey(randPriv, compressed);
      setPubKeyInput(bytesToHex(pub));
      updateFromPubKey();
    }
  };

  const handlePrivKeyChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPrivKey(target.value);
    updateFromPrivKey();
  };

  const handlePubKeyChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setPubKeyInput(target.value);
    updateFromPubKey();
  };

  const switchMode = (newMode: 'privkey' | 'pubkey') => {
    setMode(newMode);
    if (newMode === 'privkey') {
      if (!privKey()) {
        setPrivKey(getRandomHexKey());
      }
      updateFromPrivKey();
    } else {
      if (!pubKeyInput()) {
        const randPriv = parseHexInput(getRandomHexKey());
        const pub = Secp256k1.getPublicKey(randPriv, true);
        setPubKeyInput(bytesToHex(pub));
      }
      updateFromPubKey();
    }
  };

  const copy = (text: string, label: string) => {
    if (text !== '-') copyToClipboard(text, label);
  };

  onMount(async () => {
    await initWasm();
    setPrivKey(getRandomHexKey());
    updateFromPrivKey();
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>📫 Address Module Laboratory</h1>
          <p class={styles.pageDescription}>
            Generación instantánea de direcciones Bitcoin (P2PKH, P2SH, SegWit, Taproot), Ethereum EIP-55 y Tron desde claves privadas o cualquier clave pública secp256k1.
          </p>
        </div>
        <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={handleRandom}>
          {mode() === 'privkey' ? '🎲 Generar Clave Aleatoria' : '🎲 Clave Pública de Ejemplo'}
        </button>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔑</span> Origen de Derivación</span>
          </div>

          <div class={styles.modeTabs}>
            <button
              class={`${styles.modeTab} ${mode() === 'privkey' ? styles.modeTabActive : ''}`}
              onClick={() => switchMode('privkey')}
            >
              🔑 Clave Privada (32B)
            </button>
            <button
              class={`${styles.modeTab} ${mode() === 'pubkey' ? styles.modeTabActive : ''}`}
              onClick={() => switchMode('pubkey')}
            >
              🌐 Clave Pública (33B / 65B)
            </button>
          </div>

          <Show when={mode() === 'privkey'}>
            <div class={styles.formGroup}>
              <label class={styles.formLabel}>Clave Privada (32-bytes Hex)</label>
              <input
                type="text"
                class={styles.inputText}
                placeholder="e.g. 1111111111111111111111111111111111111111111111111111111111111111"
                value={privKey()}
                onInput={handlePrivKeyChange}
              />
            </div>
          </Show>

          <Show when={mode() === 'pubkey'}>
            <div class={styles.formGroup}>
              <label class={styles.formLabel}>Clave Pública Secp256k1 (Hexadecimal 33B o 65B)</label>
              <input
                type="text"
                class={styles.inputText}
                placeholder="Comprimida (02/03...) o Descomprimida (04...)"
                value={pubKeyInput()}
                onInput={handlePubKeyChange}
              />
              <Show when={pubStatus()}>
                <span class={`${styles.validationBadge} ${pubStatus()?.valid ? styles.valid : styles.invalid}`}>
                  {pubStatus()?.text}
                </span>
              </Show>
            </div>
          </Show>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública Comprimida (33-bytes Hex)</label>
            <div class={styles.outputBox}>
              <span>{pubComp()}</span>
              <button class={styles.copyBtn} onClick={() => copy(pubComp(), 'Pubkey Comprimida')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Clave Pública Descomprimida (65-bytes Hex)</label>
            <div class={styles.outputBox}>
              <span>{pubUncomp()}</span>
              <button class={styles.copyBtn} onClick={() => copy(pubUncomp(), 'Pubkey Descomprimida')}>Copiar</button>
            </div>
          </div>
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🏷️</span> Direcciones Derivadas</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Bitcoin P2PKH Legacy (Base58Check - Comprimido) <span class={styles.extra}>1...</span></label>
            <div class={styles.outputBox}>
              <span>{addrP2pkh()}</span>
              <button class={styles.copyBtn} onClick={() => copy(addrP2pkh(), 'P2PKH')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Bitcoin P2PKH Uncompressed (Legacy 65B) <span class={styles.extra}>1...</span></label>
            <div class={styles.outputBox}>
              <span>{addrP2pkhUncomp()}</span>
              <button class={styles.copyBtn} onClick={() => copy(addrP2pkhUncomp(), 'P2PKH Uncomp')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Bitcoin P2SH-P2WPKH (Nested SegWit) <span class={styles.extra}>3...</span></label>
            <div class={styles.outputBox}>
              <span>{addrP2sh()}</span>
              <button class={styles.copyBtn} onClick={() => copy(addrP2sh(), 'P2SH')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Bitcoin P2WPKH (Native SegWit Bech32) <span class={styles.extra}>bc1q...</span></label>
            <div class={styles.outputBox}>
              <span>{addrP2wpkh()}</span>
              <button class={styles.copyBtn} onClick={() => copy(addrP2wpkh(), 'P2WPKH')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Bitcoin P2TR (Taproot Bech32m) <span class={styles.extra}>bc1p...</span></label>
            <div class={styles.outputBox}>
              <span>{addrP2tr()}</span>
              <button class={styles.copyBtn} onClick={() => copy(addrP2tr(), 'P2TR')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Ethereum EIP-55 Checksummed Address <span class={styles.extra}>0x...</span></label>
            <div class={styles.outputBox}>
              <span>{addrEth()}</span>
              <button class={styles.copyBtn} onClick={() => copy(addrEth(), 'Ethereum')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Tron (TRX) Base58Check Address <span class={styles.extra}>T...</span></label>
            <div class={styles.outputBox}>
              <span>{addrTron()}</span>
              <button class={styles.copyBtn} onClick={() => copy(addrTron(), 'Tron')}>Copiar</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
