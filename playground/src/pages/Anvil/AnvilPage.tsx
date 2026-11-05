/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  AnvilPage.tsx — Anvil EVM Wallet Integration (Simplified)
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Secp256k1, Address } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './AnvilPage.module.css';

interface Account {
  index: number;
  address: string;
  privateKey: string;
  publicKey: string;
  balance: string;
}

export const AnvilPage: Component = () => {
  const [rpcUrl, setRpcUrl] = createSignal<string>('http://127.0.0.1:8545');
  const [connected, setConnected] = createSignal<boolean>(false);
  const [accounts, setAccounts] = createSignal<Account[]>([]);
  const [selectedAccount, setSelectedAccount] = createSignal<Account | null>(null);
  const [txStatus, setTxStatus] = createSignal<string>('');
  const [blockNumber, setBlockNumber] = createSignal<string>('-');
  const [chainId, setChainId] = createSignal<string>('-');

  const generateAccounts = () => {
    const newAccounts: Account[] = [];
    for (let i = 0; i < 10; i++) {
      const privKey = getRandomHexKey();
      const privBytes = parseHexInput(privKey);
      const pubComp = Secp256k1.getPublicKey(privBytes, true);
      const pubUncomp = Secp256k1.getPublicKey(privBytes, false);
      const address = Address.eth(pubUncomp);
      newAccounts.push({
        index: i,
        address,
        privateKey: privKey,
        publicKey: bytesToHex(pubComp),
        balance: '0 ETH',
      });
    }
    setAccounts(newAccounts);
    if (newAccounts.length > 0) {
      setSelectedAccount(newAccounts[0]);
    }
  };

  const connectAnvil = async () => {
    try {
      // Test connection
      const response = await fetch(rpcUrl(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'eth_chainId',
          params: [],
          id: 1,
        }),
      });

      const data = await response.json();
      if (data.result) {
        setChainId(`0x${parseInt(data.result).toString(16)}`);
        setConnected(true);
        fetchBlockNumber();
      } else {
        throw new Error('Invalid response');
      }
    } catch (err) {
      console.error(err);
      setTxStatus(`❌ Error conectando: ${(err as Error).message}`);
    }
  };

  const fetchBlockNumber = async () => {
    try {
      const response = await fetch(rpcUrl(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'eth_blockNumber',
          params: [],
          id: 1,
        }),
      });
      const data = await response.json();
      if (data.result) {
        setBlockNumber(parseInt(data.result, 16).toString());
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchBalance = async (address: string) => {
    try {
      const response = await fetch(rpcUrl(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'eth_getBalance',
          params: [address, 'latest'],
          id: 1,
        }),
      });
      const data = await response.json();
      if (data.result) {
        const balanceWei = BigInt(data.result);
        const balanceEth = Number(balanceWei) / 1e18;
        return `${balanceEth.toFixed(4)} ETH`;
      }
    } catch (err) {
      console.error(err);
    }
    return '0 ETH';
  };

  const selectAccount = async (account: Account) => {
    setSelectedAccount(account);
    const balance = await fetchBalance(account.address);
    setAccounts(prev => prev.map(a => a.index === account.index ? { ...a, balance } : a));
  };

  const sendTransaction = async () => {
    if (!selectedAccount()) return;
    setTxStatus('⏳ Enviando transacción...');
    // Simplified - would need ethers.js or similar for real tx
    setTxStatus('ℹ️ Implementar envío real con ethers.js/viem');
  };

  const handleRpcUrlChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setRpcUrl(target.value);
  };

  const copy = (text: string, label: string) => {
    if (text) copyToClipboard(text, label);
  };

  onMount(async () => {
    await initWasm();
    generateAccounts();
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>🔨 Anvil EVM Wallet</h1>
          <p class={styles.pageDescription}>
            Wallet EVM local con Anvil. Genera cuentas, conecta a Anvil local y gestiona transacciones.
          </p>
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🔗</span> Conexión Anvil</span>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>RPC URL</label>
            <input
              type="text"
              class={styles.inputText}
              placeholder="http://127.0.0.1:8545"
              value={rpcUrl()}
              onInput={handleRpcUrlChange}
            />
          </div>

          <div class={styles.btnGroup}>
            <button
              class={`${styles.btn} ${connected() ? styles.btnSecondary : styles.btnPrimary}`}
              onClick={connectAnvil}
              disabled={connected()}
            >
              {connected() ? '✅ Conectado' : '🔌 Conectar'}
            </button>
            <button class={`${styles.btn} ${styles.btnSecondary}`} onClick={generateAccounts}>
              🎲 Generar 10 Cuentas
            </button>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Chain ID</label>
            <div class={styles.outputBox} style={{ 'justify-content': 'flex-start' }}>
              <span>{chainId()}</span>
              <button class={styles.copyBtn} onClick={() => copy(chainId(), 'Chain ID')}>Copiar</button>
            </div>
          </div>

          <div class={styles.formGroup}>
            <label class={styles.formLabel}>Block Number</label>
            <div class={styles.outputBox} style={{ 'justify-content': 'flex-start' }}>
              <span>{blockNumber()}</span>
              <button class={styles.copyBtn} onClick={() => copy(blockNumber(), 'Block Number')}>Copiar</button>
            </div>
          </div>

          {txStatus && (
            <div class={`${styles.alert} ${styles.alertSuccess}`}>
              {txStatus()}
            </div>
          )}
        </div>

        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>👛</span> Cuentas Generadas</span>
          </div>

          <div class={styles.accountsList}>
            {accounts().map(account => (
              <div
                // @ts-ignore
                key={account.index}
                class={`${styles.accountItem} ${selectedAccount()?.index === account.index ? styles.selected : ''}`}
                onClick={() => selectAccount(account)}
              >
                <div class={styles.accountHeader}>
                  <span class={styles.accountIndex}>#{account.index}</span>
                  <span class={styles.accountBalance}>{account.balance}</span>
                </div>
                <div class={styles.accountAddress}>{account.address}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {selectedAccount() && (
        <div class={styles.grid}>
          <div class={styles.card}>
            <div class={styles.cardHeader}>
              <span class={styles.cardTitle}><span class={styles.icon}>🔑</span> Detalles de Cuenta #{selectedAccount()!.index}</span>
            </div>

            <div class={styles.formGroup}>
              <label class={styles.formLabel}>Dirección (EIP-55)</label>
              <div class={styles.outputBox}>
                <span>{selectedAccount()!.address}</span>
                <button class={styles.copyBtn} onClick={() => copy(selectedAccount()!.address, 'Address')}>Copiar</button>
              </div>
            </div>

            <div class={styles.formGroup}>
              <label class={styles.formLabel}>Clave Privada (32 bytes Hex)</label>
              <div class={styles.outputBox}>
                <span>{selectedAccount()!.privateKey}</span>
                <button class={styles.copyBtn} onClick={() => copy(selectedAccount()!.privateKey, 'Private Key')}>Copiar</button>
              </div>
            </div>

            <div class={styles.formGroup}>
              <label class={styles.formLabel}>Clave Pública Comprimida (33 bytes)</label>
              <div class={styles.outputBox}>
                <span>{selectedAccount()!.publicKey}</span>
                <button class={styles.copyBtn} onClick={() => copy(selectedAccount()!.publicKey, 'Public Key')}>Copiar</button>
              </div>
            </div>

            <div class={styles.formGroup}>
              <label class={styles.formLabel}>Balance</label>
              <div class={styles.outputBox} style={{ 'justify-content': 'flex-start', color: 'var(--green-success)' }}>
                <span>{selectedAccount()!.balance}</span>
              </div>
            </div>
          </div>

          <div class={styles.card}>
            <div class={styles.cardHeader}>
              <span class={styles.cardTitle}><span class={styles.icon}>📤</span> Enviar Transacción</span>
            </div>

            <div class={styles.formGroup}>
              <label class={styles.formLabel}>Destino (Address)</label>
              <input type="text" class={styles.inputText} placeholder="0x..." />
            </div>

            <div class={styles.formGroup}>
              <label class={styles.formLabel}>Cantidad (ETH)</label>
              <input type="number" class={styles.inputText} placeholder="0.001" step="0.0001" />
            </div>

            <div class={styles.formGroup}>
              <label class={styles.formLabel}>Gas Limit</label>
              <input type="number" class={styles.inputText} value={21000} />
            </div>

            <div class={styles.btnGroup}>
              <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={sendTransaction} disabled={!connected()}>
                📤 Enviar Transacción
              </button>
            </div>

            <p style={{ 'font-size': '11px', color: 'var(--text-muted)', 'margin-top': '8px' }}>
              Requiere conexión a Anvil. Implementación completa necesita ethers.js o viem.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};