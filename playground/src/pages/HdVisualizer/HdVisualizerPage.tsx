/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  HdVisualizerPage.tsx — HD Wallet Tree Visualizer
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component, createSignal, onMount } from 'solid-js';
import { Bip32, Bip44 } from 'blockchain-wasm';
import { initWasm, bytesToHex, hexToBytes, copyToClipboard, parseHexInput, getRandomHexKey } from '../../utils/wasm';
import styles from './HdVisualizerPage.module.css';

interface TreeNode {
  path: string;
  label: string;
  xpub?: string;
  xprv?: string;
  pubKey?: string;
  privKey?: string;
  children: TreeNode[];
  expanded: boolean;
  depth: number;
}

export const HdVisualizerPage: Component = () => {
  const [seed, setSeed] = createSignal<string>('');
  const [tree, setTree] = createSignal<TreeNode[]>([]);
  const [selectedNode, setSelectedNode] = createSignal<TreeNode | null>(null);

  const generateSeed = () => {
    const newSeed = getRandomHexKey() + getRandomHexKey();
    setSeed(newSeed);
    buildTree();
  };

  const buildTree = () => {
    try {
      if (!seed().trim()) return;
      const seedBytes = parseHexInput(seed());
      if (seedBytes.length !== 64) return;

      const master = Bip32.fromSeed(seedBytes);
      const masterXpub = master.toXpub();
      const masterXprv = master.toXprv();
      const masterPubKey = bytesToHex(master.getPublicKey());

      const root: TreeNode = {
        path: 'm',
        label: 'Master',
        xpub: masterXpub,
        xprv: masterXprv,
        pubKey: masterPubKey,
        children: [],
        expanded: true,
        depth: 0,
      };

      // Add BIP-44 paths
      const purposes = [
        { path: "44'", label: "BIP-44 (Legacy)", coinTypes: [0, 60] },
        { path: "49'", label: "BIP-49 (Nested SegWit)", coinTypes: [0] },
        { path: "84'", label: "BIP-84 (Native SegWit)", coinTypes: [0] },
        { path: "86'", label: "BIP-86 (Taproot)", coinTypes: [0] },
      ];

      purposes.forEach(purpose => {
        const purposeNode: TreeNode = {
          path: `m/${purpose.path}`,
          label: purpose.label,
          children: [],
          expanded: true,
          depth: 1,
        };

        purpose.coinTypes.forEach(coinType => {
          const coinLabel = coinType === 0 ? 'BTC' : coinType === 60 ? 'ETH' : `Coin ${coinType}`;
          const coinNode: TreeNode = {
            path: `m/${purpose.path}/${coinType}'`,
            label: coinLabel,
            children: [],
            expanded: false,
            depth: 2,
          };

          // Add first 3 accounts
          for (let acc = 0; acc < 3; acc++) {
            try {
              const accXprv = Bip44.accountXprv(seedBytes, parseInt(purpose.path.replace("'", "")), coinType, acc);
              const accXpub = Bip44.accountXpub(seedBytes, parseInt(purpose.path.replace("'", "")), coinType, acc);
              const accNode: TreeNode = {
                path: `m/${purpose.path}/${coinType}'/${acc}'`,
                label: `Account ${acc}`,
                xprv: accXprv,
                xpub: accXpub,
                children: [],
                expanded: false,
                depth: 3,
              };

              // Add first 2 addresses (external chain)
              for (let addr = 0; addr < 2; addr++) {
                const leaf = Bip44.deriveKeys(seedBytes, parseInt(purpose.path.replace("'", "")), coinType, acc, 0, addr);
                const addrNode: TreeNode = {
                  path: `m/${purpose.path}/${coinType}'/${acc}'/0/${addr}`,
                  label: `Address ${addr}`,
                  privKey: bytesToHex(leaf.privateKey),
                  pubKey: bytesToHex(leaf.publicKey),
                  children: [],
                  expanded: false,
                  depth: 4,
                };
                accNode.children.push(addrNode);
              }

              coinNode.children.push(accNode);
            } catch (err) {
              console.error(err);
            }
          }

          purposeNode.children.push(coinNode);
        });

        root.children.push(purposeNode);
      });

      setTree([root]);
    } catch (err) {
      console.error(err);
    }
  };

  const toggleNode = (node: TreeNode) => {
    setTree(prev => prev.map(n => toggleRecursive(n, node)));
  };

  const toggleRecursive = (current: TreeNode, target: TreeNode): TreeNode => {
    if (current.path === target.path) {
      return { ...current, expanded: !current.expanded };
    }
    return {
      ...current,
      children: current.children.map(c => toggleRecursive(c, target)),
    };
  };

  const selectNode = (node: TreeNode) => {
    setSelectedNode(node);
  };

  const handleSeedChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    setSeed(target.value);
    buildTree();
  };

  const copy = (text: string, label: string) => {
    if (text && text !== '-') copyToClipboard(text, label);
  };

  const renderNode = (node: TreeNode) => (
    <div class={styles.treeNode} style={{ 'margin-left': `${node.depth * 20}px` }}>
      <div
        class={styles.treeNodeContent}
        onClick={() => { toggleNode(node); selectNode(node); }}
      >
        <span class={node.expanded ? styles.expanded : styles.collapsed}>
          {node.expanded ? '▼' : '▶'}
        </span>
        <span class={styles.nodeLabel}>{node.label}</span>
        <span class={styles.nodePath}>{node.path}</span>
      </div>
      {node.expanded && node.children.length > 0 && (
        <div class={styles.treeChildren}>
          {node.children.map(child => renderNode(child))}
        </div>
      )}
    </div>
  );

  onMount(async () => {
    await initWasm();
    generateSeed();
  });

  return (
    <div class={styles.page}>
      <div class={styles.pageHeader}>
        <div>
          <h1 class={styles.pageTitle}>🌲 HD Wallet Tree Visualizer</h1>
          <p class={styles.pageDescription}>
            Árbol de derivación HD interactivo: Master → Purpose → Coin Type → Account → Change → Address.
          </p>
        </div>
        <button class={`${styles.btn} ${styles.btnPrimary}`} onClick={generateSeed}>🎲 Nueva Seed Aleatoria</button>
      </div>

      <div class={styles.grid}>
        <div class={styles.card}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🌱</span> Seed</span>
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
        </div>
      </div>

      <div class={styles.grid}>
        <div class={styles.card} style={{ flex: 1, 'min-height': '500px' }}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>🌳</span> Árbol de Derivación</span>
          </div>
          <div class={styles.treeContainer}>
            {tree().map(node => renderNode(node))}
          </div>
        </div>

        <div class={styles.card} style={{ flex: 1 }}>
          <div class={styles.cardHeader}>
            <span class={styles.cardTitle}><span class={styles.icon}>📋</span> Detalles del Nodo</span>
          </div>

          {selectedNode() ? (
            <>
              <div class={styles.formGroup}>
                <label class={styles.formLabel}>Path</label>
                <div class={styles.outputBox} style={{ 'justify-content': 'flex-start' }}>
                  <span>{selectedNode()!.path}</span>
                  <button class={styles.copyBtn} onClick={() => copy(selectedNode()!.path, 'Path')}>Copiar</button>
                </div>
              </div>

              {selectedNode()!.xpub && (
                <div class={styles.formGroup}>
                  <label class={styles.formLabel}>XPUB</label>
                  <div class={styles.outputBox}>
                    <span>{selectedNode()!.xpub}</span>
                    <button class={styles.copyBtn} onClick={() => copy(selectedNode()!.xpub!, 'XPUB')}>Copiar</button>
                  </div>
                </div>
              )}

              {selectedNode()!.xprv && (
                <div class={styles.formGroup}>
                  <label class={styles.formLabel}>XPRV</label>
                  <div class={styles.outputBox}>
                    <span>{selectedNode()!.xprv}</span>
                    <button class={styles.copyBtn} onClick={() => copy(selectedNode()!.xprv!, 'XPRV')}>Copiar</button>
                  </div>
                </div>
              )}

              {selectedNode()!.pubKey && (
                <div class={styles.formGroup}>
                  <label class={styles.formLabel}>Public Key</label>
                  <div class={styles.outputBox}>
                    <span>{selectedNode()!.pubKey}</span>
                    <button class={styles.copyBtn} onClick={() => copy(selectedNode()!.pubKey!, 'PubKey')}>Copiar</button>
                  </div>
                </div>
              )}

              {selectedNode()!.privKey && (
                <div class={styles.formGroup}>
                  <label class={styles.formLabel}>Private Key</label>
                  <div class={styles.outputBox}>
                    <span>{selectedNode()!.privKey}</span>
                    <button class={styles.copyBtn} onClick={() => copy(selectedNode()!.privKey!, 'PrivKey')}>Copiar</button>
                  </div>
                </div>
              )}
            </>
          ) : (
            <p style={{ color: 'var(--text-muted)', 'font-size': '12px', padding: '20px' }}>
              Haz clic en un nodo del árbol para ver sus detalles
            </p>
          )}
        </div>
      </div>
    </div>
  );
};