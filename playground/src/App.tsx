/**
 * ════════════════════════════════════════════════════════════════════════════
 *  App.tsx — Componente raíz con layout y routing
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { Component } from 'solid-js';
import { Router, Route, RouteSectionProps } from '@solidjs/router';
import { Header } from './components/Header/Header';
import { Sidebar } from './components/Sidebar/Sidebar';
import { Dashboard } from './pages/Dashboard/Dashboard';
import { AddressPage } from './pages/Address/AddressPage';
import { HashPage } from './pages/Hash/HashPage';
import { EncodingPage } from './pages/Encoding/EncodingPage';
import { Bip39Page } from './pages/Bip39/Bip39Page';
import { Bip32Page } from './pages/Bip32/Bip32Page';
import { Bip44Page } from './pages/Bip44/Bip44Page';
import { EcdsaPage } from './pages/Ecdsa/EcdsaPage';
import { SchnorrPage } from './pages/Schnorr/SchnorrPage';
import { EcdhPage } from './pages/Ecdh/EcdhPage';
import { Secp256k1Page } from './pages/Secp256k1/Secp256k1Page';
import { Pbkdf2Page } from './pages/Pbkdf2/Pbkdf2Page';
import { WifPage } from './pages/Wif/WifPage';
import { HdVisualizerPage } from './pages/HdVisualizer/HdVisualizerPage';
import { MessageSigningPage } from './pages/MessageSigning/MessageSigningPage';
import { VanityPage } from './pages/Vanity/VanityPage';
import { AnvilPage } from './pages/Anvil/AnvilPage';
import './global.css';

const AppLayout: Component<RouteSectionProps> = (props) => {
  return (
    <div class="app-viewport">
      <Header />
      <div class="app-body">
        <Sidebar />
        <main class="app-content">
          {props.children}
        </main>
      </div>
    </div>
  );
};

export function App() {
  return (
    <Router root={AppLayout}>
      <Route path="/" component={Dashboard} />
      <Route path="/anvil" component={AnvilPage} />
      <Route path="/address" component={AddressPage} />
      <Route path="/hash" component={HashPage} />
      <Route path="/encoding" component={EncodingPage} />
      <Route path="/hd-visualizer" component={HdVisualizerPage} />
      <Route path="/message-signing" component={MessageSigningPage} />
      <Route path="/vanity" component={VanityPage} />
      <Route path="/bip39" component={Bip39Page} />
      <Route path="/bip32" component={Bip32Page} />
      <Route path="/bip44" component={Bip44Page} />
      <Route path="/ecdsa" component={EcdsaPage} />
      <Route path="/schnorr" component={SchnorrPage} />
      <Route path="/ecdh" component={EcdhPage} />
      <Route path="/secp256k1" component={Secp256k1Page} />
      <Route path="/pbkdf2" component={Pbkdf2Page} />
      <Route path="/wif" component={WifPage} />
    </Router>
  );
}
