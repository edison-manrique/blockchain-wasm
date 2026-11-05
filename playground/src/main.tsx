/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  main.tsx — Punto de entrada de la aplicación SolidJS
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { render } from 'solid-js/web';
import { App } from './App';

render(() => <App />, document.getElementById('root')!);