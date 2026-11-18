import { defineConfig } from 'vite'
import solidPlugin from 'vite-plugin-solid'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  base: './',
  plugins: [solidPlugin()],
  server: {
    port: 3000,
    open: true
  },
  build: {
    target: 'esnext',
    minify: 'esbuild',
    sourcemap: true
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
      'blockchain-wasm': fileURLToPath(new URL('../dist/index.js', import.meta.url))
    }
  }
})