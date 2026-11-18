import { defineConfig } from 'vite'
import solidPlugin from 'vite-plugin-solid'
import path from 'path'

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
      '@': path.resolve(process.cwd(), 'src'),
      'blockchain-wasm': path.resolve(process.cwd(), '../dist/index.js')
    }
  }
})