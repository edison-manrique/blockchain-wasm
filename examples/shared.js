/**
 * shared.js — helper utilities for all blockchain-wasm demo pages.
 *
 * Loads the WASM module once (singleton) and exposes helpers for
 * hex/bytes conversion, UI feedback, and clipboard operations.
 */

// ── WASM singleton ────────────────────────────────────────────────────────

/** Cached instance (set after first load) */
let _wasm = null

/**
 * Retorna la instancia compartida de BlockchainWasm, cargándola automáticamente.
 */
export async function getWasm() {
  if (_wasm) return _wasm
  const { BlockchainWasm } = await import('../dist/index.js')
  _wasm = await BlockchainWasm.load()
  return _wasm
}

// ── Hex helpers ───────────────────────────────────────────────────────────

export function hexToBytes(hex) {
  hex = hex.replace(/^0x/i, '').replace(/\s+/g, '')
  if (hex.length % 2 !== 0) hex = '0' + hex
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function bytesToHex(bytes, prefix = '') {
  return prefix + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

export function textToBytes(str) {
  return new TextEncoder().encode(str)
}

export function randomBytes(n) {
  const buf = new Uint8Array(n)
  crypto.getRandomValues(buf)
  return buf
}

/** Returns true if s looks like a valid hex string */
export function isHex(s) {
  return /^(0x)?[0-9a-f]*$/i.test(s.trim()) && s.replace(/^0x/i, '').length % 2 === 0
}

// ── UI helpers ────────────────────────────────────────────────────────────

/**
 * Muestra una sección de salida con su valor o un mensaje de error.
 * @param {string} id      — id del elemento .output
 * @param {string} content — string de contenido o error
 * @param {'ok'|'error'|'warn'} type
 */
export function showOutput(id, content, type = 'ok') {
  const el = document.getElementById(id)
  if (!el) return
  el.classList.add('visible')
  
  if (type === 'error') {
    let errBox = el.querySelector('.error-banner')
    if (!errBox) {
      errBox = document.createElement('div')
      errBox.className = 'error-banner error'
      errBox.style.cssText = 'padding: 12px; border-radius: 8px; background: rgba(252,129,129,0.1); border: 1px solid rgba(252,129,129,0.3); color: var(--accent5); margin-top: 8px; font-size: 0.85rem;'
      el.appendChild(errBox)
    }
    errBox.textContent = content
    errBox.style.display = 'block'
  } else {
    const errBox = el.querySelector('.error-banner')
    if (errBox) errBox.style.display = 'none'
    
    const box = el.querySelector('.output-box')
    if (box) {
      box.className = `output-box ${type === 'ok' ? '' : type}`.trim()
      box.innerHTML = content
    }
  }
}

export function hideOutput(id) {
  const el = document.getElementById(id)
  if (el) {
    el.classList.remove('visible')
    const errBox = el.querySelector('.error-banner')
    if (errBox) errBox.style.display = 'none'
  }
}

/** Render bytes as a highlighted hex string (groups of 8) */
export function prettyHex(bytes, label = '') {
  const hex = bytesToHex(bytes)
  const groups = hex.match(/.{1,16}/g) || []
  const lines = groups.map((g, i) => {
    const offset = (i * 8).toString(16).padStart(4, '0')
    const spaced = g.match(/.{1,2}/g).join(' ')
    return `<span style="color:var(--muted);user-select:none">${offset}  </span>${spaced}`
  })
  return (label ? `<span style="color:var(--muted);font-size:0.75em;display:block;margin-bottom:6px">${label}</span>` : '')
    + lines.join('\n')
}

/** Format a status badge */
export function statusBadge(ok, okLabel = 'VÁLIDO ✓', failLabel = 'INVÁLIDO ✗') {
  return `<span class="status ${ok ? 'ok' : 'fail'}">${ok ? okLabel : failLabel}</span>`
}

/** Copy text to clipboard and flash button */
export function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent
    btn.textContent = '¡Copiado!'
    setTimeout(() => (btn.textContent = orig), 1500)
  })
}

/** Make all .output-box elements with a .copy-btn work */
export function initCopyButtons() {
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const box = btn.closest('.output-box')
      if (box) copyToClipboard(box.innerText, btn)
    })
  })
}

/** Set button loading state */
export function setLoading(btnId, loading) {
  const btn = document.getElementById(btnId)
  if (!btn) return
  const spinner = btn.querySelector('.spinner')
  if (loading) {
    btn.disabled = true
    btn.classList.add('loading')
    if (spinner) spinner.style.display = 'inline-block'
  } else {
    btn.disabled = false
    btn.classList.remove('loading')
    if (spinner) spinner.style.display = 'none'
  }
}

/** Wrap an async handler with loading state + error display */
export function withWasm(btnId, outputId, fn) {
  return async () => {
    setLoading(btnId, true)
    hideOutput(outputId)
    try {
      const wasm = await getWasm()
      await fn(wasm)
    } catch (e) {
      showOutput(outputId, `⚠ ${e.message || e}`, 'error')
    } finally {
      setLoading(btnId, false)
      initCopyButtons()
    }
  }
}

/** Fill an input with random hex of given byte length */
export function fillRandom(inputId, byteLen) {
  const el = document.getElementById(inputId)
  if (el) el.value = bytesToHex(randomBytes(byteLen))
}
