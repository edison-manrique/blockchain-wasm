/**
 * BlockchainWasm - Wrapper de TypeScript para la biblioteca criptográfica en WASM.
 *
 * Expone una interfaz limpia y completamente tipada para el módulo WASM de AssemblyScript
 * compilado con `--runtime minimal`.
 *
 * Implementa un asignador estático de memoria personalizado ("scratchpad") para pasar
 * argumentos (Uint8Arrays y Strings) a WASM sin requerir los bindings o cargadores por
 * defecto de `asc` o la exportación de `__new`.
 */

// ── Tipos ──────────────────────────────────────────────────────────────────

/** Exports crudos de WASM producidos por AssemblyScript con `--runtime minimal` */
interface AsmExports extends WebAssembly.Exports {
  memory: WebAssembly.Memory

  // ── Hashing ────────────────────────────────────────────────────────────
  sha256: (dataPtr: number) => number
  hmac_sha256: (keyPtr: number, dataPtr: number) => number
  hmac_sha512: (keyPtr: number, dataPtr: number) => number
  keccak: (dataPtr: number) => number

  // ── ECDSA ──────────────────────────────────────────────────────────────
  get_message_hash: (messagePtr: number, format: number) => number
  ecdsa_sign: (hashPtr: number, privKeyPtr: number) => number
  ecdsa_verify: (hashPtr: number, signaturePtr: number, pubKeyPtr: number) => number
  sign_text_message: (messagePtr: number, privKeyPtr: number, format: number) => number
  verify_text_message: (messagePtr: number, signaturePtr: number, pubKeyPtr: number, format: number) => number

  // ── Schnorr ────────────────────────────────────────────────────────────
  signSchnorr: (hashPtr: number, privKeyPtr: number, auxRandPtr: number) => number
  verifySchnorr: (sigPtr: number, hashPtr: number, pubKeyPtr: number) => number
  getSchnorrPublicKey: (privKeyPtr: number) => number

  // ── ECDH ───────────────────────────────────────────────────────────────
  shared_secret: (privKeyPtr: number, pubKeyPtr: number) => number

  // ── Direcciones ──────────────────────────────────────────────────────────
  getBitcoinAddress: (pubKeyPtr: number) => number
  getBitcoinP2SHAddress: (pubKeyPtr: number) => number
  getBitcoinP2WPKHAddress: (pubKeyPtr: number) => number
  getBitcoinP2TRAddress: (pubKeyPtr: number) => number
  getEthereumAddress: (pubKeyPtr: number) => number
  getPublicKeyCompressed: (privKeyPtr: number) => number
  getPublicKeyUncompressed: (privKeyPtr: number) => number
  compressPublicKey: (pubKeyPtr: number) => number
  uncompressPublicKey: (pubKeyPtr: number) => number

  // ── BIP32 ──────────────────────────────────────────────────────────────
  bip32_derive_path: (seedPtr: number, pathPtr: number) => number
  bip32_get_pubkey: (seedPtr: number, pathPtr: number) => number

  // ── WIF ────────────────────────────────────────────────────────────────
  toWIF: (privKeyPtr: number) => number
  fromWIF: (wifPtr: number) => number

  // ── PBKDF2 ─────────────────────────────────────────────────────────────
  pbkdf2_sha512: (passwordPtr: number, saltPtr: number, iterations: number, keyLen: number) => number

  // ── Utilidades ──────────────────────────────────────────────────────────
  bytesToHex: (dataPtr: number) => number
  hexToBytes: (hexPtr: number) => number
  bytesToBase64: (dataPtr: number) => number
  base64ToBytes: (b64Ptr: number) => number
  isSameBytes: (aPtr: number, bPtr: number) => number
  concatBytes: (aPtr: number, bPtr: number) => number

  // ── Runtime de AssemblyScript ──────────────────────────────────────────
  // Requerido antes de invocar cualquier export con parámetros opcionales.
  __setArgumentsLength: (argc: number) => void
}

// ── Asignador de Memoria Personalizado (Marshaller) ─────────────────────────

/**
 * Gestiona la asignación de memoria WebAssembly para el paso de parámetros.
 * Aloja estructuras de memoria temporales para cadenas (Strings) y arreglos de bytes (Uint8Arrays)
 * en un bloque de memoria seguro y dedicado.
 */
class WasmAllocator {
  private memory: WebAssembly.Memory
  private startOffset: number
  private currentOffset: number

  constructor(memory: WebAssembly.Memory) {
    this.memory = memory
    // Crecemos la memoria en 256 páginas (zona de seguridad de 16 MB)
    // Esto asegura que las alocaciones internas de AS durante la llamada
    // no colisionen con nuestro scratchpad en el extremo superior de la memoria.
    memory.grow(256)
    this.startOffset = memory.buffer.byteLength
    memory.grow(8) // Asignamos 512 KB de espacio de scratchpad para parámetros de entrada
    this.currentOffset = this.startOffset
  }

  /** Restablece el puntero del asignador para la próxima secuencia de llamadas */
  reset(): void {
    this.currentOffset = this.startOffset
  }

  private alloc(size: number): number {
    // Alinear a límites de 8 bytes
    const alignedSize = (size + 7) & ~7
    const ptr = this.currentOffset
    this.currentOffset += alignedSize

    // Si excedemos el tamaño de memoria actual, crecemos dinámicamente
    if (this.currentOffset > this.memory.buffer.byteLength) {
      const needed = this.currentOffset - this.memory.buffer.byteLength
      const pages = Math.ceil(needed / 65536)
      this.memory.grow(pages)
    }
    return ptr
  }

  /** Escribe un Uint8Array de JS en la memoria WASM y retorna el puntero de la estructura de AS */
  writeBytes(data: Uint8Array): number {
    // 1. Alojar y escribir el ArrayBuffer subyacente
    // Layout: 16 bytes de cabecera de metadatos de GC + datos del payload
    const bufPtr = this.alloc(16 + data.length)
    let dv = new DataView(this.memory.buffer)
    let heap = new Uint8Array(this.memory.buffer)

    // Punteros next/prev del GC: autoreferenciales para simular un objeto raíz fijado ("pinned")
    dv.setUint32(bufPtr, bufPtr, true) // .next -> self
    dv.setUint32(bufPtr + 4, bufPtr, true) // .prev -> self
    // Class ID de ArrayBuffer = 1
    dv.setUint32(bufPtr + 8, 1, true)
    // Longitud en bytes del ArrayBuffer
    dv.setUint32(bufPtr + 12, data.length, true)
    // Copiar el contenido del payload
    heap.set(data, bufPtr + 16)

    const dataStart = bufPtr + 16

    // 2. Alojar y escribir la cabecera/estructura contenedora de la clase Uint8Array
    // Layout: 16 bytes de cabecera de metadatos de GC + 12 bytes de campos de la estructura
    const structHeaderPtr = this.alloc(16 + 12)
    // Recreamos DataView por si alloc() causó un redimensionamiento de memoria (grow)
    dv = new DataView(this.memory.buffer)

    dv.setUint32(structHeaderPtr, structHeaderPtr, true) // .next -> self
    dv.setUint32(structHeaderPtr + 4, structHeaderPtr, true) // .prev -> self
    // Class ID de Uint8Array = 7
    dv.setUint32(structHeaderPtr + 8, 7, true)
    // Tamaño del payload de la estructura = 12 bytes
    dv.setUint32(structHeaderPtr + 12, 12, true)

    // Campos de la estructura: { buffer: u32, dataStart: u32, byteLength: u32 }
    const structPtr = structHeaderPtr + 16
    dv.setUint32(structPtr, dataStart, true) // .buffer
    dv.setUint32(structPtr + 4, dataStart, true) // .dataStart
    dv.setUint32(structPtr + 8, data.length, true) // .byteLength

    return structPtr
  }

  /** Escribe un String de JS como UTF-16LE, retornando el puntero a los caracteres del String de AS */
  writeString(str: string): number {
    const byteLen = str.length * 2
    // Layout: 16 bytes de cabecera de metadatos de GC + caracteres UTF-16
    const ptr = this.alloc(16 + byteLen)
    const dv = new DataView(this.memory.buffer)

    // GC next/prev: autoreferenciales para simular un objeto raíz fijado ("pinned")
    dv.setUint32(ptr, ptr, true) // .next -> self
    dv.setUint32(ptr + 4, ptr, true) // .prev -> self
    // Class ID de String = 2
    dv.setUint32(ptr + 8, 2, true)
    // Longitud en bytes de los datos de la cadena
    dv.setUint32(ptr + 12, byteLen, true)

    // Escribir los caracteres UTF-16LE a partir de ptr + 16 (dataStart)
    const dataStart = ptr + 16
    for (let i = 0; i < str.length; i++) {
      dv.setUint16(dataStart + i * 2, str.charCodeAt(i), true)
    }

    return dataStart
  }

  /** Lee un Uint8Array de AS desde la memoria WASM a un Uint8Array de JS */
  readBytes(arrPtr: number): Uint8Array {
    if (!arrPtr) return new Uint8Array(0)
    const dv = new DataView(this.memory.buffer)
    const dataStart = dv.getUint32(arrPtr + 4, true) // .dataStart (puntero absoluto a los datos crudos)
    const byteLength = dv.getUint32(arrPtr + 8, true) // .byteLength

    const heap = new Uint8Array(this.memory.buffer)
    return heap.slice(dataStart, dataStart + byteLength)
  }

  /** Lee un String de AS desde la memoria WASM a un String de JS */
  readString(strPtr: number): string {
    if (!strPtr) return ""
    const dv = new DataView(this.memory.buffer)
    const byteLen = dv.getUint32(strPtr - 4, true)
    let result = ""
    for (let i = 0; i < byteLen; i += 2) {
      result += String.fromCharCode(dv.getUint16(strPtr + i, true))
    }
    return result
  }
}

// ── Enum para Formatos de Firma (refleja SignatureFormat en AS) ────────────
export enum SignatureFormat {
  /** Formato crudo de bytes planos — sin prefijos */
  Raw = 0,
  /** Prefijo de firma personal de Ethereum: "\x19Ethereum Signed Message:\n" + longitud */
  Ethereum = 1,
  /** Prefijo de firma de mensajes de Bitcoin */
  Bitcoin = 2
}

// ── Clase Principal ────────────────────────────────────────────────────────

export class BlockchainWasm {
  private exp: AsmExports
  private allocator: WasmAllocator

  private constructor(exp: AsmExports) {
    this.exp = exp
    this.allocator = new WasmAllocator(exp.memory)
  }

  private static instance: BlockchainWasm | null = null

  /**
   * Resuelve automáticamente la ruta por defecto del archivo WASM respecto a este script.
   */
  static getDefaultWasmUrl(): string {
    const baseUrl = "./blockchain.wasm"
    try {
      return new URL(baseUrl, import.meta.url).href
    } catch {
      return baseUrl
    }
  }

  /**
   * Carga y devuelve de forma automática la instancia singleton de BlockchainWasm.
   */
  static async load(url?: string, imports: WebAssembly.Imports = {}): Promise<BlockchainWasm> {
    if (this.instance) return this.instance
    const targetUrl = url || this.getDefaultWasmUrl()
    this.instance = await this.fromUrl(targetUrl, imports)
    return this.instance
  }

  /**
   * Carga el módulo WASM desde una URL.
   * Utiliza instanciación por streaming si está disponible para máxima velocidad.
   */
  static async fromUrl(url: string, imports: WebAssembly.Imports = {}): Promise<BlockchainWasm> {
    const defaultImports = {
      env: {
        abort(message: number, fileName: number, lineNumber: number, columnNumber: number) {
          console.error("WASM Abort")
        },
        seed() {
          return Math.random()
        }
      }
    }
    const finalImports = {
      ...defaultImports,
      ...imports,
      env: {
        ...defaultImports.env,
        ...((imports.env as Record<string, unknown>) || {})
      }
    }

    let instance: WebAssembly.Instance
    if (typeof WebAssembly.instantiateStreaming === "function") {
      const response = await fetch(url)
      const result = await WebAssembly.instantiateStreaming(response, finalImports)
      instance = result.instance
    } else {
      const response = await fetch(url)
      const buffer = await response.arrayBuffer()
      const result = await WebAssembly.instantiate(buffer, finalImports)
      instance = result.instance
    }
    return new BlockchainWasm(instance.exports as AsmExports)
  }

  /**
   * Carga el módulo WASM desde un búfer en memoria (ideal para Node.js / Bun).
   */
  static async fromBuffer(
    buffer: ArrayBuffer | Uint8Array,
    imports: WebAssembly.Imports = {}
  ): Promise<BlockchainWasm> {
    const defaultImports = {
      env: {
        abort(message: number, fileName: number, lineNumber: number, columnNumber: number) {
          console.error("WASM Abort")
        },
        seed() {
          return Math.random()
        }
      }
    }
    const finalImports = {
      ...defaultImports,
      ...imports,
      env: {
        ...defaultImports.env,
        ...((imports.env as Record<string, unknown>) || {})
      }
    }
    const buf = buffer instanceof Uint8Array ? buffer.buffer : buffer
    const { instance } = await WebAssembly.instantiate(buf, finalImports)
    return new BlockchainWasm(instance.exports as AsmExports)
  }

  // ── Helpers Internos ─────────────────────────────────────────────────────

  /** Debe ejecutarse previo a cualquier llamada a funciones WASM. */
  private call(argc: number): void {
    this.allocator.reset()
    this.exp.__setArgumentsLength(argc)
  }

  // ── Hashing ─────────────────────────────────────────────────────────────

  /** Calcula el hash SHA-256 de los bytes de entrada */
  sha256(data: Uint8Array): Uint8Array {
    this.call(1)
    return this.allocator.readBytes(this.exp.sha256(this.allocator.writeBytes(data)))
  }

  /** Calcula el HMAC-SHA-256 usando la clave y los datos provistos */
  hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    this.call(2)
    return this.allocator.readBytes(
      this.exp.hmac_sha256(this.allocator.writeBytes(key), this.allocator.writeBytes(data))
    )
  }

  /** Calcula el HMAC-SHA-512 usando la clave y los datos provistos */
  hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
    this.call(2)
    return this.allocator.readBytes(
      this.exp.hmac_sha512(this.allocator.writeBytes(key), this.allocator.writeBytes(data))
    )
  }

  /** Calcula el hash Keccak-256 (estilo Ethereum) de los bytes de entrada */
  keccak256(data: Uint8Array): Uint8Array {
    this.call(1)
    return this.allocator.readBytes(this.exp.keccak(this.allocator.writeBytes(data)))
  }

  // ── ECDSA ────────────────────────────────────────────────────────────────

  /** Firma un hash de 32 bytes usando una clave privada de 32 bytes. Retorna 65 bytes [R(32) | S(32) | V(1)] */
  ecdsaSign(hash: Uint8Array, privKey: Uint8Array): Uint8Array {
    this.call(2)
    return this.allocator.readBytes(
      this.exp.ecdsa_sign(this.allocator.writeBytes(hash), this.allocator.writeBytes(privKey))
    )
  }

  /** Verifica una firma ECDSA contra un hash de 32 bytes y una clave pública descomprimida de 65 bytes */
  ecdsaVerify(hash: Uint8Array, signature: Uint8Array, pubKey: Uint8Array): boolean {
    this.call(3)
    return (
      this.exp.ecdsa_verify(
        this.allocator.writeBytes(hash),
        this.allocator.writeBytes(signature),
        this.allocator.writeBytes(pubKey)
      ) !== 0
    )
  }

  /** Obtiene el hash de mensaje según el protocolo (Raw, Bitcoin o Ethereum) */
  getMessageHash(message: string, format: SignatureFormat = SignatureFormat.Raw): Uint8Array {
    this.call(2)
    return this.allocator.readBytes(this.exp.get_message_hash(this.allocator.writeString(message), format))
  }

  /** Firma un mensaje de texto plano aplicando el formato e ingresando la clave privada */
  signTextMessage(message: string, privKey: Uint8Array, format: SignatureFormat = SignatureFormat.Raw): Uint8Array {
    this.call(3)
    return this.allocator.readBytes(
      this.exp.sign_text_message(this.allocator.writeString(message), this.allocator.writeBytes(privKey), format)
    )
  }

  /** Verifica la firma de un mensaje de texto plano con el formato y clave pública descomprimida */
  verifyTextMessage(
    message: string,
    signature: Uint8Array,
    pubKey: Uint8Array,
    format: SignatureFormat = SignatureFormat.Raw
  ): boolean {
    this.call(4)
    return (
      this.exp.verify_text_message(
        this.allocator.writeString(message),
        this.allocator.writeBytes(signature),
        this.allocator.writeBytes(pubKey),
        format
      ) !== 0
    )
  }

  // ── Schnorr ──────────────────────────────────────────────────────────────

  /** Firma un hash de 32 bytes con Schnorr BIP-340. Permite pasar entropía auxRand de 32 bytes */
  signSchnorr(hash: Uint8Array, privKey: Uint8Array, auxRand?: Uint8Array): Uint8Array {
    this.call(3)
    const aux = auxRand || new Uint8Array(32)
    return this.allocator.readBytes(
      this.exp.signSchnorr(
        this.allocator.writeBytes(hash),
        this.allocator.writeBytes(privKey),
        this.allocator.writeBytes(aux)
      )
    )
  }

  /** Verifica una firma Schnorr BIP-340 de 64 bytes contra el hash y una clave pública x-only de 32 bytes */
  verifySchnorr(hash: Uint8Array, signature: Uint8Array, pubKey: Uint8Array): boolean {
    this.call(3)
    return (
      this.exp.verifySchnorr(
        this.allocator.writeBytes(signature),
        this.allocator.writeBytes(hash),
        this.allocator.writeBytes(pubKey)
      ) !== 0
    )
  }

  /** Deriva la clave pública Schnorr x-only (32 bytes) desde una clave privada */
  getSchnorrPublicKey(privKey: Uint8Array): Uint8Array {
    this.call(1)
    return this.allocator.readBytes(this.exp.getSchnorrPublicKey(this.allocator.writeBytes(privKey)))
  }

  // ── ECDH ─────────────────────────────────────────────────────────────────

  /** Calcula un secreto compartido Diffie-Hellman a partir de una privada y una pública descomprimida de 65 bytes */
  sharedSecret(privKey: Uint8Array, pubKey: Uint8Array): Uint8Array {
    this.call(2)
    return this.allocator.readBytes(
      this.exp.shared_secret(this.allocator.writeBytes(privKey), this.allocator.writeBytes(pubKey))
    )
  }

  // ── Addresses ────────────────────────────────────────────────────────────

  /** Obtiene la dirección Bitcoin legacy (P2PKH) a partir de una llave pública comprimida */
  getBitcoinAddress(pubKey: Uint8Array): string {
    this.call(1)
    return this.allocator.readString(this.exp.getBitcoinAddress(this.allocator.writeBytes(pubKey)))
  }

  /** Obtiene la dirección Bitcoin P2SH (SegWit anidado) a partir de la llave pública comprimida */
  getBitcoinP2SHAddress(pubKey: Uint8Array): string {
    this.call(1)
    return this.allocator.readString(this.exp.getBitcoinP2SHAddress(this.allocator.writeBytes(pubKey)))
  }

  /** Obtiene la dirección Bitcoin Native SegWit P2WPKH (Bech32) desde la llave pública comprimida */
  getBitcoinP2WPKHAddress(pubKey: Uint8Array): string {
    this.call(1)
    return this.allocator.readString(this.exp.getBitcoinP2WPKHAddress(this.allocator.writeBytes(pubKey)))
  }

  /** Obtiene la dirección Bitcoin Taproot P2TR (Bech32m) desde la llave pública comprimida */
  getBitcoinP2TRAddress(pubKey: Uint8Array): string {
    this.call(1)
    return this.allocator.readString(this.exp.getBitcoinP2TRAddress(this.allocator.writeBytes(pubKey)))
  }

  /** Obtiene la dirección Ethereum (con formato de suma de verificación) desde la llave pública descomprimida */
  getEthereumAddress(pubKey: Uint8Array): string {
    this.call(1)
    return this.allocator.readString(this.exp.getEthereumAddress(this.allocator.writeBytes(pubKey)))
  }

  /** Deriva la llave pública comprimida (33 bytes) desde una llave privada */
  getPublicKeyCompressed(privKey: Uint8Array): Uint8Array {
    this.call(1)
    return this.allocator.readBytes(this.exp.getPublicKeyCompressed(this.allocator.writeBytes(privKey)))
  }

  /** Deriva la llave pública descomprimida (65 bytes) desde una llave privada */
  getPublicKeyUncompressed(privKey: Uint8Array): Uint8Array {
    this.call(1)
    return this.allocator.readBytes(this.exp.getPublicKeyUncompressed(this.allocator.writeBytes(privKey)))
  }

  /** Comprime una llave pública descomprimida de 65 bytes a su forma de 33 bytes */
  compressPublicKey(pubKey: Uint8Array): Uint8Array {
    this.call(1)
    return this.allocator.readBytes(this.exp.compressPublicKey(this.allocator.writeBytes(pubKey)))
  }

  /** Descomprime una llave pública de 33 bytes a su formato extendido de 65 bytes */
  uncompressPublicKey(pubKey: Uint8Array): Uint8Array {
    this.call(1)
    return this.allocator.readBytes(this.exp.uncompressPublicKey(this.allocator.writeBytes(pubKey)))
  }

  // ── BIP32 ────────────────────────────────────────────────────────────────

  /** Deriva la clave privada hija en la ruta indicada a partir de una semilla de 64 bytes */
  bip32DerivePath(seed: Uint8Array, path: string): Uint8Array {
    this.call(2)
    return this.allocator.readBytes(
      this.exp.bip32_derive_path(this.allocator.writeBytes(seed), this.allocator.writeString(path))
    )
  }

  /** Deriva la clave pública comprimida hija en la ruta indicada a partir de la semilla */
  bip32GetPublicKey(seed: Uint8Array, path: string): Uint8Array {
    this.call(2)
    return this.allocator.readBytes(
      this.exp.bip32_get_pubkey(this.allocator.writeBytes(seed), this.allocator.writeString(path))
    )
  }

  // ── WIF ──────────────────────────────────────────────────────────────────

  /** Codifica una llave privada de 32 bytes a su representación Wallet Import Format (WIF) de Bitcoin */
  toWIF(privKey: Uint8Array): string {
    this.call(1)
    return this.allocator.readString(this.exp.toWIF(this.allocator.writeBytes(privKey)))
  }

  /** Decodifica una cadena WIF de Bitcoin y retorna la clave privada cruda de 32 bytes */
  fromWIF(wif: string): Uint8Array {
    this.call(1)
    return this.allocator.readBytes(this.exp.fromWIF(this.allocator.writeString(wif)))
  }

  // ── PBKDF2 ───────────────────────────────────────────────────────────────

  /** Deriva una llave con PBKDF2-SHA512 utilizando una contraseña, sal, iteraciones y la longitud de clave requerida */
  pbkdf2Sha512(password: Uint8Array, salt: Uint8Array, iterations: number, keyLen: number): Uint8Array {
    this.call(4)
    return this.allocator.readBytes(
      this.exp.pbkdf2_sha512(this.allocator.writeBytes(password), this.allocator.writeBytes(salt), iterations, keyLen)
    )
  }

  // ── Utilidades ───────────────────────────────────────────────────────────

  /** Convierte un arreglo de bytes en una representación hexadecimal de cadena */
  bytesToHex(data: Uint8Array): string {
    this.call(1)
    return this.allocator.readString(this.exp.bytesToHex(this.allocator.writeBytes(data)))
  }

  /** Convierte una cadena hexadecimal válida a su arreglo de bytes equivalente */
  hexToBytes(hex: string): Uint8Array {
    this.call(1)
    return this.allocator.readBytes(this.exp.hexToBytes(this.allocator.writeString(hex)))
  }

  /** Convierte un arreglo de bytes en un string codificado en Base64 */
  bytesToBase64(data: Uint8Array): string {
    this.call(1)
    return this.allocator.readString(this.exp.bytesToBase64(this.allocator.writeBytes(data)))
  }

  /** Convierte un string Base64 en su arreglo de bytes crudo equivalente */
  base64ToBytes(b64: string): Uint8Array {
    this.call(1)
    return this.allocator.readBytes(this.exp.base64ToBytes(this.allocator.writeString(b64)))
  }

  /** Compara dos arreglos de bytes y retorna true únicamente si son idénticos */
  isSameBytes(a: Uint8Array, b: Uint8Array): boolean {
    this.call(2)
    return this.exp.isSameBytes(this.allocator.writeBytes(a), this.allocator.writeBytes(b)) !== 0
  }

  /** Concatena dos arreglos de bytes en uno solo */
  concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    this.call(2)
    return this.allocator.readBytes(this.exp.concatBytes(this.allocator.writeBytes(a), this.allocator.writeBytes(b)))
  }
}

export { BlockchainWasm as default }
