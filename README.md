# BlockchainWasm

Biblioteca criptográfica de alto rendimiento y bajo nivel que compila primitivas criptográficas avanzadas escritas en **AssemblyScript** a un binario **WebAssembly (WASM)** altamente optimizado.

Incluye un wrapper de TypeScript limpio y robusto que implementa un asignador estático de memoria personalizado (*scratchpad*) para intercomunicar datos complejos (`Uint8Array` y `string`) a través de la memoria lineal de WASM sin depender del cargador/bindings por defecto de `asc`, utilizando un runtime minimalista libre de sobrecarga.

## Características

- **Algoritmos de Hash**: SHA-256, Keccak-256, HMAC-SHA-256 y HMAC-SHA-512.
- **Firmas Digitales**:
  - ECDSA sobre curva `secp256k1` con esquemas de recuperación e ID (compatibilidad con firmas de Ethereum personalizadas y de Bitcoin).
  - Schnorr según el estándar `BIP-340` (utilizado en Bitcoin Taproot).
- **Intercambio de Claves**: ECDH Diffie-Hellman sobre `secp256k1`.
- **Derivación de Direcciones**: Legacy (P2PKH), Nested SegWit (P2SH), Native SegWit (P2WPKH), Taproot (P2TR) y Ethereum.
- **Jerarquía Determinista (BIP-32)**: Derivación de claves y cuentas para billeteras deterministas.
- **Utilidades**: Codificación/decodificación WIF (Wallet Import Format), codificación/decodificación Base64, PBKDF2-SHA512 para derivación de semillas y funciones de conversión Hex ↔ Bytes.

---

## Estructura del Proyecto

```bash
├── assembly/        # Código fuente en AssemblyScript (Primitivas criptográficas)
├── src/             # Wrapper en TypeScript (Clase BlockchainWasm y Allocator)
├── dist/            # Código de salida (JavaScript de producción y blockchain.wasm)
└── examples/        # Ejemplos interactivos en HTML5 y CSS3 (Español)
```

---

## Instalación y Compilación

1. **Instalar dependencias**:
   ```bash
   npm install
   ```

2. **Compilar AssemblyScript a WASM**:
   ```bash
   npm run asbuild
   ```

3. **Compilar TypeScript wrapper**:
   ```bash
   npm run build
   ```

---

## Uso Básico

```typescript
import { BlockchainWasm } from './dist/index.js';

// Carga automática del archivo WASM desde la ubicación del script
const wasm = await BlockchainWasm.load();

// 1. Calcular SHA-256
const datos = new TextEncoder().encode("¡Hola, mundo!");
const hash = wasm.sha256(datos);
console.log("SHA-256:", wasm.bytesToHex(hash));

// 2. Firmar y verificar con ECDSA (secp256k1)
const clavePrivada = new Uint8Array(32);
clavePrivada.fill(0x02); // Clave privada de pruebas

const clavePublicaDesc = wasm.getPublicKeyUncompressed(clavePrivada);
const msgHash = wasm.sha256(new TextEncoder().encode("Transacción"));
const firma = wasm.ecdsaSign(msgHash, clavePrivada);

const esValida = wasm.ecdsaVerify(msgHash, firma, clavePublicaDesc);
console.log("¿Firma válida?", esValida);
```

---

## Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para obtener más detalles.
