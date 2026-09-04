# 🚨 Guía de Deprecación y Retiro de Versiones Afectadas en npm

> **Importante:** La versión `3.2.0` contiene un bug crítico en la fachada TypeScript de MuSig2 (BIP-327) que impedía la generación de firmas válidas al usar claves públicas x-only (BIP-340).
> La versión **`3.2.1`** corrige este problema al 100%.

---

## Opción 1: Deprecar Versiones en npm (Recomendado por npm)

`npm deprecate` advierte inmediatamente a cualquier usuario o sistema CI/CD que intente instalar una versión vulnerable, solicitando actualizar a `>=3.2.1`:

### Deprecar únicamente la versión 3.2.0:
```bash
npm deprecate blockchain-wasm@3.2.0 "CRITICO: Bug en MuSig2 (BIP-327). Actualice de inmediato a >=3.2.1"
```

### Deprecar todas las versiones anteriores a 3.2.1:
```bash
npm deprecate blockchain-wasm@"<3.2.1" "CRITICO: Bug en MuSig2 (BIP-327). Actualice de inmediato a >=3.2.1"
```

---

## Opción 2: Despublicar (Unpublish) de npm

> **Regla de npm:** Sólo se permite despublicar paquetes publicados dentro de las **últimas 72 horas**. Si `3.2.0` fue publicada hace menos de 72 horas, puedes retirarla completamente del registro:

### Despublicar versión 3.2.0:
```bash
npm unpublish blockchain-wasm@3.2.0 --force
```

*(Si pasaron más de 72 horas, npm rechazará `unpublish` para evitar romper dependencias existentes; en ese caso utiliza `npm deprecate` de la Opción 1).*

---

## Publicar la versión corregida 3.2.1

Una vez deprecada o despublicada la versión anterior:

```bash
# 1. Asegurar compilación limpia de binario WASM y bundle TS
bun run release

# 2. Publicar la versión 3.2.1 en npm
npm publish --access public
```
