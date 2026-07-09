/**
 * KECCAK-256: EXTREME OPTIMIZATION
 *
 * Optimizaciones aplicadas:
 * - Punteros crudos (unsafe memory access) para evitar overhead de arrays.
 * - Loop Unrolling completo en pasos críticos (Chi).
 * - Acceso secuencial a constantes (RC) mediante punteros móviles.
 * - Reducción de presión de registros mediante reutilización de variables.
 * - Inline agresivo.
 */

// Alinear memoria es clave. Usamos un StaticArray global, pero lo accederemos
// puramente por punteros.
const STATE = new StaticArray<u64>(25)
// Obtenemos el puntero base del estado una sola vez.
const STATE_PTR = changetype<usize>(STATE)

const RC = new StaticArray<u64>(24)
// Inicialización de constantes (igual que antes)
RC[0] = 0x0000000000000001
RC[1] = 0x0000000000008082
RC[2] = 0x800000000000808a
RC[3] = 0x8000000080008000
RC[4] = 0x000000000000808b
RC[5] = 0x0000000080000001
RC[6] = 0x8000000080008081
RC[7] = 0x8000000000008009
RC[8] = 0x000000000000008a
RC[9] = 0x0000000000000088
RC[10] = 0x0000000080008009
RC[11] = 0x000000008000000a
RC[12] = 0x000000008000808b
RC[13] = 0x800000000000008b
RC[14] = 0x8000000000008089
RC[15] = 0x8000000000008003
RC[16] = 0x8000000000008002
RC[17] = 0x8000000000000080
RC[18] = 0x000000000000800a
RC[19] = 0x800000008000000a
RC[20] = 0x8000000080008081
RC[21] = 0x8000000000008080
RC[22] = 0x0000000080000001
RC[23] = 0x8000000080008008

const RC_PTR = changetype<usize>(RC)

/**
 * Keccak-f[1600] Permutation
 * Totalmente inlined y operando sobre punteros crudos.
 */
// @ts-ignore
@inline
function keccakF1600(): void {
  // Variables locales para mantener en registros de CPU
  let bc0: u64, bc1: u64, bc2: u64, bc3: u64, bc4: u64
  let d0: u64, d1: u64, d2: u64, d3: u64, d4: u64
  let t: u64, last: u64

  // Puntero móvil para las constantes de ronda
  let rcCursor = RC_PTR

  // Cacheamos el puntero de estado en una variable local para acceso rápido
  let s = STATE_PTR

  for (let round = 0; round < 24; round++) {
    // --- THETA STEP ---
    // Leemos directamente de memoria (offsets pre-calculados: 0, 40, 80, 120, 160 bytes)
    // 5 words = 40 bytes. stride = 8 bytes.
    // STATE indices: 0, 5, 10, 15, 20 -> bytes: 0, 40, 80, 120, 160
    bc0 = load<u64>(s) ^ load<u64>(s + 40) ^ load<u64>(s + 80) ^ load<u64>(s + 120) ^ load<u64>(s + 160)
    bc1 = load<u64>(s + 8) ^ load<u64>(s + 48) ^ load<u64>(s + 88) ^ load<u64>(s + 128) ^ load<u64>(s + 168)
    bc2 = load<u64>(s + 16) ^ load<u64>(s + 56) ^ load<u64>(s + 96) ^ load<u64>(s + 136) ^ load<u64>(s + 176)
    bc3 = load<u64>(s + 24) ^ load<u64>(s + 64) ^ load<u64>(s + 104) ^ load<u64>(s + 144) ^ load<u64>(s + 184)
    bc4 = load<u64>(s + 32) ^ load<u64>(s + 72) ^ load<u64>(s + 112) ^ load<u64>(s + 152) ^ load<u64>(s + 192)

    d0 = bc4 ^ rotl(bc1, 1)
    d1 = bc0 ^ rotl(bc2, 1)
    d2 = bc1 ^ rotl(bc3, 1)
    d3 = bc2 ^ rotl(bc4, 1)
    d4 = bc3 ^ rotl(bc0, 1)

    // Aplicamos D al estado (Read-Modify-Write)
    // Usamos offsets directos
    store<u64>(s, load<u64>(s) ^ d0)
    store<u64>(s + 40, load<u64>(s + 40) ^ d0)
    store<u64>(s + 80, load<u64>(s + 80) ^ d0)
    store<u64>(s + 120, load<u64>(s + 120) ^ d0)
    store<u64>(s + 160, load<u64>(s + 160) ^ d0)

    store<u64>(s + 8, load<u64>(s + 8) ^ d1)
    store<u64>(s + 48, load<u64>(s + 48) ^ d1)
    store<u64>(s + 88, load<u64>(s + 88) ^ d1)
    store<u64>(s + 128, load<u64>(s + 128) ^ d1)
    store<u64>(s + 168, load<u64>(s + 168) ^ d1)

    store<u64>(s + 16, load<u64>(s + 16) ^ d2)
    store<u64>(s + 56, load<u64>(s + 56) ^ d2)
    store<u64>(s + 96, load<u64>(s + 96) ^ d2)
    store<u64>(s + 136, load<u64>(s + 136) ^ d2)
    store<u64>(s + 176, load<u64>(s + 176) ^ d2)

    store<u64>(s + 24, load<u64>(s + 24) ^ d3)
    store<u64>(s + 64, load<u64>(s + 64) ^ d3)
    store<u64>(s + 104, load<u64>(s + 104) ^ d3)
    store<u64>(s + 144, load<u64>(s + 144) ^ d3)
    store<u64>(s + 184, load<u64>(s + 184) ^ d3)

    store<u64>(s + 32, load<u64>(s + 32) ^ d4)
    store<u64>(s + 72, load<u64>(s + 72) ^ d4)
    store<u64>(s + 112, load<u64>(s + 112) ^ d4)
    store<u64>(s + 152, load<u64>(s + 152) ^ d4)
    store<u64>(s + 192, load<u64>(s + 192) ^ d4)

    // --- RHO & PI STEPS ---
    // Optimización: Lectura directa sin acceso a array y encadenamiento.
    // offsets en bytes: index * 8
    last = load<u64>(s + 8) // STATE[1]

    // Unrolling manual de las 24 rotaciones
    t = load<u64>(s + 80)
    store<u64>(s + 80, rotl(last, 1))
    last = t // STATE[10]
    t = load<u64>(s + 56)
    store<u64>(s + 56, rotl(last, 3))
    last = t // STATE[7]
    t = load<u64>(s + 88)
    store<u64>(s + 88, rotl(last, 6))
    last = t // STATE[11]
    t = load<u64>(s + 136)
    store<u64>(s + 136, rotl(last, 10))
    last = t // STATE[17]
    t = load<u64>(s + 144)
    store<u64>(s + 144, rotl(last, 15))
    last = t // STATE[18]
    t = load<u64>(s + 24)
    store<u64>(s + 24, rotl(last, 21))
    last = t // STATE[3]
    t = load<u64>(s + 40)
    store<u64>(s + 40, rotl(last, 28))
    last = t // STATE[5]
    t = load<u64>(s + 128)
    store<u64>(s + 128, rotl(last, 36))
    last = t // STATE[16]
    t = load<u64>(s + 64)
    store<u64>(s + 64, rotl(last, 45))
    last = t // STATE[8]
    t = load<u64>(s + 168)
    store<u64>(s + 168, rotl(last, 55))
    last = t // STATE[21]
    t = load<u64>(s + 192)
    store<u64>(s + 192, rotl(last, 2))
    last = t // STATE[24]
    t = load<u64>(s + 32)
    store<u64>(s + 32, rotl(last, 14))
    last = t // STATE[4]
    t = load<u64>(s + 120)
    store<u64>(s + 120, rotl(last, 27))
    last = t // STATE[15]
    t = load<u64>(s + 184)
    store<u64>(s + 184, rotl(last, 41))
    last = t // STATE[23]
    t = load<u64>(s + 152)
    store<u64>(s + 152, rotl(last, 56))
    last = t // STATE[19]
    t = load<u64>(s + 104)
    store<u64>(s + 104, rotl(last, 8))
    last = t // STATE[13]
    t = load<u64>(s + 96)
    store<u64>(s + 96, rotl(last, 25))
    last = t // STATE[12]
    t = load<u64>(s + 16)
    store<u64>(s + 16, rotl(last, 43))
    last = t // STATE[2]
    t = load<u64>(s + 160)
    store<u64>(s + 160, rotl(last, 62))
    last = t // STATE[20]
    t = load<u64>(s + 112)
    store<u64>(s + 112, rotl(last, 18))
    last = t // STATE[14]
    t = load<u64>(s + 176)
    store<u64>(s + 176, rotl(last, 39))
    last = t // STATE[22]
    t = load<u64>(s + 72)
    store<u64>(s + 72, rotl(last, 61))
    last = t // STATE[9]
    t = load<u64>(s + 48)
    store<u64>(s + 48, rotl(last, 20))
    last = t // STATE[6]
    store<u64>(s + 8, rotl(last, 44)) // STATE[1]

    // --- CHI STEP (UNROLLED) ---
    // Eliminar el bucle j+=5 es crucial. Hacemos las 5 filas manualmente.
    // Esto permite al compilador optimizar el pipeline de instrucciones al máximo.

    // Row 0 (bytes 0-32)
    bc0 = load<u64>(s)
    bc1 = load<u64>(s + 8)
    bc2 = load<u64>(s + 16)
    bc3 = load<u64>(s + 24)
    bc4 = load<u64>(s + 32)
    store<u64>(s, bc0 ^ (~bc1 & bc2))
    store<u64>(s + 8, bc1 ^ (~bc2 & bc3))
    store<u64>(s + 16, bc2 ^ (~bc3 & bc4))
    store<u64>(s + 24, bc3 ^ (~bc4 & bc0))
    store<u64>(s + 32, bc4 ^ (~bc0 & bc1))

    // Row 1 (bytes 40-72)
    bc0 = load<u64>(s + 40)
    bc1 = load<u64>(s + 48)
    bc2 = load<u64>(s + 56)
    bc3 = load<u64>(s + 64)
    bc4 = load<u64>(s + 72)
    store<u64>(s + 40, bc0 ^ (~bc1 & bc2))
    store<u64>(s + 48, bc1 ^ (~bc2 & bc3))
    store<u64>(s + 56, bc2 ^ (~bc3 & bc4))
    store<u64>(s + 64, bc3 ^ (~bc4 & bc0))
    store<u64>(s + 72, bc4 ^ (~bc0 & bc1))

    // Row 2 (bytes 80-112)
    bc0 = load<u64>(s + 80)
    bc1 = load<u64>(s + 88)
    bc2 = load<u64>(s + 96)
    bc3 = load<u64>(s + 104)
    bc4 = load<u64>(s + 112)
    store<u64>(s + 80, bc0 ^ (~bc1 & bc2))
    store<u64>(s + 88, bc1 ^ (~bc2 & bc3))
    store<u64>(s + 96, bc2 ^ (~bc3 & bc4))
    store<u64>(s + 104, bc3 ^ (~bc4 & bc0))
    store<u64>(s + 112, bc4 ^ (~bc0 & bc1))

    // Row 3 (bytes 120-152)
    bc0 = load<u64>(s + 120)
    bc1 = load<u64>(s + 128)
    bc2 = load<u64>(s + 136)
    bc3 = load<u64>(s + 144)
    bc4 = load<u64>(s + 152)
    store<u64>(s + 120, bc0 ^ (~bc1 & bc2))
    store<u64>(s + 128, bc1 ^ (~bc2 & bc3))
    store<u64>(s + 136, bc2 ^ (~bc3 & bc4))
    store<u64>(s + 144, bc3 ^ (~bc4 & bc0))
    store<u64>(s + 152, bc4 ^ (~bc0 & bc1))

    // Row 4 (bytes 160-192)
    bc0 = load<u64>(s + 160)
    bc1 = load<u64>(s + 168)
    bc2 = load<u64>(s + 176)
    bc3 = load<u64>(s + 184)
    bc4 = load<u64>(s + 192)
    store<u64>(s + 160, bc0 ^ (~bc1 & bc2))
    store<u64>(s + 168, bc1 ^ (~bc2 & bc3))
    store<u64>(s + 176, bc2 ^ (~bc3 & bc4))
    store<u64>(s + 184, bc3 ^ (~bc4 & bc0))
    store<u64>(s + 192, bc4 ^ (~bc0 & bc1))

    // --- IOTA STEP ---
    // Usamos el puntero a RC, lo leemos y avanzamos el puntero 8 bytes.
    // Esto es más rápido que calcular RC[i] (bounds checks + mult).
    store<u64>(s, load<u64>(s) ^ load<u64>(rcCursor))
    rcCursor += 8
  }
}

/**
 * 🚀 KECCAK-256 Public API
 */
export function keccak256(message: Uint8Array): Uint8Array {
  // 1. Reset STATE ultrarrápido (simd memset en Wasm moderno)
  memory.fill(STATE_PTR, 0, 200)

  // 2. Setup Punteros
  // Evitamos overhead de objetos.
  let msgPtr = changetype<usize>(message.buffer) + message.byteOffset
  let msgRemaining = message.length
  let offset: usize = 0

  // Rate = 136 bytes (17 palabras de 64 bits)
  const RATE_WORDS = 17
  const RATE_BYTES = 136

  // 3. Absorción de bloques completos
  // Bucle principal optimizado
  while (msgRemaining >= RATE_BYTES) {
    // Absorber 17 u64s.
    // Unrolling parcial para aprovechar pipelining de CPU (Wasm engine JIT).
    // Read-Modify-Write directo a memoria.
    for (let i = 0; i < RATE_WORDS; i++) {
      let stateAddr = STATE_PTR + ((<usize>i) << 3)
      let msgVal = load<u64>(msgPtr + offset + ((<usize>i) << 3))
      store<u64>(stateAddr, load<u64>(stateAddr) ^ msgVal)
    }

    keccakF1600()

    offset += RATE_BYTES
    msgRemaining -= RATE_BYTES
  }

  // 4. Absorción final y Padding
  // Procesamos byte a byte lo que sobra
  let ptr = msgPtr + offset
  for (let i: usize = 0; i < <usize>msgRemaining; i++) {
    // Cálculo optimizado de índice de palabra y bit
    let wordOffset = (i >>> 3) << 3 // (i / 8) * 8
    let bitShift = (i & 7) << 3 // (i % 8) * 8

    let stateAddr = STATE_PTR + wordOffset
    let byteVal = <u64>load<u8>(ptr + i)

    store<u64>(stateAddr, load<u64>(stateAddr) ^ (byteVal << bitShift))
  }

  // Padding start: 0x01
  let idx = <usize>msgRemaining
  let wordOffset = (idx >>> 3) << 3
  let bitShift = (idx & 7) << 3
  let stateAddr = STATE_PTR + wordOffset
  store<u64>(stateAddr, load<u64>(stateAddr) ^ ((<u64>0x01) << bitShift))

  // Padding end: 0x80 en el byte 135 (palabra 16, MSB)
  // STATE[16] es byte offset 128 (16 * 8)
  let lastWordAddr = STATE_PTR + 128
  store<u64>(lastWordAddr, load<u64>(lastWordAddr) ^ 0x8000000000000000)

  // Última permutación
  keccakF1600()

  // 5. Extracción (Squeeze)
  // Única asignación de memoria en toda la función.
  const result = new Uint8Array(32)
  let resPtr = changetype<usize>(result.buffer) + result.byteOffset

  // Copia directa de memoria de 4 palabras (256 bits)
  store<u64>(resPtr, load<u64>(STATE_PTR))
  store<u64>(resPtr + 8, load<u64>(STATE_PTR + 8))
  store<u64>(resPtr + 16, load<u64>(STATE_PTR + 16))
  store<u64>(resPtr + 24, load<u64>(STATE_PTR + 24))

  return result
}
