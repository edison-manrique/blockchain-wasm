type aisize = i32

/**
 * (best-effort) Constant-time hexadecimal encoding
 * @param bin Binary data
 * @returns Hex-encoded representation
 */
export function bin2hex(bin: Uint8Array): string {
  let len = bin.length
  let out = new Uint8Array(len << 1)
  for (let i = 0; i < len; i++) {
    let b = bin[i]
    let h = b >> 4
    let l = b & 0xf
    out[i << 1] = h < 10 ? 48 + h : 87 + h
    out[(i << 1) + 1] = l < 10 ? 48 + l : 87 + l
  }
  return String.UTF8.decode(out.buffer)
}

/**
 * (best-effort) Constant-time hexadecimal decoding
 * @param hex Hex-encoded data
 * @returns Raw binary representation
 */
function hex2bin(hex: string): Uint8Array | null {
  let hex_len = hex.length
  if ((hex_len & 1) !== 0) {
    return null
  }
  let bin = new Uint8Array(<aisize>(hex_len / 2))
  let c_acc = 0
  let bin_pos = 0
  let state = false
  for (let hex_pos = 0; hex_pos < hex_len; hex_pos++) {
    let c = hex.charCodeAt(hex_pos) as u32
    let c_num = c ^ 48
    let c_num0 = (c_num - 10) >> 8
    let c_alpha = (c & ~32) - 55
    let c_alpha0 = ((c_alpha - 10) ^ (c_alpha - 16)) >> 8
    if ((c_num0 | c_alpha0) === 0) {
      return null
    }
    let c_val = ((c_num0 & c_num) | (c_alpha0 & c_alpha)) as u8
    if (state === false) {
      c_acc = c_val << 4
    } else {
      bin[bin_pos++] = c_acc | c_val
    }
    state = !state
  }
  return bin
}

/**
 * (best-effort) Constant-time verification that x == y
 * @param x array 1
 * @param y array 2
 * @returns true if both arrays contain the same data
 */
export function verify(x: Uint8Array, y: Uint8Array): bool {
  let d: u8 = 0

  if (x.length != y.length) {
    return false
  }
  for (let i = 0; i < x.length; ++i) {
    d |= x[i] ^ y[i]
  }
  return d === 0
}
