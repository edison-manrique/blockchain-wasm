export const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

const GENERATOR: u32[] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

function polymod(values: Uint8Array): u32 {
  let chk: u32 = 1
  for (let p = 0; p < values.length; p++) {
    const top = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ (values[p] as u32)
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) {
        chk ^= GENERATOR[i]
      }
    }
  }
  return chk
}

function hrpExpand(hrp: string): Uint8Array {
  const ret = new Uint8Array(hrp.length * 2 + 1)
  for (let p = 0; p < hrp.length; ++p) {
    const c = hrp.charCodeAt(p)
    ret[p] = (c >> 5) as u8
    ret[p + hrp.length + 1] = (c & 31) as u8
  }
  ret[hrp.length] = 0
  return ret
}

function createChecksum(hrp: string, data: Uint8Array, enc: u32): Uint8Array {
  const hrpLength = hrp.length
  // hrp expanded is length * 2 + 1
  const hrpExpLen = hrpLength * 2 + 1

  const values = new Uint8Array(hrpExpLen + data.length + 6)
  const hrpExp = hrpExpand(hrp)

  for (let i = 0; i < hrpExpLen; i++) values[i] = hrpExp[i]
  for (let i = 0; i < data.length; i++) values[hrpExpLen + i] = data[i]

  const mod = polymod(values) ^ enc

  const ret = new Uint8Array(6)
  for (let p = 0; p < 6; p++) {
    ret[p] = ((mod >> (5 * (5 - p))) & 31) as u8
  }
  return ret
}

// Convert from 8-bit to 5-bit
export function convertBits(data: Uint8Array, frombits: u32, tobits: u32, pad: bool): Uint8Array | null {
  let acc: u32 = 0
  let bits: u32 = 0
  let ret = new Array<u8>()
  const maxv: u32 = (1 << tobits) - 1

  for (let p = 0; p < data.length; p++) {
    const value = data[p] as u32
    if (value < 0 || value >> frombits !== 0) {
      return null
    }
    acc = (acc << frombits) | value
    bits += frombits
    while (bits >= tobits) {
      bits -= tobits
      ret.push(((acc >> bits) & maxv) as u8)
    }
  }
  if (pad) {
    if (bits > 0) {
      ret.push(((acc << (tobits - bits)) & maxv) as u8)
    }
  } else if (bits >= frombits || (acc << (tobits - bits)) & maxv) {
    return null
  }

  const res = new Uint8Array(ret.length)
  for (let i = 0; i < ret.length; i++) res[i] = ret[i]
  return res
}

export function encodeBech32(hrp: string, data: Uint8Array, enc: u32 = 1): string {
  const checksum = createChecksum(hrp, data, enc)

  let ret = hrp + "1"
  for (let p = 0; p < data.length; p++) {
    ret += BECH32_CHARSET.charAt(data[p])
  }
  for (let p = 0; p < checksum.length; p++) {
    ret += BECH32_CHARSET.charAt(checksum[p])
  }
  return ret
}
