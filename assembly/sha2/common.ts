@inline
export function load32_be(ptr: usize): u32 {
  return bswap(load<u32>(ptr))
}

@inline
export function store32_be(ptr: usize, u: u32): void {
  store<u32>(ptr, bswap(u))
}

@inline
export function load64_be(ptr: usize): u64 {
  return bswap(load<u64>(ptr))
}

@inline
export function store64_be(ptr: usize, u: u64): void {
  store<u64>(ptr, bswap(u))
}

@inline
export function store64_be_arr(x: Uint8Array, offset: isize, u: u64): void {
  store<u64>(changetype<usize>(x.buffer) + offset, bswap(u))
}

// SHA256 Bitwise helpers
@inline
export function sigma0_256(x: u32): u32 {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

@inline
export function sigma1_256(x: u32): u32 {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

@inline
export function Sigma0_256(x: u32): u32 {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

@inline
export function Sigma1_256(x: u32): u32 {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

@inline
export function Ch32(x: u32, y: u32, z: u32): u32 {
  return z ^ (x & (y ^ z))
}

@inline
export function Maj32(x: u32, y: u32, z: u32): u32 {
  return (x & y) ^ (z & (x ^ y))
}

// SHA512 Bitwise helpers
@inline
export function sigma0_512(x: u64): u64 {
  return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
}

@inline
export function sigma1_512(x: u64): u64 {
  return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)
}

@inline
export function Sigma0_512(x: u64): u64 {
  return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}

@inline
export function Sigma1_512(x: u64): u64 {
  return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}

@inline
export function Ch64(x: u64, y: u64, z: u64): u64 {
  return z ^ (x & (y ^ z))
}

@inline
export function Maj64(x: u64, y: u64, z: u64): u64 {
  return (x & y) ^ (z & (x ^ y))
}
