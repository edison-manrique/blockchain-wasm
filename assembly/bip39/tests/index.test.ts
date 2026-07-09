/**
 * BIP39 WASM Test Suite — Verified Vectors
 * Generated with @scure/bip39 (audited library)
 */

import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed, validateMnemonic, generateMnemonic } from ".."
import { hexToBytes } from "../../utils"

function expectBytes(actual: Uint8Array, expected: Uint8Array): bool {
  if (actual.length != expected.length) return false
  return memory.compare(actual.dataStart, expected.dataStart, actual.length) == 0
}

// ═══════════════════════════════════════════════════════
// Vector 1: All-zeros entropy (12 words)
// ═══════════════════════════════════════════════════════

export function test_bip39_v1_entropy_to_mnemonic(): bool {
  const entropy = hexToBytes("00000000000000000000000000000000")
  const expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  return entropyToMnemonic(entropy) == expected
}

export function test_bip39_v1_mnemonic_to_entropy(): bool {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  const expected = hexToBytes("00000000000000000000000000000000")
  return expectBytes(mnemonicToEntropy(mnemonic), expected)
}

export function test_bip39_v1_seed_no_pass(): bool {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  const expected = hexToBytes(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
  )
  return expectBytes(mnemonicToSeed(mnemonic, ""), expected)
}

export function test_bip39_v1_seed_trezor(): bool {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  const expected = hexToBytes(
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  )
  return expectBytes(mnemonicToSeed(mnemonic, "TREZOR"), expected)
}

// ═══════════════════════════════════════════════════════
// Vector 2: 32 bytes 0x7f (24 words)
// ═══════════════════════════════════════════════════════

export function test_bip39_v2_entropy_to_mnemonic(): bool {
  const entropy = hexToBytes("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
  const expected =
    "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
  return entropyToMnemonic(entropy) == expected
}

export function test_bip39_v2_roundtrip(): bool {
  const mnemonic =
    "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
  const entropy = mnemonicToEntropy(mnemonic)
  const expected = hexToBytes("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
  return expectBytes(entropy, expected)
}

export function test_bip39_v2_seed(): bool {
  const mnemonic =
    "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
  const expected = hexToBytes(
    "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87"
  )
  return expectBytes(mnemonicToSeed(mnemonic, "TREZOR"), expected)
}

// ═══════════════════════════════════════════════════════
// Vector 3: 20 bytes 0x80 (15 words)
// ═══════════════════════════════════════════════════════

export function test_bip39_v3_entropy_to_mnemonic(): bool {
  const entropy = hexToBytes("8080808080808080808080808080808080808080")
  const expected =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor accident"
  return entropyToMnemonic(entropy) == expected
}

export function test_bip39_v3_seed(): bool {
  const mnemonic =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor accident"
  const expected = hexToBytes(
    "bc40a19ec918698b32e3e13ed906006d9e3b9987ba7dee6fc53a824774cc5be68f89b865bbfbac21b2fb99c016e214f54f239f77dd99881c1b81de275c60be3d"
  )
  return expectBytes(mnemonicToSeed(mnemonic, "TREZOR"), expected)
}

// ═══════════════════════════════════════════════════════
// Vector 4: 16 bytes 0xff (12 words)
// ═══════════════════════════════════════════════════════

export function test_bip39_v4_entropy_to_mnemonic(): bool {
  const entropy = hexToBytes("ffffffffffffffffffffffffffffffff")
  const expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
  return entropyToMnemonic(entropy) == expected
}

export function test_bip39_v4_roundtrip(): bool {
  const mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
  const entropy = mnemonicToEntropy(mnemonic)
  const expected = hexToBytes("ffffffffffffffffffffffffffffffff")
  return expectBytes(entropy, expected)
}

export function test_bip39_v4_seed(): bool {
  const mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
  const expected = hexToBytes(
    "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"
  )
  return expectBytes(mnemonicToSeed(mnemonic, "TREZOR"), expected)
}

// ═══════════════════════════════════════════════════════
// Vector 5: Specific pattern
// ═══════════════════════════════════════════════════════

export function test_bip39_v5_entropy_to_mnemonic(): bool {
  const entropy = hexToBytes("068c783727ced34a2816746c8005149a")
  const expected = "alley glow assist exhibit unfold pink park soldier hold ability early crystal"
  return entropyToMnemonic(entropy) == expected
}

export function test_bip39_v5_seed(): bool {
  const mnemonic = "alley glow assist exhibit unfold pink park soldier hold ability early crystal"
  const expected = hexToBytes(
    "991c52b4d8318839e98aa5736bb9676019613b19d4a8a828f512f960954b983c2387f86eae866692de84ae21b46ad0725b6e834abe73326ad458f127dcab4ebe"
  )
  return expectBytes(mnemonicToSeed(mnemonic, "TREZOR"), expected)
}

// ═══════════════════════════════════════════════════════
// Validation tests
// ═══════════════════════════════════════════════════════

export function test_bip39_validate_v1(): bool {
  return validateMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  )
}

export function test_bip39_validate_v2(): bool {
  return validateMnemonic(
    "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
  )
}

export function test_bip39_validate_v4(): bool {
  return validateMnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
}

export function test_bip39_validate_invalid_checksum(): bool {
  // "zoo" instead of "about" breaks checksum
  return !validateMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo"
  )
}

export function test_bip39_validate_invalid_word(): bool {
  return !validateMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz"
  )
}

export function test_bip39_validate_wrong_count(): bool {
  return !validateMnemonic("abandon abandon abandon abandon abandon")
}

// ═══════════════════════════════════════════════════════
// Generation tests
// ═══════════════════════════════════════════════════════

export function test_bip39_generate_12(): bool {
  const mnemonic = generateMnemonic(12)
  const words = mnemonic.split(" ")
  if (words.length != 12) return false
  return validateMnemonic(mnemonic)
}

export function test_bip39_generate_15(): bool {
  const mnemonic = generateMnemonic(15)
  const words = mnemonic.split(" ")
  if (words.length != 15) return false
  return validateMnemonic(mnemonic)
}

export function test_bip39_generate_24(): bool {
  const mnemonic = generateMnemonic(24)
  const words = mnemonic.split(" ")
  if (words.length != 24) return false
  return validateMnemonic(mnemonic)
}
