/**
 * BIP32/BIP44 WASM Test Suite — Verified Vectors
 * Generated with @scure/bip32 (audited library)
 *
 * Master seed: BIP39 "abandon...about" + "TREZOR" passphrase
 * = c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
 */

import { HDKey, derivePrivateKey, derivePublicKey } from "../bip32"
import { hexToBytes, bytesToHex } from "../../utils"

// ── Shared seed constant ──
const SEED_HEX =
  "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"

// ── Second seed: zoo...wrong + TREZOR ──
const SEED2_HEX =
  "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"

// ── Third seed: abandon...about + no passphrase ──
const SEED3_HEX =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

function expectHex(actual: Uint8Array, expectedHex: string): bool {
  return bytesToHex(actual) == expectedHex
}

function getMaster(): HDKey {
  return HDKey.fromSeed(hexToBytes(SEED_HEX))
}

// ═══════════════════════════════════════════════════════
// TEST: Master key from seed
// ═══════════════════════════════════════════════════════

export function test_bip32_master_privkey(): bool {
  const master = getMaster()
  return expectHex(master.keyData, "cbedc75b0d6412c85c79bc13875112ef912fd1e756631b5a00330866f22ff184")
}

export function test_bip32_master_pubkey(): bool {
  const master = getMaster()
  return expectHex(master.getPublicKey(), "02f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd")
}

export function test_bip32_master_chaincode(): bool {
  const master = getMaster()
  return expectHex(master.chainCode, "a3fa8c983223306de0f0f65e74ebb1e98aba751633bf91d5fb56529aa5c132c1")
}

// ═══════════════════════════════════════════════════════
// TEST: BIP44 BTC (m/44'/0'/0'/0/0)
// ═══════════════════════════════════════════════════════

export function test_bip44_btc_addr0_privkey(): bool {
  const master = getMaster()
  const key = derivePrivateKey(master, 44, 0, 0, 0, 0)
  return expectHex(key, "cdd74cbef2372344879b8a0aa8799435ff55bf5bde335638cb7a8d09fd0f9759")
}

export function test_bip44_btc_addr0_pubkey(): bool {
  const master = getMaster()
  const key = derivePublicKey(master, 44, 0, 0, 0, 0)
  return expectHex(key, "027440c6c46ec617a202f44bc886a249b10f98a8ff5d8a0aa56a350ab930a0ec79")
}

export function test_bip44_btc_addr1_privkey(): bool {
  const master = getMaster()
  const key = derivePrivateKey(master, 44, 0, 0, 0, 1)
  return expectHex(key, "eb9cbdfcfcdf6b682fae39cd133e587b6f238027ef541a1a28bb370edc085493")
}

export function test_bip44_btc_addr2_privkey(): bool {
  const master = getMaster()
  const key = derivePrivateKey(master, 44, 0, 0, 0, 2)
  return expectHex(key, "07380ae85f2f5fa4a2c8ca8538d0c0d23c517b9f45c735406b0e3e90b69e66d6")
}

// ═══════════════════════════════════════════════════════
// TEST: BIP44 ETH (m/44'/60'/0'/0/0)
// ═══════════════════════════════════════════════════════

export function test_bip44_eth_addr0_privkey(): bool {
  const master = getMaster()
  const key = derivePrivateKey(master, 44, 60, 0, 0, 0)
  return expectHex(key, "62f1d86b246c81bdd8f6c166d56896a4a5e1eddbcaebe06480e5c0bc74c28224")
}

export function test_bip44_eth_addr0_pubkey(): bool {
  const master = getMaster()
  const key = derivePublicKey(master, 44, 60, 0, 0, 0)
  return expectHex(key, "03986dee3b8afe24cb8ccb2ac23dac3f8c43d22850d14b809b26d6b8aa5a1f4778")
}

export function test_bip44_eth_addr1_privkey(): bool {
  const master = getMaster()
  const key = derivePrivateKey(master, 44, 60, 0, 0, 1)
  return expectHex(key, "49ee230b1605382ac1c40079191bca937fc30e8c2fa845b7de27a96ffcc4ddbf")
}

// ═══════════════════════════════════════════════════════
// TEST: BIP44 TRX (m/44'/195'/0'/0/0)
// ═══════════════════════════════════════════════════════

export function test_bip44_trx_addr0_privkey(): bool {
  const master = getMaster()
  const key = derivePrivateKey(master, 44, 195, 0, 0, 0)
  return expectHex(key, "554d613c6ae7cfe1f7cc0814f48e8eab176ca316fd7d1153fcd7a45b73fee11e")
}

// ═══════════════════════════════════════════════════════
// TEST: BIP84 BTC SegWit (m/84'/0'/0'/0/0)
// ═══════════════════════════════════════════════════════

export function test_bip84_btc_addr0_privkey(): bool {
  const master = getMaster()
  const key = derivePrivateKey(master, 84, 0, 0, 0, 0)
  return expectHex(key, "697e2dcb4c29ef4af9c937cd915c3872afc35217ad240794df09dd6fccdfb059")
}

export function test_bip84_btc_addr0_pubkey(): bool {
  const master = getMaster()
  const key = derivePublicKey(master, 84, 0, 0, 0, 0)
  return expectHex(key, "02a0f073d11f80811fb4e6d2b0299695c866a0988c1acf9f82a96ebb925524f328")
}

// ═══════════════════════════════════════════════════════
// TEST: BIP86 BTC Taproot (m/86'/0'/0'/0/0)
// ═══════════════════════════════════════════════════════

export function test_bip86_btc_addr0_privkey(): bool {
  const master = getMaster()
  const key = derivePrivateKey(master, 86, 0, 0, 0, 0)
  return expectHex(key, "e58f3379b0a7baea0c8a1e106aed77ea6ea1cc2ae09e886daf2a072fb79a133b")
}

export function test_bip86_btc_addr0_pubkey(): bool {
  const master = getMaster()
  const key = derivePublicKey(master, 86, 0, 0, 0, 0)
  return expectHex(key, "036cf32115c2fd0dc462fe82e267d89a17e5f5b43087cfcb3be52b89ac70fac245")
}

// ═══════════════════════════════════════════════════════
// TEST: Second seed (zoo...wrong + TREZOR)
// ═══════════════════════════════════════════════════════

export function test_bip44_seed2_master_privkey(): bool {
  const master = HDKey.fromSeed(hexToBytes(SEED2_HEX))
  return expectHex(master.keyData, "e1330e46e88f1c65cc1e228a16e3f0b94a316ae4fcfda1df4996b85c70d7b909")
}

export function test_bip44_seed2_btc_addr0(): bool {
  const master = HDKey.fromSeed(hexToBytes(SEED2_HEX))
  const key = derivePrivateKey(master, 44, 0, 0, 0, 0)
  return expectHex(key, "56f0c5facda0636533236194a0840ecf8b7bdd2938095d6516a30432cd4968e9")
}

export function test_bip44_seed2_eth_addr0(): bool {
  const master = HDKey.fromSeed(hexToBytes(SEED2_HEX))
  const key = derivePrivateKey(master, 44, 60, 0, 0, 0)
  return expectHex(key, "4f54c1357bcd855f1ed4315e66dd0771c83318c6726d3c1847510825a72a38e0")
}

// ═══════════════════════════════════════════════════════
// TEST: Third seed (abandon...about + no passphrase)
// ═══════════════════════════════════════════════════════

export function test_bip44_seed3_master_privkey(): bool {
  const master = HDKey.fromSeed(hexToBytes(SEED3_HEX))
  return expectHex(master.keyData, "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67")
}

export function test_bip44_seed3_btc_addr0(): bool {
  const master = HDKey.fromSeed(hexToBytes(SEED3_HEX))
  const key = derivePrivateKey(master, 44, 0, 0, 0, 0)
  return expectHex(key, "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372")
}

export function test_bip44_seed3_eth_addr0(): bool {
  const master = HDKey.fromSeed(hexToBytes(SEED3_HEX))
  const key = derivePrivateKey(master, 44, 60, 0, 0, 0)
  return expectHex(key, "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
}

// ═══════════════════════════════════════════════════════
// TEST: DerivePath consistency
// ═══════════════════════════════════════════════════════

export function test_bip32_derivepath_vs_manual(): bool {
  const master = getMaster()
  const key1 = master.derivePath("m/44'/0'/0'/0/0")
  const key2 = master
    .derive(44 + 0x80000000)
    .derive(0 + 0x80000000)
    .derive(0 + 0x80000000)
    .derive(0)
    .derive(0)

  if (key1.depth != key2.depth) return false
  if (memory.compare(key1.keyData.dataStart, key2.keyData.dataStart, 32) != 0) return false
  if (memory.compare(key1.chainCode.dataStart, key2.chainCode.dataStart, 32) != 0) return false
  return true
}

// ═══════════════════════════════════════════════════════
// TEST: Neuter
// ═══════════════════════════════════════════════════════

export function test_bip32_neuter(): bool {
  const master = getMaster()
  const neutered = master.neuter()
  if (neutered.isPrivate) return false
  if (neutered.keyData.length != 33) return false
  return expectHex(neutered.keyData, "02f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd")
}

// ═══════════════════════════════════════════════════════
// TEST: Multiple addresses are unique
// ═══════════════════════════════════════════════════════

export function test_bip44_unique_addresses(): bool {
  const master = getMaster()
  const keys = new Array<Uint8Array>(5)
  for (let i: u32 = 0; i < 5; i++) {
    keys[i] = derivePrivateKey(master, 44, 0, 0, 0, i)
  }
  for (let i = 0; i < 5; i++) {
    for (let j = i + 1; j < 5; j++) {
      if (memory.compare(keys[i].dataStart, keys[j].dataStart, 32) == 0) return false
    }
  }
  return true
}
