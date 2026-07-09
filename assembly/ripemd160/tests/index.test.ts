import { bytesToHex } from "../../utils"
import { Ripemd160 } from ".."

export function test_ripemd160_basic_vectors(): bool {
  let all_passed = true

  // Vector 1: ""
  if (bytesToHex(Ripemd160.hash(new Uint8Array(0))) != "9c1185a5c5e9fc54612808977ee8f548b2258d31") {
    trace("FAIL RIPEMD160 - Empty")
    all_passed = false
  }

  // Vector 2: "abc"
  let abc = String.UTF8.encode("abc")
  if (bytesToHex(Ripemd160.hash(Uint8Array.wrap(abc))) != "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc") {
    trace("FAIL RIPEMD160 - abc")
    all_passed = false
  }

  // Vector 3: Long string
  let longStr = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  let longBuf = String.UTF8.encode(longStr)
  if (bytesToHex(Ripemd160.hash(Uint8Array.wrap(longBuf))) != "12a053384a9c0c88e405a06c27dcf49ada62eb2b") {
    trace("FAIL RIPEMD160 - Long")
    all_passed = false
  }

  return all_passed
}

export function test_ripemd160_streaming(): bool {
  const data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  const expected = "12a053384a9c0c88e405a06c27dcf49ada62eb2b"

  let u8data = Uint8Array.wrap(String.UTF8.encode(data))
  let hasher = new Ripemd160()

  // Update in chunks
  hasher.update(u8data.subarray(0, 10))
  hasher.update(u8data.subarray(10, 30))
  hasher.update(u8data.subarray(30))

  let result = bytesToHex(hasher.final())
  return result == expected
}
