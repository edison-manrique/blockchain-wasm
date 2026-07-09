import { expect, test } from "bun:test";
import { Keccak256 } from "../src/index.ts";

function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

test("empty message hash", () => {
  const expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
  const hash = Keccak256.hex(new Uint8Array(0));
  expect(hash).toBe(expected);
});

test("single character hash", () => {
  const expected = "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb";
  const hash = Keccak256.hex("a");
  expect(hash).toBe(expected);
});

test("multiple characters hash", () => {
  const expected = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
  const hash = Keccak256.hex("abc");
  expect(hash).toBe(expected);
});

test("longer message hash", () => {
  const expected = "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15";
  const hash = Keccak256.hex("The quick brown fox jumps over the lazy dog");
  expect(hash).toBe(expected);
});

test("bytes hash returns correct Uint8Array", () => {
  const message = utf8ToBytes("abc");
  const hashBytes = Keccak256.hash(message);
  
  expect(hashBytes).toBeInstanceOf(Uint8Array);
  expect(hashBytes.length).toBe(32);
  
  // Convert result bytes back to hex and check
  let hex = "";
  for (let i = 0; i < hashBytes.length; i++) {
    const byte = hashBytes[i];
    hex += (byte < 16 ? "0" : "") + byte.toString(16);
  }
  expect(hex).toBe("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
});
