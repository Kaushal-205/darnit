import type { Hex } from "viem";
import { describe, expect, it } from "vitest";
import { flzCompress, flzDecompress } from "../src/lz.js";

// Input builders and expected outputs produced by Solady's reference js/solady.js LibZip.flzCompress.
const SIG: Hex = `0x${"00".repeat(31)}20${"00".repeat(31)}41${"ab".repeat(32)}${"cd".repeat(32)}1b${"00".repeat(31)}`;
const REP: Hex = `0x${"01020304".repeat(400)}`;
const MIXED: Hex = `0x${Array.from({ length: 600 }, (_, i) =>
  ((i * i * 31 + 7) % 256).toString(16).padStart(2, "0"),
).join("")}`;

describe("flzCompress", () => {
  it("matches the Solady reference byte for byte", () => {
    expect(flzCompress(SIG)).toBe(
      "0x010000e014010020e0141d03000041abe0160000cde01600001b2044e00e00040000000000",
    );
    expect(flzCompress(REP)).toBe(
      "0x0301020304e0fd03e0fd03e0fd03e0fd03e0fd03e0fd03e00a03040401020304",
    );
    expect(flzCompress("0xdeadbeef")).toBe("0x03deadbeef");
    expect(flzCompress("0x")).toBe("0x");
  });

  it.each([
    ["signature", SIG],
    ["repetitive", REP],
    ["mixed", MIXED],
    ["short", "0xdeadbeef" as Hex],
    ["empty", "0x" as Hex],
  ])("round-trips %s", (_name, data) => {
    expect(flzDecompress(flzCompress(data))).toBe(data);
  });
});
