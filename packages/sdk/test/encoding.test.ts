import {
  decodeAbiParameters,
  decodeFunctionData,
  encodeAbiParameters,
  getAddress,
  keccak256,
  parseAbiParameters,
  slice,
} from "viem";
import { describe, expect, it } from "vitest";
import { safe7579Abi } from "../src/abi/external.js";
import {
  ChangeKind,
  DUMMY_ECDSA_SIGNATURE,
  encodeChange,
  encodeExecute,
  encodeGlobalHookInitData,
  encodeModuleInitData,
  encodeOwnableValidatorData,
  encodeSmartSessionUseSignature,
  permissionIdOf,
  validatorFromNonce,
  validatorNonceKey,
} from "../src/encoding.js";
import { flzDecompress } from "../src/lz.js";

const A = getAddress("0x00000000000000000000000000000000000000aa");
const B = getAddress("0x00000000000000000000000000000000000000bb");
const C = "0x2483DA3A338895199E5e538530213157e931Bf06" as const;
const ID = `0x${"11".repeat(32)}` as const;

describe("encodeExecute", () => {
  it("packs a single call: mode 0x00, target ++ value ++ data", () => {
    const { functionName, args } = decodeFunctionData({
      abi: safe7579Abi,
      data: encodeExecute([{ to: A, data: "0x1234" }]),
    });
    expect(functionName).toBe("execute");
    const [mode, exec] = args as readonly [`0x${string}`, `0x${string}`];
    expect(mode).toBe(`0x${"00".repeat(32)}`);
    expect(exec).toBe(`${A.toLowerCase()}${"00".repeat(32)}1234`);
  });

  it("abi-encodes a batch: mode 0x01, default exec type (revert on failure)", () => {
    const { args } = decodeFunctionData({
      abi: safe7579Abi,
      data: encodeExecute([
        { to: A, data: "0x12" },
        { to: B, value: 5n },
      ]),
    });
    const [mode, exec] = args as readonly [`0x${string}`, `0x${string}`];
    expect(slice(mode, 0, 2)).toBe("0x0100");
    const [calls] = decodeAbiParameters(
      parseAbiParameters("(address target, uint256 value, bytes callData)[]"),
      exec,
    );
    expect(
      calls.map((c) => [c.target.toLowerCase(), c.value, c.callData]),
    ).toEqual([
      [A.toLowerCase(), 0n, "0x12"],
      [B.toLowerCase(), 5n, "0x"],
    ]);
  });

  it("refuses an empty call list", () => {
    expect(() => encodeExecute([])).toThrow();
  });
});

describe("nonce key", () => {
  it("puts the validator in the top 20 bytes of the nonce", () => {
    const nonce = (validatorNonceKey(C) << 64n) | 7n;
    expect(validatorFromNonce(nonce)).toBe(C);
    expect(nonce >> 96n).toBe(BigInt(C));
    expect(nonce & 0xffffffffffffffffn).toBe(7n);
  });
});

describe("Smart Sessions", () => {
  it("permission id is keccak(abi.encode(validator, initData, salt))", () => {
    const expected = keccak256(
      encodeAbiParameters(parseAbiParameters("address, bytes, bytes32"), [
        C,
        "0xabcd",
        ID,
      ]),
    );
    expect(permissionIdOf(C, "0xabcd", ID)).toBe(expected);
  });

  it("USE signature is mode 0x00 ++ permissionId ++ flz(abi.encode(sig))", () => {
    const encoded = encodeSmartSessionUseSignature(ID, DUMMY_ECDSA_SIGNATURE);
    expect(slice(encoded, 0, 1)).toBe("0x00");
    expect(slice(encoded, 1, 33)).toBe(ID);
    const [sig] = decodeAbiParameters(
      [{ type: "bytes" }],
      flzDecompress(slice(encoded, 33)),
    );
    expect(sig).toBe(DUMMY_ECDSA_SIGNATURE);
  });
});

describe("install data", () => {
  it("module init data matches FirewallModule.onInstall", () => {
    const data = encodeModuleInitData({
      hourlyCap: 1000n,
      tokens: [A],
      destinations: [B],
      markets: [{ market: C, adapter: A }],
    });
    const [cap, tokens, dests, markets, adapters] = decodeAbiParameters(
      parseAbiParameters("uint128, address[], address[], address[], address[]"),
      data,
    );
    expect(cap).toBe(1000n);
    expect(tokens[0].toLowerCase()).toBe(A.toLowerCase());
    expect(dests[0].toLowerCase()).toBe(B.toLowerCase());
    expect(markets[0]).toBe(C);
    expect(adapters[0].toLowerCase()).toBe(A.toLowerCase());
  });

  it("hook init data selects the global hook", () => {
    const [hookType, selector, init] = decodeAbiParameters(
      parseAbiParameters("uint8, bytes4, bytes"),
      encodeGlobalHookInitData(),
    );
    expect([hookType, selector, init]).toEqual([0, "0x00000000", "0x"]);
  });

  it("OwnableValidator owners are sorted ascending (it rejects unsorted lists)", () => {
    const [threshold, owners] = decodeAbiParameters(
      parseAbiParameters("uint256, address[]"),
      encodeOwnableValidatorData([C, B, A]),
    );
    expect(threshold).toBe(1n);
    expect(owners.map((o) => BigInt(o))).toEqual([
      BigInt(A),
      BigInt(B),
      BigInt(C),
    ]);
  });
});

describe("encodeChange", () => {
  it("encodes each kind the way FirewallModule.execute decodes it", () => {
    expect(encodeChange({ kind: "addDestination", destination: A })).toEqual({
      kind: ChangeKind.AddDestination,
      data: encodeAbiParameters([{ type: "address" }], [A]),
    });
    expect(
      encodeChange({ kind: "addMarket", market: A, adapter: B }).kind,
    ).toBe(ChangeKind.AddMarket);
    expect(encodeChange({ kind: "addToken", token: A }).kind).toBe(
      ChangeKind.AddToken,
    );
    expect(encodeChange({ kind: "raiseCap", hourlyCap: 5n })).toEqual({
      kind: ChangeKind.RaiseCap,
      data: encodeAbiParameters([{ type: "uint128" }], [5n]),
    });
    expect(encodeChange({ kind: "unfreeze" })).toEqual({
      kind: ChangeKind.Unfreeze,
      data: "0x",
    });
    expect(
      encodeChange({ kind: "configCall", target: A, data: "0x12" }),
    ).toEqual({
      kind: ChangeKind.ConfigCall,
      data: encodeAbiParameters(parseAbiParameters("address, uint256, bytes"), [
        A,
        0n,
        "0x12",
      ]),
    });
  });
});
