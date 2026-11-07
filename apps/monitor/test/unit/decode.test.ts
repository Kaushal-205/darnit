import { encodeAbiParameters, encodeErrorResult, encodeFunctionData, parseAbi, toFunctionSelector, zeroAddress } from "viem";
import { describe, expect, it } from "vitest";
import { FirewallErrorsAbi } from "../../abis/FirewallErrors.ts";
import { Safe7579Abi } from "../../abis/Safe7579.ts";
import { CHANGE_KINDS, FIREWALL_ERROR_NAMES, decodeChange, decodeRevertReason } from "../../src/lib/decode.ts";

const ADDR = "0x1111111111111111111111111111111111111111";

function sampleArgs(inputs: readonly { type: string }[]) {
  return inputs.map((i) => {
    if (i.type === "address") return ADDR;
    if (i.type === "bytes4") return "0xa9059cbb";
    if (i.type === "bytes32") return `0x${"ab".repeat(32)}`;
    if (i.type.startsWith("uint")) return 1_500_000n;
    throw new Error(`unhandled ${i.type}`);
  });
}

describe("decodeRevertReason", () => {
  it("covers every error in FirewallErrors and ExecutionDecoder", () => {
    // The 17 FirewallErrors + ExecutionDecoder.Malformed.
    expect(FIREWALL_ERROR_NAMES).toHaveLength(18);
    expect(FIREWALL_ERROR_NAMES).toContain("UnexplainedOutflow");
    expect(FIREWALL_ERROR_NAMES).toContain("Malformed");
  });

  for (const err of FirewallErrorsAbi) {
    it(`decodes ${err.name} (${toFunctionSelector(`${err.name}(${err.inputs.map((i) => i.type).join(",")})`)})`, () => {
      const data = encodeErrorResult({
        abi: [err],
        errorName: err.name,
        args: sampleArgs(err.inputs) as never,
      });
      const d = decodeRevertReason(data);
      expect(d.kind).toBe("firewall");
      expect(d.name).toBe(err.name);
      expect(d.nested).toBe(false);
      expect(d.args).toHaveLength(err.inputs.length);
      // Every firewall error has a specific sentence, never the generic fallback.
      expect(d.description).not.toMatch(/^Reverted with/);
    });
  }

  it("formats BudgetExceeded amounts as USDC", () => {
    const data = encodeErrorResult({ abi: FirewallErrorsAbi, errorName: "BudgetExceeded", args: [2_500_000n, 1_000_000n] });
    expect(decodeRevertReason(data).description).toContain("2.5 USDC");
  });

  it("checksums address arguments", () => {
    const data = encodeErrorResult({
      abi: FirewallErrorsAbi,
      errorName: "UnregisteredSpender",
      args: ["0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"],
    });
    expect(decodeRevertReason(data).args[0]).toBe("0xABcdEFABcdEFabcdEfAbCdefabcdeFABcDEFabCD");
  });

  it("decodes Safe7579 ExecutionFailed() (V10)", () => {
    const data = encodeErrorResult({ abi: Safe7579Abi, errorName: "ExecutionFailed" });
    expect(data).toBe(toFunctionSelector("ExecutionFailed()"));
    const d = decodeRevertReason(data);
    expect(d.kind).toBe("executionFailed");
    expect(d.name).toBe("ExecutionFailed");
    expect(d.description).toContain("likely");
  });

  it("decodes Error(string) and Panic(uint256)", () => {
    const err = encodeErrorResult({ abi: parseAbi(["error Error(string)"]), errorName: "Error", args: ["GS013"] });
    expect(decodeRevertReason(err)).toMatchObject({ kind: "error", name: "Error", args: ["GS013"] });
    const panic = encodeErrorResult({ abi: parseAbi(["error Panic(uint256)"]), errorName: "Panic", args: [0x11n] });
    expect(decodeRevertReason(panic)).toMatchObject({ kind: "panic", name: "Panic", args: ["17"] });
  });

  it("finds a firewall error wrapped inside another error's bytes", () => {
    const inner = encodeErrorResult({ abi: FirewallErrorsAbi, errorName: "UnexplainedOutflow", args: [ADDR, 0n] });
    const wrapped = encodeErrorResult({
      abi: parseAbi(["error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner)"]),
      errorName: "FailedOpWithRevert",
      args: [0n, "AA23 reverted", inner],
    });
    const d = decodeRevertReason(wrapped);
    expect(d).toMatchObject({ kind: "firewall", name: "UnexplainedOutflow", nested: true });
  });

  it("keeps unknown and empty reasons raw", () => {
    expect(decodeRevertReason("0x")).toMatchObject({ kind: "empty", name: null });
    const d = decodeRevertReason("0xdeadbeef00");
    expect(d).toMatchObject({ kind: "unknown", name: null });
    expect(d.description).toContain("0xdeadbeef");
  });
});

describe("decodeChange", () => {
  it("names every ChangeKind", () => {
    expect(CHANGE_KINDS).toEqual(["AddDestination", "AddMarket", "AddToken", "RaiseCap", "Unfreeze", "ConfigCall"]);
  });

  it("decodes each kind's data", () => {
    const one = encodeAbiParameters([{ type: "address" }], [ADDR]);
    expect(decodeChange(0, one).summary).toBe(`Add withdrawal destination ${ADDR}`);
    expect(decodeChange(1, encodeAbiParameters([{ type: "address" }, { type: "address" }], [ADDR, zeroAddress])).fields).toEqual({
      market: ADDR,
      adapter: zeroAddress,
    });
    expect(decodeChange(2, one).fields.token).toBe(ADDR);
    expect(decodeChange(3, encodeAbiParameters([{ type: "uint128" }], [1_000_000_000n])).summary).toBe(
      "Raise hourly risk cap to 1000 USDC",
    );
    expect(decodeChange(4, "0x").kind).toBe("Unfreeze");
  });

  it("labels a ConfigCall that uninstalls a module", () => {
    const callData = encodeFunctionData({
      abi: parseAbi(["function uninstallModule(uint256,address,bytes)"]),
      functionName: "uninstallModule",
      args: [4n, ADDR, "0x"],
    });
    const data = encodeAbiParameters([{ type: "address" }, { type: "uint256" }, { type: "bytes" }], [ADDR, 0n, callData]);
    const d = decodeChange(5, data);
    expect(d.fields.function).toBe("uninstallModule");
    expect(d.summary).toContain("removing the firewall");
  });

  it("survives malformed data and unknown kinds", () => {
    expect(decodeChange(0, "0x12").summary).toContain("undecodable");
    expect(decodeChange(9, "0x").kind).toBe("Unknown");
  });
});
