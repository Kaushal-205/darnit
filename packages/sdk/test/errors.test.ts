import {
  type AbiParameter,
  BaseError,
  type Client,
  type Hex,
  encodeAbiParameters,
  encodeErrorResult,
  getAddress,
  toFunctionSelector,
} from "viem";
import { describe, expect, it } from "vitest";
import { executionDecoderAbi, firewallErrorsAbi } from "../src/abi/index.js";
import {
  EXECUTION_FAILED_SELECTOR,
  decodeFirewallError,
  explainRevert,
  extractRevertData,
  findFirewallErrorInTrace,
} from "../src/errors.js";

const USDC = getAddress("0x00000000000000000000000000000000000000aa");
const ATTACKER = getAddress("0x00000000000000000000000000000000000000bb");
const ID = `0x${"11".repeat(32)}` as const;

const sample = (p: AbiParameter) => {
  switch (p.type) {
    case "address":
      return USDC;
    case "bytes4":
      return "0xa9059cbb";
    case "bytes32":
      return ID;
    default:
      return 1_000_000n;
  }
};

const err = (name: string, args: readonly unknown[] = []): Hex =>
  encodeErrorResult({ abi: firewallErrorsAbi, errorName: name, args } as never);

describe("decodeFirewallError", () => {
  const errors = firewallErrorsAbi.filter((x) => x.type === "error");

  it("covers the full FirewallErrors interface", () => {
    expect(errors.length).toBe(17);
  });

  it.each(errors.map((e) => [e.name, e] as const))(
    "explains %s in a sentence",
    (name, abiItem) => {
      const d = decodeFirewallError(err(name, abiItem.inputs.map(sample)));
      expect(d?.name).toBe(name);
      expect(d?.isFirewallError).toBe(true);
      expect(d?.isOpaque).toBe(false);
      expect(d?.message).toMatch(/\.$/);
      expect(d?.message).not.toMatch(/^Reverted with/);
    },
  );

  it("names the numbers in BudgetExceeded", () => {
    expect(
      decodeFirewallError(err("BudgetExceeded", [200_000_000n, 50_500_000n]))
        ?.message,
    ).toContain("up to $200, but only $50.5");
  });

  it("names the asset, or share id, in UnexplainedOutflow", () => {
    expect(
      decodeFirewallError(err("UnexplainedOutflow", [USDC, 0n]))?.message,
    ).toContain(USDC);
    expect(
      decodeFirewallError(err("UnexplainedOutflow", [USDC, 2n]))?.message,
    ).toContain("share id 2");
  });

  it("explains ExecutionDecoder.Malformed", () => {
    const d = decodeFirewallError(
      encodeErrorResult({ abi: executionDecoderAbi, errorName: "Malformed" }),
    );
    expect(d?.name).toBe("Malformed");
    expect(d?.isFirewallError).toBe(true);
  });

  it("marks ExecutionFailed() as opaque", () => {
    expect(toFunctionSelector("ExecutionFailed()")).toBe(
      EXECUTION_FAILED_SELECTOR,
    );
    const d = decodeFirewallError(EXECUTION_FAILED_SELECTOR);
    expect(d?.name).toBe("ExecutionFailed");
    expect(d?.isOpaque).toBe(true);
    expect(d?.isFirewallError).toBe(false);
  });

  it("explains EntryPoint validation failures", () => {
    const data = `0x220266b6${encodeAbiParameters(
      [{ type: "uint256" }, { type: "string" }],
      [0n, "AA24 signature error"],
    ).slice(2)}` as Hex;
    const d = decodeFirewallError(data);
    expect(d?.name).toBe("FailedOp");
    expect(d?.message).toContain("session");
  });

  it("decodes Error(string) and unknown selectors without throwing", () => {
    const e =
      `0x08c379a0${encodeAbiParameters([{ type: "string" }], ["nope"]).slice(2)}` as Hex;
    expect(decodeFirewallError(e)?.message).toBe("Reverted: nope");
    expect(decodeFirewallError("0x12345678")?.isFirewallError).toBe(false);
  });

  it("returns undefined when there is no revert data", () => {
    expect(decodeFirewallError("0x")).toBeUndefined();
    expect(decodeFirewallError(undefined)).toBeUndefined();
    expect(decodeFirewallError(new Error("network down"))).toBeUndefined();
  });

  it("finds data nested in a viem error chain, and ignores hex that is merely in its text", () => {
    const inner = Object.assign(new BaseError("inner"), {
      data: err("Frozen"),
    });
    const outer = new BaseError("outer", { cause: inner });
    expect(extractRevertData(outer)).toBe(err("Frozen"));
    expect(decodeFirewallError(outer)?.name).toBe("Frozen");
    expect(
      extractRevertData(new BaseError("bad", { details: `address ${USDC}` })),
    ).toBeUndefined();
  });
});

describe("findFirewallErrorInTrace", () => {
  it("returns the innermost firewall error under ExecutionFailed wrappers", () => {
    const trace = {
      error: "execution reverted",
      output: EXECUTION_FAILED_SELECTOR,
      calls: [
        { output: "0x" as Hex },
        {
          error: "execution reverted",
          output: EXECUTION_FAILED_SELECTOR,
          calls: [
            {
              error: "execution reverted",
              output: err("UnregisteredSpender", [ATTACKER]),
            },
          ],
        },
      ],
    };
    expect(findFirewallErrorInTrace(trace)?.name).toBe("UnregisteredSpender");
  });

  it("ignores frames that did not revert", () => {
    expect(findFirewallErrorInTrace({ output: err("Frozen") })).toBeUndefined();
  });
});

describe("explainRevert", () => {
  const client = (handler: (method: string, params: unknown) => unknown) =>
    ({
      request: async ({
        method,
        params,
      }: { method: string; params: unknown }) => handler(method, params),
    }) as unknown as Client;
  const call = { from: ATTACKER, to: USDC, data: "0x12345678" as Hex };

  it("returns visible firewall errors without touching the node", async () => {
    const c = client(() => {
      throw new Error("should not be called");
    });
    expect((await explainRevert(c, { revertData: err("Frozen") }))?.name).toBe(
      "Frozen",
    );
  });

  it("traces the transaction when only ExecutionFailed() is visible", async () => {
    const methods: string[] = [];
    const c = client((method) => {
      methods.push(method);
      return {
        error: "execution reverted",
        output: EXECUTION_FAILED_SELECTOR,
        calls: [
          {
            error: "execution reverted",
            output: err("BudgetExceeded", [2n, 1n]),
          },
        ],
      };
    });
    const d = await explainRevert(c, {
      revertData: EXECUTION_FAILED_SELECTOR,
      transactionHash: ID,
    });
    expect(d?.name).toBe("BudgetExceeded");
    expect(methods).toEqual(["debug_traceTransaction"]);
  });

  it("re-simulates a call with debug_traceCall", async () => {
    const c = client((method) => {
      expect(method).toBe("debug_traceCall");
      return { error: "execution reverted", output: err("Frozen") };
    });
    expect(
      (await explainRevert(c, { revertData: EXECUTION_FAILED_SELECTOR, call }))
        ?.name,
    ).toBe("Frozen");
  });

  it("reports the innermost non-firewall reason when the firewall did not block it", async () => {
    const c = client(() => ({
      error: "execution reverted",
      output: EXECUTION_FAILED_SELECTOR,
      calls: [{ error: "execution reverted", output: "0x12345678" as Hex }],
    }));
    expect(
      (
        await explainRevert(c, {
          revertData: EXECUTION_FAILED_SELECTOR,
          transactionHash: ID,
        })
      )?.name,
    ).toBe("0x12345678");
  });

  it("falls back to the hook's preCheck when the node has no debug methods", async () => {
    const methods: string[] = [];
    const c = client((method) => {
      methods.push(method);
      if (method === "eth_call")
        throw Object.assign(new BaseError("reverted"), {
          data: err("UnknownTarget", [USDC, "0xa9059cbb"]),
        });
      throw new Error("method not found");
    });
    const d = await explainRevert(c, {
      revertData: EXECUTION_FAILED_SELECTOR,
      call,
      hook: ATTACKER,
    });
    expect(d?.name).toBe("UnknownTarget");
    expect(methods).toEqual(["debug_traceCall", "eth_call"]);
  });

  it("stays with ExecutionFailed() when nothing better can be found", async () => {
    const c = client(() => {
      throw new Error("method not found");
    });
    expect(
      (await explainRevert(c, { revertData: EXECUTION_FAILED_SELECTOR, call }))
        ?.name,
    ).toBe("ExecutionFailed");
  });
});
