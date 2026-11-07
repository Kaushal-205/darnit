import {
  ChangeKind,
  firewallModuleAbi,
  safe7579Abi,
} from "@session-firewall/sdk";
import {
  type Address,
  decodeAbiParameters,
  decodeFunctionData,
  erc20Abi,
} from "viem";
import { describe, expect, it } from "vitest";
import { parseAmount, planExit } from "../src/calls.js";
import type {
  AccountSnapshot,
  ShareBalance,
  TokenBalance,
} from "../src/reads.js";
import { queueRecoveryInstall } from "../src/recovery.js";

const account: Address = "0x00000000000000000000000000000000000000aa";
const dest: Address = "0x00000000000000000000000000000000000000bb";
const usdc: TokenBalance = {
  kind: "token",
  token: "0x00000000000000000000000000000000000000c1",
  symbol: "USDC",
  decimals: 6,
  balance: 5_000_000n,
};
const yes: ShareBalance = {
  kind: "share",
  token: "0x00000000000000000000000000000000000000c2",
  id: 7n,
  label: "Market 1 YES",
  balance: 3_000_000n,
};
const snap: AccountSnapshot = {
  account,
  module: "0x00000000000000000000000000000000000000d1",
  hook: "0x00000000000000000000000000000000000000d2",
  frozen: true,
  hourlyCap: 0n,
  availableBudget: 0n,
  destinations: [dest],
  validators: [],
  tokens: [usdc],
  shares: [yes],
  ethBalance: 0n,
};

describe("amounts", () => {
  it("parses decimals, blank means all, refuses too much", () => {
    expect(parseAmount("1.5", usdc)).toBe(1_500_000n);
    expect(parseAmount("", usdc)).toBe(5_000_000n);
    expect(parseAmount("all", yes)).toBe(3_000_000n);
    expect(() => parseAmount("6", usdc)).toThrow(/more than/);
    expect(() => parseAmount("1e3", usdc)).toThrow(/like 12.5/);
    expect(() => parseAmount("0", usdc)).toThrow(/more than zero/);
  });
});

describe("exit plan", () => {
  it("only to a trusted destination", () => {
    expect(() =>
      planExit(snap, usdc, 1n, "0x00000000000000000000000000000000000000ee"),
    ).toThrow(/trusted destination/);
  });

  it("one token transfer", () => {
    const p = planExit(snap, usdc, 1_000_000n, dest);
    expect(p.calls).toHaveLength(1);
    expect(p.calls[0].to).toBe(usdc.token);
    const d = decodeFunctionData({
      abi: erc20Abi,
      data: p.calls[0].data ?? "0x",
    });
    expect(d.functionName).toBe("transfer");
    expect(d.args).toEqual([dest, 1_000_000n]);
  });

  it("everything: every token and share with a balance, in one request", () => {
    const p = planExit(snap, "all", undefined, dest);
    expect(p.lines.map((l) => l.amount)).toEqual([5_000_000n, 3_000_000n]);
    expect(p.calls[1].to).toBe(yes.token);
    expect(p.calls[1].data?.slice(0, 10)).toBe("0xf242432a"); // safeTransferFrom(address,address,uint256,uint256,bytes)
  });

  it("refuses an empty account", () => {
    expect(() =>
      planExit({ ...snap, tokens: [], shares: [] }, "all", undefined, dest),
    ).toThrow(/nothing/);
  });
});

describe("recovery key enrollment", () => {
  it("queues a ConfigCall that installs the second validator with the new key", () => {
    const x = `0x${"11".repeat(32)}` as const;
    const y = `0x${"22".repeat(32)}` as const;
    const validator: Address = "0x00000000000000000000000000000000000000f1";
    const q = queueRecoveryInstall({
      account,
      recoveryValidator: validator,
      x,
      y,
    });
    const queued = decodeFunctionData({ abi: firewallModuleAbi, data: q.data });
    expect(queued.functionName).toBe("queue");
    expect(q.change.kind).toBe(ChangeKind.ConfigCall);
    const [target, value, callData] = decodeAbiParameters(
      [{ type: "address" }, { type: "uint256" }, { type: "bytes" }],
      q.change.data,
    );
    expect(target.toLowerCase()).toBe(account);
    expect(value).toBe(0n);
    const install = decodeFunctionData({ abi: safe7579Abi, data: callData });
    expect(install.functionName).toBe("installModule");
    expect(install.args?.[0]).toBe(1n);
    expect(String(install.args?.[1]).toLowerCase()).toBe(validator);
  });
});
