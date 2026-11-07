import {
  ChangeKind,
  FirewallError,
  ORDER_SIDE,
  type SignedOrder,
  decodeFirewallError,
  encodeChange,
  firewallErrorsAbi,
} from "@session-firewall/sdk";
import { IDBFactory } from "fake-indexeddb";
import { type Abi, type Address, type Hex, encodeErrorResult } from "viem";
import { describe, expect, it } from "vitest";
// @ts-expect-error plain ESM helper without declarations
import { scanText } from "../../scripts/origins.mjs";
import {
  ATTACKER,
  fundsUnchanged,
  initialAttempts,
} from "../../src/attack/compromised";
import { describeChange } from "../../src/lib/changes";
import {
  ConfigError,
  parseRuntimeConfig,
  serializeRuntimeConfig,
} from "../../src/lib/config";
import { explainError, sentenceFor } from "../../src/lib/errors";
import {
  formatEta,
  formatRemaining,
  formatShares,
  formatUsd,
  parseAmount,
} from "../../src/lib/format";
import { validateOnboarding } from "../../src/lib/onboard";
import {
  buildBook,
  fillCost,
  orderHash,
  pickLevel,
  worstCaseLoss,
} from "../../src/lib/orderbook";
import { stubAuthFor } from "../../src/lib/passkey";
import {
  loadSettings,
  saveSettings,
  validateSettings,
} from "../../src/lib/settings";
import { sessionStatus } from "../../src/lib/snapshot";
import {
  type StoredSession,
  deleteSession,
  listSessions,
  putSession,
} from "../../src/lib/store";

const A = "0x00000000000000000000000000000000000000aa" as Address;
const B = "0x00000000000000000000000000000000000000bb" as Address;
const C = "0x00000000000000000000000000000000000000cc" as Address;

const encode = (errorName: string, args: readonly unknown[] = []) =>
  encodeErrorResult({ abi: firewallErrorsAbi as Abi, errorName, args });
const decoded = (data: Hex) => {
  const d = decodeFirewallError(data);
  if (!d) throw new Error("undecodable");
  return d;
};

describe("format", () => {
  it("formats and parses money", () => {
    expect(formatUsd(1_234_560_000n)).toBe("$1,234.56");
    expect(formatUsd(0n)).toBe("$0.00");
    expect(formatShares(100_500_000n)).toBe("100.5");
    expect(parseAmount("1,000")).toBe(1_000_000_000n);
    expect(parseAmount("$25.5")).toBe(25_500_000n);
    for (const bad of ["", "0", "abc", "-1", "1.1234567"])
      expect(parseAmount(bad)).toBeUndefined();
  });
  it("formats time left", () => {
    expect(formatEta(100n, 100n)).toBe("ready now");
    expect(formatEta(86_400n, 0n)).toBe("in 24 h 0 min");
    expect(formatRemaining(7n * 86_400n, 0n)).toBe("7 days left");
    expect(formatRemaining(0n, 1n)).toBe("expired");
  });
});

describe("firewall errors in plain sentences", () => {
  const known = { usdc: A, market: B, shares: C };
  it("names what the user knows", () => {
    expect(
      sentenceFor(decoded(encode("UnexplainedOutflow", [A, 0n])), known),
    ).toMatch(/send USDC/);
    expect(
      sentenceFor(decoded(encode("UnexplainedOutflow", [B, 0n])), known),
    ).toMatch(/market trade/);
    expect(
      sentenceFor(decoded(encode("UnregisteredSpender", [C])), known),
    ).toMatch(/registered market/);
    expect(sentenceFor(decoded(encode("ForbiddenExecution")), known)).toMatch(
      /may not call itself/,
    );
  });
  it("gives every firewall error a sentence without jargon or raw names", () => {
    const errors = (firewallErrorsAbi as Abi).filter((x) => x.type === "error");
    expect(errors.length).toBeGreaterThan(5);
    for (const e of errors) {
      if (e.type !== "error") continue;
      const args = e.inputs.map((i) =>
        i.type === "address"
          ? A
          : i.type === "bytes32"
            ? `0x${"0".repeat(64)}`
            : i.type === "bytes4"
              ? "0x12345678"
              : 1n,
      );
      const text = sentenceFor(decoded(encode(e.name, args)), known);
      expect(text, e.name).not.toMatch(/^Reverted with/);
    }
  });
  it("marks firewall refusals and keeps hashes", () => {
    const hash = `0x${"1".repeat(64)}` as Hex;
    const e = new FirewallError(decoded(encode("BudgetExceeded", [5n, 1n])), {
      userOpHash: hash,
    });
    const p = explainError(e, known);
    expect(p.blockedByFirewall).toBe(true);
    expect(p.userOpHash).toBe(hash);
  });
  it("explains browser and network failures", () => {
    const dom = Object.assign(new Error("x"), { name: "NotAllowedError" });
    expect(explainError(dom).message).toMatch(/passkey prompt/);
    expect(explainError(dom).blockedByFirewall).toBe(false);
    expect(explainError(new Error("Failed to fetch")).message).toMatch(
      /Network screen/,
    );
  });
});

describe("order book", () => {
  const order = (
    side: 0 | 1,
    price: bigint,
    amount: bigint,
    tokenId = 1n,
    expiry = 100n,
  ): SignedOrder => ({
    order: { maker: A, tokenId, side, price, amount, expiry, salt: price },
    signature: "0x",
  });
  const orders = [
    order(ORDER_SIDE.Sell, 520_000n, 100n),
    order(ORDER_SIDE.Sell, 500_000n, 100n),
    order(ORDER_SIDE.Buy, 450_000n, 100n),
    order(ORDER_SIDE.Buy, 480_000n, 100n),
    order(ORDER_SIDE.Sell, 400_000n, 100n, 2n), // other token
    order(ORDER_SIDE.Sell, 300_000n, 100n, 1n, 1n), // expired
  ];
  const hashes = new Map(
    orders.map((o) => [o, orderHash(o, B, 31337)] as const),
  );
  it("sorts best first, drops expired and filled", () => {
    const filled = new Map([[hashes.get(orders[1]) as Hex, 100n]]);
    const book = buildBook(orders, 1n, filled, hashes, 50n);
    expect(book.asks.map((l) => l.price)).toEqual([520_000n]);
    expect(book.bids.map((l) => l.price)).toEqual([480_000n, 450_000n]);
    expect(pickLevel(book, "sell", 100n)?.price).toBe(480_000n);
    expect(pickLevel(book, "buy", 101n)).toBeUndefined();
  });
  it("rounds like the market and values shares at $1", () => {
    expect(fillCost({ price: 333_333n }, 1n, "buy")).toBe(1n);
    expect(fillCost({ price: 333_333n }, 1n, "sell")).toBe(0n);
    expect(worstCaseLoss({ price: 900_000n }, 1_000_000n, "sell")).toBe(
      100_000n,
    );
    expect(worstCaseLoss({ price: 500_000n }, 1_000_000n, "buy")).toBe(
      500_000n,
    );
  });
});

describe("runtime config", () => {
  const raw = {
    network: {
      chainId: 11155111,
      name: "Sepolia",
      rpcUrl: "https://rpc.example",
    },
    deployment: null,
  };
  it("parses a network without a deployment", () => {
    const c = parseRuntimeConfig(raw);
    expect(c.network.chainId).toBe(11155111);
    expect(c.deployment).toBeNull();
    expect(c.local).toBeUndefined();
  });
  it("rejects bad input with a readable error", () => {
    expect(() =>
      parseRuntimeConfig({
        ...raw,
        network: { ...raw.network, rpcUrl: "javascript:x" },
      }),
    ).toThrow(ConfigError);
    expect(() =>
      parseRuntimeConfig({
        ...raw,
        deployment: { addresses: { module: "nope" } },
      }),
    ).toThrow(/deployment\./);
  });
  it("round trips bigints", () => {
    const text = serializeRuntimeConfig({
      network: raw.network,
      deployment: null,
      local: undefined,
      big: 5n,
    } as never);
    expect(JSON.parse(text).big).toBe("5");
  });
});

describe("network settings", () => {
  const config = parseRuntimeConfig({
    network: { chainId: 1, name: "x", rpcUrl: "https://default.example" },
    deployment: null,
  });
  const memory = () => {
    const m = new Map<string, string>();
    return {
      getItem: (k: string) => m.get(k) ?? null,
      setItem: (k: string, v: string) => void m.set(k, v),
      removeItem: (k: string) => void m.delete(k),
    };
  };
  it("persists, and ignores corrupt or unsafe values", () => {
    const kv = memory();
    expect(loadSettings(config, kv).rpcUrl).toBe("https://default.example");
    saveSettings(
      config,
      { rpcUrl: "https://mine.example", bundlerUrl: "", paymasterUrl: "" },
      kv,
    );
    expect(loadSettings(config, kv).rpcUrl).toBe("https://mine.example");
    kv.setItem(
      "session-firewall:network:1",
      '{"rpcUrl":"javascript:alert(1)"}',
    );
    expect(loadSettings(config, kv).rpcUrl).toBe("https://default.example");
    kv.setItem("session-firewall:network:1", "{not json");
    expect(loadSettings(config, kv).rpcUrl).toBe("https://default.example");
  });
  it("needs a bundler for a paymaster", () => {
    expect(
      validateSettings({
        rpcUrl: "https://a.example",
        bundlerUrl: "",
        paymasterUrl: "https://p.example",
      }),
    ).toHaveLength(1);
  });
});

describe("session keys in IndexedDB", () => {
  it("stores per account and deletes", async () => {
    const idb = new IDBFactory();
    const make = (id: string, account: Address, createdAt: number) =>
      ({
        permissionId: id,
        account,
        createdAt,
        chainId: 1,
        epoch: "0",
      }) as unknown as StoredSession;
    await putSession(make("0x01", A, 1), idb);
    await putSession(make("0x02", A, 2), idb);
    await putSession(make("0x03", B, 3), idb);
    expect((await listSessions(A, idb)).map((s) => s.permissionId)).toEqual([
      "0x02",
      "0x01",
    ]);
    await deleteSession("0x02" as Hex, idb);
    expect(await listSessions(A, idb)).toHaveLength(1);
  });
  it("derives status from chain facts", () => {
    const s = { validUntil: 100, epoch: "1" };
    const chain = { enabled: true, epoch: 1n, frozen: false, now: 50n };
    expect(sessionStatus(s, chain)).toBe("active");
    expect(sessionStatus(s, { ...chain, now: 100n })).toBe("expired");
    expect(sessionStatus(s, { ...chain, epoch: 2n })).toBe("ended");
    expect(sessionStatus(s, { ...chain, enabled: false })).toBe("ended");
    expect(sessionStatus(s, { ...chain, frozen: true })).toBe("paused");
  });
});

describe("misc UI logic", () => {
  it("describes queued changes", () => {
    const d = encodeChange({ kind: "raiseCap", hourlyCap: 2_000_000_000n });
    expect(describeChange(d.kind, d.data)).toBe(
      "Raise the hourly limit to $2,000.00",
    );
    expect(describeChange(ChangeKind.Unfreeze, "0x")).toMatch(/Resume trading/);
    expect(describeChange(99, "0x")).toMatch(/Unknown/);
  });
  it("validates onboarding in plain language", () => {
    expect(validateOnboarding("nope", 1n)).toMatch(/Safe/);
    expect(validateOnboarding(A, undefined)).toMatch(/per hour/);
    expect(validateOnboarding(A, 1n)).toBeUndefined();
  });
  it("builds a stub assertion with correct JSON offsets", () => {
    const s = stubAuthFor("https://app.example", "app.example");
    expect(
      s.clientDataJSON.slice(Number(s.typeIndex)).startsWith('"type":'),
    ).toBe(true);
    expect(
      s.clientDataJSON
        .slice(Number(s.challengeIndex))
        .startsWith('"challenge":'),
    ).toBe(true);
    expect(s.authenticatorData.length).toBe(2 + 37 * 2);
  });
  it("attack covers A1, A2, A5, A9 with a fresh attacker address", () => {
    expect(initialAttempts().map((a) => a.id)).toEqual([
      "A1",
      "A2",
      "A5",
      "A9",
      "A9-passkey",
    ]);
    expect(ATTACKER).toMatch(/^0x[0-9a-fA-F]{40}$/);
    const f = {
      accountUsdc: 1n,
      accountYes: 0n,
      accountNo: 0n,
      attackerUsdc: 0n,
      attackerYes: 0n,
      attackerNo: 0n,
    };
    expect(fundsUnchanged(f, { ...f })).toBe(true);
    expect(fundsUnchanged(f, { ...f, attackerUsdc: 1n })).toBe(false);
  });
});

describe("origin scan", () => {
  it("fails on loaded third-party assets even if allowlisted as text", () => {
    const html = '<script src="https://viem.sh/x.js"></script>';
    expect(
      scanText("index.html", html).some((p: { reason: string }) =>
        /loaded/.test(p.reason),
      ),
    ).toBe(true);
    expect(
      scanText("a.css", "@import url(https://fonts.example/x.css);").length,
    ).toBeGreaterThan(0);
  });
  it("fails on unknown origins and passes reviewed text", () => {
    expect(
      scanText("a.js", 'fetch("https://evil.example/collect")'),
    ).toHaveLength(1);
    expect(scanText("a.js", '"see https://viem.sh/docs"')).toHaveLength(0);
    expect(scanText("a.js", 'new URL("https://a")')).toHaveLength(0);
  });
});
