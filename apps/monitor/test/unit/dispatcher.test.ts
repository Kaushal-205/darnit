import { describe, expect, it } from "vitest";
import {
  type AlertRecord,
  type RuleName,
  type Severity,
  renderAlert,
} from "../../src/lib/rules.ts";
import {
  type Channel,
  emailChannel,
  fakeChannel,
  telegramChannel,
} from "../../worker/channels.ts";
import {
  type AlertSource,
  createDispatcher,
  httpSource,
} from "../../worker/dispatcher.ts";
import { rateLimiter } from "../../worker/rateLimit.ts";
import { memoryStore } from "../../worker/store.ts";

const A = "0x00000000000000000000000000000000000000aa";
const B = "0x00000000000000000000000000000000000000bb";
const quiet = { info() {}, warn() {} };

let n = 0;
function alert(
  p: Partial<AlertRecord> & { rule?: RuleName; severity?: Severity } = {},
): AlertRecord {
  n++;
  return {
    id: `evt:${n}`,
    rule: "change_queued",
    severity: "high",
    account: A,
    facts: {
      changeId: `0x${n.toString(16).padStart(64, "0")}`,
      kind: "Unfreeze",
      summary: "Unfreeze",
      eta: "999999",
    },
    blockNumber: 100n,
    logIndex: n,
    occurredAt: 1_000n,
    expiresAt: 10_000n,
    txHash: `0x${n.toString(16).padStart(64, "0")}`,
    ...p,
  };
}

function arraySource(rows: AlertRecord[]) {
  const calls: bigint[] = [];
  const source: AlertSource = {
    async fetch(from) {
      calls.push(from);
      return rows.filter((r) => r.blockNumber >= from);
    },
  };
  return { source, calls, rows };
}

async function setup(opts: {
  rows: AlertRecord[];
  channel?: Channel;
  now?: number;
  limiterMax?: number;
}) {
  const store = memoryStore();
  await store.addSubscriptions(A, [{ type: "email", to: "a@example.com" }]);
  const fake = fakeChannel("email");
  const src = arraySource(opts.rows);
  const d = createDispatcher({
    store,
    source: src.source,
    channels: { email: opts.channel ?? fake.channel },
    appUrl: "https://app.example",
    now: () => opts.now ?? 2_000,
    limiter: rateLimiter({ max: opts.limiterMax ?? 10 }),
    log: quiet,
  });
  return { store, fake, src, d };
}

describe("dispatcher", () => {
  it("delivers to the account's subscribers only", async () => {
    const { fake, d } = await setup({ rows: [alert(), alert({ account: B })] });
    const s = await d.tick();
    expect(s.sent).toBe(1);
    expect(fake.deliveries).toHaveLength(1);
    expect(fake.deliveries[0]?.alert.links[0]?.url).toContain("#cancel-0x");
  });

  it("dedupes across polls and across reorg re-indexing (new event id, same fact)", async () => {
    const first = alert();
    const { fake, d, src } = await setup({ rows: [first] });
    await d.tick();
    await d.tick();
    src.rows.push({ ...first, id: "evt:reorged", blockNumber: 101n });
    const s = await d.tick();
    expect(s.duplicate).toBe(2); // the original (re-read from the slack) and the reorged copy
    expect(fake.deliveries).toHaveLength(1);
  });

  it("dedupes per contact: a second contact still gets the alert", async () => {
    const { fake, d, store } = await setup({ rows: [alert()] });
    await d.tick();
    await store.addSubscriptions(A, [{ type: "email", to: "b@example.com" }]);
    await d.tick();
    expect(
      fake.deliveries.map((x) =>
        x.contact.type === "email" ? x.contact.to : "",
      ),
    ).toEqual(["a@example.com", "b@example.com"]);
  });

  it("skips expired alerts (e.g. a change whose eta passed)", async () => {
    const { fake, d } = await setup({ rows: [alert({ expiresAt: 1_999n })] });
    const s = await d.tick();
    expect(s.expired).toBe(1);
    expect(fake.deliveries).toHaveLength(0);
  });

  it("re-reads a reorg slack behind the cursor", async () => {
    const { d, src } = await setup({ rows: [alert({ blockNumber: 500n })] });
    await d.tick();
    await d.tick();
    expect(src.calls).toEqual([0n, 484n]);
  });

  it("rate-limits warning/info per contact but never high/critical", async () => {
    const rows = [
      ...Array.from({ length: 4 }, () =>
        alert({ rule: "freeze", severity: "info", facts: {} }),
      ),
      ...Array.from({ length: 3 }, () => alert()),
      alert({
        rule: "emergency_uninstall",
        severity: "critical",
        facts: { hook: B, requestedAt: "1", removableAt: "2" },
      }),
    ];
    const { fake, d } = await setup({ rows, limiterMax: 2 });
    const s = await d.tick();
    expect(s.suppressed).toBe(2);
    expect(
      fake.deliveries.filter((x) => x.alert.severity === "info"),
    ).toHaveLength(2);
    expect(
      fake.deliveries.filter((x) => x.alert.severity === "high"),
    ).toHaveLength(3);
    expect(
      fake.deliveries.filter((x) => x.alert.severity === "critical"),
    ).toHaveLength(1);
    // The next delivered alert mentions the suppressed ones.
    expect(
      fake.deliveries.some((x) =>
        x.alert.lines.some((l) => l.includes("2 lower-priority")),
      ),
    ).toBe(true);
  });

  it("retries failed deliveries with backoff, then delivers once", async () => {
    const failing = fakeChannel("email", { failTimes: 2 });
    let now = 2_000;
    const store = memoryStore();
    await store.addSubscriptions(A, [{ type: "email", to: "a@example.com" }]);
    const d = createDispatcher({
      store,
      source: arraySource([alert()]).source,
      channels: { email: failing.channel },
      appUrl: "https://app.example",
      now: () => now,
      log: quiet,
    });
    expect((await d.tick()).sent).toBe(0);
    expect(d.pendingCount()).toBe(1);
    now += 1; // backoff 2s not elapsed
    expect((await d.tick()).sent).toBe(0);
    now += 2;
    await d.tick(); // second failure, backoff 4s
    now += 4;
    expect((await d.tick()).sent).toBe(1);
    now += 100;
    await d.tick();
    expect(failing.deliveries).toHaveLength(1);
    expect(d.pendingCount()).toBe(0);
  });

  it("keeps retrying a high alert until it expires, and holds the cursor behind it", async () => {
    const failing = fakeChannel("email", { failTimes: 1_000 });
    let now = 2_000;
    const store = memoryStore();
    await store.addSubscriptions(A, [{ type: "email", to: "a@example.com" }]);
    const d = createDispatcher({
      store,
      source: arraySource([
        alert({ blockNumber: 50n, expiresAt: 5_000n }),
        alert({
          blockNumber: 90n,
          rule: "freeze",
          severity: "info",
          facts: {},
          account: B,
        }),
      ]).source,
      channels: { email: failing.channel },
      appUrl: "https://app.example",
      now: () => now,
      maxAttempts: 2,
      log: quiet,
    });
    for (let i = 0; i < 11; i++) {
      await d.tick();
      now += 250;
    }
    expect(now).toBeLessThan(5_000);
    expect(d.pendingCount()).toBe(1); // well past maxAttempts
    expect(await store.getCursor()).toBe(50n); // not past the unsent alert at block 50
    now = 5_001;
    const s = await d.tick();
    expect(s.failed).toBe(1);
    expect(d.pendingCount()).toBe(0);
    expect(await store.getCursor()).toBe(90n);
  });

  it("drops contacts of a disabled channel once, without looping", async () => {
    const store = memoryStore();
    await store.addSubscriptions(A, [{ type: "telegram", chatId: "1" }]);
    const warnings: string[] = [];
    const d = createDispatcher({
      store,
      source: arraySource([alert()]).source,
      channels: {},
      appUrl: "https://app.example",
      now: () => 2_000,
      log: { info() {}, warn: (m) => void warnings.push(m) },
    });
    await d.tick();
    await d.tick();
    expect(warnings).toHaveLength(1);
    expect(d.pendingCount()).toBe(0);
  });

  it("gives up on a low-severity alert after maxAttempts", async () => {
    const failing = fakeChannel("email", { failTimes: 100 });
    let now = 2_000;
    const store = memoryStore();
    await store.addSubscriptions(A, [{ type: "email", to: "a@example.com" }]);
    const d = createDispatcher({
      store,
      source: arraySource([
        alert({ rule: "freeze", severity: "info", facts: {} }),
      ]).source,
      channels: { email: failing.channel },
      appUrl: "https://app.example",
      now: () => now,
      maxAttempts: 2,
      log: quiet,
    });
    await d.tick();
    now += 10;
    const s = await d.tick();
    expect(s.failed).toBe(1);
    expect(d.pendingCount()).toBe(0);
    now += 100;
    await d.tick();
    expect(d.pendingCount()).toBe(0);
    expect(failing.deliveries).toHaveLength(0);
  });
});

describe("httpSource", () => {
  it("reads every page", async () => {
    const urls: string[] = [];
    const row = {
      id: "x",
      rule: "freeze",
      severity: "info",
      account: A,
      facts: {},
      blockNumber: "1",
      logIndex: 0,
      occurredAt: "1",
      expiresAt: "2",
      txHash: "0x01",
    };
    const f = (async (url: string) => {
      urls.push(url);
      return new Response(
        JSON.stringify(urls.length === 1 ? Array(1_000).fill(row) : [row]),
      );
    }) as unknown as typeof fetch;
    const rows = await httpSource("http://indexer/", f).fetch(7n);
    expect(rows).toHaveLength(1_001);
    expect(rows[0]?.blockNumber).toBe(1n);
    expect(urls).toEqual([
      "http://indexer/alerts?fromBlock=7&limit=1000&offset=0",
      "http://indexer/alerts?fromBlock=7&limit=1000&offset=1000",
    ]);
  });
});

describe("email and telegram channels", () => {
  const rendered = renderAlert(alert(), "https://app.example");

  it("email goes through the provider interface", async () => {
    const sent: unknown[] = [];
    const ch = emailChannel({
      name: "test",
      send: async (m) => void sent.push(m),
    });
    await ch.send(A, { type: "email", to: "a@example.com" }, rendered);
    expect(sent[0]).toMatchObject({
      to: "a@example.com",
      subject: expect.stringContaining("[ACTION NEEDED] Change queued"),
    });
  });

  it("telegram posts sendMessage with the chat id", async () => {
    const calls: { url: string; body: string }[] = [];
    const ch = telegramChannel({
      botToken: "123:abc",
      fetch: (async (url: string, init: RequestInit) => {
        calls.push({ url, body: String(init.body) });
        return new Response('{"ok":true}');
      }) as unknown as typeof fetch,
    });
    await ch.send(A, { type: "telegram", chatId: "-100200" }, rendered);
    expect(calls[0]?.url).toBe(
      "https://api.telegram.org/bot123:abc/sendMessage",
    );
    const body = JSON.parse(calls[0]?.body ?? "{}");
    expect(body.chat_id).toBe("-100200");
    expect(body.text).toContain(
      "Cancel this change: https://app.example/settings?account=",
    );
  });
});
