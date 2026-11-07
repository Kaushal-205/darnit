import { encodeAbiParameters, getAddress } from "viem";
import { describe, expect, it } from "vitest";
import { decodeRevertReason } from "../../src/lib/decode.ts";
import {
  type AlertDraft,
  type AlertRecord,
  blockedAttemptAlert,
  budgetAlert,
  changeQueuedAlert,
  dedupeKey,
  emergencyUninstallAlert,
  evaluateBudgetWindow,
  freezeAlert,
  links,
  renderAlert,
  sessionsRevokedAlert,
} from "../../src/lib/rules.ts";

const ACCOUNT = "0x00000000000000000000000000000000000000aa";
const APP = "https://app.example/";
const ID = `0x${"12".repeat(32)}` as const;

function record(d: AlertDraft, extra: Partial<AlertRecord> = {}): AlertRecord {
  return {
    id: "evt:1",
    rule: d.rule,
    severity: d.severity,
    account: d.account,
    facts: d.facts,
    blockNumber: 10n,
    logIndex: 0,
    occurredAt: 1_000n,
    expiresAt: d.expiresAt,
    txHash: `0x${"cd".repeat(32)}`,
    ...extra,
  };
}

describe("rule 1: ChangeQueued", () => {
  const data = encodeAbiParameters(
    [{ type: "address" }],
    ["0x2222222222222222222222222222222222222222"],
  );
  const draft = changeQueuedAlert({
    account: ACCOUNT,
    id: ID,
    kind: 0,
    data,
    eta: 90_000n,
  });

  it("fires high severity, lives until eta, carries decoded data", () => {
    expect(draft.rule).toBe("change_queued");
    expect(draft.severity).toBe("high");
    expect(draft.expiresAt).toBe(90_000n);
    expect(draft.facts).toMatchObject({
      changeId: ID,
      kind: "AddDestination",
      eta: "90000",
    });
  });

  it("renders the cancel and freeze links", () => {
    const r = renderAlert(record(draft), APP);
    expect(r.links).toEqual([
      {
        label: "Cancel this change",
        url: `https://app.example/settings?account=${getAddress(ACCOUNT)}#cancel-${ID}`,
      },
      {
        label: "Freeze account",
        url: `https://app.example/settings?account=${getAddress(ACCOUNT)}#freeze`,
      },
    ]);
    expect(r.lines[0]).toContain("Add withdrawal destination 0x2222");
    expect(r.lines[1]).toContain("1970-01-02T01:00:00Z");
  });
});

describe("rule 2: budget > 80% in a rolling hour", () => {
  const cap = 1_000_000_000n; // 1000 USDC
  const now = 10_000n;

  it("does not fire at exactly 80%", () => {
    const r = evaluateBudgetWindow({
      entries: [{ amount: 800_000_000n, timestamp: now }],
      cap,
      now,
      lastAlertAt: null,
    });
    expect(r).toEqual({ fire: false, used: 800_000_000n, usedBps: 8_000n });
  });

  it("fires just above 80%, summing several entries", () => {
    const entries = [
      { amount: 400_000_000n, timestamp: now - 3_000n },
      { amount: 400_000_001n, timestamp: now },
    ];
    expect(
      evaluateBudgetWindow({ entries, cap, now, lastAlertAt: null }).fire,
    ).toBe(true);
  });

  it("ignores entries older than the window (boundary exclusive)", () => {
    const entries = [
      { amount: 500_000_000n, timestamp: now - 3_600n }, // exactly one hour ago: out
      { amount: 400_000_000n, timestamp: now - 3_599n },
    ];
    const r = evaluateBudgetWindow({ entries, cap, now, lastAlertAt: null });
    expect(r.used).toBe(400_000_000n);
    expect(r.fire).toBe(false);
  });

  it("ignores entries after now (replays)", () => {
    const r = evaluateBudgetWindow({
      entries: [{ amount: cap, timestamp: now + 1n }],
      cap,
      now,
      lastAlertAt: null,
    });
    expect(r.used).toBe(0n);
  });

  it("fires at most once per rolling hour", () => {
    const entries = [{ amount: 900_000_000n, timestamp: now }];
    expect(
      evaluateBudgetWindow({ entries, cap, now, lastAlertAt: now - 100n }).fire,
    ).toBe(false);
    expect(
      evaluateBudgetWindow({ entries, cap, now, lastAlertAt: now - 3_600n })
        .fire,
    ).toBe(true);
  });

  it("never fires for a zero cap (frozen account cannot consume)", () => {
    const r = evaluateBudgetWindow({
      entries: [{ amount: 1n, timestamp: now }],
      cap: 0n,
      now,
      lastAlertAt: null,
    });
    expect(r.fire).toBe(false);
  });

  it("honours custom threshold and window", () => {
    const entries = [{ amount: 500_000_000n, timestamp: now - 100n }];
    expect(
      evaluateBudgetWindow({
        entries,
        cap,
        now,
        lastAlertAt: null,
        thresholdBps: 4_000n,
      }).fire,
    ).toBe(true);
    expect(
      evaluateBudgetWindow({
        entries,
        cap,
        now,
        lastAlertAt: null,
        thresholdBps: 4_000n,
        windowSeconds: 50n,
      }).fire,
    ).toBe(false);
  });

  it("renders percentage and amounts", () => {
    const r = renderAlert(
      record(
        budgetAlert({
          account: ACCOUNT,
          used: 850_000_000n,
          cap,
          usedBps: 8_500n,
          now,
        }),
      ),
      APP,
    );
    expect(r.title).toContain("85%");
    expect(r.lines[0]).toContain("850 of the 1000 USDC");
    expect(r.links[0]?.url).toContain("#freeze");
  });
});

describe("rule 3: blocked attempt", () => {
  it("names the firewall error", () => {
    const decoded = decodeRevertReason("0x");
    const d = blockedAttemptAlert({
      account: ACCOUNT,
      userOpHash: ID,
      nonce: 3n,
      decoded,
      rawReason: "0x",
      now: 5n,
    });
    expect(d.severity).toBe("warning");
    expect(d.expiresAt).toBe(3_605n);
    const r = renderAlert(record(d), APP);
    expect(r.lines.join("\n")).toContain(ID);
  });

  it("shows the raw reason when unknown", () => {
    const decoded = decodeRevertReason("0xdeadbeef");
    const d = blockedAttemptAlert({
      account: ACCOUNT,
      userOpHash: ID,
      nonce: 3n,
      decoded,
      rawReason: "0xdeadbeef",
      now: 5n,
    });
    expect(renderAlert(record(d), APP).lines.join("\n")).toContain(
      "Raw reason: 0xdeadbeef",
    );
  });
});

describe("rule 4: EmergencyHookUninstallRequest", () => {
  it("is critical with an exit link and a 3-day lifetime", () => {
    const d = emergencyUninstallAlert({
      account: ACCOUNT,
      hook: "0x3333333333333333333333333333333333333333",
      time: 1_000n,
    });
    expect(d.severity).toBe("critical");
    expect(d.facts.removableAt).toBe("87400");
    expect(d.expiresAt).toBe(1_000n + 3n * 86_400n);
    const r = renderAlert(record(d), APP);
    expect(r.title).toMatch(/^CRITICAL/);
    expect(r.title).toContain("Exit now");
    expect(r.links).toEqual([
      { label: "Exit now", url: "https://app.example/exit" },
    ]);
  });
});

describe("rule 5: informational", () => {
  it("freeze and sessions revoked are info", () => {
    expect(freezeAlert({ account: ACCOUNT, now: 1n }).severity).toBe("info");
    const s = sessionsRevokedAlert({ account: ACCOUNT, epoch: 4n, now: 1n });
    expect(s.severity).toBe("info");
    expect(renderAlert(record(s), APP).lines[0]).toContain("epoch 4");
  });
});

describe("links and dedupe keys", () => {
  it("builds the documented paths", () => {
    const l = links("https://x.test///", ACCOUNT);
    expect(l.cancel("0x1")).toBe(
      `https://x.test/settings?account=${ACCOUNT}#cancel-0x1`,
    );
    expect(l.freeze).toBe(`https://x.test/settings?account=${ACCOUNT}#freeze`);
    expect(l.exit).toBe("https://x.test/exit");
  });

  it("dedupe key ignores the event id / block (reorg-stable)", () => {
    const d = changeQueuedAlert({
      account: ACCOUNT,
      id: ID,
      kind: 4,
      data: "0x",
      eta: 1n,
    });
    const a = record(d, { id: "a", blockNumber: 1n });
    const b = record(d, {
      id: "b",
      blockNumber: 2n,
      account: ACCOUNT.toUpperCase().replace("0X", "0x") as `0x${string}`,
    });
    expect(dedupeKey(a)).toBe(dedupeKey(b));
    expect(dedupeKey(a)).toBe(`change_queued:${ACCOUNT}:${ID}`);
  });
});
