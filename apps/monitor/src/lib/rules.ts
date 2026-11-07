import { type Address, type Hex, formatUnits, getAddress } from "viem";
import { type DecodedRevert, decodeChange } from "./decode.ts";

export type Severity = "critical" | "high" | "warning" | "info";

export type RuleName =
  | "change_queued"
  | "budget_80"
  | "blocked_attempt"
  | "emergency_uninstall"
  | "freeze"
  | "sessions_revoked";

/** What an indexing function writes to the alert outbox. Facts are JSON-safe. */
export type AlertDraft = {
  rule: RuleName;
  severity: Severity;
  account: Address;
  facts: Record<string, unknown>;
  /** Unix seconds after which delivering the alert is pointless. */
  expiresAt: bigint;
};

export const HOUR = 3_600n;
export const DAY = 86_400n;

// -------------------------------------------------------------------- rule 1: any queued change

export function changeQueuedAlert(p: {
  account: Address;
  id: Hex;
  kind: number;
  data: Hex;
  eta: bigint;
}): AlertDraft {
  const decoded = decodeChange(p.kind, p.data);
  return {
    rule: "change_queued",
    severity: "high",
    account: p.account,
    facts: {
      changeId: p.id,
      kind: decoded.kind,
      summary: decoded.summary,
      fields: decoded.fields,
      eta: p.eta.toString(),
    },
    // Worth delivering for as long as the change can still be cancelled.
    expiresAt: p.eta,
  };
}

// -------------------------------------------------------------------- rule 2: budget > 80% in an hour

export type BudgetEntry = { amount: bigint; timestamp: bigint };

export type BudgetEvaluation = {
  fire: boolean;
  /** Sum of BudgetConsumed amounts in (now - window, now]. */
  used: bigint;
  /** used / cap in basis points (capped at 1_000_000 when cap is 0). */
  usedBps: bigint;
};

/**
 * Fires when the BudgetConsumed amounts inside the rolling window ending at `now` exceed
 * `thresholdBps` of the current hourly cap, at most once per window per account.
 */
export function evaluateBudgetWindow(p: {
  entries: BudgetEntry[];
  cap: bigint;
  now: bigint;
  lastAlertAt: bigint | null;
  windowSeconds?: bigint;
  thresholdBps?: bigint;
}): BudgetEvaluation {
  const window = p.windowSeconds ?? HOUR;
  const threshold = p.thresholdBps ?? 8_000n;
  const from = p.now - window;
  let used = 0n;
  for (const e of p.entries)
    if (e.timestamp > from && e.timestamp <= p.now) used += e.amount;
  const usedBps =
    p.cap === 0n ? (used > 0n ? 1_000_000n : 0n) : (used * 10_000n) / p.cap;
  // A frozen / zero-cap account cannot consume (consume reverts), so cap 0 never fires.
  const over = p.cap > 0n && used * 10_000n > threshold * p.cap;
  const cooledDown = p.lastAlertAt === null || p.now - p.lastAlertAt >= window;
  return { fire: over && cooledDown, used, usedBps };
}

export function budgetAlert(p: {
  account: Address;
  used: bigint;
  cap: bigint;
  usedBps: bigint;
  now: bigint;
}): AlertDraft {
  return {
    rule: "budget_80",
    severity: "warning",
    account: p.account,
    facts: {
      used: p.used.toString(),
      cap: p.cap.toString(),
      usedBps: p.usedBps.toString(),
    },
    expiresAt: p.now + HOUR,
  };
}

// -------------------------------------------------------------------- rule 3: blocked attempt

export function blockedAttemptAlert(p: {
  account: Address;
  userOpHash: Hex;
  nonce: bigint;
  decoded: DecodedRevert;
  rawReason: Hex;
  now: bigint;
}): AlertDraft {
  return {
    rule: "blocked_attempt",
    severity: "warning",
    account: p.account,
    facts: {
      userOpHash: p.userOpHash,
      nonce: p.nonce.toString(),
      errorKind: p.decoded.kind,
      errorName: p.decoded.name,
      errorArgs: p.decoded.args,
      description: p.decoded.description,
      rawReason: p.rawReason,
    },
    expiresAt: p.now + HOUR,
  };
}

// -------------------------------------------------------------------- rule 4: emergency hook uninstall

export const EMERGENCY_TIMELOCK = DAY;

export function emergencyUninstallAlert(p: {
  account: Address;
  hook: Address;
  time: bigint;
}): AlertDraft {
  return {
    rule: "emergency_uninstall",
    severity: "critical",
    account: p.account,
    facts: {
      hook: p.hook,
      requestedAt: p.time.toString(),
      // After 1 day anyone holding the signature can remove the hook; after 3 days the request resets.
      removableAt: (p.time + EMERGENCY_TIMELOCK).toString(),
    },
    expiresAt: p.time + 3n * EMERGENCY_TIMELOCK,
  };
}

// -------------------------------------------------------------------- rule 5: informational

export function freezeAlert(p: { account: Address; now: bigint }): AlertDraft {
  return {
    rule: "freeze",
    severity: "info",
    account: p.account,
    facts: {},
    expiresAt: p.now + HOUR,
  };
}

export function sessionsRevokedAlert(p: {
  account: Address;
  epoch: bigint;
  now: bigint;
}): AlertDraft {
  return {
    rule: "sessions_revoked",
    severity: "info",
    account: p.account,
    facts: { epoch: p.epoch.toString() },
    expiresAt: p.now + HOUR,
  };
}

// -------------------------------------------------------------------- rendering

export type AlertRecord = {
  id: string;
  rule: RuleName;
  severity: Severity;
  account: Address;
  facts: Record<string, unknown>;
  blockNumber: bigint;
  logIndex: number;
  occurredAt: bigint;
  expiresAt: bigint;
  txHash: Hex;
};

export type AlertLink = { label: string; url: string };

export type RenderedAlert = {
  id: string;
  rule: RuleName;
  severity: Severity;
  account: Address;
  title: string;
  lines: string[];
  links: AlertLink[];
  occurredAt: number;
  txHash: Hex;
  facts: Record<string, unknown>;
};

export function links(appUrl: string, account: Address) {
  const base = appUrl.replace(/\/+$/, "");
  const q = `account=${account}`;
  return {
    cancel: (id: string) => `${base}/settings?${q}#cancel-${id}`,
    freeze: `${base}/settings?${q}#freeze`,
    settings: `${base}/settings?${q}`,
    exit: `${base}/exit`,
  };
}

function iso(unix: unknown): string {
  const n = Number(unix);
  return Number.isFinite(n)
    ? new Date(n * 1000).toISOString().replace(".000Z", "Z")
    : String(unix);
}

function usdc(v: unknown): string {
  try {
    return formatUnits(BigInt(String(v)), 6);
  } catch {
    return String(v);
  }
}

export function renderAlert(
  record: AlertRecord,
  appUrl: string,
): RenderedAlert {
  // The indexer stores lowercase addresses; show checksummed ones.
  const a = { ...record, account: getAddress(record.account) };
  const l = links(appUrl, a.account);
  const f = a.facts;
  let title: string;
  let lines: string[];
  let ls: AlertLink[];
  switch (a.rule) {
    case "change_queued":
      title = `Change queued on ${a.account}: ${String(f.kind)}`;
      lines = [
        String(f.summary),
        `It takes effect after ${iso(f.eta)}. If you did not queue this, cancel it now and freeze the account.`,
        `Change id: ${String(f.changeId)}`,
      ];
      ls = [
        { label: "Cancel this change", url: l.cancel(String(f.changeId)) },
        { label: "Freeze account", url: l.freeze },
      ];
      break;
    case "budget_80":
      title = `Risk budget ${(Number(f.usedBps) / 100).toFixed(0)}% used in the last hour on ${a.account}`;
      lines = [
        `${usdc(f.used)} of the ${usdc(f.cap)} USDC hourly cap was charged in the last 60 minutes.`,
        "If this trading is not yours, freeze the account: it stops all sessions immediately.",
      ];
      ls = [
        { label: "Freeze account", url: l.freeze },
        { label: "Review settings", url: l.settings },
      ];
      break;
    case "blocked_attempt":
      title = `Blocked attempt on ${a.account}${f.errorName ? `: ${String(f.errorName)}` : ""}`;
      lines = [
        String(f.description),
        `User operation ${String(f.userOpHash)} (nonce ${String(f.nonce)}).`,
        ...(f.errorKind === "unknown"
          ? [`Raw reason: ${String(f.rawReason)}`]
          : []),
        "If a session key did this, it may be compromised. Freezing revokes every session.",
      ];
      ls = [{ label: "Freeze account", url: l.freeze }];
      break;
    case "emergency_uninstall":
      title = `CRITICAL: firewall removal requested on ${a.account}. Exit now.`;
      lines = [
        `An emergency uninstall of the firewall hook ${String(f.hook)} was requested at ${iso(f.requestedAt)}.`,
        `It can be completed from ${iso(f.removableAt)} and cannot be cancelled.`,
        "Move your funds to a registered destination now using the exit page.",
      ];
      ls = [{ label: "Exit now", url: l.exit }];
      break;
    case "freeze":
      title = `Account ${a.account} frozen`;
      lines = [
        "The firewall froze the account: the cap is 0 and every session is revoked. Unfreezing takes 24 hours.",
      ];
      ls = [{ label: "Settings", url: l.settings }];
      break;
    case "sessions_revoked":
      title = `Sessions revoked on ${a.account}`;
      lines = [`All session keys were revoked (epoch ${String(f.epoch)}).`];
      ls = [{ label: "Settings", url: l.settings }];
      break;
  }
  return {
    id: a.id,
    rule: a.rule,
    severity: a.severity,
    account: a.account,
    title,
    lines,
    links: ls,
    occurredAt: Number(a.occurredAt),
    txHash: a.txHash,
    facts: a.facts,
  };
}

/**
 * Semantic dedupe key: the same on-chain fact gives the same key even if a reorg re-includes the
 * transaction in another block (which changes the Ponder event id and so the alert id).
 */
export function dedupeKey(
  a: Pick<AlertRecord, "rule" | "account" | "facts" | "txHash">,
): string {
  const f = a.facts;
  const acct = a.account.toLowerCase();
  switch (a.rule) {
    case "change_queued":
      return `change_queued:${acct}:${String(f.changeId)}`;
    case "blocked_attempt":
      return `blocked_attempt:${acct}:${String(f.userOpHash)}`;
    case "emergency_uninstall":
      return `emergency_uninstall:${acct}:${String(f.hook).toLowerCase()}:${String(f.requestedAt)}`;
    case "sessions_revoked":
      return `sessions_revoked:${acct}:${String(f.epoch)}`;
    default:
      return `${a.rule}:${acct}:${a.txHash}`;
  }
}

export function alertText(r: RenderedAlert): string {
  return [
    r.title,
    "",
    ...r.lines,
    "",
    ...r.links.map((x) => `${x.label}: ${x.url}`),
    "",
    `Tx: ${r.txHash}`,
  ].join("\n");
}
