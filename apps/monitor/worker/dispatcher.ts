import type { Address, Hex } from "viem";
import {
  type AlertRecord,
  type RenderedAlert,
  type RuleName,
  type Severity,
  dedupeKey,
  renderAlert,
} from "../src/lib/rules.ts";
import {
  type Channel,
  type Contact,
  type ContactType,
  contactKey,
} from "./channels.ts";
import { type RateLimiter, rateLimiter } from "./rateLimit.ts";
import type { Store } from "./store.ts";

/** Where alerts come from: the indexer's `/alerts` endpoint in production, an array in tests. */
export type AlertSource = { fetch(fromBlock: bigint): Promise<AlertRecord[]> };

type AlertJson = {
  id: string;
  rule: RuleName;
  severity: Severity;
  account: Address;
  facts: Record<string, unknown>;
  blockNumber: string;
  logIndex: number;
  occurredAt: string;
  expiresAt: string;
  txHash: Hex;
};

export function parseAlertJson(r: AlertJson): AlertRecord {
  return {
    ...r,
    blockNumber: BigInt(r.blockNumber),
    occurredAt: BigInt(r.occurredAt),
    expiresAt: BigInt(r.expiresAt),
  };
}

const PAGE = 1_000;
const MAX_BACKOFF_SECONDS = 300;

export function httpSource(
  indexerUrl: string,
  f: typeof fetch = fetch,
): AlertSource {
  const base = indexerUrl.replace(/\/+$/, "");
  return {
    async fetch(fromBlock) {
      // Reads every page: a flood of low-severity rows must not hide a later critical one.
      const out: AlertRecord[] = [];
      for (;;) {
        const url = `${base}/alerts?fromBlock=${fromBlock}&limit=${PAGE}&offset=${out.length}`;
        const res = await f(url, { signal: AbortSignal.timeout(10_000) });
        if (!res.ok) throw new Error(`indexer /alerts: HTTP ${res.status}`);
        const rows = (await res.json()) as AlertJson[];
        out.push(...rows.map(parseAlertJson));
        if (rows.length < PAGE) return out;
      }
    },
  };
}

export type Logger = {
  info(msg: string, extra?: unknown): void;
  warn(msg: string, extra?: unknown): void;
};
const consoleLogger: Logger = {
  info: (m, e) =>
    console.log(
      JSON.stringify({ level: "info", msg: m, ...(e ? { extra: e } : {}) }),
    ),
  warn: (m, e) =>
    console.warn(
      JSON.stringify({
        level: "warn",
        msg: m,
        ...(e ? { extra: String(e) } : {}),
      }),
    ),
};

type Pending = {
  alert: RenderedAlert;
  account: string;
  contact: Contact;
  key: string;
  attempts: number;
  nextAt: number;
  blockNumber: bigint;
  expiresAt: bigint;
};

export type DispatchStats = {
  fetched: number;
  sent: number;
  expired: number;
  duplicate: number;
  suppressed: number;
  failed: number;
};

export function createDispatcher(p: {
  store: Store;
  source: AlertSource;
  channels: Partial<Record<ContactType, Channel>>;
  appUrl: string;
  limiter?: RateLimiter;
  /** Unix seconds. */
  now?: () => number;
  /** Blocks re-read behind the cursor on every poll, to pick up rows rewritten after a reorg. */
  reorgSlack?: bigint;
  /** Attempts for warning and info alerts. Critical and high alerts retry until they expire. */
  maxAttempts?: number;
  log?: Logger;
  onSent?: (alert: RenderedAlert, contact: Contact) => void;
}) {
  const now = p.now ?? (() => Math.floor(Date.now() / 1000));
  const limiter = p.limiter ?? rateLimiter();
  const slack = p.reorgSlack ?? 16n;
  const maxAttempts = p.maxAttempts ?? 5;
  const log = p.log ?? consoleLogger;
  const pending = new Map<string, Pending>();
  let timer: NodeJS.Timeout | null = null;
  let running = false;

  async function attempt(job: Pending, stats: DispatchStats) {
    const channel = p.channels[job.contact.type];
    if (!channel) {
      log.warn(
        `no ${job.contact.type} channel configured; dropping`,
        job.alert.id,
      );
      await p.store.markDelivered(job.key, now());
      pending.delete(job.key);
      return;
    }
    try {
      await channel.send(job.account, job.contact, job.alert);
      await p.store.markDelivered(job.key, now());
      pending.delete(job.key);
      stats.sent++;
      p.onSent?.(job.alert, job.contact);
    } catch (err) {
      job.attempts++;
      const urgent =
        job.alert.severity === "critical" || job.alert.severity === "high";
      const exhausted = urgent
        ? BigInt(now()) > job.expiresAt
        : job.attempts >= maxAttempts;
      if (exhausted) {
        // Terminal: recorded so the alert is not picked up again from the reorg slack.
        await p.store.markDelivered(job.key, now());
        pending.delete(job.key);
        stats.failed++;
        log.warn(
          `giving up on ${job.alert.id} via ${job.contact.type} after ${job.attempts} attempts`,
          err,
        );
      } else {
        job.nextAt = now() + Math.min(2 ** job.attempts, MAX_BACKOFF_SECONDS);
        pending.set(job.key, job);
        log.warn(
          `delivery of ${job.alert.id} via ${job.contact.type} failed; retrying`,
          err,
        );
      }
    }
  }

  async function tick(): Promise<DispatchStats> {
    const stats: DispatchStats = {
      fetched: 0,
      sent: 0,
      expired: 0,
      duplicate: 0,
      suppressed: 0,
      failed: 0,
    };
    const t = now();
    const jobs: Promise<void>[] = [];

    for (const job of pending.values())
      if (job.nextAt <= t) jobs.push(attempt(job, stats));

    const cursor = await p.store.getCursor();
    const from = cursor > slack ? cursor - slack : 0n;
    const alerts = await p.source.fetch(from);
    stats.fetched = alerts.length;
    let maxBlock = cursor;

    for (const a of alerts) {
      if (a.blockNumber > maxBlock) maxBlock = a.blockNumber;
      if (BigInt(t) > a.expiresAt) {
        stats.expired++;
        continue;
      }
      const contacts = await p.store.subscriptionsFor(a.account);
      if (contacts.length === 0) continue;
      const base = dedupeKey(a);
      for (const contact of contacts) {
        const key = `${base}|${contactKey(contact)}`;
        if (pending.has(key) || (await p.store.wasDelivered(key))) {
          stats.duplicate++;
          continue;
        }
        const limitKey = `${a.account.toLowerCase()}|${contactKey(contact)}`;
        if (!limiter.allow(limitKey, a.severity, t)) {
          stats.suppressed++;
          await p.store.markDelivered(key, t); // suppressed for good, not retried
          continue;
        }
        const rendered = renderAlert(a, p.appUrl);
        const skipped = limiter.takeSuppressed(limitKey);
        if (skipped > 0)
          rendered.lines.push(
            `(${skipped} lower-priority alert(s) for this account were rate-limited.)`,
          );
        const job: Pending = {
          alert: rendered,
          account: a.account,
          contact,
          key,
          attempts: 0,
          nextAt: t,
          blockNumber: a.blockNumber,
          expiresAt: a.expiresAt,
        };
        pending.set(key, job);
        jobs.push(attempt(job, stats));
      }
    }

    await Promise.all(jobs);
    // Unsent alerts live in memory, so the cursor stays behind them: a restart reads them again.
    for (const job of pending.values())
      if (job.blockNumber < maxBlock) maxBlock = job.blockNumber;
    if (maxBlock > cursor) await p.store.setCursor(maxBlock);
    return stats;
  }

  return {
    tick,
    pendingCount: () => pending.size,
    start(intervalMs: number) {
      const loop = async () => {
        if (running) return;
        running = true;
        try {
          const s = await tick();
          if (s.sent || s.failed || s.suppressed) log.info("dispatch", s);
        } catch (err) {
          log.warn("dispatch tick failed", err);
        } finally {
          running = false;
        }
      };
      timer = setInterval(loop, intervalMs);
      void loop();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
    },
  };
}
