import { index, onchainEnum, onchainTable, primaryKey } from "ponder";

// Everything here is public chain data. Contact details (subscriptions) live in the worker's own
// tables (worker/pgStore.ts), never in the indexer.

export const changeStatus = onchainEnum("change_status", [
  "queued",
  "executed",
  "cancelled",
]);

/** One row per account that ever called FirewallModule.onInstall. */
export const account = onchainTable("account", (t) => ({
  address: t.hex().primaryKey(),
  installed: t.boolean().notNull(),
  installedAt: t.bigint().notNull(),
  /** Current hourly cap in USDC base units (6 decimals), tracked from Installed / CapLowered / RaiseCap. */
  hourlyCap: t.bigint().notNull(),
  frozen: t.boolean().notNull(),
  sessionEpoch: t.bigint().notNull(),
  /** Block timestamp of the last budget-80% alert, for the one-per-rolling-hour rule. */
  lastBudgetAlertAt: t.bigint(),
}));

export const change = onchainTable(
  "change",
  (t) => ({
    account: t.hex().notNull(),
    id: t.hex().notNull(),
    kind: t.integer().notNull(),
    data: t.hex().notNull(),
    eta: t.bigint().notNull(),
    status: changeStatus("status").notNull(),
    queuedAt: t.bigint().notNull(),
    queuedTx: t.hex().notNull(),
    resolvedAt: t.bigint(),
    resolvedTx: t.hex(),
  }),
  (table) => ({
    pk: primaryKey({ columns: [table.account, table.id] }),
    statusIdx: index().on(table.account, table.status),
  }),
);

/** BudgetConsumed log. `amount` is the worst-case outflow charged; `remaining` is the bucket after it. */
export const budgetConsumption = onchainTable(
  "budget_consumption",
  (t) => ({
    id: t.text().primaryKey(),
    account: t.hex().notNull(),
    amount: t.bigint().notNull(),
    remaining: t.bigint().notNull(),
    timestamp: t.bigint().notNull(),
    txHash: t.hex().notNull(),
  }),
  (table) => ({ windowIdx: index().on(table.account, table.timestamp) }),
);

/** DestinationRemoved, MarketRemoved, SessionCreated, SessionRemoved: history only, no alert rule. */
export const moduleEvent = onchainTable(
  "module_event",
  (t) => ({
    id: t.text().primaryKey(),
    account: t.hex().notNull(),
    name: t.text().notNull(),
    detail: t.json().$type<Record<string, string>>().notNull(),
    timestamp: t.bigint().notNull(),
    txHash: t.hex().notNull(),
  }),
  (table) => ({ accountIdx: index().on(table.account) }),
);

/** UserOperationRevertReason for a firewall account. */
export const blockedAttempt = onchainTable(
  "blocked_attempt",
  (t) => ({
    id: t.text().primaryKey(),
    account: t.hex().notNull(),
    userOpHash: t.hex().notNull(),
    nonce: t.bigint().notNull(),
    /** Decoded error name (firewall error, ExecutionFailed, Error, Panic) or null when unknown. */
    errorName: t.text(),
    errorArgs: t.json().$type<string[]>(),
    rawReason: t.hex().notNull(),
    timestamp: t.bigint().notNull(),
    txHash: t.hex().notNull(),
  }),
  (table) => ({ accountIdx: index().on(table.account) }),
);

/** Safe7579 EmergencyHookUninstallRequest attributed to a firewall account (docs/decisions.md V11). */
export const emergencyUninstall = onchainTable("emergency_uninstall", (t) => ({
  id: t.text().primaryKey(),
  account: t.hex().notNull(),
  hook: t.hex().notNull(),
  requestedAt: t.bigint().notNull(),
  txHash: t.hex().notNull(),
}));

/**
 * Alert outbox. Indexing functions decide *whether* an alert fires; the worker renders, routes,
 * dedupes and delivers. `facts` is JSON-safe (bigints as decimal strings).
 */
export const alert = onchainTable(
  "alert",
  (t) => ({
    id: t.text().primaryKey(),
    rule: t.text().notNull(),
    severity: t.text().notNull(),
    account: t.hex().notNull(),
    facts: t.json().$type<Record<string, unknown>>().notNull(),
    blockNumber: t.bigint().notNull(),
    logIndex: t.integer().notNull(),
    occurredAt: t.bigint().notNull(),
    expiresAt: t.bigint().notNull(),
    txHash: t.hex().notNull(),
  }),
  (table) => ({ blockIdx: index().on(table.blockNumber) }),
);
