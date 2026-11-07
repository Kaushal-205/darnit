import { type Context, type Event, ponder } from "ponder:registry";
import {
  account,
  alert,
  blockedAttempt,
  budgetConsumption,
  change,
  emergencyUninstall,
} from "ponder:schema";
import { and, eq, gt } from "ponder";
import { type Address, decodeAbiParameters, decodeEventLog, isAddressEqual } from "viem";
import { EntryPointAbi } from "../abis/EntryPoint.ts";
import { changeKindName, decodeRevertReason } from "./lib/decode.ts";
import {
  type AlertDraft,
  HOUR,
  blockedAttemptAlert,
  budgetAlert,
  changeQueuedAlert,
  emergencyUninstallAlert,
  evaluateBudgetWindow,
  freezeAlert,
  sessionsRevokedAlert,
} from "./lib/rules.ts";

const lower = (a: string) => a.toLowerCase() as Address;

type AnyEvent = Event;

async function emitAlert(context: Context, event: AnyEvent, draft: AlertDraft) {
  await context.db
    .insert(alert)
    .values({
      id: `${event.id}:${draft.rule}`,
      rule: draft.rule,
      severity: draft.severity,
      account: lower(draft.account),
      facts: draft.facts,
      blockNumber: event.block.number,
      logIndex: "log" in event ? event.log.logIndex : 0,
      occurredAt: event.block.timestamp,
      expiresAt: draft.expiresAt,
      txHash: "transaction" in event ? event.transaction.hash : "0x",
    })
    .onConflictDoNothing();
}

async function firewallAccount(context: Context, address: Address) {
  const row = await context.db.find(account, { address: lower(address) });
  return row?.installed ? row : null;
}

// ------------------------------------------------------------------ FirewallModule

ponder.on("FirewallModule:Installed", async ({ event, context }) => {
  await context.db
    .insert(account)
    .values({
      address: lower(event.args.account),
      installed: true,
      installedAt: event.block.timestamp,
      hourlyCap: event.args.hourlyCap,
      frozen: false,
      sessionEpoch: 0n,
      lastBudgetAlertAt: null,
    })
    .onConflictDoUpdate({ installed: true, installedAt: event.block.timestamp, hourlyCap: event.args.hourlyCap, frozen: false });
});

ponder.on("FirewallModule:Uninstalled", async ({ event, context }) => {
  if (!(await context.db.find(account, { address: lower(event.args.account) }))) return;
  await context.db.update(account, { address: lower(event.args.account) }).set({ installed: false });
});

ponder.on("FirewallModule:ChangeQueued", async ({ event, context }) => {
  const { account: acct, id, kind, data, eta } = event.args;
  await context.db
    .insert(change)
    .values({
      account: lower(acct),
      id,
      kind,
      data,
      eta,
      status: "queued",
      queuedAt: event.block.timestamp,
      queuedTx: event.transaction.hash,
    })
    .onConflictDoNothing();
  await emitAlert(context, event, changeQueuedAlert({ account: acct, id, kind, data, eta }));
});

ponder.on("FirewallModule:ChangeExecuted", async ({ event, context }) => {
  const key = { account: lower(event.args.account), id: event.args.id };
  const row = await context.db.find(change, key);
  if (!row) return;
  await context.db
    .update(change, key)
    .set({ status: "executed", resolvedAt: event.block.timestamp, resolvedTx: event.transaction.hash });
  const acct = await context.db.find(account, { address: key.account });
  if (!acct) return;
  const kind = changeKindName(row.kind);
  if (kind === "RaiseCap") {
    const [newCap] = decodeAbiParameters([{ type: "uint128" }], row.data);
    await context.db.update(account, { address: key.account }).set({ hourlyCap: newCap });
  } else if (kind === "Unfreeze") {
    await context.db.update(account, { address: key.account }).set({ frozen: false });
  }
});

ponder.on("FirewallModule:ChangeCancelled", async ({ event, context }) => {
  const key = { account: lower(event.args.account), id: event.args.id };
  if (!(await context.db.find(change, key))) return;
  await context.db
    .update(change, key)
    .set({ status: "cancelled", resolvedAt: event.block.timestamp, resolvedTx: event.transaction.hash });
});

ponder.on("FirewallModule:CapLowered", async ({ event, context }) => {
  const address = lower(event.args.account);
  if (!(await context.db.find(account, { address }))) return;
  await context.db.update(account, { address }).set({ hourlyCap: event.args.newCap });
});

ponder.on("FirewallModule:BudgetConsumed", async ({ event, context }) => {
  const address = lower(event.args.account);
  const now = event.block.timestamp;
  await context.db.insert(budgetConsumption).values({
    id: event.id,
    account: address,
    amount: event.args.amount,
    remaining: event.args.remaining,
    timestamp: now,
    txHash: event.transaction.hash,
  });
  const acct = await context.db.find(account, { address });
  if (!acct) return;
  const entries = await context.db.sql
    .select({ amount: budgetConsumption.amount, timestamp: budgetConsumption.timestamp })
    .from(budgetConsumption)
    .where(and(eq(budgetConsumption.account, address), gt(budgetConsumption.timestamp, now - HOUR)));
  const r = evaluateBudgetWindow({ entries, cap: acct.hourlyCap, now, lastAlertAt: acct.lastBudgetAlertAt ?? null });
  if (!r.fire) return;
  await context.db.update(account, { address }).set({ lastBudgetAlertAt: now });
  await emitAlert(context, event, budgetAlert({ account: address, used: r.used, cap: acct.hourlyCap, usedBps: r.usedBps, now }));
});

ponder.on("FirewallModule:FreezeActivated", async ({ event, context }) => {
  const address = lower(event.args.account);
  if (await context.db.find(account, { address })) {
    await context.db.update(account, { address }).set({ frozen: true, hourlyCap: 0n });
  }
  await emitAlert(context, event, freezeAlert({ account: address, now: event.block.timestamp }));
});

ponder.on("FirewallModule:SessionsRevoked", async ({ event, context }) => {
  const address = lower(event.args.account);
  if (await context.db.find(account, { address })) {
    await context.db.update(account, { address }).set({ sessionEpoch: event.args.epoch });
  }
  await emitAlert(
    context,
    event,
    sessionsRevokedAlert({ account: address, epoch: event.args.epoch, now: event.block.timestamp }),
  );
});

// ------------------------------------------------------------------ EntryPoint v0.7

ponder.on("EntryPoint:UserOperationRevertReason", async ({ event, context }) => {
  const { userOpHash, sender, nonce, revertReason } = event.args;
  if (!(await firewallAccount(context, sender))) return;
  const decoded = decodeRevertReason(revertReason);
  await context.db
    .insert(blockedAttempt)
    .values({
      id: event.id,
      account: lower(sender),
      userOpHash,
      nonce,
      errorName: decoded.name,
      errorArgs: decoded.args,
      rawReason: revertReason,
      timestamp: event.block.timestamp,
      txHash: event.transaction.hash,
    })
    .onConflictDoNothing();
  await emitAlert(
    context,
    event,
    blockedAttemptAlert({ account: sender, userOpHash, nonce, decoded, rawReason: revertReason, now: event.block.timestamp }),
  );
});

// ------------------------------------------------------------------ Safe7579

/**
 * The event comes from the Safe7579 singleton and names no account. Attribution:
 *  1. a direct call: `tx.to` is the Safe;
 *  2. a user operation: EntryPoint v0.7 emits `UserOperationEvent` right after each op executes, so
 *     the first UserOperationEvent after this log in the same transaction names the sender.
 * Only accounts that installed the firewall are kept.
 */
async function attributeEmergency(context: Context, event: Event<"Safe7579:EmergencyHookUninstallRequest">) {
  const to = event.transaction.to;
  if (to && (await firewallAccount(context, to))) return lower(to);
  const receipt = await context.client.getTransactionReceipt({ hash: event.transaction.hash });
  const entryPoint = context.contracts.EntryPoint.address as Address;
  for (const log of receipt.logs) {
    if (log.logIndex <= event.log.logIndex || !isAddressEqual(log.address, entryPoint)) continue;
    try {
      const d = decodeEventLog({ abi: EntryPointAbi, data: log.data, topics: log.topics });
      if (d.eventName !== "UserOperationEvent") continue;
      return (await firewallAccount(context, d.args.sender)) ? lower(d.args.sender) : null;
    } catch {
      // not an EntryPoint event
    }
  }
  return null;
}

ponder.on("Safe7579:EmergencyHookUninstallRequest", async ({ event, context }) => {
  const acct = await attributeEmergency(context, event);
  if (!acct) return;
  await context.db
    .insert(emergencyUninstall)
    .values({
      id: event.id,
      account: acct,
      hook: lower(event.args.hook),
      requestedAt: event.args.time,
      txHash: event.transaction.hash,
    })
    .onConflictDoNothing();
  await emitAlert(context, event, emergencyUninstallAlert({ account: acct, hook: event.args.hook, time: event.args.time }));
});
