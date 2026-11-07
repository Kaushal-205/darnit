import {
  type Address,
  type Hex,
  decodeEventLog,
  encodeErrorResult,
  encodeFunctionData,
  isAddressEqual,
} from "viem";
import { erc20Abi } from "./abi/external.js";
import { firewallErrorsAbi, firewallModuleAbi } from "./abi/index.js";
import { type FirewallAccount, executeAsOwner } from "./account.js";
import { type Change, encodeChange } from "./encoding.js";
import { FirewallError, decodeFirewallError } from "./errors.js";
import type { UserOpResult } from "./userop.js";

const moduleCall = (account: FirewallAccount, data: Hex) =>
  executeAsOwner(account, [{ to: account.client.addresses.module, data }]);

/** Queue a loosening change (R6). It can be executed after the 24-hour delay and cancelled any time before. */
export async function queueChange(
  account: FirewallAccount,
  change: Change,
): Promise<{ id: Hex; eta: bigint; result: UserOpResult }> {
  const { kind, data } = encodeChange(change);
  const result = await moduleCall(
    account,
    encodeFunctionData({
      abi: firewallModuleAbi,
      functionName: "queue",
      args: [kind, data],
    }),
  );
  for (const log of result.logs) {
    if (!isAddressEqual(log.address, account.client.addresses.module)) continue;
    try {
      const ev = decodeEventLog({
        abi: firewallModuleAbi,
        data: log.data,
        topics: log.topics,
      });
      if (ev.eventName === "ChangeQueued")
        return { id: ev.args.id, eta: BigInt(ev.args.eta), result };
    } catch {
      // other module events
    }
  }
  throw new Error("queueChange: ChangeQueued event not found");
}

/** Cancel a queued change (instant). */
export function cancelChange(
  account: FirewallAccount,
  id: Hex,
): Promise<UserOpResult> {
  return moduleCall(
    account,
    encodeFunctionData({
      abi: firewallModuleAbi,
      functionName: "cancel",
      args: [id],
    }),
  );
}

/** Execute a matured change. Sent alone, as the hook requires (D7). Reverts TooEarly before the eta. */
export function executeChange(
  account: FirewallAccount,
  id: Hex,
): Promise<UserOpResult> {
  return moduleCall(
    account,
    encodeFunctionData({
      abi: firewallModuleAbi,
      functionName: "execute",
      args: [id],
    }),
  );
}

/** Kill switch (R8): revoke every session and drop the budget to zero, instantly. Exits keep working. */
export function freeze(account: FirewallAccount): Promise<UserOpResult> {
  return moduleCall(
    account,
    encodeFunctionData({ abi: firewallModuleAbi, functionName: "freeze" }),
  );
}

/** Revoke all sessions (instant) without freezing. */
export function revokeSessions(
  account: FirewallAccount,
): Promise<UserOpResult> {
  return moduleCall(
    account,
    encodeFunctionData({
      abi: firewallModuleAbi,
      functionName: "revokeSessions",
    }),
  );
}

/** Remove one session (instant). */
export function removeSession(
  account: FirewallAccount,
  permissionId: Hex,
): Promise<UserOpResult> {
  return moduleCall(
    account,
    encodeFunctionData({
      abi: firewallModuleAbi,
      functionName: "removeSession",
      args: [permissionId],
    }),
  );
}

/** Lower the hourly cap (instant). */
export function lowerCap(
  account: FirewallAccount,
  hourlyCap: bigint,
): Promise<UserOpResult> {
  return moduleCall(
    account,
    encodeFunctionData({
      abi: firewallModuleAbi,
      functionName: "lowerCap",
      args: [hourlyCap],
    }),
  );
}

/** Approve a registered market to pull a tracked token (R2 allows only registered markets). */
export function approveMarket(
  account: FirewallAccount,
  p: { token: Address; market: Address; amount: bigint },
): Promise<UserOpResult> {
  return executeAsOwner(account, [
    {
      to: p.token,
      data: encodeFunctionData({
        abi: erc20Abi,
        functionName: "approve",
        args: [p.market, p.amount],
      }),
    },
  ]);
}

/**
 * Exit (R5): send a tracked token to a registered destination. Never blocked by the budget or a freeze.
 * Checks the destination first so the user gets a clear error instead of a revert.
 */
export async function exit(
  account: FirewallAccount,
  p: { token: Address; amount: bigint; destination: Address },
): Promise<UserOpResult> {
  const ok = await account.client.publicClient.readContract({
    address: account.client.addresses.module,
    abi: firewallModuleAbi,
    functionName: "isDestination",
    args: [account.address, p.destination],
  });
  if (!ok) {
    // the same refusal the hook would give, without spending gas on it
    throw new FirewallError(
      decodeFirewallError(encodeErrorUnexplainedOutflow(p.token)),
    );
  }
  return executeAsOwner(account, [
    {
      to: p.token,
      data: encodeFunctionData({
        abi: erc20Abi,
        functionName: "transfer",
        args: [p.destination, p.amount],
      }),
    },
  ]);
}

function encodeErrorUnexplainedOutflow(token: Address): Hex {
  return encodeErrorResult({
    abi: firewallErrorsAbi,
    errorName: "UnexplainedOutflow",
    args: [token, 0n],
  });
}

/** Read the account's firewall config, lists and remaining budget. */
export async function getFirewallState(account: FirewallAccount) {
  const { publicClient, addresses } = account.client;
  const [view, availableBudget, sessionEpoch] = await Promise.all([
    publicClient.readContract({
      address: addresses.module,
      abi: firewallModuleAbi,
      functionName: "accountView",
      args: [account.address],
    }),
    publicClient.readContract({
      address: addresses.module,
      abi: firewallModuleAbi,
      functionName: "availableBudget",
      args: [account.address],
    }),
    publicClient.readContract({
      address: addresses.module,
      abi: firewallModuleAbi,
      functionName: "sessionEpoch",
      args: [account.address],
    }),
  ]);
  return { ...view, availableBudget, sessionEpoch };
}
