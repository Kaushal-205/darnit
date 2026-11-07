import {
  type FirewallAccount,
  getFirewallState,
  mockUsdcAbi,
  outcomeSharesAbi,
  referenceMarketAbi,
  smartSessionsAbi,
} from "@session-firewall/sdk";
import type { Hex } from "viem";
import { type PendingChange, listPendingChanges } from "./changes";
import type { Deployment, RuntimeConfig } from "./config";
import { type Book, buildBook, orderHash } from "./orderbook";
import { type StoredSession, listSessions } from "./store";

export type SessionStatus = "active" | "expired" | "ended" | "paused";

export type SessionView = StoredSession & { status: SessionStatus };

/** Status of a saved session from chain facts. Revoke-all bumps the epoch; a pause also ends sessions. */
export function sessionStatus(
  s: Pick<StoredSession, "validUntil" | "epoch">,
  chain: { enabled: boolean; epoch: bigint; frozen: boolean; now: bigint },
): SessionStatus {
  if (!chain.enabled || BigInt(s.epoch) !== chain.epoch)
    return chain.frozen ? "paused" : "ended";
  if (chain.frozen) return "paused";
  return BigInt(s.validUntil) <= chain.now ? "expired" : "active";
}

export type Snapshot = {
  now: bigint;
  eth: bigint;
  usdc: bigint;
  yes: bigint;
  no: bigint;
  marketAllowance: bigint;
  hourlyCap: bigint;
  budgetLeft: bigint;
  frozen: boolean;
  epoch: bigint;
  destinations: readonly `0x${string}`[];
  markets: readonly `0x${string}`[];
  tokens: readonly `0x${string}`[];
  pending: PendingChange[];
  sessions: SessionView[];
  yesBook: Book;
  noBook: Book;
};

export async function loadSnapshot(
  config: RuntimeConfig,
  deployment: Deployment,
  account: FirewallAccount,
): Promise<Snapshot> {
  const { publicClient, addresses } = account.client;
  const { market } = deployment;
  const me = account.address;
  const share = (id: bigint) =>
    publicClient.readContract({
      address: market.shares,
      abi: outcomeSharesAbi,
      functionName: "balanceOf",
      args: [me, id],
    });
  const hashes = new Map(
    market.orders.map(
      (o) => [o, orderHash(o, market.address, config.network.chainId)] as const,
    ),
  );
  const [
    block,
    eth,
    usdc,
    yes,
    no,
    marketAllowance,
    state,
    pending,
    saved,
    filledList,
  ] = await Promise.all([
    publicClient.getBlock(),
    publicClient.getBalance({ address: me }),
    publicClient.readContract({
      address: market.usdc,
      abi: mockUsdcAbi,
      functionName: "balanceOf",
      args: [me],
    }),
    share(market.yesId),
    share(market.noId),
    publicClient.readContract({
      address: market.usdc,
      abi: mockUsdcAbi,
      functionName: "allowance",
      args: [me, market.address],
    }),
    getFirewallState(account),
    listPendingChanges(account.client, me, deployment.fromBlock),
    listSessions(me),
    Promise.all(
      [...hashes.values()].map(async (h) => {
        const filled = await publicClient.readContract({
          address: market.address,
          abi: referenceMarketAbi,
          functionName: "filled",
          args: [h],
        });
        return [h, filled] as [Hex, bigint];
      }),
    ),
  ]);
  const enabled = await Promise.all(
    saved.map((s) =>
      publicClient.readContract({
        address: addresses.smartSessions,
        abi: smartSessionsAbi,
        functionName: "isPermissionEnabled",
        args: [s.permissionId, me],
      }),
    ),
  );
  const now = block.timestamp;
  const frozen = state.config.frozen;
  const epoch = BigInt(state.sessionEpoch);
  const filled = new Map(filledList);
  return {
    now,
    eth,
    usdc,
    yes,
    no,
    marketAllowance,
    hourlyCap: BigInt(state.config.hourlyCap),
    budgetLeft: state.availableBudget,
    frozen,
    epoch,
    destinations: state.destinations,
    markets: state.markets,
    tokens: state.tokens,
    pending,
    sessions: saved.map((s, i) => ({
      ...s,
      status: sessionStatus(s, { enabled: enabled[i], epoch, frozen, now }),
    })),
    yesBook: buildBook(market.orders, market.yesId, filled, hashes, now),
    noBook: buildBook(market.orders, market.noId, filled, hashes, now),
  };
}
