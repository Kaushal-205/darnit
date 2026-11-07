import { type Call, erc20Abi, outcomeSharesAbi } from "@session-firewall/sdk";
import {
  type Address,
  encodeFunctionData,
  isAddressEqual,
  parseUnits,
} from "viem";
import type { AccountSnapshot, Asset } from "./reads.js";

/** Shares use 6 decimals (1e6 = one share), like USDC. */
export const SHARE_DECIMALS = 6;

export function assetKey(a: Asset): string {
  return a.kind === "token" ? `token:${a.token}` : `share:${a.token}:${a.id}`;
}

export function decimalsOf(a: Asset): number {
  return a.kind === "token" ? a.decimals : SHARE_DECIMALS;
}

/** Parse an amount typed by the user; "all" or empty means the whole balance. */
export function parseAmount(text: string, a: Asset): bigint {
  const t = text.trim().replaceAll(",", "");
  if (t === "" || t.toLowerCase() === "all") return a.balance;
  if (!/^\d*(\.\d*)?$/.test(t) || t === ".")
    throw new Error("Type an amount like 12.5, or leave it empty for all.");
  const v = parseUnits(t, decimalsOf(a));
  if (v === 0n) throw new Error("The amount must be more than zero.");
  if (v > a.balance) throw new Error("That is more than the account holds.");
  return v;
}

/** One transfer of one asset to the destination. The hook allows it (R5) and it never uses the budget. */
export function transferCall(
  account: Address,
  a: Asset,
  amount: bigint,
  destination: Address,
): Call {
  if (a.kind === "token")
    return {
      to: a.token,
      data: encodeFunctionData({
        abi: erc20Abi,
        functionName: "transfer",
        args: [destination, amount],
      }),
    };
  return {
    to: a.token,
    data: encodeFunctionData({
      abi: outcomeSharesAbi,
      functionName: "safeTransferFrom",
      args: [account, destination, a.id, amount, "0x"],
    }),
  };
}

export type ExitPlan = {
  calls: Call[];
  lines: { asset: Asset; amount: bigint }[];
};

/** Build the calls for one asset, or for everything with a balance when `asset` is "all". */
export function planExit(
  snap: AccountSnapshot,
  asset: Asset | "all",
  amount: bigint | undefined,
  destination: Address,
): ExitPlan {
  if (!snap.destinations.some((d) => isAddressEqual(d, destination)))
    throw new Error(
      "That address is not one of this account's trusted destinations. Funds can only go to a trusted destination.",
    );
  const lines =
    asset === "all"
      ? [...snap.tokens, ...snap.shares]
          .filter((a) => a.balance > 0n)
          .map((a) => ({ asset: a, amount: a.balance }))
      : [{ asset, amount: amount ?? asset.balance }];
  if (lines.length === 0 || lines.every((l) => l.amount === 0n))
    throw new Error("There is nothing to move.");
  return {
    lines,
    calls: lines.map((l) =>
      transferCall(snap.account, l.asset, l.amount, destination),
    ),
  };
}
