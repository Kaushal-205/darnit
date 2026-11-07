/**
 * M8: the "compromised website" script.
 *
 * This code plays an attacker who took over the page. It deliberately uses only what any script injected
 * into this origin could reach: the session key in IndexedDB, the configured RPC/bundler and the browser's
 * passkey prompt. It does not use the app's safety checks. It tries real, signed user operations that go
 * to the real contracts. Only the onchain firewall stops them, and nothing here pretends otherwise: an
 * attempt counts as blocked only if the chain refused it.
 */
import {
  type FirewallAccount,
  MODULE_TYPE,
  ORDER_SIDE,
  type SignedOrder,
  type UserOpResult,
  encodeFill,
  executeAsOwner,
  executeAsSession,
  mockUsdcAbi,
  outcomeSharesAbi,
  safe7579Abi,
} from "@session-firewall/sdk";
import {
  type Address,
  type Hash,
  encodeFunctionData,
  getAddress,
  keccak256,
  maxUint256,
  slice,
  stringToHex,
} from "viem";
import { type KnownAddresses, explainError } from "../lib/errors";
import { listSessions } from "../lib/store";

/** A fixed address nobody registered, standing in for the attacker's wallet. */
export const ATTACKER: Address = getAddress(
  slice(keccak256(stringToHex("session-firewall demo attacker")), 12),
);

export type AttemptStatus = "pending" | "running" | "blocked" | "not-blocked" | "not-signed" | "error";

export type Attempt = {
  id: string;
  rule: string;
  title: string;
  signer: "session key" | "passkey";
  status: AttemptStatus;
  message?: string;
  code?: string;
  /** False when the chain refused it at the signature check, so no transaction exists. */
  mined?: boolean;
  userOpHash?: Hash;
  transactionHash?: Hash;
};

export type FundsSnapshot = {
  accountUsdc: bigint;
  accountYes: bigint;
  accountNo: bigint;
  attackerUsdc: bigint;
  attackerYes: bigint;
  attackerNo: bigint;
};

export type AttackContext = {
  account: FirewallAccount;
  market: {
    address: Address;
    usdc: Address;
    shares: Address;
    yesId: bigint;
    noId: bigint;
    orders: readonly SignedOrder[];
  };
};

export async function snapshotFunds(ctx: AttackContext): Promise<FundsSnapshot> {
  const { publicClient } = ctx.account.client;
  const { market } = ctx;
  const usdc = (who: Address) =>
    publicClient.readContract({
      address: market.usdc,
      abi: mockUsdcAbi,
      functionName: "balanceOf",
      args: [who],
    });
  const share = (who: Address, id: bigint) =>
    publicClient.readContract({
      address: market.shares,
      abi: outcomeSharesAbi,
      functionName: "balanceOf",
      args: [who, id],
    });
  const me = ctx.account.address;
  const [accountUsdc, accountYes, accountNo, attackerUsdc, attackerYes, attackerNo] = await Promise.all([
    usdc(me),
    share(me, market.yesId),
    share(me, market.noId),
    usdc(ATTACKER),
    share(ATTACKER, market.yesId),
    share(ATTACKER, market.noId),
  ]);
  return { accountUsdc, accountYes, accountNo, attackerUsdc, attackerYes, attackerNo };
}

/** True when every balance is identical: the attacker gained nothing and the account lost nothing. */
export function fundsUnchanged(a: FundsSnapshot, b: FundsSnapshot): boolean {
  return (
    a.accountUsdc === b.accountUsdc &&
    a.accountYes === b.accountYes &&
    a.accountNo === b.accountNo &&
    a.attackerUsdc === b.attackerUsdc &&
    a.attackerYes === b.attackerYes &&
    a.attackerNo === b.attackerNo
  );
}

export function initialAttempts(): Attempt[] {
  const base = { status: "pending" as const };
  return [
    {
      ...base,
      id: "A1",
      rule: "Outflow rule",
      title: "Send all your USDC to the attacker",
      signer: "session key",
    },
    {
      ...base,
      id: "A2",
      rule: "Approval rule",
      title: "Allow the attacker to spend all your USDC",
      signer: "session key",
    },
    {
      ...base,
      id: "A5",
      rule: "Outflow rule",
      title: "Buy on the market, but deliver the shares to the attacker",
      signer: "session key",
    },
    {
      ...base,
      id: "A9",
      rule: "No self-calls",
      title: "Install the attacker's module on your account",
      signer: "session key",
    },
    {
      ...base,
      id: "A9-passkey",
      rule: "No self-calls",
      title: "Trick you into signing the same install with your passkey",
      signer: "passkey",
    },
  ];
}

/**
 * Run every attack in order. `onUpdate` receives each attempt as it changes. Resolves with the final list.
 * Throws only if there is no session key to steal.
 */
export async function runCompromisedScript(
  ctx: AttackContext,
  onUpdate: (a: Attempt) => void,
): Promise<Attempt[]> {
  const { account, market } = ctx;
  // What an injected script does first: read the key straight out of IndexedDB.
  const stolen = (await listSessions(account.address))[0];
  if (!stolen) throw new Error("No session key on this device to steal. Start a trading session first.");
  const balance = await account.client.publicClient.readContract({
    address: market.usdc,
    abi: mockUsdcAbi,
    functionName: "balanceOf",
    args: [account.address],
  });
  const ask = market.orders.find((o) => o.order.side === ORDER_SIDE.Sell && o.order.tokenId === market.yesId);
  const install = encodeFunctionData({
    abi: safe7579Abi,
    functionName: "installModule",
    args: [MODULE_TYPE.executor, ATTACKER, "0x"],
  });
  const send: Record<string, () => Promise<UserOpResult>> = {
    A1: () =>
      executeAsSession(account, stolen, [
        {
          to: market.usdc,
          data: encodeFunctionData({
            abi: mockUsdcAbi,
            functionName: "transfer",
            args: [ATTACKER, balance],
          }),
        },
      ]),
    A2: () =>
      executeAsSession(account, stolen, [
        {
          to: market.usdc,
          data: encodeFunctionData({
            abi: mockUsdcAbi,
            functionName: "approve",
            args: [ATTACKER, maxUint256],
          }),
        },
      ]),
    A5: () => {
      if (!ask) throw new Error("The demo market has no maker order to abuse.");
      return executeAsSession(account, stolen, [
        { to: market.address, data: encodeFill(ask, 10_000_000n, ATTACKER) },
      ]);
    },
    A9: () => executeAsSession(account, stolen, [{ to: account.address, data: install }]),
    "A9-passkey": () => executeAsOwner(account, [{ to: account.address, data: install }]),
  };
  const known: KnownAddresses = {
    usdc: market.usdc,
    market: market.address,
    shares: market.shares,
    account: account.address,
  };

  const results: Attempt[] = [];
  for (const attempt of initialAttempts()) {
    onUpdate({ ...attempt, status: "running" });
    let done: Attempt;
    try {
      const r = await send[attempt.id]();
      done = {
        ...attempt,
        status: "not-blocked",
        message: "This attack was NOT blocked.",
        mined: true,
        userOpHash: r.userOpHash,
        transactionHash: r.transactionHash,
      };
    } catch (e) {
      const plain = explainError(e, known);
      const notSigned = /passkey prompt/i.test(plain.message);
      done = {
        ...attempt,
        status: plain.blockedByFirewall ? "blocked" : notSigned ? "not-signed" : "error",
        message: plain.message,
        code: plain.code,
        mined: !!plain.transactionHash,
        userOpHash: plain.userOpHash,
        transactionHash: plain.transactionHash,
      };
    }
    results.push(done);
    onUpdate(done);
  }
  return results;
}
