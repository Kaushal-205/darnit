import { type DecodedFirewallError, FirewallError, decodeFirewallError } from "@session-firewall/sdk";
import { type Address, type Hash, isAddressEqual } from "viem";

/** Names for addresses the user knows, so messages can say "USDC" instead of 0x... */
export type KnownAddresses = {
  usdc?: Address;
  market?: Address;
  shares?: Address;
  account?: Address;
};

export type PlainError = {
  /** One plain sentence (or two) for a person who knows nothing about smart accounts. */
  message: string;
  /** Firewall error name when there is one ("UnexplainedOutflow", ...). */
  code?: string;
  /** True when the onchain firewall refused the action (as opposed to a network or prompt problem). */
  blockedByFirewall: boolean;
  /** True when the operation was refused at the signature check and never executed. */
  rejectedAtValidation: boolean;
  userOpHash?: Hash;
  transactionHash?: Hash;
};

const same = (a: unknown, b: Address | undefined) =>
  typeof a === "string" && b !== undefined && isAddressEqual(a as Address, b);

/** Rewrite the SDK's sentence with the names the user knows. Falls back to the SDK decoder's text. */
export function sentenceFor(d: DecodedFirewallError, known: KnownAddresses = {}): string {
  const a0 = d.args[0];
  switch (d.name) {
    case "UnexplainedOutflow":
      if (same(a0, known.market))
        return "Blocked: this market trade would send its proceeds to an address that is not your account or one of your withdrawal addresses.";
      if (same(a0, known.usdc))
        return "Blocked: this would send USDC to an address that is not one of your withdrawal addresses.";
      if (same(a0, known.shares))
        return "Blocked: this would send outcome shares to an address that is not one of your withdrawal addresses.";
      return d.message;
    case "UnregisteredSpender":
      return `Blocked: only the registered market may be allowed to spend from this account, and ${a0} is not it.`;
    case "ForbiddenExecution":
      return "Blocked: the account may not call itself, so nobody can install a module, add an owner or change settings this way. Changes like that wait 24 hours in the queue, where you can cancel them.";
    case "UnknownTarget":
      return `Blocked: ${a0} is not a token, market or withdrawal address registered on this account, so it cannot be called.`;
    case "FailedOp":
    case "FailedOpWithRevert": {
      const reason = String(d.args[1] ?? "");
      if (reason.startsWith("AA23") || reason.startsWith("AA24"))
        return "Refused before it ran: a trading session can only trade on the registered market. It cannot call the account itself, move funds out or change settings, and an expired or ended session cannot do anything.";
      return d.message;
    }
    default:
      return d.message;
  }
}

function webAuthnMessage(e: unknown): string | undefined {
  const name = (e as { name?: string })?.name;
  const text = String((e as { message?: string })?.message ?? "");
  if (name === "NotAllowedError" || /NotAllowedError|not allowed|timed out|cancel/i.test(text))
    return "The passkey prompt was cancelled or timed out. Nothing was signed.";
  if (name === "InvalidStateError")
    return "This device already has a passkey for this account. Use it, or pick another device.";
  if (name === "SecurityError")
    return "Passkeys need a secure page (https or localhost) on this site's own domain.";
  if (name === "NotSupportedError")
    return "This browser or device cannot create the kind of passkey we need (P-256).";
  return undefined;
}

/** Turn anything thrown by the SDK, viem or the browser into a plain sentence. */
export function explainError(e: unknown, known: KnownAddresses = {}): PlainError {
  if (e instanceof FirewallError) {
    const d = e.decoded;
    const rejectedAtValidation = d?.name === "FailedOp" || d?.name === "FailedOpWithRevert";
    return {
      message: d ? sentenceFor(d, known) : e.message,
      code: d?.name,
      blockedByFirewall: !!d && (d.isFirewallError || rejectedAtValidation),
      rejectedAtValidation,
      userOpHash: e.userOpHash,
      transactionHash: e.transactionHash,
    };
  }
  const wa = webAuthnMessage(e);
  if (wa) return { message: wa, blockedByFirewall: false, rejectedAtValidation: false };

  const decoded = decodeFirewallError(e);
  if (decoded && decoded.name !== "Error") {
    return {
      message: sentenceFor(decoded, known),
      code: decoded.name,
      blockedByFirewall: decoded.isFirewallError,
      rejectedAtValidation: decoded.name.startsWith("FailedOp"),
    };
  }
  const text = String((e as { shortMessage?: string; message?: string })?.shortMessage ?? (e as Error)?.message ?? e);
  if (/fetch failed|Failed to fetch|NetworkError|HTTP request failed|ECONNREFUSED/i.test(text))
    return {
      message: "Could not reach the network. Check the RPC and bundler addresses on the Network screen.",
      blockedByFirewall: false,
      rejectedAtValidation: false,
    };
  if (/insufficient funds|AA21/i.test(text))
    return {
      message: "The account has no ETH to pay network fees. Add some, or set a paymaster on the Network screen.",
      blockedByFirewall: false,
      rejectedAtValidation: false,
    };
  return {
    message: text.split("\n")[0].slice(0, 300) || "Something went wrong.",
    blockedByFirewall: false,
    rejectedAtValidation: false,
  };
}
