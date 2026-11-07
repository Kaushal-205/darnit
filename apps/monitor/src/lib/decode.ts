import {
  type Hex,
  decodeAbiParameters,
  decodeErrorResult,
  formatUnits,
  getAddress,
  size,
  slice,
  toFunctionSelector,
} from "viem";
import { FirewallErrorsAbi } from "../../abis/FirewallErrors.ts";
import { Safe7579Abi } from "../../abis/Safe7579.ts";

// ------------------------------------------------------------------ revert reasons

const ERRORS_ABI = [...FirewallErrorsAbi, ...Safe7579Abi.filter((x) => x.type === "error")] as const;

export const FIREWALL_ERROR_NAMES: readonly string[] = FirewallErrorsAbi.map((e) => e.name);

export type DecodedRevert = {
  /** firewall: a FirewallErrors/ExecutionDecoder error; executionFailed: Safe7579 swallowed the reason (V10). */
  kind: "firewall" | "executionFailed" | "error" | "panic" | "empty" | "unknown";
  name: string | null;
  /** Arguments as strings (addresses checksummed, ints in decimal). */
  args: string[];
  /** True when the firewall error was found inside a wrapping error rather than at offset 0. */
  nested: boolean;
  description: string;
};

const DESCRIPTIONS: Record<string, (a: string[]) => string> = {
  UnknownTarget: (a) => `Blocked a call to ${a[0]} (selector ${a[1]}), which is not a registered market, token or destination.`,
  ForbiddenExecution: () => "Blocked an execution type the firewall never allows (delegatecall, module management or similar).",
  UnregisteredSpender: (a) => `Blocked an approval to ${a[0]}, which is not a registered market.`,
  UnexplainedOutflow: (a) => `Blocked a transfer of ${a[0]} (id ${a[1]}) to an address that is not yours or a registered destination.`,
  BudgetExceeded: (a) => `Blocked: the trade needed ${usdc(a[0])} USDC of risk budget but only ${usdc(a[1])} USDC was left this hour.`,
  TooEarly: (a) => `Blocked: a queued change was executed before its delay ended (eta ${a[0]}).`,
  UnknownChange: (a) => `Blocked: change ${a[0]} does not exist or was cancelled.`,
  NotLoosening: () => "Rejected a queued change that would not loosen the configuration.",
  NotTightening: () => "Rejected a tightening call that would not tighten the configuration.",
  Frozen: () => "Blocked: the account is frozen.",
  NotInitialized: (a) => `Rejected: the firewall is not installed on ${a[0]}.`,
  AlreadyInitialized: (a) => `Rejected: the firewall is already installed on ${a[0]}.`,
  OnlyHook: () => "Rejected: only the firewall hook may charge the budget.",
  TooMany: () => "Rejected: a configuration list is full.",
  InvalidEntry: (a) => `Rejected an invalid entry ${a[0]}.`,
  ZeroAddress: () => "Rejected the zero address.",
  InvalidExpiry: () => "Rejected a session expiry outside the allowed range.",
  Malformed: () => "Blocked execution calldata the firewall could not parse.",
  ExecutionFailed: () =>
    "An execution reverted inside the account. Safe7579 hides the reason (ExecutionFailed), so this is likely, but not certainly, a firewall block.",
};

function usdc(v: string | undefined): string {
  if (v === undefined) return "?";
  try {
    return formatUnits(BigInt(v), 6);
  } catch {
    return v;
  }
}

function stringifyArg(v: unknown): string {
  if (typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v)) return getAddress(v);
  if (typeof v === "bigint") return v.toString();
  return String(v);
}

function tryDecode(data: Hex): { name: string; args: string[] } | null {
  try {
    const r = decodeErrorResult({ abi: ERRORS_ABI, data });
    return { name: r.errorName, args: (r.args ?? []).map(stringifyArg) };
  } catch {
    return null;
  }
}

function classify(name: string): DecodedRevert["kind"] {
  if (FIREWALL_ERROR_NAMES.includes(name)) return "firewall";
  if (name === "ExecutionFailed") return "executionFailed";
  if (name === "Error") return "error";
  if (name === "Panic") return "panic";
  return "unknown";
}

function describe(name: string, args: string[]): string {
  const d = DESCRIPTIONS[name];
  if (d) return d(args);
  if (name === "Error") return `Reverted: ${args[0] ?? ""}`;
  if (name === "Panic") return `Reverted with panic code ${args[0] ?? "?"}.`;
  return `Reverted with ${name}.`;
}

const FIREWALL_SELECTORS = new Set(
  FirewallErrorsAbi.map((e) => toFunctionSelector(`${e.name}(${e.inputs.map((i) => i.type).join(",")})`)),
);

/**
 * Decodes the `revertReason` of an EntryPoint v0.7 `UserOperationRevertReason`. Firewall errors are
 * named when present (at offset 0 or wrapped inside another error's bytes argument); otherwise the
 * raw reason is kept and the caller shows it as-is.
 */
export function decodeRevertReason(reason: Hex): DecodedRevert {
  if (!reason || reason === "0x") {
    return { kind: "empty", name: null, args: [], nested: false, description: "Reverted without a reason." };
  }
  const direct = tryDecode(reason);
  if (direct && classify(direct.name) !== "error") {
    return { kind: classify(direct.name), ...direct, nested: false, description: describe(direct.name, direct.args) };
  }
  // A wrapper (e.g. Error(string) is fine, but FailedOpWithRevert / custom wrappers carry raw bytes):
  // look for an embedded firewall selector at any byte offset.
  const len = size(reason);
  for (let i = 4; i + 4 <= len; i++) {
    const sel = slice(reason, i, i + 4);
    if (!FIREWALL_SELECTORS.has(sel)) continue;
    for (const end of [len, ...candidateEnds(i, len)]) {
      const inner = tryDecode(slice(reason, i, end));
      if (inner && classify(inner.name) === "firewall") {
        return { kind: "firewall", ...inner, nested: true, description: describe(inner.name, inner.args) };
      }
    }
  }
  if (direct) {
    return { kind: classify(direct.name), ...direct, nested: false, description: describe(direct.name, direct.args) };
  }
  return {
    kind: "unknown",
    name: null,
    args: [],
    nested: false,
    description: `Reverted with an unrecognised reason (selector ${len >= 4 ? slice(reason, 0, 4) : reason}).`,
  };
}

function candidateEnds(start: number, len: number): number[] {
  // Firewall errors carry at most two static words, so try 4, 36 and 68 byte payloads too.
  return [start + 4, start + 36, start + 68].filter((e) => e <= len);
}

// ------------------------------------------------------------------ queued change data

export const CHANGE_KINDS = ["AddDestination", "AddMarket", "AddToken", "RaiseCap", "Unfreeze", "ConfigCall"] as const;
export type ChangeKindName = (typeof CHANGE_KINDS)[number] | "Unknown";

export function changeKindName(kind: number): ChangeKindName {
  return CHANGE_KINDS[kind] ?? "Unknown";
}

const KNOWN_CONFIG_SELECTORS: Record<string, string> = {
  [toFunctionSelector("uninstallModule(uint256,address,bytes)")]: "uninstallModule",
  [toFunctionSelector("installModule(uint256,address,bytes)")]: "installModule",
  [toFunctionSelector("setFallbackHandler(address)")]: "setFallbackHandler",
  [toFunctionSelector("addOwnerWithThreshold(address,uint256)")]: "addOwnerWithThreshold",
  [toFunctionSelector("swapOwner(address,address,address)")]: "swapOwner",
  [toFunctionSelector("enableModule(address)")]: "enableModule",
};

export type DecodedChange = {
  kind: ChangeKindName;
  /** One-line plain-English summary. */
  summary: string;
  /** Decoded fields as strings. */
  fields: Record<string, string>;
};

export function decodeChange(kind: number, data: Hex): DecodedChange {
  const name = changeKindName(kind);
  try {
    switch (name) {
      case "AddDestination": {
        const [d] = decodeAbiParameters([{ type: "address" }], data);
        return { kind: name, summary: `Add withdrawal destination ${d}`, fields: { destination: d } };
      }
      case "AddMarket": {
        const [m, a] = decodeAbiParameters([{ type: "address" }, { type: "address" }], data);
        return { kind: name, summary: `Add market ${m} (adapter ${a})`, fields: { market: m, adapter: a } };
      }
      case "AddToken": {
        const [t] = decodeAbiParameters([{ type: "address" }], data);
        return { kind: name, summary: `Track token ${t}`, fields: { token: t } };
      }
      case "RaiseCap": {
        const [c] = decodeAbiParameters([{ type: "uint128" }], data);
        return {
          kind: name,
          summary: `Raise hourly risk cap to ${formatUnits(c, 6)} USDC`,
          fields: { newCap: c.toString() },
        };
      }
      case "Unfreeze":
        return { kind: name, summary: "Unfreeze the account", fields: {} };
      case "ConfigCall": {
        const [target, value, callData] = decodeAbiParameters(
          [{ type: "address" }, { type: "uint256" }, { type: "bytes" }],
          data,
        );
        const selector = size(callData) >= 4 ? slice(callData, 0, 4) : "0x";
        const fn = KNOWN_CONFIG_SELECTORS[selector];
        return {
          kind: name,
          summary: `Arbitrary account call to ${target}${fn ? ` (${fn})` : ` (selector ${selector})`}${value > 0n ? ` with ${formatUnits(value, 18)} ETH` : ""}. This can change anything, including removing the firewall.`,
          fields: { target, value: value.toString(), selector, ...(fn ? { function: fn } : {}), callData },
        };
      }
      default:
        return { kind: "Unknown", summary: `Unknown change kind ${kind}`, fields: { data } };
    }
  } catch {
    return { kind: name, summary: `${name} change with undecodable data`, fields: { data } };
  }
}
