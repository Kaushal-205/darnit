import {
  type Abi,
  type Address,
  BaseError,
  type Client,
  type Hash,
  type Hex,
  decodeErrorResult,
  encodeFunctionData,
  formatUnits,
  isHex,
  size,
  slice,
} from "viem";
import { entryPointErrorsAbi, safe7579Abi } from "./abi/external.js";
import {
  executionDecoderAbi,
  firewallErrorsAbi,
  firewallHookAbi,
} from "./abi/index.js";

const DECODE_ABI = [
  ...firewallErrorsAbi,
  ...executionDecoderAbi,
  ...safe7579Abi.filter((x) => x.type === "error"),
  ...entryPointErrorsAbi,
] as const satisfies Abi;

/** Selector of Safe7579's `ExecutionFailed()`, which (v1.0.0) replaces every inner revert reason. */
export const EXECUTION_FAILED_SELECTOR: Hex = "0xacfdb444";

export type DecodedFirewallError = {
  /** Custom error name, e.g. "UnexplainedOutflow", or "Error"/"Panic" for standard reverts. */
  name: string;
  args: readonly unknown[];
  /** Plain-English explanation for end users. */
  message: string;
  /** True when the error comes from the firewall (hook, module, policies, decoder). */
  isFirewallError: boolean;
  /** True when the account hid the real reason (`ExecutionFailed()`); use `explainRevert` to dig. */
  isOpaque: boolean;
  data: Hex;
};

const usd = (v: unknown) => `$${formatUnits(BigInt(v as bigint), 6)}`;
const FIREWALL_ERRORS = new Set<string>([
  ...firewallErrorsAbi.filter((x) => x.type === "error").map((x) => x.name),
  "Malformed",
]);

function sentence(name: string, args: readonly unknown[]): string {
  switch (name) {
    case "UnknownTarget":
      return `Blocked: ${args[0]} is not a registered token, market or destination of this account, so it cannot be called (function ${args[1]}).`;
    case "ForbiddenExecution":
      return "Blocked: this kind of execution is not allowed (delegatecall, a call to the account itself, installing or removing modules, or a queued change bundled with other calls).";
    case "UnregisteredSpender":
      return `Blocked: approvals can only go to registered markets, and ${args[0]} is not one.`;
    case "UnexplainedOutflow": {
      const id = BigInt(args[1] as bigint);
      return `Blocked: this would move ${id === 0n ? "" : `share id ${id} of `}${args[0]} out of the account to an address that is not a registered destination.`;
    }
    case "BudgetExceeded":
      return `Blocked: this trade could lose up to ${usd(args[0])}, but only ${usd(args[1])} of the hourly budget is left. Try a smaller trade or wait for the budget to refill.`;
    case "TooEarly":
      return `This change is still in its 24-hour waiting period. It can be executed after ${new Date(Number(args[0]) * 1000).toISOString()}.`;
    case "UnknownChange":
      return `There is no pending change with id ${args[0]}. It may have been cancelled or already executed.`;
    case "NotLoosening":
      return "This change does not loosen the configuration, so it does not need the queue. Apply it directly.";
    case "NotTightening":
      return "The new cap is higher than the current one. Raising the cap must be queued and waits 24 hours.";
    case "Frozen":
      return "The account is frozen: sessions are revoked and trading is off. Exits to registered destinations still work; unfreezing takes 24 hours.";
    case "NotInitialized":
      return `The firewall is not installed on account ${args[0]}.`;
    case "AlreadyInitialized":
      return `The firewall is already installed on account ${args[0]}.`;
    case "OnlyHook":
      return "Only the firewall hook may charge the risk budget.";
    case "TooMany":
      return "Too many entries: an account can have at most 4 tokens, 8 destinations and 4 markets.";
    case "InvalidEntry":
      return `${args[0]} cannot be registered or removed here (it is zero, already registered, not registered, the account itself, a firewall contract, or does not match its market adapter).`;
    case "ZeroAddress":
      return "An address argument was zero.";
    case "InvalidExpiry":
      return "The session expiry must be in the future and at most 30 days away.";
    case "Malformed":
      return "Blocked: the execution data is malformed.";
    case "ExecutionFailed":
      return "The account's call reverted, but the account did not pass on the reason.";
    case "FailedOp":
    case "FailedOpWithRevert":
      return entryPointSentence(String(args[1]));
    case "Error":
      return `Reverted: ${args[0]}`;
    case "Panic":
      return `Reverted with panic code ${args[0]}.`;
    default:
      return `Reverted with ${name}.`;
  }
}

function entryPointSentence(reason: string): string {
  if (reason.startsWith("AA24") || reason.startsWith("AA23"))
    return `The signature was rejected (${reason}). For a session key this means the session expired, was revoked or removed, the account is frozen, or the session called something outside its scope.`;
  if (reason.startsWith("AA22"))
    return `The signature has expired (${reason}). The session is past its expiry.`;
  if (reason.startsWith("AA21"))
    return `The account cannot pay for gas (${reason}). Fund it with ETH or use a paymaster.`;
  if (reason.startsWith("AA25"))
    return `Wrong nonce (${reason}). Another operation from this key is pending; retry.`;
  return `The EntryPoint rejected the operation (${reason}).`;
}

/** Find revert data inside a viem error (or accept raw hex). */
export function extractRevertData(error: unknown): Hex | undefined {
  if (typeof error === "string") return isHex(error) ? error : undefined;
  if (error instanceof BaseError) {
    let found: Hex | undefined;
    error.walk((e) => {
      const d = (e as { data?: unknown }).data;
      if (typeof d === "string" && isHex(d) && size(d) >= 4) {
        found = d;
        return true;
      }
      if (
        d &&
        typeof d === "object" &&
        "data" in d &&
        typeof d.data === "string" &&
        isHex(d.data)
      ) {
        found = d.data;
        return true;
      }
      return false;
    });
    return found;
  }
  if (
    error &&
    typeof error === "object" &&
    "data" in error &&
    typeof error.data === "string" &&
    isHex(error.data)
  )
    return error.data;
  return undefined;
}

/**
 * Decode revert data (or a viem error carrying it) into a plain-English sentence. Handles every
 * `FirewallErrors` error, `ExecutionDecoder.Malformed`, Safe7579's `ExecutionFailed()`, EntryPoint
 * `FailedOp`/`FailedOpWithRevert` (recursing into the inner revert) and `Error(string)` / `Panic`.
 * Returns undefined when nothing decodable is present.
 */
export function decodeFirewallError(
  revert: Hex | unknown,
): DecodedFirewallError | undefined {
  const data = extractRevertData(revert);
  if (!data || size(data) < 4) return undefined;
  let decoded: { errorName: string; args?: readonly unknown[] };
  try {
    decoded = decodeErrorResult({ abi: DECODE_ABI, data });
  } catch {
    return {
      name: slice(data, 0, 4),
      args: [],
      message: `Reverted with unknown error ${slice(data, 0, 4)}.`,
      isFirewallError: false,
      isOpaque: false,
      data,
    };
  }
  const args = decoded.args ?? [];
  if (decoded.errorName === "FailedOpWithRevert") {
    const inner = decodeFirewallError(args[2] as Hex);
    if (inner && inner.name !== "ExecutionFailed") {
      return { ...inner, message: `${inner.message} (${args[1]})` };
    }
  }
  return {
    name: decoded.errorName,
    args,
    message: sentence(decoded.errorName, args),
    isFirewallError: FIREWALL_ERRORS.has(decoded.errorName),
    isOpaque: decoded.errorName === "ExecutionFailed",
    data,
  };
}

/** Error thrown by SDK actions when an operation reverts. */
export class FirewallError extends Error {
  readonly decoded: DecodedFirewallError | undefined;
  readonly userOpHash: Hash | undefined;
  readonly transactionHash: Hash | undefined;
  constructor(
    decoded: DecodedFirewallError | undefined,
    opts: { userOpHash?: Hash; transactionHash?: Hash; cause?: unknown } = {},
  ) {
    super(decoded?.message ?? "The operation reverted for an unknown reason.", {
      cause: opts.cause,
    });
    this.name = "FirewallError";
    this.decoded = decoded;
    this.userOpHash = opts.userOpHash;
    this.transactionHash = opts.transactionHash;
  }
}

type CallFrame = {
  from?: Address;
  to?: Address;
  input?: Hex;
  output?: Hex;
  error?: string;
  revertReason?: string;
  calls?: CallFrame[];
};

/** Output of the deepest reverted frame with a real reason (anything but ExecutionFailed), or undefined. */
export function findInnermostRevert(frame: CallFrame): Hex | undefined {
  for (const child of frame.calls ?? []) {
    const inner = findInnermostRevert(child);
    if (inner) return inner;
  }
  if (
    frame.error &&
    frame.output &&
    size(frame.output) >= 4 &&
    slice(frame.output, 0, 4) !== EXECUTION_FAILED_SELECTOR
  ) {
    return frame.output;
  }
  return undefined;
}

/** Deepest reverted frame whose output decodes to a firewall error (depth-first, innermost wins). */
export function findFirewallErrorInTrace(
  frame: CallFrame,
): DecodedFirewallError | undefined {
  for (const child of frame.calls ?? []) {
    const inner = findFirewallErrorInTrace(child);
    if (inner) return inner;
  }
  if (frame.error && frame.output && size(frame.output) >= 4) {
    const d = decodeFirewallError(frame.output);
    if (d?.isFirewallError) return d;
  }
  return undefined;
}

export type ExplainRevertParams = {
  /** Revert data already seen (e.g. from UserOperationRevertReason). Returned as-is unless opaque. */
  revertData?: Hex;
  /** Re-trace a mined transaction (debug_traceTransaction). Exact: same state as the failure. */
  transactionHash?: Hash;
  /** Or re-simulate a call (debug_traceCall), e.g. EntryPoint -> account with the user operation's callData. */
  call?: { from: Address; to: Address; data: Hex; blockNumber?: bigint };
  /** Fallback when the node has no debug_* methods: run the hook's preCheck as the account. */
  hook?: Address;
};

/**
 * Explain a revert when only `ExecutionFailed()` (or nothing) is visible (docs/decisions.md V10).
 * Order: decode `revertData`; trace the transaction or call with `callTracer` and return the innermost
 * firewall error; finally, if `hook` and `call` are given, `eth_call` FirewallHook.preCheck from the
 * account, which reproduces every pre-execution block (UnknownTarget, UnregisteredSpender, recipients
 * check of UnexplainedOutflow, ForbiddenExecution). Post-execution errors (BudgetExceeded, post-check
 * UnexplainedOutflow) need a tracing node.
 */
export async function explainRevert(
  client: Client,
  p: ExplainRevertParams,
): Promise<DecodedFirewallError | undefined> {
  const direct = p.revertData ? decodeFirewallError(p.revertData) : undefined;
  if (direct && !direct.isOpaque) return direct;

  const tracer = { tracer: "callTracer", tracerConfig: { withLog: false } };
  try {
    let trace: CallFrame | undefined;
    if (p.transactionHash) {
      trace = (await client.request({
        method: "debug_traceTransaction" as never,
        params: [p.transactionHash, tracer] as never,
      })) as CallFrame;
    } else if (p.call) {
      const block =
        p.call.blockNumber === undefined
          ? "latest"
          : `0x${p.call.blockNumber.toString(16)}`;
      trace = (await client.request({
        method: "debug_traceCall" as never,
        params: [
          { from: p.call.from, to: p.call.to, data: p.call.data },
          block,
          tracer,
        ] as never,
      })) as CallFrame;
    }
    if (trace) {
      const found = findFirewallErrorInTrace(trace);
      if (found) return found;
      const inner = findInnermostRevert(trace);
      if (inner) return decodeFirewallError(inner);
    }
  } catch {
    // node without debug_* methods: fall through
  }

  if (p.hook && p.call) {
    try {
      await client.request({
        method: "eth_call",
        params: [
          {
            from: p.call.to,
            to: p.hook,
            data: encodePreCheck(p.call.from, p.call.data),
          },
          "latest",
        ],
      });
    } catch (e) {
      const d = decodeFirewallError(e);
      if (d?.isFirewallError) return d;
    }
  }
  return direct;
}

function encodePreCheck(msgSender: Address, msgData: Hex): Hex {
  return encodeFunctionData({
    abi: firewallHookAbi,
    functionName: "preCheck",
    args: [msgSender, 0n, msgData],
  });
}
