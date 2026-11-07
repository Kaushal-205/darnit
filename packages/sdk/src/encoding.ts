import { encode7579Calls } from "permissionless";
import {
  type Address,
  type Hex,
  concatHex,
  encodeAbiParameters,
  getAddress,
  keccak256,
  parseAbiParameters,
  zeroAddress,
} from "viem";
import { flzCompress } from "./lz.js";

export const MODULE_TYPE = {
  validator: 1n,
  executor: 2n,
  fallback: 3n,
  hook: 4n,
} as const;

/** One call made by the account. */
export type Call = { to: Address; value?: bigint; data?: Hex };

export type MarketEntry = { market: Address; adapter: Address };

/** Mirrors IFirewallModule.ChangeKind. */
export enum ChangeKind {
  AddDestination = 0,
  AddMarket = 1,
  AddToken = 2,
  RaiseCap = 3,
  Unfreeze = 4,
  ConfigCall = 5,
}

/** A loosening change for the 24-hour queue (R6). */
export type Change =
  | { kind: "addDestination"; destination: Address }
  | { kind: "addMarket"; market: Address; adapter: Address }
  | { kind: "addToken"; token: Address }
  | { kind: "raiseCap"; hourlyCap: bigint }
  | { kind: "unfreeze" }
  | { kind: "configCall"; target: Address; value?: bigint; data: Hex };

export function encodeChange(change: Change): { kind: ChangeKind; data: Hex } {
  switch (change.kind) {
    case "addDestination":
      return {
        kind: ChangeKind.AddDestination,
        data: encodeAbiParameters([{ type: "address" }], [change.destination]),
      };
    case "addMarket":
      return {
        kind: ChangeKind.AddMarket,
        data: encodeAbiParameters(parseAbiParameters("address, address"), [
          change.market,
          change.adapter,
        ]),
      };
    case "addToken":
      return {
        kind: ChangeKind.AddToken,
        data: encodeAbiParameters([{ type: "address" }], [change.token]),
      };
    case "raiseCap":
      return {
        kind: ChangeKind.RaiseCap,
        data: encodeAbiParameters([{ type: "uint128" }], [change.hourlyCap]),
      };
    case "unfreeze":
      return { kind: ChangeKind.Unfreeze, data: "0x" };
    case "configCall":
      return {
        kind: ChangeKind.ConfigCall,
        data: encodeAbiParameters(
          parseAbiParameters("address, uint256, bytes"),
          [change.target, change.value ?? 0n, change.data],
        ),
      };
  }
}

/** FirewallModule.onInstall data: abi.encode(uint128 cap, address[] tokens, address[] dests, address[] markets, address[] adapters). */
export function encodeModuleInitData(p: {
  hourlyCap: bigint;
  tokens: readonly Address[];
  destinations: readonly Address[];
  markets: readonly MarketEntry[];
}): Hex {
  return encodeAbiParameters(
    parseAbiParameters("uint128, address[], address[], address[], address[]"),
    [
      p.hourlyCap,
      [...p.tokens],
      [...p.destinations],
      p.markets.map((m) => m.market),
      p.markets.map((m) => m.adapter),
    ],
  );
}

/** Safe7579 v1.0.0 hook install data: abi.encode(HookType.GLOBAL, bytes4(0), bytes initData). */
export function encodeGlobalHookInitData(initData: Hex = "0x"): Hex {
  return encodeAbiParameters(parseAbiParameters("uint8, bytes4, bytes"), [
    0,
    "0x00000000",
    initData,
  ]);
}

/** OwnableValidator config: abi.encode(uint256 threshold, address[] owners) with owners sorted ascending. */
export function encodeOwnableValidatorData(
  owners: readonly Address[],
  threshold = 1n,
): Hex {
  const sorted = [...owners]
    .map((a) => getAddress(a))
    .sort((x, y) =>
      BigInt(x) < BigInt(y) ? -1 : BigInt(x) > BigInt(y) ? 1 : 0,
    );
  return encodeAbiParameters(parseAbiParameters("uint256, address[]"), [
    threshold,
    sorted,
  ]);
}

/** Safe7579 `execute` calldata: single call mode for one call, batch mode otherwise. Revert on error. */
export function encodeExecute(calls: readonly Call[]): Hex {
  if (calls.length === 0) throw new Error("encodeExecute: no calls");
  return encode7579Calls({
    mode: {
      type: calls.length > 1 ? "batchcall" : "call",
      revertOnError: false,
      selector: "0x",
      context: "0x",
    },
    callData: calls.map((c) => ({
      to: c.to,
      value: c.value ?? 0n,
      data: c.data ?? "0x",
    })),
  });
}

/**
 * Safe7579 selects the validator from the ERC-4337 nonce key: the top 20 bytes of the 24-byte key.
 * Returns the 192-bit key (validator << 32).
 */
export function validatorNonceKey(validator: Address): bigint {
  return BigInt(validator) << 32n;
}

/** Validator address encoded in a Safe7579 nonce. */
export function validatorFromNonce(nonce: bigint): Address {
  return getAddress(`0x${(nonce >> 96n).toString(16).padStart(40, "0")}`);
}

/** Smart Sessions permission id: keccak256(abi.encode(sessionValidator, sessionValidatorInitData, salt)). */
export function permissionIdOf(
  sessionValidator: Address,
  sessionValidatorInitData: Hex,
  salt: Hex,
): Hex {
  return keccak256(
    encodeAbiParameters(parseAbiParameters("address, bytes, bytes32"), [
      sessionValidator,
      sessionValidatorInitData,
      salt,
    ]),
  );
}

/** Smart Sessions USE-mode signature: mode 0x00 ++ permissionId ++ flzCompress(abi.encode(bytes sig)). */
export function encodeSmartSessionUseSignature(
  permissionId: Hex,
  signature: Hex,
): Hex {
  return concatHex([
    "0x00",
    permissionId,
    flzCompress(encodeAbiParameters([{ type: "bytes" }], [signature])),
  ]);
}

/** A 65-byte ECDSA-shaped signature for gas estimation (never valid). */
export const DUMMY_ECDSA_SIGNATURE: Hex =
  "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c";

/** A placeholder attester for the launchpad's registry setup; the registry is switched off right after. */
export const PLACEHOLDER_ATTESTER: Address =
  "0x0000000000000000000000000000000000000001";
export { zeroAddress };
