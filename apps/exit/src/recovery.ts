import {
  type ChangeKind,
  MODULE_TYPE,
  encodeChange,
  firewallModuleAbi,
  safe7579Abi,
} from "@session-firewall/sdk";
import {
  type Address,
  type Hex,
  encodeAbiParameters,
  encodeFunctionData,
} from "viem";

/**
 * Recovery key enrollment (see README "Passkeys and origins").
 *
 * FirewallOwnerValidator holds one passkey per account, so a second key is a second deployment of the
 * same, unmodified validator contract, installed as an additional ERC-7579 validator. Installing a module
 * is a loosening change: it goes through the 24-hour queue as a ConfigCall, and can be cancelled. The
 * second deployment applies exactly the same rules (D12) as the first, so it cannot sign permits,
 * enable-mode sessions or an emergency hook uninstall.
 */
export function recoveryInitData(x: Hex, y: Hex): Hex {
  return encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }, { type: "string[]" }],
    [x, y, []],
  );
}

/** The owner call (to FirewallModule) that queues installing the recovery validator. */
export function queueRecoveryInstall(p: {
  account: Address;
  recoveryValidator: Address;
  x: Hex;
  y: Hex;
}): { to: "module"; data: Hex; change: { kind: ChangeKind; data: Hex } } {
  const install = encodeFunctionData({
    abi: safe7579Abi,
    functionName: "installModule",
    args: [
      MODULE_TYPE.validator,
      p.recoveryValidator,
      recoveryInitData(p.x, p.y),
    ],
  });
  const change = encodeChange({
    kind: "configCall",
    target: p.account,
    data: install,
  });
  return {
    to: "module",
    change,
    data: encodeFunctionData({
      abi: firewallModuleAbi,
      functionName: "queue",
      args: [change.kind, change.data],
    }),
  };
}
