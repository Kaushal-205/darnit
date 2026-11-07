import { ChangeKind, type FirewallClientConfig, firewallModuleAbi } from "@session-firewall/sdk";
import { type Address, type Hex, decodeAbiParameters, getAbiItem, parseAbiParameters } from "viem";
import { formatUsd } from "./format";

export type PendingChange = {
  id: Hex;
  kind: number;
  data: Hex;
  eta: bigint;
  description: string;
};

/** Plain description of a queued change, e.g. "Add withdrawal address 0x12…". */
export function describeChange(kind: number, data: Hex): string {
  try {
    switch (kind) {
      case ChangeKind.AddDestination: {
        const [a] = decodeAbiParameters([{ type: "address" }], data);
        return `Add withdrawal address ${a}`;
      }
      case ChangeKind.AddMarket: {
        const [m] = decodeAbiParameters(parseAbiParameters("address, address"), data);
        return `Add market ${m}`;
      }
      case ChangeKind.AddToken: {
        const [t] = decodeAbiParameters([{ type: "address" }], data);
        return `Track token ${t}`;
      }
      case ChangeKind.RaiseCap: {
        const [cap] = decodeAbiParameters([{ type: "uint128" }], data);
        return `Raise the hourly limit to ${formatUsd(cap)}`;
      }
      case ChangeKind.Unfreeze:
        return "Resume trading (undo pause)";
      case ChangeKind.ConfigCall: {
        const [target] = decodeAbiParameters(parseAbiParameters("address, uint256, bytes"), data);
        return `Advanced settings call to ${target}`;
      }
    }
  } catch {
    // fall through
  }
  return `Unknown change (kind ${kind})`;
}

const changeQueued = getAbiItem({ abi: firewallModuleAbi, name: "ChangeQueued" });

/** Changes still waiting in the 24-hour queue (queued, not executed or cancelled). */
export async function listPendingChanges(
  client: FirewallClientConfig,
  account: Address,
  fromBlock: bigint,
): Promise<PendingChange[]> {
  const { publicClient, addresses } = client;
  const logs = await publicClient.getLogs({
    address: addresses.module,
    event: changeQueued,
    args: { account },
    fromBlock,
    toBlock: "latest",
  });
  const ids = [...new Set(logs.map((l) => l.args.id).filter((x): x is Hex => !!x))];
  const states = await Promise.all(
    ids.map((id) =>
      publicClient.readContract({
        address: addresses.module,
        abi: firewallModuleAbi,
        functionName: "pendingChange",
        args: [account, id],
      }),
    ),
  );
  const out: PendingChange[] = [];
  ids.forEach((id, i) => {
    const s = states[i];
    if (!s || s.eta === 0n) return;
    out.push({
      id,
      kind: Number(s.kind),
      data: s.data,
      eta: BigInt(s.eta),
      description: describeChange(Number(s.kind), s.data),
    });
  });
  return out.sort((a, b) => (a.eta < b.eta ? -1 : 1));
}
