import { createConfig } from "ponder";
import { EntryPointAbi } from "./abis/EntryPoint.ts";
import { FirewallModuleAbi } from "./abis/FirewallModule.ts";
import { Safe7579Abi } from "./abis/Safe7579.ts";
import { parseIndexerEnv } from "./src/lib/env.ts";

const env = parseIndexerEnv(process.env);

// Ponder indexes unfinalized blocks as soon as it sees them (no confirmation wait) and rolls back on
// reorg, so alert latency is roughly block time + pollingInterval + worker poll. See README "Latency".
// Database: Postgres when DATABASE_URL is set (Neon in production), PGlite in .ponder/ otherwise.
export default createConfig({
  ...(!process.env.DATABASE_URL && process.env.PGLITE_DIR
    ? { database: { kind: "pglite" as const, directory: process.env.PGLITE_DIR } }
    : {}),
  chains: {
    chain: {
      id: env.chainId,
      rpc: env.rpcUrls,
      pollingInterval: env.pollingIntervalMs,
    },
  },
  contracts: {
    FirewallModule: {
      chain: "chain",
      abi: FirewallModuleAbi,
      address: env.firewallModule,
      startBlock: env.startBlock,
    },
    // Every UserOperationRevertReason is fetched; the handler keeps only senders that installed the
    // firewall (Ponder event filters can only match static indexed values).
    EntryPoint: {
      chain: "chain",
      abi: EntryPointAbi,
      address: env.entryPoint,
      startBlock: env.startBlock,
    },
    // Safe7579 runs as the Safe's fallback handler, so its events come from the adapter singleton and
    // carry no account. The handler attributes them from the transaction (see src/index.ts).
    Safe7579: {
      chain: "chain",
      abi: Safe7579Abi,
      address: env.safe7579,
      startBlock: env.startBlock,
    },
  },
});
