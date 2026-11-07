import { type Address, getAddress } from "viem";

/** EntryPoint v0.7, same address on every chain. */
export const ENTRYPOINT_V07: Address =
  "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
/** Safe7579 adapter v1.0.0 (CREATE2; code verified on Ethereum Sepolia, docs/sepolia-infrastructure.json). */
export const SAFE7579_DEFAULT: Address =
  "0x7579EE8307284F293B1927136486880611F20002";
/** Ethereum Sepolia (override with CHAIN_ID). */
export const DEFAULT_CHAIN_ID = 11155111;

type Env = Record<string, string | undefined>;

export function required(env: Env, name: string): string {
  const v = env[name]?.trim();
  if (!v) throw new Error(`missing env var ${name}`);
  return v;
}

export function parseAddress(
  env: Env,
  name: string,
  fallback?: Address,
): Address {
  const v = env[name]?.trim();
  if (!v) {
    if (fallback) return fallback;
    throw new Error(`missing env var ${name}`);
  }
  return getAddress(v);
}

export function parseInteger(env: Env, name: string, fallback: number): number {
  const v = env[name]?.trim();
  if (!v) return fallback;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error(`env var ${name} must be a non-negative integer`);
  return n;
}

/** `RPC_URLS` is a comma-separated list; Ponder load-balances and falls back across them. */
export function parseRpcUrls(env: Env): string[] {
  const urls = required(env, "RPC_URLS")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  for (const u of urls) {
    if (!/^(https?|wss?):\/\//.test(u))
      throw new Error(`RPC_URLS entry is not a URL: ${u}`);
  }
  return urls;
}

export type IndexerEnv = {
  chainId: number;
  rpcUrls: string[];
  firewallModule: Address;
  entryPoint: Address;
  safe7579: Address;
  startBlock: number;
  pollingIntervalMs: number;
};

export function parseIndexerEnv(env: Env): IndexerEnv {
  return {
    chainId: parseInteger(env, "CHAIN_ID", DEFAULT_CHAIN_ID),
    rpcUrls: parseRpcUrls(env),
    firewallModule: parseAddress(env, "FIREWALL_MODULE"),
    entryPoint: parseAddress(env, "ENTRYPOINT_ADDRESS", ENTRYPOINT_V07),
    safe7579: parseAddress(env, "SAFE7579_ADDRESS", SAFE7579_DEFAULT),
    startBlock: parseInteger(env, "START_BLOCK", 0),
    pollingIntervalMs: parseInteger(env, "PONDER_POLLING_INTERVAL_MS", 1_000),
  };
}
