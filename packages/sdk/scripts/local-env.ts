/**
 * `local` environment: an Anvil fork of Base Sepolia with our contracts and fixtures deployed by the
 * Foundry scripts. Used by scripts/demo.ts and the integration test.
 *
 * Env:
 *   FORK_URLS   comma-separated Base Sepolia RPCs to fork (tried in order; default public endpoints)
 *   RPC_URL     use an already running node instead of starting Anvil (it must allow oversize code,
 *               see contracts/script/DeploySmartSessions.s.sol)
 *   FOUNDRY_BIN directory with forge/anvil (default: PATH, then ~/.foundry/bin)
 */
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Address } from "viem";
import {
  BASE_SEPOLIA,
  type FirewallAddresses,
  baseSepoliaAddresses,
} from "../src/addresses.js";

const here = dirname(fileURLToPath(import.meta.url));
export const CONTRACTS_DIR = join(here, "../../../contracts");

/** Well-known Anvil dev keys (public test keys, never use with real funds). */
export const ANVIL_KEYS = {
  deployer:
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  maker: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  bundler: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
} as const;

export const LOCAL_CHAIN_ID = 31337;
const DEFAULT_FORK_URLS = [
  "https://sepolia.base.org",
  "https://base-sepolia-rpc.publicnode.com",
];

export type Fixtures = {
  usdc: Address;
  market: Address;
  shares: Address;
  adapter: Address;
  maker: Address;
  marketId: number;
  yesId: number;
  noId: number;
};

export type LocalEnv = {
  rpcUrl: string;
  addresses: FirewallAddresses;
  fixtures: Fixtures;
  stop: () => void;
};

function bin(name: string): string {
  if (process.env.FOUNDRY_BIN) return join(process.env.FOUNDRY_BIN, name);
  try {
    execFileSync(name, ["--version"], { stdio: "ignore" });
    return name;
  } catch {
    const p = join(homedir(), ".foundry/bin", name);
    if (existsSync(p)) return p;
    throw new Error(`${name} not found: install Foundry or set FOUNDRY_BIN`);
  }
}

async function rpcReady(url: string, timeoutMs: number): Promise<boolean> {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try {
      const r = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "eth_chainId",
          params: [],
        }),
      });
      if (r.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((res) => setTimeout(res, 250));
  }
  return false;
}

async function startAnvil(
  port: number,
): Promise<{ proc: ChildProcess; rpcUrl: string }> {
  const forkUrls =
    process.env.FORK_URLS?.split(",").filter(Boolean) ?? DEFAULT_FORK_URLS;
  const rpcUrl = `http://127.0.0.1:${port}`;
  let lastErr = "";
  for (let attempt = 0; attempt < forkUrls.length * 2; attempt++) {
    const forkUrl = forkUrls[attempt % forkUrls.length];
    const proc = spawn(
      bin("anvil"),
      [
        "--fork-url",
        forkUrl,
        "--chain-id",
        String(LOCAL_CHAIN_ID),
        "--disable-code-size-limit",
        "--port",
        String(port),
        "--fork-retry-backoff",
        "1000",
        "--retries",
        "10",
        "--silent",
      ],
      { stdio: ["ignore", "ignore", "pipe"] },
    );
    proc.stderr?.on("data", (d) => {
      lastErr += d.toString();
    });
    if (await rpcReady(rpcUrl, 30_000)) return { proc, rpcUrl };
    proc.kill();
    await new Promise((res) => setTimeout(res, 2000 * (attempt + 1)));
  }
  throw new Error(`could not start an Anvil fork of Base Sepolia: ${lastErr}`);
}

function forgeScript(
  script: string,
  rpcUrl: string,
  env: Record<string, string>,
  extra: string[] = [],
) {
  execFileSync(
    bin("forge"),
    [
      "script",
      script,
      "--rpc-url",
      rpcUrl,
      "--broadcast",
      "--private-key",
      ANVIL_KEYS.deployer,
      "--slow",
      ...extra,
    ],
    {
      cwd: CONTRACTS_DIR,
      env: { ...process.env, ...env },
      stdio: process.env.VERBOSE ? "inherit" : "pipe",
    },
  );
}

function readDeployment<T>(file: string): T {
  return JSON.parse(
    readFileSync(join(CONTRACTS_DIR, "deployments", file), "utf8"),
  ) as T;
}

/** Deploy Smart Sessions (local build), the firewall and the fixtures with the Foundry scripts. */
export function deployAll(rpcUrl: string): {
  addresses: FirewallAddresses;
  fixtures: Fixtures;
} {
  forgeScript(
    "script/DeploySmartSessions.s.sol",
    rpcUrl,
    { ALLOW_OVERSIZE: "true" },
    ["--disable-code-size-limit"],
  );
  const { smartSessions } = readDeployment<{ smartSessions: Address }>(
    `${LOCAL_CHAIN_ID}.smartsessions.json`,
  );
  forgeScript("script/Deploy.s.sol", rpcUrl, { SMART_SESSIONS: smartSessions });
  forgeScript("script/DeployFixtures.s.sol", rpcUrl, {
    MAKER_PRIVATE_KEY: ANVIL_KEYS.maker,
  });
  const firewall = readDeployment<Parameters<typeof baseSepoliaAddresses>[0]>(
    `${LOCAL_CHAIN_ID}.json`,
  );
  forgeScript(
    "script/DeployLocalAttestations.s.sol",
    rpcUrl,
    {
      REGISTRY: BASE_SEPOLIA.registry,
      MODULES: [
        firewall.signaturePolicy,
        firewall.actionPolicy,
        BASE_SEPOLIA.ownableValidator,
      ].join(","),
    },
    ["--tc", "DeployLocalAttestations"],
  );
  const { attester } = readDeployment<{ attester: Address }>(
    `${LOCAL_CHAIN_ID}.attester.json`,
  );
  const fixtures = readDeployment<Fixtures>(`${LOCAL_CHAIN_ID}.fixtures.json`);
  return { addresses: baseSepoliaAddresses(firewall, { attester }), fixtures };
}

/** Start (or attach to) a local node and deploy everything. */
export async function startLocalEnv(
  opts: { port?: number } = {},
): Promise<LocalEnv> {
  let stop = () => {};
  let rpcUrl = process.env.RPC_URL;
  if (!rpcUrl) {
    const anvil = await startAnvil(
      opts.port ?? 8545 + Math.floor(Math.random() * 1000) + 100,
    );
    rpcUrl = anvil.rpcUrl;
    stop = () => anvil.proc.kill();
  }
  try {
    const { addresses, fixtures } = deployAll(rpcUrl);
    return { rpcUrl, addresses, fixtures, stop };
  } catch (e) {
    stop();
    throw e;
  }
}
