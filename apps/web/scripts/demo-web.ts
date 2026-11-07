/**
 * `pnpm demo:web`: one command to a working local demo.
 *  1. starts an Anvil fork of Ethereum Sepolia (chain id 31337 locally);
 *  2. deploys the firewall contracts and fixtures with the SDK's local-env scripts;
 *  3. signs fixture maker orders and writes out/runtime-config.json;
 *  4. builds the static app if needed and serves it on http://localhost:4173.
 *
 * Env: FORK_URLS, FORK_BLOCK_NUMBER, FOUNDRY_BIN, ANVIL_PORT, PORT, REBUILD=1, RESET=1 (with READY_FILE for tests).
 * Only public Anvil development keys are used. Never fund them on a real network.
 */
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ORDER_SIDE,
  type SignedOrder,
  signReferenceOrder,
} from "@session-firewall/sdk";
import { http, createPublicClient, defineChain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  ANVIL_KEYS,
  LOCAL_CHAIN_ID,
  deployAll,
} from "../../../packages/sdk/scripts/local-env.ts";
import {
  type RuntimeConfig,
  serializeRuntimeConfig,
} from "../src/lib/config.ts";

const here = dirname(fileURLToPath(import.meta.url));
const webDir = join(here, "..");
const outDir = join(webDir, "out");
const repoRoot = join(webDir, "../..");

const FORK_URLS = (
  process.env.FORK_URLS ??
  "https://ethereum-sepolia-rpc.publicnode.com,https://sepolia.drpc.org"
)
  .split(",")
  .filter(Boolean);
// Pinned so runs are reproducible. Override when the provider has pruned this state.
const FORK_BLOCK = process.env.FORK_BLOCK_NUMBER ?? "12080000";
const ANVIL_PORT = Number(process.env.ANVIL_PORT ?? 8546);
const PORT = Number(process.env.PORT ?? 4173);
const QUESTION = "Will it rain tomorrow?";

function foundry(name: string): string {
  if (process.env.FOUNDRY_BIN) return join(process.env.FOUNDRY_BIN, name);
  const p = join(homedir(), ".foundry/bin", name);
  return existsSync(p) ? p : name;
}

async function rpc(
  url: string,
  method: string,
  params: unknown[] = [],
): Promise<unknown> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const j = (await r.json()) as {
    result?: unknown;
    error?: { message: string };
  };
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
}

async function startAnvil(): Promise<{ proc: ChildProcess; url: string }> {
  const url = `http://127.0.0.1:${ANVIL_PORT}`;
  for (const forkUrl of FORK_URLS) {
    const proc = spawn(
      foundry("anvil"),
      [
        "--fork-url",
        forkUrl,
        "--fork-block-number",
        FORK_BLOCK,
        "--chain-id",
        String(LOCAL_CHAIN_ID),
        // Local Smart Sessions build only; see docs/decisions.md V13. Not deployable publicly as is.
        "--disable-code-size-limit",
        "--port",
        String(ANVIL_PORT),
        "--retries",
        "10",
        "--fork-retry-backoff",
        "1000",
        "--silent",
      ],
      { stdio: "ignore" },
    );
    const end = Date.now() + 45_000;
    while (Date.now() < end && proc.exitCode === null) {
      try {
        await rpc(url, "eth_chainId");
        return { proc, url };
      } catch {
        await new Promise((r) => setTimeout(r, 300));
      }
    }
    proc.kill();
    console.error(`Could not fork from ${forkUrl}, trying the next RPC.`);
  }
  throw new Error(
    "Could not start an Anvil fork of Ethereum Sepolia. Set FORK_URLS to a working RPC.",
  );
}

/** The public dev keys carry EIP-7702 delegations on Sepolia, which break the fixtures' ERC-1155 receive check. */
async function clearDevKeyCode(url: string) {
  for (const key of Object.values(ANVIL_KEYS)) {
    await rpc(url, "anvil_setCode", [privateKeyToAccount(key).address, "0x"]);
  }
}

async function signOrders(
  url: string,
  fx: { market: `0x${string}`; yesId: number; noId: number },
): Promise<SignedOrder[]> {
  const client = createPublicClient({
    chain: defineChain({
      id: LOCAL_CHAIN_ID,
      name: "fork",
      nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: { default: { http: [url] } },
    }),
    transport: http(url),
  });
  const { timestamp } = await client.getBlock();
  const maker = privateKeyToAccount(ANVIL_KEYS.maker);
  const expiry = timestamp + 365n * 86_400n;
  const levels: Array<[number, 0 | 1, bigint, bigint]> = [
    [fx.yesId, ORDER_SIDE.Sell, 500_000n, 2_000_000_000n],
    [fx.yesId, ORDER_SIDE.Sell, 520_000n, 5_000_000_000n],
    [fx.yesId, ORDER_SIDE.Buy, 480_000n, 2_000_000_000n],
    [fx.yesId, ORDER_SIDE.Buy, 450_000n, 5_000_000_000n],
    [fx.noId, ORDER_SIDE.Sell, 510_000n, 2_000_000_000n],
    [fx.noId, ORDER_SIDE.Sell, 530_000n, 5_000_000_000n],
    [fx.noId, ORDER_SIDE.Buy, 470_000n, 2_000_000_000n],
    [fx.noId, ORDER_SIDE.Buy, 440_000n, 5_000_000_000n],
  ];
  return Promise.all(
    levels.map(([tokenId, side, price, amount], i) =>
      signReferenceOrder(maker, {
        market: fx.market,
        chainId: LOCAL_CHAIN_ID,
        order: {
          tokenId: BigInt(tokenId),
          side,
          price,
          amount,
          expiry,
          salt: BigInt(i + 1),
        },
      }),
    ),
  );
}

const running: { anvil?: ChildProcess } = {};
const stop = () => {
  running.anvil?.kill();
  process.exit(0);
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
process.on("exit", () => running.anvil?.kill());

if (process.env.REBUILD === "1" || !existsSync(join(outDir, "index.html"))) {
  console.log("Building the SDK and the web app…");
  execFileSync("pnpm", ["--filter", "@session-firewall/sdk", "build"], {
    cwd: repoRoot,
    stdio: "inherit",
  });
  execFileSync("pnpm", ["--filter", "@session-firewall/web", "build"], {
    cwd: repoRoot,
    stdio: "inherit",
  });
}

console.log(`Forking Ethereum Sepolia at block ${FORK_BLOCK}…`);
const started = await startAnvil();
running.anvil = started.proc;
await clearDevKeyCode(started.url);
console.log("Deploying contracts and fixtures (about a minute)…");
const fromBlock = BigInt((await rpc(started.url, "eth_blockNumber")) as string);
const { addresses, fixtures } = deployAll(started.url);
const orders = await signOrders(started.url, fixtures);

const config: RuntimeConfig = {
  network: {
    chainId: LOCAL_CHAIN_ID,
    name: "Ethereum Sepolia fork (local demo)",
    rpcUrl: started.url,
  },
  deployment: {
    addresses,
    fromBlock,
    market: {
      address: fixtures.market,
      adapter: fixtures.adapter,
      usdc: fixtures.usdc,
      shares: fixtures.shares,
      question: QUESTION,
      yesId: BigInt(fixtures.yesId),
      noId: BigInt(fixtures.noId),
      orders,
    },
  },
  local: { bundlerPrivateKey: ANVIL_KEYS.bundler, faucet: true },
};
// Written to the served folder only: the source runtime-config.json stays the public default.
writeFileSync(
  join(outDir, "runtime-config.json"),
  serializeRuntimeConfig(config),
);

const { serve } = (await import("./serve.mjs" as string)) as {
  serve: (o: { dir: string; port: number }) => Promise<unknown>;
};
await serve({ dir: outDir, port: PORT });
console.log(
  `\nDemo ready: http://localhost:${PORT}\nRPC: ${started.url}. Press Ctrl+C to stop.`,
);
