/**
 * End to end: Anvil -> FirewallModule -> Ponder (`ponder start`, PGlite) -> /alerts -> dispatcher -> fake channel.
 *
 * Needs `anvil` (Foundry) on PATH or in ~/.foundry/bin, and `forge build` output in contracts/out.
 * A plain EOA plays the account: it calls `onInstall` then `queue`, which is enough for the indexer
 * (the module keys state by msg.sender). Asserts the alert arrives < 60 s after the queue tx is mined.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import {
  type Hex,
  createPublicClient,
  createWalletClient,
  encodeAbiParameters,
  http,
  parseEther,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FirewallModuleAbi } from "../../abis/FirewallModule.ts";
import { fakeChannel } from "../../worker/channels.ts";
import { createDispatcher, httpSource } from "../../worker/dispatcher.ts";
import { memoryStore } from "../../worker/store.ts";

const ROOT = join(import.meta.dirname, "..", "..");
const ARTIFACT = join(ROOT, "..", "..", "contracts", "out", "FirewallModule.sol", "FirewallModule.json");
// Anvil's first default key (public test key, never used outside a local devnet).
const DEPLOYER = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const ACCOUNT = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

function anvilBin(): string {
  const local = join(homedir(), ".foundry", "bin", "anvil");
  return existsSync(local) ? local : "anvil";
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.listen(0, () => {
      const addr = s.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      s.close(() => resolve(port));
    });
    s.on("error", reject);
  });
}

async function waitFor<T>(fn: () => Promise<T | undefined>, timeoutMs: number, what: string): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const v = await fn();
      if (v !== undefined) return v;
    } catch {
      // not yet
    }
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

const procs: ChildProcess[] = [];
let pgliteDir = "";
const logs: string[] = [];

describe("e2e: queue -> alert on Anvil", () => {
  let rpcUrl = "";
  let ponderUrl = "";
  let module: Hex = "0x";

  beforeAll(async () => {
    if (!existsSync(ARTIFACT)) throw new Error("run `forge build` in contracts/ first");
    const anvilPort = await freePort();
    rpcUrl = `http://127.0.0.1:${anvilPort}`;
    const anvil = spawn(anvilBin(), ["--port", String(anvilPort), "--block-time", "1", "--silent"], { stdio: "ignore" });
    procs.push(anvil);
    const chain = { ...foundry, rpcUrls: { default: { http: [rpcUrl] } } };
    const pub = createPublicClient({ chain, transport: http(rpcUrl) });
    await waitFor(() => pub.getBlockNumber(), 20_000, "anvil");

    // Deploy FirewallModule. Constructor args only need to be non-zero for queue/onInstall.
    const deployer = createWalletClient({ account: DEPLOYER, chain, transport: http(rpcUrl) });
    const bytecode = JSON.parse(readFileSync(ARTIFACT, "utf8")).bytecode.object as Hex;
    const deployTx = await deployer.deployContract({
      abi: FirewallModuleAbi,
      bytecode,
      args: [
        "0x000000000000000000000000000000000000000a",
        "0x000000000000000000000000000000000000000b",
        "0x000000000000000000000000000000000000000c",
        "0x000000000000000000000000000000000000000d",
      ],
    });
    const deployed = await pub.waitForTransactionReceipt({ hash: deployTx });
    module = deployed.contractAddress as Hex;

    await deployer.sendTransaction({ to: ACCOUNT.address, value: parseEther("1") });
    const wallet = createWalletClient({ account: ACCOUNT, chain, transport: http(rpcUrl) });
    const installData = encodeAbiParameters(
      [{ type: "uint128" }, { type: "address[]" }, { type: "address[]" }, { type: "address[]" }, { type: "address[]" }],
      [1_000_000_000n, [], ["0x00000000000000000000000000000000000000d1"], [], []],
    );
    const installTx = await wallet.writeContract({ address: module, abi: FirewallModuleAbi, functionName: "onInstall", args: [installData] });
    await pub.waitForTransactionReceipt({ hash: installTx });

    // Start the indexer.
    const ponderPort = await freePort();
    ponderUrl = `http://127.0.0.1:${ponderPort}`;
    pgliteDir = mkdtempSync(join(tmpdir(), "monitor-e2e-"));
    const ponder = spawn(join(ROOT, "node_modules", ".bin", "ponder"), ["start", "--port", String(ponderPort), "--schema", "e2e"], {
      cwd: ROOT,
      env: {
        ...process.env,
        DATABASE_URL: "",
        PGLITE_DIR: pgliteDir,
        CHAIN_ID: "31337",
        RPC_URLS: rpcUrl,
        FIREWALL_MODULE: module,
        START_BLOCK: "0",
        PONDER_POLLING_INTERVAL_MS: "1000",
        PONDER_TELEMETRY_DISABLED: "true",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    ponder.stdout?.on("data", (d) => logs.push(String(d)));
    ponder.stderr?.on("data", (d) => logs.push(String(d)));
    procs.push(ponder);
    await waitFor(
      async () => ((await fetch(`${ponderUrl}/ready`)).ok ? true : undefined),
      90_000,
      "ponder /ready",
    ).catch((e) => {
      throw new Error(`${e.message}\n${logs.join("").slice(-4000)}`);
    });
  }, 150_000);

  afterAll(() => {
    for (const p of procs) p.kill("SIGTERM");
    if (pgliteDir) rmSync(pgliteDir, { recursive: true, force: true });
  });

  it("delivers a ChangeQueued alert in under 60 seconds", async () => {
    const chain = { ...foundry, rpcUrls: { default: { http: [rpcUrl] } } };
    const pub = createPublicClient({ chain, transport: http(rpcUrl) });
    const wallet = createWalletClient({ account: ACCOUNT, chain, transport: http(rpcUrl) });

    const store = memoryStore();
    await store.addSubscriptions(ACCOUNT.address, [{ type: "telegram", chatId: "42" }]);
    const fake = fakeChannel("telegram");
    const dispatcher = createDispatcher({
      store,
      source: httpSource(ponderUrl),
      channels: { telegram: fake.channel },
      appUrl: "https://app.example",
      log: { info() {}, warn() {} },
    });
    dispatcher.start(500);

    try {
      const dest = "0x00000000000000000000000000000000000000d2";
      const hash = await wallet.writeContract({
        address: module,
        abi: FirewallModuleAbi,
        functionName: "queue",
        args: [0, encodeAbiParameters([{ type: "address" }], [dest])],
      });
      const receipt = await pub.waitForTransactionReceipt({ hash, pollingInterval: 100 });
      const block = await pub.getBlock({ blockNumber: receipt.blockNumber });
      const minedAtMs = Number(block.timestamp) * 1000;
      const confirmedAt = Date.now();

      const delivery = await waitFor(async () => fake.deliveries.find((d) => d.alert.rule === "change_queued"), 60_000, "alert");
      const sinceMined = delivery.at - minedAtMs;
      const sinceReceipt = delivery.at - confirmedAt;
      console.log(`[e2e] ChangeQueued alert latency: ${sinceMined} ms after block timestamp, ${sinceReceipt} ms after receipt`);

      expect(sinceMined).toBeLessThan(60_000);
      expect(delivery.alert.account).toBe(ACCOUNT.address);
      expect(delivery.alert.facts.kind).toBe("AddDestination");
      expect(delivery.alert.lines[0]).toContain("Add withdrawal destination 0x00000000000000000000000000000000000000D2");
      const changeId = delivery.alert.facts.changeId as string;
      expect(delivery.alert.links[0]?.url).toBe(
        `https://app.example/settings?account=${ACCOUNT.address}#cancel-${changeId}`,
      );

      // Freeze -> informational alert, delivered once.
      const freezeTx = await wallet.writeContract({ address: module, abi: FirewallModuleAbi, functionName: "freeze" });
      await pub.waitForTransactionReceipt({ hash: freezeTx });
      await waitFor(async () => fake.deliveries.find((d) => d.alert.rule === "freeze"), 30_000, "freeze alert");
      await new Promise((r) => setTimeout(r, 1_500));
      expect(fake.deliveries.filter((d) => d.alert.rule === "change_queued")).toHaveLength(1);
      expect(fake.deliveries.filter((d) => d.alert.rule === "freeze")).toHaveLength(1);
    } finally {
      dispatcher.stop();
    }
  }, 120_000);
});
