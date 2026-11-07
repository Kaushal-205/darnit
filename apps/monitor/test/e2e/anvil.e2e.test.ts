/**
 * End to end: Anvil -> FirewallModule -> `ponder start` (PGlite) -> /alerts -> `worker/main.ts` as a real
 * process -> signed webhook into a fake receiver in this test. Subscribing goes through the HTTP API with
 * a real EIP-191 signature, checked on Anvil.
 *
 * Needs `anvil` (Foundry) on PATH or in ~/.foundry/bin, and `forge build` output in contracts/out.
 *
 * Plain EOAs play the accounts: the module keys state by msg.sender, so `onInstall` then `queue` is enough.
 * The hook is an EOA too, so it can call `consume`. EntryPoint and Safe7579 are small hand-assembled log
 * emitters placed with anvil_setCode, which lets the test produce their exact events without a real
 * user operation. Only the log shape matters to the indexer.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { type Server, createServer as createHttpServer } from "node:http";
import { createServer } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import {
  http,
  type Address,
  type Hex,
  concat,
  createPublicClient,
  createTestClient,
  createWalletClient,
  encodeAbiParameters,
  encodeErrorResult,
  encodeEventTopics,
  numberToHex,
  size,
  zeroAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EntryPointAbi } from "../../abis/EntryPoint.ts";
import { FirewallErrorsAbi } from "../../abis/FirewallErrors.ts";
import { FirewallModuleAbi } from "../../abis/FirewallModule.ts";
import { Safe7579Abi } from "../../abis/Safe7579.ts";
import {
  SIGNATURE_HEADER,
  verifyWebhookSignature,
} from "../../src/lib/webhook.ts";
import { subscriptionMessage } from "../../worker/api.ts";

const ROOT = join(import.meta.dirname, "..", "..");
const ARTIFACT = join(
  ROOT,
  "..",
  "..",
  "contracts",
  "out",
  "FirewallModule.sol",
  "FirewallModule.json",
);
const ENTRY_POINT: Address = "0x00000000000000000000000000000000000000e7";
const SAFE7579: Address = "0x0000000000000000000000000000000000007579";
const APP_URL = "https://app.example";

// Anvil's default keys: public test keys, never used outside a local devnet.
const DEPLOYER = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);
const ACCOUNT = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);
const SAFE_LIKE = privateKeyToAccount(
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
);

const word = (n: number) => numberToHex(n, { size: 1 }).slice(2);

/** Runtime that emits calldata as LOGn: the first n words are topics, the rest is data. */
function logEmitter(n: number): Hex {
  let code = "";
  for (let i = n - 1; i >= 0; i--) code += `60${word(i * 32)}35`;
  const h = word(n * 32);
  code += `60${h}360380`; // size = calldatasize - h, kept on the stack
  code += `60${h}600037`; // calldatacopy(0, h, size)
  code += `6000${word(0xa0 + n)}00`; // logN(0, size, topic0, ...), stop
  return `0x${code}`;
}

/** Runtime that makes these calls in order: a Safe forwarding to its fallback handler, or a bundle. */
function callSequence(calls: { to: Address; data: Hex }[]): Hex {
  const head = 44;
  let offset = calls.length * head + 1;
  let code = "";
  for (const c of calls) {
    const len = numberToHex(size(c.data), { size: 2 }).slice(2);
    code += `61${len}61${numberToHex(offset, { size: 2 }).slice(2)}600039`; // codecopy(0, offset, len)
    code += `6000600061${len}60006000`; // retSize, retOffset, argsSize, argsOffset, value
    code += `73${c.to.slice(2)}5af150`; // to, gas, call, pop
    offset += size(c.data);
  }
  return `0x${code}00${calls.map((c) => c.data.slice(2)).join("")}`;
}

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

async function waitFor<T>(
  fn: () => Promise<T | undefined> | T | undefined,
  timeoutMs: number,
  what: string,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const v = await fn();
      if (v !== undefined) return v;
    } catch {
      // not yet
    }
    if (Date.now() > deadline)
      throw new Error(
        `timed out waiting for ${what}\n${logs.join("").slice(-4000)}`,
      );
    await new Promise((r) => setTimeout(r, 100));
  }
}

type Received = {
  at: number;
  body: string;
  signature: string;
  json: {
    id: string;
    type: string;
    severity: string;
    account: Address;
    title: string;
    lines: string[];
    links: { label: string; url: string }[];
    facts: Record<string, unknown>;
  };
};

const procs: ChildProcess[] = [];
const logs: string[] = [];
const received: Received[] = [];
let receiver: Server;
let pgliteDir = "";

function capture(p: ChildProcess) {
  p.stdout?.on("data", (d) => logs.push(String(d)));
  p.stderr?.on("data", (d) => logs.push(String(d)));
  procs.push(p);
}

describe("e2e: on-chain event -> delivered alert", () => {
  let rpcUrl = "";
  let module: Address = zeroAddress;
  let hookUrl = "";
  let accountSecret = "";

  const chain = () => ({
    ...foundry,
    rpcUrls: { default: { http: [rpcUrl] } },
  });
  const pub = () =>
    createPublicClient({ chain: chain(), transport: http(rpcUrl) });
  const wallet = (account: typeof DEPLOYER) =>
    createWalletClient({ account, chain: chain(), transport: http(rpcUrl) });
  const testClient = () =>
    createTestClient({
      mode: "anvil",
      chain: chain(),
      transport: http(rpcUrl),
    });

  const sentFor = (account: Address, rule: string) =>
    received.filter((r) => r.json.account === account && r.json.type === rule);
  const waitAlert = (
    account: Address,
    rule: string,
    timeoutMs = 60_000,
    count = 1,
  ) =>
    waitFor(
      () => {
        const rows = sentFor(account, rule);
        return rows.length >= count ? rows[count - 1] : undefined;
      },
      timeoutMs,
      `${rule} alert`,
    );

  async function mined(hash: Hex) {
    return pub().waitForTransactionReceipt({ hash, pollingInterval: 100 });
  }

  async function install(account: typeof DEPLOYER) {
    const data = encodeAbiParameters(
      [
        { type: "uint128" },
        { type: "address[]" },
        { type: "address[]" },
        { type: "address[]" },
        { type: "address[]" },
      ],
      [
        1_000_000_000n,
        [],
        ["0x00000000000000000000000000000000000000d1"],
        [],
        [],
      ],
    );
    await mined(
      await wallet(account).writeContract({
        address: module,
        abi: FirewallModuleAbi,
        functionName: "onInstall",
        args: [data],
      }),
    );
  }

  async function subscribe(api: string, account: typeof DEPLOYER) {
    const contacts = [{ type: "webhook" as const, url: hookUrl }];
    const issuedAt = Math.floor(Date.now() / 1000);
    const nonce = `e2e${account.address.slice(2, 14)}`;
    const message = subscriptionMessage({
      action: "subscribe",
      account: account.address,
      chainId: 31337,
      contacts,
      issuedAt,
      nonce,
    });
    const res = await fetch(`${api}/v1/subscribe`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        account: account.address,
        channels: contacts,
        issuedAt,
        nonce,
        signature: await account.signMessage({ message }),
      }),
    });
    expect(res.status).toBe(200);
    return ((await res.json()) as { webhookSecrets: Record<string, string> })
      .webhookSecrets[hookUrl] as string;
  }

  beforeAll(async () => {
    if (!existsSync(ARTIFACT))
      throw new Error("run `forge build` in contracts/ first");

    const anvilPort = await freePort();
    rpcUrl = `http://127.0.0.1:${anvilPort}`;
    procs.push(
      spawn(
        anvilBin(),
        ["--port", String(anvilPort), "--block-time", "2", "--silent"],
        { stdio: "ignore" },
      ),
    );
    await waitFor(() => pub().getBlockNumber(), 20_000, "anvil");

    await testClient().setCode({ address: SAFE7579, bytecode: logEmitter(1) });

    // The hook is the deployer, so the test can call consume(). The rest only has to be non-zero.
    const bytecode = JSON.parse(readFileSync(ARTIFACT, "utf8")).bytecode
      .object as Hex;
    const deployTx = await wallet(DEPLOYER).deployContract({
      abi: FirewallModuleAbi,
      bytecode,
      args: [
        DEPLOYER.address,
        "0x000000000000000000000000000000000000000b",
        "0x000000000000000000000000000000000000000c",
        "0x000000000000000000000000000000000000000d",
      ],
    });
    module = (await mined(deployTx)).contractAddress as Address;
    await install(ACCOUNT);
    await install(SAFE_LIKE);

    receiver = createHttpServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString();
        received.push({
          at: Date.now(),
          body,
          signature: String(req.headers[SIGNATURE_HEADER.toLowerCase()]),
          json: JSON.parse(body),
        });
        res.end("ok");
      });
    });
    await new Promise<void>((r) => receiver.listen(0, "127.0.0.1", r));
    const addr = receiver.address();
    hookUrl = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}/hook`;

    const ponderPort = await freePort();
    const ponderUrl = `http://127.0.0.1:${ponderPort}`;
    pgliteDir = mkdtempSync(join(tmpdir(), "monitor-e2e-"));
    const shared = {
      ...process.env,
      DATABASE_URL: "",
      CHAIN_ID: "31337",
      RPC_URLS: rpcUrl,
    };
    capture(
      spawn(
        join(ROOT, "node_modules", ".bin", "ponder"),
        ["start", "--port", String(ponderPort), "--schema", "e2e"],
        {
          cwd: ROOT,
          env: {
            ...shared,
            PGLITE_DIR: pgliteDir,
            FIREWALL_MODULE: module,
            ENTRYPOINT_ADDRESS: ENTRY_POINT,
            SAFE7579_ADDRESS: SAFE7579,
            START_BLOCK: "0",
            PONDER_TELEMETRY_DISABLED: "true",
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      ),
    );
    await waitFor(
      async () => ((await fetch(`${ponderUrl}/ready`)).ok ? true : undefined),
      90_000,
      "ponder /ready",
    );

    const apiPort = await freePort();
    const api = `http://127.0.0.1:${apiPort}`;
    capture(
      spawn(
        process.execPath,
        ["--experimental-strip-types", "worker/main.ts"],
        {
          cwd: ROOT,
          env: {
            ...shared,
            APP_URL,
            INDEXER_URL: ponderUrl,
            PORT: String(apiPort),
            WEBHOOK_SIGNING_SECRET: "e2e-master-secret",
            ALLOW_INSECURE_WEBHOOKS: "true",
            EMAIL_API_KEY: "",
            TELEGRAM_BOT_TOKEN: "",
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      ),
    );
    await waitFor(
      async () => ((await fetch(`${api}/health`)).ok ? true : undefined),
      20_000,
      "worker /health",
    );

    accountSecret = await subscribe(api, ACCOUNT);
    await subscribe(api, SAFE_LIKE);
  }, 180_000);

  afterAll(() => {
    for (const p of procs) p.kill("SIGTERM");
    receiver?.close();
    if (pgliteDir) rmSync(pgliteDir, { recursive: true, force: true });
  });

  it("rule 1: delivers each ChangeQueued in under 60 s, signed, with decoded data and a cancel link", async () => {
    const samples: number[] = [];
    for (let i = 0; i < 3; i++) {
      const dest = `0x00000000000000000000000000000000000000f${i}` as Address;
      const sentAt = Date.now();
      await wallet(ACCOUNT).writeContract({
        address: module,
        abi: FirewallModuleAbi,
        functionName: "queue",
        args: [0, encodeAbiParameters([{ type: "address" }], [dest])],
      });
      const got = await waitAlert(
        ACCOUNT.address,
        "change_queued",
        60_000,
        i + 1,
      );
      samples.push(got.at - sentAt);

      expect(got.at - sentAt).toBeLessThan(60_000);
      expect(got.json.severity).toBe("high");
      expect(got.json.facts.kind).toBe("AddDestination");
      expect(got.json.lines[0]?.toLowerCase()).toContain(dest);
      expect(got.json.links[0]?.url).toBe(
        `${APP_URL}/settings?account=${ACCOUNT.address}#cancel-${got.json.facts.changeId}`,
      );
      expect(got.json.links[1]?.url).toBe(
        `${APP_URL}/settings?account=${ACCOUNT.address}#freeze`,
      );
      expect(
        verifyWebhookSignature({
          secret: accountSecret,
          header: got.signature,
          body: got.body,
        }).ok,
      ).toBe(true);
    }
    console.log(
      `[e2e] ChangeQueued latency, tx send to webhook received, 2 s blocks: ${samples.join(" ms, ")} ms`,
    );
  }, 200_000);

  it("rule 2: alerts once when more than 80% of the cap is consumed in the hour", async () => {
    const consume = async (amount: bigint) =>
      mined(
        await wallet(DEPLOYER).writeContract({
          address: module,
          abi: FirewallModuleAbi,
          functionName: "consume",
          args: [ACCOUNT.address, amount],
        }),
      );
    await consume(500_000_000n);
    await consume(350_000_000n); // 85%
    const got = await waitAlert(ACCOUNT.address, "budget_80");
    expect(got.json.title).toContain("85%");
    await consume(100_000_000n); // 95%: inside the cooldown, so no second alert
    await new Promise((r) => setTimeout(r, 6_000));
    expect(sentFor(ACCOUNT.address, "budget_80")).toHaveLength(1);
  }, 90_000);

  it("rule 3: alerts on blocked attempts of firewall accounts only, decoding V10's two shapes", async () => {
    await testClient().setCode({
      address: ENTRY_POINT,
      bytecode: logEmitter(3),
    });
    const revert = async (sender: Address, tag: string, reason: Hex) => {
      const topics = encodeEventTopics({
        abi: EntryPointAbi,
        eventName: "UserOperationRevertReason",
        args: { userOpHash: `0x${tag.repeat(32)}`, sender },
      }) as Hex[];
      const data = encodeAbiParameters(
        [{ type: "uint256" }, { type: "bytes" }],
        [7n, reason],
      );
      await mined(
        await wallet(DEPLOYER).sendTransaction({
          to: ENTRY_POINT,
          data: concat([...topics, data]),
        }),
      );
    };

    const stranger: Address = "0x00000000000000000000000000000000000000cc";
    await revert(stranger, "aa", "0xdeadbeef");
    await revert(
      ACCOUNT.address,
      "bb",
      encodeErrorResult({
        abi: FirewallErrorsAbi,
        errorName: "BudgetExceeded",
        args: [2_000_000n, 1_000_000n],
      }),
    );
    await revert(
      ACCOUNT.address,
      "cc",
      encodeErrorResult({ abi: Safe7579Abi, errorName: "ExecutionFailed" }),
    );

    await waitAlert(ACCOUNT.address, "blocked_attempt", 60_000, 2);
    const names = sentFor(ACCOUNT.address, "blocked_attempt").map(
      (r) => r.json.facts.errorName,
    );
    expect(names).toEqual(["BudgetExceeded", "ExecutionFailed"]);
    expect(sentFor(stranger, "blocked_attempt")).toHaveLength(0);
  }, 90_000);

  it("rule 4: critical exit alert, attributed from a direct Safe call and from a user operation", async () => {
    const hook: Address = "0x00000000000000000000000000000000000000ab";
    const request = (time: bigint): Hex =>
      concat([
        ...(encodeEventTopics({
          abi: Safe7579Abi,
          eventName: "EmergencyHookUninstallRequest",
        }) as Hex[]),
        encodeAbiParameters(
          [{ type: "address" }, { type: "uint256" }],
          [hook, time],
        ),
      ]);
    const now = BigInt(Math.floor(Date.now() / 1000));

    // Direct call: tx.to is the Safe, which forwards to Safe7579 as its fallback handler.
    await testClient().setCode({
      address: SAFE_LIKE.address,
      bytecode: callSequence([{ to: SAFE7579, data: request(now) }]),
    });
    await mined(
      await wallet(DEPLOYER).sendTransaction({
        to: SAFE_LIKE.address,
        gas: 500_000n,
      }),
    );
    const direct = await waitAlert(SAFE_LIKE.address, "emergency_uninstall");
    expect(direct.json.severity).toBe("critical");
    expect(direct.json.title).toContain("Exit now");
    expect(direct.json.links).toEqual([
      { label: "Exit now", url: `${APP_URL}/exit` },
    ]);

    // A bundle: the request, then this op's UserOperationEvent, then a later op of another account.
    await testClient().setCode({
      address: ENTRY_POINT,
      bytecode: logEmitter(4),
    });
    const opEvent = (sender: Address): Hex =>
      concat([
        ...(encodeEventTopics({
          abi: EntryPointAbi,
          eventName: "UserOperationEvent",
          args: {
            userOpHash: `0x${"dd".repeat(32)}`,
            sender,
            paymaster: zeroAddress,
          },
        }) as Hex[]),
        encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "bool" },
            { type: "uint256" },
            { type: "uint256" },
          ],
          [0n, true, 1n, 1n],
        ),
      ]);
    const bundler: Address = "0x00000000000000000000000000000000000000b0";
    await testClient().setCode({
      address: bundler,
      bytecode: callSequence([
        { to: SAFE7579, data: request(now + 1n) },
        { to: ENTRY_POINT, data: opEvent(ACCOUNT.address) },
        { to: ENTRY_POINT, data: opEvent(SAFE_LIKE.address) },
      ]),
    });
    await mined(
      await wallet(DEPLOYER).sendTransaction({ to: bundler, gas: 1_000_000n }),
    );
    const viaUserOp = await waitAlert(ACCOUNT.address, "emergency_uninstall");
    expect(viaUserOp.json.severity).toBe("critical");
    expect(sentFor(SAFE_LIKE.address, "emergency_uninstall")).toHaveLength(1);
  }, 90_000);

  it("rule 5: FreezeActivated and SessionsRevoked are informational, and each alert arrives once", async () => {
    await mined(
      await wallet(ACCOUNT).writeContract({
        address: module,
        abi: FirewallModuleAbi,
        functionName: "revokeSessions",
      }),
    );
    const revoked = await waitAlert(ACCOUNT.address, "sessions_revoked");
    expect(revoked.json.severity).toBe("info");
    await mined(
      await wallet(ACCOUNT).writeContract({
        address: module,
        abi: FirewallModuleAbi,
        functionName: "freeze",
      }),
    );
    const frozen = await waitAlert(ACCOUNT.address, "freeze");
    expect(frozen.json.severity).toBe("info");

    await new Promise((r) => setTimeout(r, 4_000));
    expect(sentFor(ACCOUNT.address, "freeze")).toHaveLength(1);
    expect(sentFor(ACCOUNT.address, "change_queued")).toHaveLength(3);
    expect(new Set(received.map((r) => r.json.id)).size).toBe(received.length);
  }, 60_000);
});
