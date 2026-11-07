/**
 * The exit page against a local Anvil fork of Ethereum Sepolia with the real Safe, Safe7579, EntryPoint
 * and our contracts. The "main website" (firewall.test) does not exist, so it is unreachable throughout.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { type Page, expect, test } from "@playwright/test";
import {
  http,
  type Address,
  type Hex,
  createTestClient,
  createWalletClient,
  decodeEventLog,
  encodeFunctionData,
  getAddress,
  parseEther,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { localClientConfig } from "../../../packages/sdk/scripts/demo.js";
import {
  ANVIL_KEYS,
  CONTRACTS_DIR,
  type LocalEnv,
  startLocalEnv,
} from "../../../packages/sdk/scripts/local-env.js";
import {
  type FirewallAccount,
  ORDER_SIDE,
  approveMarket,
  buildAccountInit,
  createFirewallAccount,
  createSession,
  executeAsOwner,
  executeChange,
  fill,
  firewallModuleAbi,
  freeze,
  getFirewallState,
  mockUsdcAbi,
  outcomeSharesAbi,
  signReferenceOrder,
} from "../../../packages/sdk/src/index.js";
import {
  addVirtualAuthenticator,
  serveFile,
  softwareKey,
  startMockBundler,
} from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const EXIT_HTML = join(here, "../dist/exit.html");
const MAIN_RP = "firewall.test";
const HOURLY_CAP = 100_000_000n; // $100
const MINTED = 1_000_000_000n; // $1,000
const SHARES_BOUGHT = 200_000_000n; // 200 YES at $0.50 uses the whole $100 budget

// Ethereum Sepolia unless overridden; `local-env` still defaults to Base on main.
process.env.FORK_URLS ||=
  "https://ethereum-sepolia-rpc.publicnode.com,https://sepolia.drpc.org";
process.env.FORK_BLOCK_NUMBER ||= "12080000";

let env: LocalEnv;
let account: FirewallAccount;
let mainKey: ReturnType<typeof softwareKey>;
let recoveryValidator: Address;
let server: Awaited<ReturnType<typeof serveFile>>;
let page: Page;
const destination = privateKeyToAccount(generatePrivateKey()).address;

const usdcOf = (who: Address) =>
  account.client.publicClient.readContract({
    address: env.fixtures.usdc,
    abi: mockUsdcAbi,
    functionName: "balanceOf",
    args: [who],
  });
const yesOf = (who: Address) =>
  account.client.publicClient.readContract({
    address: env.fixtures.shares,
    abi: outcomeSharesAbi,
    functionName: "balanceOf",
    args: [who, BigInt(env.fixtures.yesId)],
  });

async function connect(
  p: Page,
  submit: { eoa: Hex } | { bundler: string } = { eoa: ANVIL_KEYS.bundler },
) {
  await p.fill("#rpc", env.rpcUrl);
  await p.fill("#chain-id", "31337");
  await p.fill("#account", account.address);
  if ("eoa" in submit) {
    await p.check('input[name="submit"][value="eoa"]');
    await p.fill("#eoa-key", submit.eoa);
  } else await p.fill("#bundler", submit.bundler);
  await p.click("#connect-btn");
  await expect(p.locator("#connect-status")).toHaveText("Connected.", {
    timeout: 60_000,
  });
}

async function moved(p: Page) {
  await expect(p.locator("#result")).toBeVisible({ timeout: 120_000 });
  await expect(p.locator("#move-status")).toHaveClass(/good/);
  await expect(p.locator("#result-userop")).toHaveText(/^0x[0-9a-f]{64}$/);
  await expect(p.locator("#result-tx")).toHaveText(/^0x[0-9a-f]{64}$/);
}

test.describe.serial("exit page", () => {
  test.beforeAll(async ({ browser }) => {
    test.setTimeout(15 * 60_000);
    env = await startLocalEnv();
    const client = localClientConfig(env);
    const { publicClient, addresses } = client;
    const testClient = createTestClient({
      chain: publicClient.chain,
      mode: "anvil",
      transport: http(env.rpcUrl),
    });
    const deployer = createWalletClient({
      chain: publicClient.chain,
      transport: http(env.rpcUrl),
      account: privateKeyToAccount(ANVIL_KEYS.deployer),
    });
    const fx = env.fixtures;

    // The main key: bound to the website, used by the app.
    mainKey = softwareKey(addresses.ownerValidator, MAIN_RP);
    const params = {
      owner: mainKey.owner,
      destinations: [destination],
      markets: [{ market: fx.market, adapter: fx.adapter }],
      tokens: [fx.usdc],
      hourlyCap: HOURLY_CAP,
      saltNonce: BigInt(Date.now()),
    };
    const predicted = (await buildAccountInit(client, params)).address;
    await testClient.setBalance({
      address: predicted,
      value: parseEther("5"),
    });
    account = await createFirewallAccount(client, params);

    // A second, unmodified deployment of the owner validator holds the recovery key.
    const artifact = JSON.parse(
      readFileSync(
        join(
          CONTRACTS_DIR,
          "out/FirewallOwnerValidator.sol/FirewallOwnerValidator.json",
        ),
        "utf8",
      ),
    );
    const deployTx = await deployer.deployContract({
      abi: artifact.abi,
      bytecode: artifact.bytecode.object,
      args: [addresses.module],
    });
    const deployed = await publicClient.waitForTransactionReceipt({
      hash: deployTx,
    });
    recoveryValidator = getAddress(deployed.contractAddress as Address);

    // Enrol through the page itself, on http://localhost, using the calldata it prints.
    server = await serveFile(readFileSync(EXIT_HTML, "utf8"));
    const context = await browser.newContext();
    page = await context.newPage();
    await addVirtualAuthenticator(page);
    await page.goto(server.url);
    await page.fill("#account", account.address);
    await page.locator("#recovery summary").click();
    await page.fill("#recovery-validator", recoveryValidator);
    await page.click("#recovery-btn");
    await expect(page.locator("#recovery-status")).toHaveClass(/good/);
    const printed = (await page.locator("#recovery-out").textContent()) ?? "";
    const calldata = /calldata: (0x[0-9a-f]+)/.exec(printed)?.[1] as Hex;
    expect(calldata).toBeTruthy();

    const queued = await executeAsOwner(account, [
      { to: addresses.module, data: calldata },
    ]);
    let changeId: Hex | undefined;
    for (const log of queued.logs) {
      try {
        const ev = decodeEventLog({
          abi: firewallModuleAbi,
          data: log.data,
          topics: log.topics,
        });
        if (ev.eventName === "ChangeQueued") changeId = ev.args.id;
      } catch {
        // other events
      }
    }
    expect(changeId).toBeTruthy();
    await testClient.increaseTime({ seconds: 86_401 });
    await testClient.mine({ blocks: 1 });
    await executeChange(account, changeId as Hex);

    // Fund, buy shares until the budget is gone, freeze.
    await publicClient.waitForTransactionReceipt({
      hash: await deployer.sendTransaction({
        to: fx.usdc,
        data: encodeFunctionData({
          abi: mockUsdcAbi,
          functionName: "mint",
          args: [account.address, MINTED],
        }),
      }),
    });
    await approveMarket(account, {
      token: fx.usdc,
      market: fx.market,
      amount: 2n ** 256n - 1n,
    });
    const now = (await publicClient.getBlock()).timestamp;
    const session = await createSession(account, {
      expiresAt: Number(now) + 3_600,
      markets: [fx.market],
    });
    const maker = privateKeyToAccount(ANVIL_KEYS.maker);
    for (const salt of [1n, 2n]) {
      const order = await signReferenceOrder(maker, {
        market: fx.market,
        chainId: publicClient.chain.id,
        order: {
          tokenId: BigInt(fx.yesId),
          side: ORDER_SIDE.Sell,
          price: 500_000n,
          amount: SHARES_BOUGHT / 2n,
          expiry: now + 86_400n,
          salt: BigInt(Date.now()) + salt,
        },
      });
      await fill(account, session, {
        market: fx.market,
        order,
        amount: SHARES_BOUGHT / 2n,
      });
    }
    const spent = await getFirewallState(account);
    expect(spent.availableBudget).toBeLessThan(1_000_000n);
    await freeze(account);
    const frozen = await getFirewallState(account);
    expect(frozen.config.frozen).toBe(true);
    expect(frozen.availableBudget).toBe(0n);
    expect(await yesOf(account.address)).toBe(SHARES_BOUGHT);
    expect(await usdcOf(account.address)).toBe(MINTED - 100_000_000n);
    console.log(
      `account ${account.address} frozen, budget 0; recovery validator ${recoveryValidator}`,
    );
  });

  test.afterAll(() => {
    server?.close();
    env?.stop();
  });

  test("the browser refuses the website's passkey on other origins (recorded facts)", async ({
    browser,
  }) => {
    const attempt = (rpId: string) =>
      async function run(p: Page) {
        return p.evaluate(async (id) => {
          try {
            await navigator.credentials.get({
              publicKey: {
                challenge: new Uint8Array(32),
                rpId: id,
                userVerification: "required",
                timeout: 5_000,
              },
            });
            return "signed";
          } catch (e) {
            return `${(e as Error).name}: ${(e as Error).message}`;
          }
        }, rpId);
      };
    const context = await browser.newContext();

    // localhost cannot claim the app's RP ID. firewall.test is unreachable, so the Related Origin
    // Requests lookup of https://firewall.test/.well-known/webauthn cannot succeed either.
    const local = await context.newPage();
    await addVirtualAuthenticator(local);
    await local.goto(server.url);
    const fromLocalhost = await attempt(MAIN_RP)(local);
    console.log(`localhost, rpId ${MAIN_RP} -> ${fromLocalhost}`);
    expect(fromLocalhost).toMatch(/^SecurityError/);

    // A page opened as a file has an opaque origin: no RP ID is usable.
    const file = await context.newPage();
    await addVirtualAuthenticator(file);
    await file.goto(pathToFileURL(EXIT_HTML).href);
    for (const rpId of ["localhost", MAIN_RP]) {
      const fromFile = await attempt(rpId)(file);
      console.log(`file://, rpId ${rpId} -> ${fromFile}`);
      expect(fromFile).not.toBe("signed");
    }
    await context.close();
  });

  test("from http://localhost: recovery passkey moves USDC and shares while frozen with no budget", async ({
    context,
  }) => {
    const requests: string[] = [];
    page.context().on("request", (r) => requests.push(r.url()));
    await page.goto(server.url);
    await connect(page);

    // Reads
    await expect(page.locator("#account-state")).toContainText(
      "Trading is paused",
    );
    await expect(page.locator("#destinations")).toContainText(destination);
    await expect(page.locator("#balances")).toContainText("900 USDC");
    await expect(page.locator("#balances")).toContainText("Market 1 YES");
    await expect(page.locator("#balances")).toContainText("200 shares");
    await expect(page.locator('input[name="key"]')).toHaveCount(2);

    // The browser itself now refuses any other connection (not only the fetch wrapper).
    const violation = await page.evaluate(
      () =>
        new Promise<string>((resolve) => {
          document.addEventListener("securitypolicyviolation", (e) =>
            resolve(`${e.effectiveDirective} ${e.blockedURI}`),
          );
          const x = new XMLHttpRequest();
          x.open("GET", "https://example.com/");
          x.send();
          setTimeout(() => resolve("no violation"), 3_000);
        }),
    );
    console.log(`CSP after Connect: ${violation}`);
    expect(violation).toContain("connect-src");
    expect(violation).toContain("example.com");

    // The wrong key is caught before anything is sent.
    await page.check(
      `input[name="key"][value="${account.owner.validator}"]`,
    );
    await page.selectOption("#destination", destination);
    await page.selectOption("#asset", `token:${env.fixtures.usdc}`);
    await page.fill("#amount", "100");
    await page.click("#move-btn");
    await expect(page.locator("#move-status")).toContainText(
      "not the selected key",
      { timeout: 60_000 },
    );
    expect(await usdcOf(destination)).toBe(0n);

    // Part of the USDC with the recovery key.
    await page.check(`input[name="key"][value="${recoveryValidator}"]`);
    await page.click("#move-btn");
    await moved(page);
    expect(await usdcOf(destination)).toBe(100_000_000n);
    await expect(page.locator("#balances")).toContainText("800 USDC");

    // Then everything: remaining USDC and the shares, in one request.
    await page.selectOption("#asset", "all");
    await page.click("#move-btn");
    await expect(page.locator("#move-status")).toContainText("Market 1 YES", {
      timeout: 120_000,
    });
    await moved(page);
    expect(await usdcOf(destination)).toBe(MINTED - 100_000_000n);
    expect(await yesOf(destination)).toBe(SHARES_BOUGHT);
    expect(await usdcOf(account.address)).toBe(0n);
    expect(await yesOf(account.address)).toBe(0n);
    await expect(page.locator("#balances")).toContainText("0 USDC");
    expect((await getFirewallState(account)).availableBudget).toBe(0n);

    // Nothing but the page and the RPC was contacted.
    const rpcOrigin = new URL(env.rpcUrl).origin;
    const pageOrigin = new URL(server.url).origin;
    const others = requests.filter((u) => {
      const o = new URL(u).origin;
      return o !== rpcOrigin && o !== pageOrigin;
    });
    console.log(`${requests.length} requests; to others: ${others.length}`);
    expect(others).toEqual([]);
    void context;
  });

  test("from file://: native passkeys are refused with a clear message; an external signer works", async ({
    browser,
  }) => {
    // Refill from the destination-independent minter, so there is something to move.
    const client = localClientConfig(env);
    const deployer = createWalletClient({
      chain: client.publicClient.chain,
      transport: http(env.rpcUrl),
      account: privateKeyToAccount(ANVIL_KEYS.deployer),
    });
    await client.publicClient.waitForTransactionReceipt({
      hash: await deployer.sendTransaction({
        to: env.fixtures.usdc,
        data: encodeFunctionData({
          abi: mockUsdcAbi,
          functionName: "mint",
          args: [account.address, 50_000_000n],
        }),
      }),
    });
    const before = await usdcOf(destination);

    const context = await browser.newContext();
    const p = await context.newPage();
    const requests: string[] = [];
    context.on("request", (r) => requests.push(r.url()));
    await p.goto(pathToFileURL(EXIT_HTML).href);
    await expect(p.locator("#origin-note")).toContainText("as a file");
    await connect(p);

    await p.check(`input[name="key"][value="${account.owner.validator}"]`);
    await p.selectOption("#asset", `token:${env.fixtures.usdc}`);
    await p.selectOption("#destination", destination);
    await p.click("#move-btn");
    await expect(p.locator("#move-status")).toContainText(
      "not allow passkeys on a page opened as a file",
    );

    // The website's key, signing outside any browser with the website unreachable.
    await p.check('input[name="signer"][value="external"]');
    await p.fill("#external-rpid", MAIN_RP);
    await p.click("#move-btn");
    await expect(p.locator("#external")).toBeVisible({ timeout: 60_000 });
    const request = (await p.locator("#external-request").textContent()) ?? "";
    const hash = request.split("\n")[0];
    await p.fill("#external-response", mainKey.fido2AssertOutput(hash));
    await p.click("#external-btn");
    await moved(p);
    expect(await usdcOf(destination)).toBe(before + 50_000_000n);
    expect(await usdcOf(account.address)).toBe(0n);

    const rpcOrigin = new URL(env.rpcUrl).origin;
    const others = requests.filter(
      (u) => !u.startsWith("file:") && new URL(u).origin !== rpcOrigin,
    );
    expect(others).toEqual([]);
    await context.close();
  });

  test("bundler path: the page speaks ERC-4337 JSON-RPC to the bundler address (mock bundler)", async () => {
    const client = localClientConfig(env);
    const deployer = createWalletClient({
      chain: client.publicClient.chain,
      transport: http(env.rpcUrl),
      account: privateKeyToAccount(ANVIL_KEYS.deployer),
    });
    await client.publicClient.waitForTransactionReceipt({
      hash: await deployer.sendTransaction({
        to: env.fixtures.usdc,
        data: encodeFunctionData({
          abi: mockUsdcAbi,
          functionName: "mint",
          args: [account.address, 25_000_000n],
        }),
      }),
    });
    const before = await usdcOf(destination);
    const bundler = await startMockBundler(
      client.publicClient,
      createWalletClient({
        chain: client.publicClient.chain,
        transport: http(env.rpcUrl),
        account: privateKeyToAccount(ANVIL_KEYS.bundler),
      }),
      env.addresses.entryPoint,
    );
    try {
      await page.goto(server.url);
      await connect(page, { bundler: bundler.url });
      await page.check(`input[name="key"][value="${recoveryValidator}"]`);
      await page.selectOption("#asset", `token:${env.fixtures.usdc}`);
      await page.selectOption("#destination", destination);
      await page.click("#move-btn");
      await moved(page);
      expect(await usdcOf(destination)).toBe(before + 25_000_000n);
      expect(bundler.methods).toContain("eth_estimateUserOperationGas");
      expect(bundler.methods).toContain("eth_sendUserOperation");
      expect(bundler.methods).toContain("eth_getUserOperationReceipt");
    } finally {
      bundler.close();
    }
  });
});
