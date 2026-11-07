/**
 * M5/M8 end to end, by clicking, in a real browser against the local Anvil stack with real contracts.
 * The passkey is a CDP virtual authenticator, so real navigator.credentials calls produce real P-256
 * signatures that FirewallOwnerValidator verifies onchain. Nothing in the app is mocked.
 */
import { type Page, expect, test } from "@playwright/test";
import { http, type Address, createPublicClient, erc20Abi } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const SCREENSHOTS = process.env.E2E_SCREENSHOTS;
const ATTACKS = ["A1", "A2", "A5", "A9", "A9-passkey"] as const;
const EXPECTED_MESSAGE: Record<(typeof ATTACKS)[number], RegExp> = {
  A1: /Blocked: this would send USDC to an address that is not one of your withdrawal addresses/,
  A2: /Blocked: only the registered market may be allowed to spend/,
  A5: /Blocked: this market trade would send its proceeds/,
  A9: /Refused before it ran: a trading session can only trade on the registered market/,
  "A9-passkey": /Blocked: the account may not call itself/,
};

const shot = async (page: Page, name: string) => {
  if (SCREENSHOTS)
    await page.screenshot({
      path: `${SCREENSHOTS}/${name}.png`,
      fullPage: true,
    });
};

test("onboard, session, buy, attack blocked, exit", async ({
  page,
  context,
  request,
  baseURL,
}) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  const external: string[] = [];
  const cspViolations: string[] = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.hostname !== "localhost" && u.hostname !== "127.0.0.1")
      external.push(r.url());
  });
  page.on("console", (m) => {
    if (/Content Security Policy/i.test(m.text())) cspViolations.push(m.text());
  });

  const config = await (
    await request.get(`${baseURL}/runtime-config.json`)
  ).json();
  const usdc: Address = config.deployment.market.usdc;
  const pub = createPublicClient({ transport: http(config.network.rpcUrl) });
  const usdcOf = (who: Address) =>
    pub.readContract({
      address: usdc,
      abi: erc20Abi,
      functionName: "balanceOf",
      args: [who],
    });
  const destination = privateKeyToAccount(generatePrivateKey()).address;

  // --- Onboard
  await page.goto("/");
  await page.getByTestId("create-passkey").click();
  await expect(page.getByTestId("passkey-ready")).toBeVisible();
  await page.getByTestId("destination").fill(destination);
  await page.getByTestId("hourly-cap").fill("1000");
  await shot(page, "1-onboarding");
  await page.getByTestId("create-account").click();
  await expect(page.getByTestId("account-address")).toBeVisible({
    timeout: 180_000,
  });
  const account = (
    await page.getByTestId("account-address").innerText()
  ).trim() as Address;
  await expect(page.getByTestId("balance-usdc")).toHaveText("$10,000.00");
  await expect(page.getByTestId("summary-cap")).toHaveText("$1,000.00");
  expect(await usdcOf(account)).toBe(10_000_000_000n);

  // --- Session (default 7 days)
  await page.getByTestId("tab-sessions").click();
  await expect(page.getByTestId("session-days")).toHaveValue("7");
  await page.getByTestId("create-session").click();
  await expect(page.getByTestId("session-status")).toHaveText("Active");
  await shot(page, "2-session");

  // --- Buy 100 YES at $0.50 with the session key (no passkey needed)
  await page.getByTestId("tab-trade").click();
  await expect(page.getByTestId("book-yes")).toContainText("$0.50");
  await page.getByTestId("amount-yes").fill("100");
  await page.getByTestId("buy-yes").click();
  await expect(page.getByTestId("held-yes")).toHaveText("100");
  await expect(page.getByTestId("balance-usdc")).toHaveText("$9,950.00");
  await expect(page.getByTestId("summary-budget")).not.toHaveText("$1,000.00");
  await shot(page, "3-bought");

  // --- Sell 40 back at $0.48
  await page.getByTestId("amount-yes").fill("40");
  await page.getByTestId("sell-yes").click();
  await expect(page.getByTestId("held-yes")).toHaveText("60");
  await expect(page.getByTestId("balance-usdc")).toHaveText("$9,969.20");

  // --- Attack
  const usdcBefore = await usdcOf(account);
  await page.getByTestId("attack-toggle").check();
  await page.getByTestId("run-attack").click();
  await expect(page.getByTestId("attack-verdict")).toBeVisible({
    timeout: 180_000,
  });
  for (const id of ATTACKS) {
    await expect(page.getByTestId(`attempt-${id}-status`), id).toHaveAttribute(
      "data-status",
      "blocked",
    );
    await expect(page.getByTestId(`attempt-${id}-message`), id).toHaveText(
      EXPECTED_MESSAGE[id],
    );
    await expect(page.getByTestId(`attempt-${id}`), id).toContainText(
      "User operation: 0x",
    );
  }
  // These reach the chain and revert in the hook; A9 from a session is refused at validation (D13).
  for (const id of ["A1", "A2", "A5", "A9-passkey"]) {
    await expect(page.getByTestId(`attempt-${id}`), id).toContainText(
      "Reverted transaction: 0x",
    );
  }
  await expect(page.getByTestId("attack-verdict")).toHaveText(
    /Your funds are unchanged/,
  );
  await shot(page, "4-attack-blocked");
  const attacker = (
    await page
      .getByTestId("attack-panel")
      .locator("span.font-mono")
      .first()
      .innerText()
  ).trim();
  expect(await usdcOf(attacker as Address)).toBe(0n);
  expect(await usdcOf(account)).toBe(usdcBefore);
  await page.getByTestId("attack-toggle").uncheck();

  // --- Settings: queue a loosening change with an ETA, cancel it, lower the cap
  await page.getByTestId("tab-settings").click();
  await page
    .getByTestId("queue-destination")
    .fill(privateKeyToAccount(generatePrivateKey()).address);
  await page.getByTestId("queue-destination-submit").click();
  await expect(page.getByTestId("pending-eta")).toContainText(/in 2[34] h/);
  await page.getByTestId("cancel-change").click();
  await expect(page.getByTestId("pending-change")).toHaveCount(0);
  await page.getByTestId("lower-cap-amount").fill("500");
  await page.getByTestId("lower-cap").click();
  await expect(page.getByTestId("config-cap")).toHaveText("$500.00");

  // --- A plain error on a trade over the limit, in the normal UI
  await page.getByTestId("tab-trade").click();
  await page.getByTestId("amount-yes").fill("1900");
  await page.getByTestId("buy-yes").click();
  await expect(page.getByTestId("outcome-error")).toContainText(
    /hourly budget is left/,
  );

  // --- Freeze, then exit still works
  await page.getByTestId("tab-settings").click();
  await page.getByTestId("freeze").click();
  await expect(page.getByTestId("trading-state")).toHaveText("Paused");
  await page.getByTestId("exit-submit").click();
  await expect(page.getByTestId("balance-usdc")).toHaveText("$0.00");
  await shot(page, "5-exited");
  expect(await usdcOf(destination)).toBe(usdcBefore);
  expect(await usdcOf(account)).toBe(0n);

  // --- RPC setting persists across reload; account is remembered
  await page.getByTestId("tab-network").click();
  await page
    .getByTestId("rpc-url")
    .fill(config.network.rpcUrl.replace("127.0.0.1", "localhost"));
  await page.getByTestId("save-network").click();
  await page.reload();
  await page.getByTestId("tab-network").click();
  await expect(page.getByTestId("rpc-url")).toHaveValue(/localhost/);
  await expect(page.getByTestId("account-address")).toHaveText(account);

  // --- No third-party request and no CSP violation during the whole run
  expect(external).toEqual([]);
  expect(cspViolations).toEqual([]);
});
