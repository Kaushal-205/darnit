/**
 * M4 demo: onboard -> session -> trade -> blocked drain -> exit, against the `local` environment
 * (Anvil fork of Base Sepolia). Run: `pnpm --filter @session-firewall/sdk demo`.
 * Also exercised by test/integration/demo.test.ts.
 */
import { pathToFileURL } from "node:url";
import {
  http,
  type Address,
  type Chain,
  createPublicClient,
  createTestClient,
  createWalletClient,
  defineChain,
  encodeFunctionData,
  formatUnits,
  parseEther,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  FirewallError,
  ORDER_SIDE,
  approveMarket,
  buildAccountInit,
  createFirewallAccount,
  createSession,
  ecdsaOwner,
  executeAsSession,
  exit,
  fill,
  getFirewallState,
  mockUsdcAbi,
  outcomeSharesAbi,
  signReferenceOrder,
} from "../src/index.js";
import type { FirewallClientConfig } from "../src/userop.js";
import {
  ANVIL_KEYS,
  type Fixtures,
  LOCAL_CHAIN_ID,
  type LocalEnv,
  startLocalEnv,
} from "./local-env.js";

export type DemoResult = {
  account: Address;
  destination: Address;
  attacker: Address;
  sharesBought: bigint;
  budgetAfterTrade: bigint;
  blockedError: string | undefined;
  blockedMessage: string;
  attackerBalance: bigint;
  destinationBalance: bigint;
  accountUsdcAfterExit: bigint;
};

const usd = (v: bigint) => `$${formatUnits(v, 6)}`;

export function localChain(rpcUrl: string): Chain {
  return defineChain({
    id: LOCAL_CHAIN_ID,
    name: "Base Sepolia fork (local)",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

export function localClientConfig(
  env: Pick<LocalEnv, "rpcUrl" | "addresses">,
): FirewallClientConfig {
  const chain = localChain(env.rpcUrl);
  const publicClient = createPublicClient({
    chain,
    transport: http(env.rpcUrl),
    pollingInterval: 100,
  });
  const bundlerUrl = process.env.BUNDLER_URL;
  return {
    publicClient,
    addresses: env.addresses,
    bundlerUrl,
    paymasterUrl: process.env.PAYMASTER_URL,
    localBundler: bundlerUrl
      ? undefined
      : createWalletClient({
          chain,
          transport: http(env.rpcUrl),
          account: privateKeyToAccount(ANVIL_KEYS.bundler),
        }),
  };
}

export async function runDemo(
  env: Pick<LocalEnv, "rpcUrl" | "addresses" | "fixtures">,
  log: (line: string) => void = console.log,
): Promise<DemoResult> {
  const client = localClientConfig(env);
  const { publicClient } = client;
  const fx: Fixtures = env.fixtures;
  const chain = publicClient.chain;
  const test = createTestClient({
    chain,
    mode: "anvil",
    transport: http(env.rpcUrl),
  });
  const deployer = createWalletClient({
    chain,
    transport: http(env.rpcUrl),
    account: privateKeyToAccount(ANVIL_KEYS.deployer),
  });
  const maker = privateKeyToAccount(ANVIL_KEYS.maker);

  const owner = ecdsaOwner(privateKeyToAccount(generatePrivateKey()), {
    validator: env.addresses.ownableValidator,
  });
  const destination = privateKeyToAccount(generatePrivateKey()).address; // the user's cold wallet
  const attacker = privateKeyToAccount(generatePrivateKey()).address;
  const hourlyCap = 1_000_000_000n; // $1,000 / hour

  // 1. Onboard
  log(
    "1. Onboard: deploy Safe + Safe7579 with Smart Sessions, FirewallModule and FirewallHook in one user op",
  );
  const params = {
    owner,
    destinations: [destination],
    markets: [{ market: fx.market, adapter: fx.adapter }],
    tokens: [fx.usdc],
    hourlyCap,
    saltNonce: BigInt(Date.now()),
  };
  const predicted = (await buildAccountInit(client, params)).address;
  await test.setBalance({ address: predicted, value: parseEther("1") }); // gas for the account's user ops
  const account = await createFirewallAccount(client, params);
  log(
    `   account ${account.address} (owner validator ${owner.validator}, Safe owner = NoSafeOwner)`,
  );
  const mint = encodeFunctionData({
    abi: mockUsdcAbi,
    functionName: "mint",
    args: [account.address, 10_000_000_000n],
  });
  await publicClient.waitForTransactionReceipt({
    hash: await deployer.sendTransaction({ to: fx.usdc, data: mint }),
  });
  await approveMarket(account, {
    token: fx.usdc,
    market: fx.market,
    amount: 2n ** 256n - 1n,
  });
  log(
    `   funded with ${usd(10_000_000_000n)} USDC, approved the market (R2: registered market only)`,
  );

  // 2. Session
  log(
    "2. Create a 7-day session key via FirewallModule.createSession (owner-signed)",
  );
  const session = await createSession(account, {
    expiresAt: Math.floor(Date.now() / 1000) + 7 * 24 * 3600,
    markets: [fx.market],
  });
  log(
    `   session key ${session.address}, permissionId ${session.permissionId}`,
  );

  // 3. Trade
  log("3. Session fills a maker order: buy 100 YES at $0.50");
  const block = await publicClient.getBlock();
  const order = await signReferenceOrder(maker, {
    market: fx.market,
    chainId: chain.id,
    order: {
      tokenId: BigInt(fx.yesId),
      side: ORDER_SIDE.Sell,
      price: 500_000n,
      amount: 100_000_000n,
      expiry: block.timestamp + 86_400n,
      salt: BigInt(Date.now()),
    },
  });
  await fill(account, session, {
    market: fx.market,
    order,
    amount: 100_000_000n,
  });
  const sharesBought = await publicClient.readContract({
    address: fx.shares,
    abi: outcomeSharesAbi,
    functionName: "balanceOf",
    args: [account.address, BigInt(fx.yesId)],
  });
  const budgetAfterTrade = (await getFirewallState(account)).availableBudget;
  log(
    `   shares: ${formatUnits(sharesBought, 6)} YES, budget left: ${usd(budgetAfterTrade)} of ${usd(hourlyCap)}`,
  );

  // 4. Blocked drain
  log("4. Compromised session tries to drain: USDC.transfer(attacker, $5,000)");
  let blockedError: string | undefined;
  let blockedMessage = "NOT BLOCKED";
  try {
    await executeAsSession(account, session, [
      {
        to: fx.usdc,
        data: encodeFunctionData({
          abi: mockUsdcAbi,
          functionName: "transfer",
          args: [attacker, 5_000_000_000n],
        }),
      },
    ]);
  } catch (e) {
    if (!(e instanceof FirewallError)) throw e;
    blockedError = e.decoded?.name;
    blockedMessage = e.message;
    log(`   BLOCKED (${blockedError}): ${blockedMessage}`);
    if (e.transactionHash)
      log(`   reverted on-chain in tx ${e.transactionHash}`);
  }
  const attackerBalance = await usdcBalance(client, fx.usdc, attacker);
  log(`   attacker balance: ${usd(attackerBalance)}`);

  // 5. Exit
  const balance = await usdcBalance(client, fx.usdc, account.address);
  log(
    `5. Owner exits ${usd(balance)} to the registered destination (R5: never blocked by the budget)`,
  );
  await exit(account, { token: fx.usdc, amount: balance, destination });
  const destinationBalance = await usdcBalance(client, fx.usdc, destination);
  const accountUsdcAfterExit = await usdcBalance(
    client,
    fx.usdc,
    account.address,
  );
  log(
    `   destination: ${usd(destinationBalance)}, account: ${usd(accountUsdcAfterExit)}`,
  );

  return {
    account: account.address,
    destination,
    attacker,
    sharesBought,
    budgetAfterTrade,
    blockedError,
    blockedMessage,
    attackerBalance,
    destinationBalance,
    accountUsdcAfterExit,
  };
}

function usdcBalance(
  client: FirewallClientConfig,
  usdc: Address,
  who: Address,
) {
  return client.publicClient.readContract({
    address: usdc,
    abi: mockUsdcAbi,
    functionName: "balanceOf",
    args: [who],
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const env = await startLocalEnv();
  try {
    console.log(
      `local env: ${env.rpcUrl} (Anvil fork of Base Sepolia), module ${env.addresses.module}`,
    );
    const r = await runDemo(env);
    const ok =
      r.blockedError !== undefined &&
      r.attackerBalance === 0n &&
      r.accountUsdcAfterExit === 0n;
    console.log(
      ok
        ? "\nDemo OK: onboard -> session -> trade -> blocked drain -> exit"
        : "\nDemo FAILED",
    );
    process.exitCode = ok ? 0 : 1;
  } finally {
    env.stop();
  }
}
