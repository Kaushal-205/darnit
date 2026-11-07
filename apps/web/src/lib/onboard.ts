import {
  type FirewallAccount,
  type FirewallClientConfig,
  buildAccountInit,
  createFirewallAccount,
  erc20Abi,
  executeAsOwner,
  mockUsdcAbi,
  outcomeSharesAbi,
} from "@session-firewall/sdk";
import {
  http,
  type Address,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  formatEther,
  isAddress,
  maxUint256,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { chainOf, localFundGas } from "./client";
import type { Deployment, RuntimeConfig } from "./config";
import { type StoredPasskey, passkeyOwnerFor } from "./passkey";
import type { NetworkSettings } from "./settings";

export const TEST_USDC = 10_000_000_000n; // $10,000

export function validateOnboarding(
  destination: string,
  hourlyCap: bigint | undefined,
): string | undefined {
  if (!isAddress(destination, { strict: false }))
    return "Enter the full address of the Safe you want to withdraw to (it starts with 0x).";
  if (!hourlyCap)
    return "Enter the most this app may lose per hour, in dollars.";
  return undefined;
}

/** Deploy the account: one user operation, signed with the passkey, with the firewall on from the first block. */
export async function deployAccount(p: {
  config: RuntimeConfig;
  deployment: Deployment;
  client: FirewallClientConfig;
  passkey: StoredPasskey;
  destination: Address;
  hourlyCap: bigint;
  onStep: (text: string) => void;
}): Promise<FirewallAccount> {
  const { config, deployment, client, passkey } = p;
  const params = {
    owner: passkeyOwnerFor(passkey, deployment.addresses.ownerValidator),
    destinations: [p.destination],
    markets: [
      { market: deployment.market.address, adapter: deployment.market.adapter },
    ],
    tokens: [deployment.market.usdc],
    hourlyCap: p.hourlyCap,
    // One account per passkey: the address does not depend on the other choices, so a retry finds it again.
    saltNonce: 0n,
  };
  const { address } = await buildAccountInit(client, params);
  if (config.local?.faucet) {
    p.onStep("Adding test ETH for network fees (local demo only)…");
    await localFundGas(client, address);
  } else if (!client.paymasterUrl) {
    const eth = await client.publicClient.getBalance({ address });
    if (eth === 0n)
      throw new Error(
        `Your new account has no ETH for network fees. Send a little Sepolia ETH to ${address} and try again (current balance ${formatEther(eth)} ETH).`,
      );
  }
  p.onStep("Confirm with your passkey to create the account…");
  return createFirewallAccount(client, params);
}

/** Let the registered market spend USDC and shares, so sessions can trade. The firewall allows only this spender. */
export function allowMarket(account: FirewallAccount, deployment: Deployment) {
  const { market } = deployment;
  return executeAsOwner(account, [
    {
      to: market.usdc,
      data: encodeFunctionData({
        abi: erc20Abi,
        functionName: "approve",
        args: [market.address, maxUint256],
      }),
    },
    {
      to: market.shares,
      data: encodeFunctionData({
        abi: outcomeSharesAbi,
        functionName: "setApprovalForAll",
        args: [market.address, true],
      }),
    },
  ]);
}

/** Local demo only: mint test USDC from the permissionless fixture token. */
export async function localMintUsdc(
  config: RuntimeConfig,
  settings: NetworkSettings,
  deployment: Deployment,
  to: Address,
  amount: bigint = TEST_USDC,
): Promise<void> {
  if (!config.local)
    throw new Error("Test funds exist only in the local demo.");
  const chain = chainOf(config, settings.rpcUrl);
  const wallet = createWalletClient({
    chain,
    transport: http(settings.rpcUrl),
    account: privateKeyToAccount(config.local.bundlerPrivateKey),
  });
  const hash = await wallet.writeContract({
    address: deployment.market.usdc,
    abi: mockUsdcAbi,
    functionName: "mint",
    args: [to, amount],
  });
  await createPublicClient({
    chain,
    transport: http(settings.rpcUrl),
    pollingInterval: 300,
  }).waitForTransactionReceipt({
    hash,
  });
}
