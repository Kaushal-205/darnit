import type { FirewallClientConfig } from "@session-firewall/sdk";
import {
  http,
  type Address,
  type Chain,
  createPublicClient,
  createWalletClient,
  defineChain,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { Deployment, RuntimeConfig } from "./config";
import type { NetworkSettings } from "./settings";

export function chainOf(config: RuntimeConfig, rpcUrl: string): Chain {
  return defineChain({
    id: config.network.chainId,
    name: config.network.name,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

/**
 * SDK client for the current settings. User operations go to the user's bundler when one is set;
 * otherwise, in the local demo only, a public Anvil development key submits EntryPoint.handleOps.
 */
export function makeClient(
  config: RuntimeConfig,
  deployment: Deployment,
  settings: NetworkSettings,
): FirewallClientConfig {
  const chain = chainOf(config, settings.rpcUrl);
  const publicClient = createPublicClient({
    chain,
    transport: http(settings.rpcUrl),
    pollingInterval: 500,
  });
  if (settings.bundlerUrl) {
    return {
      publicClient,
      addresses: deployment.addresses,
      bundlerUrl: settings.bundlerUrl,
      paymasterUrl: settings.paymasterUrl || undefined,
    };
  }
  if (!config.local) {
    throw new Error(
      "No bundler is set. Add a bundler address on the Network screen to send transactions.",
    );
  }
  return {
    publicClient,
    addresses: deployment.addresses,
    localBundler: createWalletClient({
      chain,
      transport: http(settings.rpcUrl),
      account: privateKeyToAccount(config.local.bundlerPrivateKey),
    }),
  };
}

/** Local demo only: give an address test ETH for fees (anvil_setBalance). */
export async function localFundGas(client: FirewallClientConfig, address: Address): Promise<void> {
  await client.publicClient.request({
    method: "anvil_setBalance" as never,
    params: [address, "0xDE0B6B3A7640000"] as never, // 1 ETH
  });
}

export function explorerTx(config: RuntimeConfig, hash: string): string | undefined {
  const base = config.network.explorerUrl;
  return base ? `${base.replace(/\/$/, "")}/tx/${hash}` : undefined;
}
