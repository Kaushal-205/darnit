/** Read-only Base Sepolia verification. Writes only a public code-hash report. */
import { writeFileSync } from "node:fs";
import { http, createPublicClient, keccak256, toFunctionSelector } from "viem";
import { baseSepolia } from "viem/chains";
import { firewallSmartSessionsAbi } from "../src/abi/iSmartSessions.js";
import { BASE_SEPOLIA } from "../src/addresses.js";

const client = createPublicClient({
  chain: baseSepolia,
  transport: http(process.env.VERIFY_RPC_URL ?? "https://sepolia.base.org"),
});
if ((await client.getChainId()) !== 84532)
  throw new Error("Expected Base Sepolia");
const blockNumber = await client.getBlockNumber();
const selector = toFunctionSelector(firewallSmartSessionsAbi[0]);
const contracts = Object.fromEntries(
  await Promise.all(
    Object.entries(BASE_SEPOLIA)
      .filter(([, v]) => typeof v === "string")
      .map(async ([name, address]) => {
        const code = await client.getBytecode({
          address: address as `0x${string}`,
          blockNumber,
        });
        if (!code || code === "0x")
          throw new Error(`No code at ${name}: ${address}`);
        return [
          name,
          {
            address,
            codeHash: keccak256(code),
            codeSize: (code.length - 2) / 2,
            ...(name.startsWith("smartSessions")
              ? {
                  hasFirewallEnableSelector: code
                    .toLowerCase()
                    .includes(`63${selector.slice(2).toLowerCase()}`),
                }
              : {}),
          },
        ];
      }),
  ),
);
const report = {
  chainId: 84532,
  blockNumber: blockNumber.toString(),
  firewallEnableSessionsSelector: selector,
  contracts,
};
const json = `${JSON.stringify(report, null, 2)}\n`;
if (process.env.VERIFY_REPORT) writeFileSync(process.env.VERIFY_REPORT, json);
console.log(json);
