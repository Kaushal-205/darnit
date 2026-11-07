/**
 * Read-only Ethereum Sepolia verification. Writes only a public code-hash report.
 *
 * Env:
 *   VERIFY_RPC_URL       Ethereum Sepolia RPC (default: public endpoint)
 *   VERIFY_BLOCK_NUMBER  block to read at (default: latest)
 *   VERIFY_REPORT        optional output path (e.g. ../../docs/sepolia-infrastructure.json)
 */
import { writeFileSync } from "node:fs";
import { http, createPublicClient, keccak256, toFunctionSelector } from "viem";
import { sepolia } from "viem/chains";
import { firewallSmartSessionsAbi } from "../src/abi/iSmartSessions.js";
import { ETHEREUM_SEPOLIA } from "../src/addresses.js";

/** Safe7579 `emergencyUninstallHook` (docs/decisions.md V11). */
const EMERGENCY_UNINSTALL_HOOK_SELECTOR = "0x5bfeadbb";

const client = createPublicClient({
  chain: sepolia,
  transport: http(
    process.env.VERIFY_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com",
  ),
});
if ((await client.getChainId()) !== ETHEREUM_SEPOLIA.chainId)
  throw new Error("Expected Ethereum Sepolia (chain 11155111)");
const blockNumber = process.env.VERIFY_BLOCK_NUMBER
  ? BigInt(process.env.VERIFY_BLOCK_NUMBER)
  : await client.getBlockNumber();
const selector = toFunctionSelector(firewallSmartSessionsAbi[0]);
/** Dispatcher check: the selector appears as a PUSH4 operand. */
const hasSelector = (code: string, sel: string) =>
  code.toLowerCase().includes(`63${sel.slice(2).toLowerCase()}`);
const contracts = Object.fromEntries(
  await Promise.all(
    Object.entries(ETHEREUM_SEPOLIA)
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
              ? { hasFirewallEnableSelector: hasSelector(code, selector) }
              : {}),
            ...(name === "safe7579"
              ? {
                  hasEmergencyUninstallHook: hasSelector(
                    code,
                    EMERGENCY_UNINSTALL_HOOK_SELECTOR,
                  ),
                }
              : {}),
          },
        ];
      }),
  ),
);
const report = {
  chainId: ETHEREUM_SEPOLIA.chainId,
  blockNumber: blockNumber.toString(),
  firewallEnableSessionsSelector: selector,
  emergencyUninstallHookSelector: EMERGENCY_UNINSTALL_HOOK_SELECTOR,
  contracts,
};
const json = `${JSON.stringify(report, null, 2)}\n`;
if (process.env.VERIFY_REPORT) writeFileSync(process.env.VERIFY_REPORT, json);
console.log(json);
