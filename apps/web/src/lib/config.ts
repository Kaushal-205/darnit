import type { FirewallAddresses, ReferenceOrder, SignedOrder } from "@session-firewall/sdk";
import { type Address, type Hex, getAddress, isAddress, isHex } from "viem";

/**
 * Runtime configuration, fetched from `./runtime-config.json` next to index.html. Nothing about the
 * network or the deployment is compiled into the bundle: the local demo script writes this file with
 * the addresses it just deployed, and a testnet host ships its own copy. The user can still override
 * the RPC and bundler URLs on the Network screen.
 */
export type RuntimeConfig = {
  network: {
    chainId: number;
    name: string;
    rpcUrl: string;
    bundlerUrl?: string;
    paymasterUrl?: string;
    /** Block explorer base URL ("https://.../tx/<hash>" links). Optional. */
    explorerUrl?: string;
  };
  /** Null when the firewall contracts are not deployed on this network yet. */
  deployment: Deployment | null;
  /** Local demo only: an Anvil development key that submits EntryPoint.handleOps and a faucet. */
  local?: { bundlerPrivateKey: Hex; faucet: boolean };
};

export type Deployment = {
  addresses: FirewallAddresses;
  /** Block the deployment was made at; logs are read from here. */
  fromBlock: bigint;
  market: {
    address: Address;
    adapter: Address;
    usdc: Address;
    shares: Address;
    question: string;
    yesId: bigint;
    noId: bigint;
    /** Maker orders signed off-line by the fixture maker. Takers fill them. */
    orders: SignedOrder[];
  };
};

const ADDRESS_KEYS = [
  "entryPoint",
  "safeSingleton",
  "safeProxyFactory",
  "safe7579",
  "safe7579Launchpad",
  "smartSessions",
  "ownableValidator",
  "module",
  "hook",
  "actionPolicy",
  "signaturePolicy",
  "noSafeOwner",
  "ownerValidator",
] as const;

export class ConfigError extends Error {}

function fail(msg: string): never {
  throw new ConfigError(`runtime-config.json: ${msg}`);
}

function addr(v: unknown, field: string): Address {
  if (typeof v !== "string" || !isAddress(v, { strict: false }))
    fail(`${field} must be an address`);
  return getAddress(v);
}

function url(v: unknown, field: string, optional: true): string | undefined;
function url(v: unknown, field: string, optional?: false): string;
function url(v: unknown, field: string, optional = false): string | undefined {
  if (v === undefined || v === null || v === "") {
    if (optional) return undefined;
    fail(`${field} is required`);
  }
  if (typeof v !== "string" || !isHttpUrl(v)) fail(`${field} must be an http(s) URL`);
  return v;
}

export function isHttpUrl(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

function big(v: unknown, field: string): bigint {
  if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
  if (typeof v === "string" && /^\d+$/.test(v)) return BigInt(v);
  fail(`${field} must be an unsigned integer`);
}

function parseOrder(raw: unknown, i: number): SignedOrder {
  const r = raw as { order?: Record<string, unknown>; signature?: unknown };
  const o = r?.order;
  if (!o) fail(`orders[${i}].order missing`);
  if (typeof r.signature !== "string" || !isHex(r.signature))
    fail(`orders[${i}].signature must be hex`);
  const side = Number(o.side);
  if (side !== 0 && side !== 1) fail(`orders[${i}].side must be 0 or 1`);
  const order: ReferenceOrder = {
    maker: addr(o.maker, `orders[${i}].maker`),
    tokenId: big(o.tokenId, `orders[${i}].tokenId`),
    side: side as 0 | 1,
    price: big(o.price, `orders[${i}].price`),
    amount: big(o.amount, `orders[${i}].amount`),
    expiry: big(o.expiry, `orders[${i}].expiry`),
    salt: big(o.salt, `orders[${i}].salt`),
  };
  return { order, signature: r.signature };
}

/** Validate untrusted JSON into a RuntimeConfig. Throws ConfigError with a readable message. */
export function parseRuntimeConfig(json: unknown): RuntimeConfig {
  const j = json as Record<string, unknown>;
  if (!j || typeof j !== "object") fail("not an object");
  const n = j.network as Record<string, unknown> | undefined;
  if (!n) fail("network missing");
  const chainId = Number(n.chainId);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) fail("network.chainId invalid");
  const network: RuntimeConfig["network"] = {
    chainId,
    name: typeof n.name === "string" ? n.name : `Chain ${chainId}`,
    rpcUrl: url(n.rpcUrl, "network.rpcUrl"),
    bundlerUrl: url(n.bundlerUrl, "network.bundlerUrl", true),
    paymasterUrl: url(n.paymasterUrl, "network.paymasterUrl", true),
    explorerUrl: url(n.explorerUrl, "network.explorerUrl", true),
  };

  let deployment: Deployment | null = null;
  const d = j.deployment as Record<string, unknown> | null | undefined;
  if (d) {
    const a = d.addresses as Record<string, unknown> | undefined;
    if (!a) fail("deployment.addresses missing");
    const addresses = Object.fromEntries(
      ADDRESS_KEYS.map((k) => [k, addr(a[k], `deployment.addresses.${k}`)]),
    ) as unknown as FirewallAddresses;
    if (a.attester) addresses.attester = addr(a.attester, "deployment.addresses.attester");
    const m = d.market as Record<string, unknown> | undefined;
    if (!m) fail("deployment.market missing");
    deployment = {
      addresses,
      fromBlock: big(d.fromBlock ?? 0, "deployment.fromBlock"),
      market: {
        address: addr(m.address, "deployment.market.address"),
        adapter: addr(m.adapter, "deployment.market.adapter"),
        usdc: addr(m.usdc, "deployment.market.usdc"),
        shares: addr(m.shares, "deployment.market.shares"),
        question: typeof m.question === "string" ? m.question : "Demo market",
        yesId: big(m.yesId, "deployment.market.yesId"),
        noId: big(m.noId, "deployment.market.noId"),
        orders: Array.isArray(m.orders) ? m.orders.map(parseOrder) : [],
      },
    };
  }

  let local: RuntimeConfig["local"];
  const l = j.local as Record<string, unknown> | undefined;
  if (l) {
    if (typeof l.bundlerPrivateKey !== "string" || !isHex(l.bundlerPrivateKey))
      fail("local.bundlerPrivateKey must be hex");
    local = { bundlerPrivateKey: l.bundlerPrivateKey, faucet: l.faucet === true };
  }
  return { network, deployment, local };
}

/** JSON-friendly form (bigints as decimal strings), used by the demo script that writes the file. */
export function serializeRuntimeConfig(c: RuntimeConfig): string {
  return JSON.stringify(
    c,
    (_k, v) => (typeof v === "bigint" ? v.toString() : v),
    2,
  );
}

export async function loadRuntimeConfig(): Promise<RuntimeConfig> {
  // Relative URL: works at the domain root and under an IPFS gateway path.
  const res = await fetch("./runtime-config.json", { cache: "no-store" });
  if (!res.ok) throw new ConfigError(`Could not load runtime-config.json (${res.status}).`);
  return parseRuntimeConfig(await res.json());
}
