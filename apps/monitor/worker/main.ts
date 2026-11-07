import { serve } from "@hono/node-server";
import { http, createPublicClient, fallback } from "viem";
import { DEFAULT_CHAIN_ID, parseInteger, parseRpcUrls, required } from "../src/lib/env.ts";
import { createApi } from "./api.ts";
import { type Channel, type ContactType, emailChannel, resendProvider, telegramChannel, webhookChannel } from "./channels.ts";
import { createDispatcher, httpSource } from "./dispatcher.ts";
import { pgStore } from "./pgStore.ts";
import { type Store, memoryStore } from "./store.ts";

// Alert worker + subscriptions API. Runs next to `ponder start` (see README).
const env = process.env;

const chainId = parseInteger(env, "CHAIN_ID", DEFAULT_CHAIN_ID);
const appUrl = required(env, "APP_URL");
const indexerUrl = env.INDEXER_URL ?? "http://localhost:42069";
const pollMs = parseInteger(env, "WORKER_POLL_INTERVAL_MS", 1_000);
const port = parseInteger(env, "PORT", 8787);

const store: Store = env.DATABASE_URL
  ? pgStore({ connectionString: env.DATABASE_URL, schema: env.WORKER_DB_SCHEMA })
  : memoryStore();
if (!env.DATABASE_URL) console.warn("DATABASE_URL not set: subscriptions are kept in memory and lost on restart");
await store.init();

const channels: Partial<Record<ContactType, Channel>> = {};
if (env.EMAIL_API_KEY) {
  channels.email = emailChannel(resendProvider({ apiKey: env.EMAIL_API_KEY, from: required(env, "EMAIL_FROM") }));
}
if (env.TELEGRAM_BOT_TOKEN) channels.telegram = telegramChannel({ botToken: env.TELEGRAM_BOT_TOKEN });
if (env.WEBHOOK_SIGNING_SECRET) channels.webhook = webhookChannel({ masterSecret: env.WEBHOOK_SIGNING_SECRET });
console.log(`channels enabled: ${Object.keys(channels).join(", ") || "none"}`);

const client = createPublicClient({ transport: fallback(parseRpcUrls(env).map((u) => http(u))) });

const dispatcher = createDispatcher({ store, source: httpSource(indexerUrl), channels, appUrl });
dispatcher.start(pollMs);

const api = createApi({
  store,
  chainId,
  webhookMasterSecret: env.WEBHOOK_SIGNING_SECRET,
  allowInsecureWebhooks: env.ALLOW_INSECURE_WEBHOOKS === "true",
  // EIP-191 for EOAs, ERC-1271 for deployed smart accounts, ERC-6492 for counterfactual ones.
  verify: ({ address, message, signature }) => client.verifyMessage({ address, message, signature }),
});
const server = serve({ fetch: api.fetch, port });
console.log(`subscriptions API on :${port}, polling ${indexerUrl} every ${pollMs} ms`);

const prune = setInterval(() => void store.prune(Math.floor(Date.now() / 1000) - 7 * 86_400), 3_600_000);

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    dispatcher.stop();
    clearInterval(prune);
    server.close();
    void store.close().finally(() => process.exit(0));
  });
}
