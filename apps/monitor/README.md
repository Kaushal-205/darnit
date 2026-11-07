# Session Firewall monitor

Opt-in Ponder indexer and alert worker. The indexer reads chain events; the worker delivers email
(Resend), Telegram messages, and signed webhooks. No signing key, bundler, or custody is required.

Requirements: Node 22.18+, pnpm 9, and Postgres for durable production subscriptions. From the repo root:

```sh
pnpm install --frozen-lockfile
cp apps/monitor/.env.example apps/monitor/.env.local
# Fill in FIREWALL_MODULE, START_BLOCK, DATABASE_URL, APP_URL and channel credentials.
pnpm --filter @session-firewall/monitor start
```

Run a second process for the worker. Ponder loads `.env.local`; Node must load it explicitly:

```sh
cd apps/monitor
node --env-file=.env.local --experimental-strip-types worker/main.ts
```

Use `pnpm --filter @session-firewall/monitor dev` for local indexing. Without DATABASE_URL, the
indexer uses PGlite and worker subscriptions disappear at restart. Production indexer and worker
share a Postgres connection string but use separate schemas; run one worker per database. Keep the
indexer's `/alerts` endpoint reachable from the worker. Expose the subscription API over HTTPS.

| Event | Alert |
| --- | --- |
| `ChangeQueued` | High priority, decoded change, cancel and freeze links; validator installs are highlighted |
| `BudgetConsumed` | Warning after usage exceeds 80% of the current hourly cap in a rolling hour |
| EntryPoint `UserOperationRevertReason` | Blocked attempt, only for firewall accounts; decodes firewall errors and generic `ExecutionFailed` |
| Safe7579 `EmergencyHookUninstallRequest` | Critical exit alert, attributed to the requesting account |
| `FreezeActivated`, `SessionsRevoked` | Informational confirmation |

`ChangeExecuted` and `ChangeCancelled` update the indexed queue. Budget alerts have an hourly
cooldown. Lower priority flood alerts are rate limited; high and critical alerts bypass the limiter.
Failed high/critical deliveries retry until expiry; other alerts get five attempts. Pending failures
hold back the persistent cursor so restarting retries them. Delivery is at least once: a crash after
a provider accepts a message but before persistence can duplicate it. Receivers should deduplicate
on the event ID. Ponder rolls back reorged records, but already sent notifications cannot be recalled.

## Subscribe and unsubscribe

POST `/v1/message` on the worker with `action`, `account`, `channels`, `issuedAt` (Unix seconds), and
a fresh URL-safe `nonce` (8–64 characters). It returns the exact EIP-191 plaintext to sign. Submit
the same fields plus `signature` to `/v1/subscribe` (omit action), or `/v1/unsubscribe`. Unsubscribe
accepts `channels: null` to remove all contacts. Example channels:

```json
[{"type":"email","to":"me@example.com"},{"type":"telegram","chatId":"12345"},{"type":"webhook","url":"https://partner.example/alerts"}]
```

EOA, ERC-1271 smart-account, and ERC-6492 signatures are verified through the configured RPC. For a
D12 passkey account, use the SDK's PersonalSign envelope and Safe7579 validator prefix; sign the
returned plaintext. The issue time must be within ten minutes and each nonce is single use. Channel
credentials must be configured before subscribing. Start the Telegram bot chat before subscribing.
Public webhook URLs require HTTPS and cannot contain credentials or literal private hostnames;
also enforce outbound network restrictions at the host to prevent DNS-based private-network access.

Subscribe returns the per-account, per-URL webhook secret. Verify the raw body with
`verifyWebhookSignature` from `src/lib/webhook.ts` before processing; its default replay tolerance is
five minutes. Headers are `X-Firewall-Signature` and `X-Firewall-Event-Id`. Store the returned secret
securely. Rotating WEBHOOK_SIGNING_SECRET changes every derived secret, so receivers must refresh it.

## Verification and latency

```sh
pnpm --filter @session-firewall/monitor test
pnpm --filter @session-firewall/monitor typecheck
pnpm --filter @session-firewall/monitor lint
cd contracts && forge build
cd .. && pnpm --filter @session-firewall/monitor test:e2e
```

The end-to-end test starts actual Anvil, Ponder, worker and HTTP receiver processes, subscribes with a
real signature, queues three changes on FirewallModule, and requires each signed webhook within
60 seconds. It also checks budget alerts, blocked attempts, emergency uninstall attribution, freeze,
revocation, and duplicates. EntryPoint and emergency events use exact event emitters; this test does
not claim a real ERC-4337 bundler or emergency-uninstall execution. On 2026-11-07, queued-change
latencies were **2723, 1967, and 1909 ms**, including submission and two-second blocks. CI repeats it.

**Public-testnet acceptance is pending M7.** No firewall instance has been deployed to Base Sepolia.
After deployment, set the real address and start block, subscribe a test receiver, queue a change
through the SDK, and measure from transaction submission to receiver arrival (must be <60 seconds).
Cancel the queued item afterwards. Test each enabled provider too; local tests do not prove provider
delivery latency. Keep indexer/worker polling at one second and watch process health and RPC errors.

## Privacy

The only private user data persisted is account addresses and selected contact details. No passkey,
session key, signatures, IP addresses, or user-agent records are stored by this application. The
indexer also retains public chain events, queue state and rolling budget entries; the worker stores
hashed delivery/nonce identifiers and a block cursor. Those identifiers are pruned after seven days.
Unsubscribing deletes contact records immediately; database backups follow the operator's retention
policy. Email, Telegram and webhook providers receive the relevant account alert and contact target.
Do not enable request-body logging on the reverse proxy. Ponder telemetry is disabled in the example.
