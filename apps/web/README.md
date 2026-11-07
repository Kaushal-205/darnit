# Session Firewall web app

A static Next.js app with no API routes. It talks directly to an RPC and a bundler. The account's limits
live onchain, so they keep working if this site is hacked or disappears.

## Run the local demo

Requirements: Node 22.18+, pnpm 9.15, Foundry (`anvil`, `forge`), and network access to an Ethereum Sepolia RPC.
Passkeys need a browser with an authenticator (for example a platform passkey or a security key).

```sh
pnpm install --frozen-lockfile
cd contracts && forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-git && forge build && cd ..
pnpm --filter @session-firewall/sdk build
pnpm demo:web
```

Open <http://localhost:4173>. The command forks Ethereum Sepolia with Anvil, deploys the contracts and
fixtures through the SDK's `local-env` scripts, signs fixture maker orders, writes `out/runtime-config.json`
and serves the export with production headers. The first run builds the app; `REBUILD=1` forces a rebuild.

Env: `FORK_URLS`, `FORK_BLOCK_NUMBER`, `FOUNDRY_BIN`, `ANVIL_PORT`, `PORT`.

The fork uses chain id 31337, and a public Anvil key submits transactions when no bundler is set. These keys
and the test-funds button exist only in the demo's generated config. **It is not a live-network deployment.**
The committed `public/runtime-config.json` targets Ethereum Sepolia with `deployment: null`, so that build
shows only a notice and the Network screen until M7 publishes addresses.

## Tests

```sh
pnpm --filter @session-firewall/web test           # unit tests
pnpm --filter @session-firewall/web typecheck
pnpm --filter @session-firewall/web build
pnpm --filter @session-firewall/web check:origins  # scans the export
pnpm --filter @session-firewall/web test:e2e       # real browser; PW_CHANNEL=chrome uses installed Chrome
```

The Playwright test starts the demo stack and clicks through onboarding, a session, buy and sell, the attack,
queue and cancel, lower cap, freeze and exit. Its passkey is a CDP virtual authenticator, so
`navigator.credentials` runs for real and the onchain validator verifies real P-256 signatures.

## The attack switch

"Simulate compromised website" reveals a panel that runs `src/attack/compromised.ts`, playing a script injected
by an attacker. It uses what such a script could reach: it reads the session key from IndexedDB, signs real
user operations, and prompts the passkey. An attempt counts as blocked only when the chain refused it.

| Attempt | Signer | Result |
|---|---|---|
| A1: send USDC to the attacker | Session key | Reverts in the hook, `UnexplainedOutflow` |
| A2: approve the attacker for the maximum | Session key | Reverts in the hook, `UnregisteredSpender` |
| A5: fill routing proceeds to the attacker | Session key | Reverts in the hook, `UnexplainedOutflow` |
| A9: install a module on the account | Session key | Refused at validation (D13), so **there is no transaction**, only a user-op hash |
| A9: same install | Passkey prompt | Reverts in the hook, `ForbiddenExecution` |

Honest limits: the script ships in the bundle and runs only behind the switch; it simulates injection and does
not load a remote script, which the CSP would refuse. A real attacker who replaced the files on the host would
bypass the CSP, which is why the demo relies only on the chain. It can also ask for the passkey, so a user who
approves a malicious prompt is still bounded by the rules. That includes the D12 residual risks: a phished
signature can queue a change, and the 24-hour delay and optional monitor are the defence there.

## Keys and storage

- The **passkey** stays in the authenticator. The app stores only its id and public key.
- **Session keys** are raw private keys in IndexedDB, because WebCrypto has no secp256k1. This is acceptable
  because the onchain hook, action policy and hourly budget bound the damage: a stolen key can only trade on
  registered markets within the limit, and the budget can be lost through bad trades. It cannot withdraw,
  approve a new spender or change settings. It expires, and ending the session or pausing cancels it at once.
- **RPC, bundler and paymaster URLs** are editable on the Network screen and saved in localStorage. Those
  providers can see your address and activity. Passkeys are bound to this site's domain, so a mirror on another
  origin cannot use the same passkey unless it was enrolled there (see `docs/crops-submission.md`).

## Build rules

- No analytics, remote fonts, or CDNs. System fonts only. Next.js telemetry is off in the build script.
- `security-headers.json` holds the CSP used by `serve.mjs`, and `postbuild.mjs` copies it to a meta tag for hosts
  without header control. `vercel.json` repeats the same headers, so change both together.
- `connect-src` allows any `https:` origin because the user picks the RPC and bundler. `script-src 'self'` stops
  new code from loading, but a script already running could send data to an https host. The firewall does not rely
  on the CSP.
- `postbuild.mjs` adds SHA-384 SRI to every script and stylesheet tag and fails on inline scripts. The app is a
  single page with chunk splitting off, so no lazy chunks escape SRI.
- `assetPrefix: "."` makes asset URLs relative for IPFS gateways. The IPFS CID is published in M7.
- `check:origins` fails on any URL in a loading position and on any origin missing from the reviewed allowlist
  in `scripts/origins.mjs`. Allowlisted entries are text only (library doc links, XML namespaces) or the replaceable
  defaults in `runtime-config.json`. The e2e test also asserts that no request leaves the machine.
