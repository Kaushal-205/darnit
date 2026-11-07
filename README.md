# Session Firewall

ERC-7579 modules that let a browser session key trade on a prediction market while the account can **never** send value to an unregistered address, approve an unknown spender, change its own config without a 24-hour delay, or lose more than an hourly USDC budget.

> Status: **M0, M1 and M2 done** (199 tests passing, including integration on real Safe7579 + Smart Sessions). M3 next. Nothing deployed. Not audited.

## Layout

```
contracts/      Foundry project: FirewallModule, FirewallHook, adapters, fixtures, tests
packages/sdk/   @session-firewall/sdk (M4)
apps/web/       static Next.js app (M5)
apps/exit/      single-file exit page (M5)
apps/monitor/   Ponder indexer + alerts (M6)
docs/           decisions.md, threat model, runbooks
```

## Contracts quickstart

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

```bash
pnpm install            # ModuleKit, for the Safe7579 + Smart Sessions integration tests
cd contracts
forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-git
forge test -vvv
```

## Rules enforced on every execution

| ID | Rule | Where |
|---|---|---|
| R1 | Calls only to tracked tokens, registered markets, their share tokens, destinations (plain value), or the firewall's config surface; no self-calls, no delegatecall | `FirewallHook.preCheck` |
| R2 | Approvals and permits only to registered markets | `FirewallHook.preCheck` |
| R3 | Any outflow from account + destinations must be explained by a declared market call | `FirewallHook.preCheck` / `postCheck` |
| R4 | Worst-case value out drawn from an hourly token bucket | `FirewallHook.postCheck`, `RiskBudget` |
| R5 | Exits to destinations never touch the budget | `FirewallHook.postCheck` |
| R6 | Loosening changes wait 24 h and can be cancelled; tightening is instant | `FirewallModule` |
| R8 | `freeze()`: cap to 0, sessions revoked, one call | `FirewallModule` |

See [docs/decisions.md](docs/decisions.md) for how each rule is made precise and what is still open.

## Privacy

The optional monitor stores only account addresses and the contact details you give it.

## License

MIT, except `contracts/test/fixtures/Safe7579Head.sol`, which is GPL-3.0: it holds upstream Safe7579 bytecode, used only by tests and never deployed.

Monitor setup, privacy, and alert verification: [apps/monitor/README.md](apps/monitor/README.md).

## CROPS

**Lead property: S — security enforced onchain.** A compromised trading session cannot replace the rules,
approve an unknown spender, or send tracked funds to an unregistered address. The hook and budget run
for every account execution without an application server authorizing it; the SDK fork demo checks both
normal trading and the blocked-drain moment. See `docs/decisions.md` for the boundaries.

- **C:** We operate the app domain and optional alert server; contract checks and owner exits need neither server. RPC and bundler are user-configurable. Browser passkeys remain RP-domain-bound: independent-origin recovery must be enrolled and tested before claiming that domain loss cannot strand a user.
- **O:** MIT, except the GPL-3.0 upstream test fixture noted below; dependencies retain their licenses. Anyone can build and run the available code with the repo, free tools and an RPC; local tests need no hosted service credentials.
- **P:** RPCs/bundlers learn IP, addresses and calls; chain/indexer data is public and hosts see requests. The opt-in monitor stores address/contact details for delivery; providers receive relevant alerts. No client analytics or trackers are implemented; browser bundle verification is a gate for M5.
- **S:** User passkeys and session keys belong on the user's device; the monitor has no spending key. Security trusts deployed code, registered adapters/markets, standard USDC, chain execution and credential security. Contracts are unaudited; RPC/bundler availability and alert delivery remain external assumptions.

The local software authenticator is a test fixture, not a place to keep real keys. Public-testnet deployment,
real-browser UX, independent-origin recovery, and the <=3-minute submission video remain release gates.

Run the SDK fork demo: [packages/sdk/README.md](packages/sdk/README.md). Submission gates and video script: [docs/crops-submission.md](docs/crops-submission.md).

