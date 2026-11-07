# Session Firewall

ERC-7579 modules that let a browser session key trade on a prediction market while the account can **never** send value to an unregistered address, approve an unknown spender, change its own config without a 24-hour delay, or lose more than an hourly USDC budget.

> Status: **M0 + M1 done** (94 tests passing, including integration on real Safe7579 + Smart Sessions). M2 next. Nothing deployed. Not audited.

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

MIT
