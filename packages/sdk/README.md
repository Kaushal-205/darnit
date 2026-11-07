# Session Firewall SDK

Typed viem/permissionless SDK for Safe7579 accounts, firewall-created sessions, trading, queued
configuration changes, freeze and owner exits. Passkey signing uses the exact D12 WebAuthn and
ERC-1271 envelopes. The bundler and optional paymaster URLs are caller-supplied.

## Run the local demo

Requirements: Node 22.18+, pnpm 9.15.0, Foundry 1.9.0 (`forge`, `anvil` on PATH or in `~/.foundry/bin`),
and network access to an Ethereum Sepolia (chain 11155111) RPC. From the repository root:

```sh
pnpm install --frozen-lockfile
cd contracts
forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-git
forge build
cd ..
pnpm --filter @session-firewall/sdk build
pnpm --filter @session-firewall/sdk demo
```

The demo forks Ethereum Sepolia at block **12080000**, deploys local fixtures and firewall contracts,
onboards a Safe with `NoSafeOwner` and `FirewallOwnerValidator`, creates a session, buys 100 YES
shares for 50 USDC, attempts a 5,000 USDC drain (blocked), and exits the remaining 9,950 USDC to the
registered destination. It starts no application server or monitor. It uses a software P-256
authenticator solely as a local browser stand-in; **never fund these fixture keys on a public chain**.

Override `FORK_URLS` with a comma-separated list of Ethereum Sepolia RPC URLs (defaults: publicnode,
drpc and 1rpc public endpoints, tried in order) or `FORK_BLOCK_NUMBER` with another snapshot. The RPC
must serve state at the fork block, so use an archive endpoint once the default block is old. `FOUNDRY_BIN` selects a Foundry directory. `RPC_URL` attaches to an existing Anvil instance
on chain 31337 (forked Ethereum Sepolia, with code-size limits disabled). The local scripts refuse other
chain IDs. The optional `BUNDLER_URL`/`PAYMASTER_URL` use third-party ERC-4337 infrastructure; otherwise
a public Anvil development key submits `EntryPoint.handleOps` locally. No live bundler is claimed tested.

## APIs and passkeys

```ts
const account = await createFirewallAccount(client, {
  owner, // webAuthnOwner(...) or passkeyOwner(...), using FirewallOwnerValidator
  destinations: [coldWallet], markets: [{ market, adapter }], tokens: [usdc], hourlyCap: 1_000_000_000n,
});
const session = await createSession(account, { expiresAt, markets: [market] });
await fill(account, session, { market, order, amount });
await queueChange(account, { kind: "addDestination", destination });
await cancelChange(account, id);
await executeChange(account, maturedId);
await freeze(account);
await exit(account, { token: usdc, amount, destination: coldWallet });
```

Session market lists are a client check; onchain sessions use the firewall's registered-market set
(D13), not an independently signed market subset. The hook and epoch/freeze rules remain authoritative.
Persist the session key only on the user's device; this SDK neither uploads nor persists it for you.
Amounts/caps use token base units; USDC and outcome shares have six decimals. Read chain time for expiry.

`webAuthnOwner({validator, credential, stubAuth})` adapts a viem `toWebAuthnAccount` credential.
`passkeyOwner({validator,x,y,signAssertion,stubAuth})` accepts an authenticator integration directly.
Request ES256 (-7) with user verification required. `stubAuth` needs realistic response lengths for
gas estimation; the SDK replaces its signature scalars with zero. Real signatures are low-s normalized.
OnInstall data is `(bytes32 x, bytes32 y, string[] allowedContentTypes)`; credential IDs stay client-side.

User-operation assertions sign the operation hash directly. `signFirewallMessage(account, plaintext)`
produces the complete Safe7579-prefixed D12 PersonalSign signature for ERC-1271 (including monitor
subscription messages). `signFirewallTypedContent(account,{appDomainSeparator,contentsType,data})`
returns the TypedDataSign equivalent. `data` is EIP-712 encodeData **without** the leading type hash;
dynamic fields must already be hashed. Type allowlists and permit-spender checks are enforced onchain.
Raw envelope/digest helpers are also exported. Account domain: `FirewallOwnerValidator`, version `1`,
the current chain, verifying contract = account, zero nested salt (D12).

`ecdsaOwner` exists only for development/comparison tests: its validator lacks D12 restrictions.
Browser credential creation, device storage, browser support and recovery-origin enrollment belong
to M5 and are not verified by the software-authenticator demo. WebAuthn credentials are RP-bound:
do not promise arbitrary-origin or saved-file passkey recovery.

`decodeFirewallError` handles firewall errors, EntryPoint validation errors and generic Safe7579
`ExecutionFailed`. `explainRevert` tries trace/re-simulation when inner errors are hidden; providers
without tracing may yield only the generic message. Preserve validation-vs-execution distinctions.

## Verification and deployment limits

```sh
pnpm --filter @session-firewall/sdk test
pnpm --filter @session-firewall/sdk typecheck
pnpm --filter @session-firewall/sdk test:integration
pnpm --filter @session-firewall/sdk verify:infrastructure
```

`verify:infrastructure` reads Ethereum Sepolia (`VERIFY_RPC_URL`, optional `VERIFY_BLOCK_NUMBER`) and
prints code hashes plus the V13/V11 selector checks; `VERIFY_REPORT=<path>` also writes the JSON.

The integration suite uses the actual forked Safe, launchpad, EntryPoint and module registry. It
checks onboarding, NoSafeOwner, hook/session installation, trades, owner/session attacks, the 24-hour
queue, expiry/revocation/freeze, exits, D12 PersonalSign/TypedDataSign/permit rejection, and V13 ABI.
CI repeats the fork suite. `abi` regenerates committed ABIs from Foundry output.

**V13 blocks public deployment.** Both listed Ethereum Sepolia Smart Sessions deployments reject the
`enableSessions` tuple currently used by FirewallModule (selector `0xf55af6d1`). The fork installs
ModuleKit 0.5.9's matching runtime locally; that runtime is larger than EIP-170 permits. The fork
therefore needs `--disable-code-size-limit`, and this workaround cannot be shipped to testnet/mainnet.
Resolve the production ABI/build first; see `docs/decisions.md`. Do not point the deploy script at a
canonical address just because code exists there. `Deploy.s.sol` checks the expected selector before
deploying. A selector check is a compatibility screen, not proof of a contract's semantics.

`Deploy.s.sol` deploys deterministic wiring and the D12 owner validator; outputs are written to
`contracts/deployments/<chainId>.json`. The checked public infrastructure addresses/code hashes are in
`docs/sepolia-infrastructure.json`, captured at Ethereum Sepolia block 12080000; they are third-party addresses,
not a Session Firewall testnet deployment. No deployer funding, live bundler, public contract verification,
browser passkeys, or production readiness is implied by a passing local fork demo.
