# Decisions and verification log

Status key: **OPEN** (not yet verified), **DECIDED** (choice made, rationale below), **VERIFIED** (checked against source, link given).

## M0 verification items (plan section 9)

Sources read on 2026-11-07: `rhinestonewtf/safe7579` @ `9f507f3` (2026-09-21), `erc7579/smartsessions` @ `f5aaf86` (2025-08-04), `rhinestonewtf/modulekit` 0.5.9 (`2210e2b`). Integration tests: `contracts/test/integration/SafeSmartSession.t.sol` (real Safe + Safe7579 + Smart Sessions bytecode via ModuleKit).

| # | Question | Status | Answer |
|---|---|---|---|
| V1 | One global hook or several? | **VERIFIED** | One global hook per account (`$globalHook[account]`); installing a second reverts `HookAlreadyInstalled` (`core/ModuleManager.sol`). We are the only hook, no multiplexer needed. Selector hooks are not used. |
| V2 | Does the hook run on every path? | **VERIFIED, with one exception** | `withHook` wraps `execute`, `executeFromExecutor`, `installModule`, `uninstallModule` and `fallback` (`Safe7579.sol`, `core/ModuleManager.sol`). Not hooked: `validateUserOp`, `isValidSignature`, `initializeAccount*` (one-shot: reverts once the executor list exists), `emergencyUninstallHook` (see **V11**). |
| V3 | Hook and policy interfaces | **VERIFIED** | `preCheck(address msgSender, uint256 msgValue, bytes msgData) returns (bytes)`, `postCheck(bytes)`. The Safe calls the hook through `execTransactionFromModule`, so `msg.sender` in the hook is the Safe. `msgData` carries 20 extra ERC-2771 bytes at the end, which our length-bounded decoder ignores. Smart Sessions: `IActionPolicy.checkAction(ConfigId, account, target, value, data) returns (uint256)`, `I1271Policy.check1271SignedAction(ConfigId, requestSender, account, hash, sig) view returns (bool)`, `IPolicy.initializeWithMultiplexer(account, ConfigId, initData)`, all ERC-165. |
| V4 | WebAuthn validator | **DECIDED; library audit gap** | Own validator, `FirewallOwnerValidator` (**D12**), on OpenZeppelin Contracts **5.6.1** `WebAuthn` and `P256` (pinned under the alias `@openzeppelin/contracts-webauthn`; the rest of the repo stays on 5.1). `P256.verify` tries the RIP-7212 precompile at `0x100`, then falls back to OZ's Solidity implementation; no curve code is ours. **Audit status, from OZ's `audits/README.md` at v5.6.1:** `P256` shipped in v5.1, whose changes were audited. `WebAuthn` first shipped in v5.5, but the v5.5 audit is listed with scope SafeERC20, ECDSA and SignatureChecker only, and no audit is listed for v5.6, so **we found no listed audit of `WebAuthn`. Put it in scope for our external audit.** Precompile: checked on Base Sepolia with a fresh signature (returns 1). A chain without it costs about 270k gas per verification through the fallback, and bundlers may refuse the call to the empty `0x100` address, so deploy only where the precompile exists. The owner user op passes ModuleKit's ERC-7562 simulation (`SIMULATE=true`, `-vvv`). Assertions need user verification (`UV`), so the web app must request `userVerification: "required"` and algorithm ES256 (-7). Origin and RP ID are the authenticator's job and are not checked onchain. **Browser support is not tested yet**; check it in the web app milestone. |
| V5 | EntryPoint / bundler on Base Sepolia; transient storage | PARTLY | Safe7579 targets EntryPoint v0.7 (`PackedUserOperation`). Transient storage is used only during execution. Bundler support still to be checked against a live endpoint. |
| V6 | Gas | **MEASURED** | Hook overhead on the owner path (`test/unit/HookGas.t.sol`): single fill **≈ 89k**, 4-fill batch **≈ 122k** (≈ 11k per extra fill), exit transfer **38–73k** (warm vs cold). Target for v1: ≤ 100k per single fill, ≤ 150k per 4-fill batch. Main fixed costs: one cold `accountView` read (≤ 27 slots) and `consume`. |
| V7 | Safe-native bypass (`execTransaction`) | **VERIFIED, mitigated by setup** | The launchpad lets the first user operation be validated by a validator module, so Safe owners can be just `NoSafeOwner` (threshold 1), a contract that rejects every signature. This also closes the Safe-signature fallbacks in `validateUserOp`, `isValidSignature` and `emergencyUninstallHook`. `signedMessages` needs a `SignMessageLib` delegatecall, which R1 blocks. **Onboarding must use `owners = [NoSafeOwner]`**, plus a test that the deployed Safe has no other owner. |
| V8 | Smart Sessions enable mode | **VERIFIED: real bypass; CLOSED by D12** | Enable mode (`SmartSession._enablePolicies`) adds any session whose digest passes `account.isValidSignature` during validation, where no hook runs. With one phished passkey signature, an attacker could enable a session with a permissive ERC-1271 policy plus ERC-7739 content, which could then sign permits (breaks R7/A13). The digest is EIP-712, so a raw-hash ban alone would not stop it: it could also be wrapped as `TypedDataSign`. The content rules in **D12** refuse it. `test_V8_*` in `test/integration/OwnerValidator.t.sol`, with a permissive-validator control showing the bypass is real. |
| V9 | `executeUserOp` | **VERIFIED** | Safe7579 does not implement `IAccountExecute`. The hook still rejects it. |
| V10 | Revert bubbling | **CONFLICTING** | HEAD source turns every inner revert into `ExecutionFailed()` (`core/ExecutionHelper.sol`). The ModuleKit 0.5.9 bytecode **bubbles our custom errors** (the integration tests assert the exact errors). The SDK must handle both: decode a firewall error when present, otherwise re-simulate (`debug_traceCall`, or a view `explain` helper on the hook). Re-check on the deployed Base Sepolia version. |
| V11 | **Emergency hook uninstall** (new) | **VERIFIED: bypass of R6; CLOSED by D12** | `emergencyUninstallHook` is not hooked and doesn't use our queue. With a signature from any installed validator via `isValidSignatureWithSender`, it removes the hook after 1 day, and **the owner cannot cancel it** (it only resets after 3 days). Smart Sessions sessions can't sign it (no 1271 policy). Safe signers can't (`NoSafeOwner`). The passkey now can't either: `EmergencyUninstall` is a reserved type (**D12**). **The function exists only in some versions:** Safe7579 at `9f507f3` has it, while the ModuleKit 0.5.9 bytecode and the contract at `0x7579EE8307284F293B1927136486880611F20002` on Base Sepolia do not (selector `0x5bfeadbb` is absent). `test_V11_*` therefore run on the upstream `9f507f3` artifact (`test/fixtures/Safe7579Head.sol`), with a control that removes the hook through a permissive validator. Any other validator added later reopens this, so the monitor should still alert on `EmergencyHookUninstallRequest` and on queued validator installs. |
| V13 | Smart Sessions struct ABI | **VERIFIED mismatch; public-deploy blocker** | At Base Sepolia block 55476014, canonical `0x00000000002B0eCfbD0496EE71e01257dA0E37DE` and legacy `0x00000000008bDABA73cD9815d79069c247Eb4bDA` lack the firewall's `enableSessions` selector `0xf55af6d1`. The fork test calls the exact old ABI against both and requires rejection. The local ModuleKit 0.5.9 runtime matches, but exceeds EIP-170 and is allowed only on Anvil 31337. Resolve a compatible deployable build or migrate the ABI before M7; no production source was changed in M4. |
| V12 | ModuleKit maintenance (new) | NOTE | ModuleKit is marked "no longer maintained". Fine as a test harness for v1. Before mainnet, re-run the integration suite against the exact deployed Safe7579 / Smart Sessions bytecode (fork test). |

## Design decisions made in M1

**D1. Snapshots travel in `hookData`, not transient storage.** DECIDED. ERC-7579 passes `preCheck`'s return value to `postCheck`, which is exactly the snapshot channel. This needs no slot bookkeeping and stays correct under nested hook calls (e.g. an ERC-1155 receiver callback during a fill). The plan's EIP-1153 note is satisfied in spirit: nothing persists past the call.

**D2. How R3 is made precise.** DECIDED. On an orderbook exchange the taker's USDC goes to the *maker*, not the market contract, so "increases at registered markets" can't be measured. Instead:

1. *Pre-check:* every direct `transfer`, `transferFrom` and `safe(Batch)TransferFrom` must send to the account or a registered destination. Every market call's adapter-declared `recipients` must be the account or a destination (this is what catches A5).
2. *Post-check:* the account and its destinations form one trust zone. Per tracked asset, if the zone's total balance fell, the drop must come from an asset a market call in this execution declared. Otherwise it reverts with `UnexplainedOutflow`. Declared drops are charged to the budget (R4).

Errors still match section 8: A1 and A5 raise `UnexplainedOutflow` (from pre-check), and post-check catches anything an adapter fails to declare (see `test_R3_postCheckCatchesUndeclaredOutflow`).

**D3. Valuation units.** DECIDED for v1. Tracked ERC-20s are $1 stablecoins with 6 decimals, and one share is 1e6 units paying at most $1. Worst case = USDC out + shares out − USDC in, floored at 0. Shares received are never credited.

**D4. Conservative charges.** `split` is charged its full USDC amount and `merge` its share outflow, even though both are value-neutral, because the budget never credits shares. This is sound but slightly strict. Revisit if it bothers users.

**D5. Hook ↔ module wiring.** The hook holds the module address immutably and the module holds the hook immutably. Deploy the hook against the *predicted* module address (see `test/Base.t.sol`; `Deploy.s.sol` will use CREATE2 for the same addresses on every chain).

**D6. Storage layout for ERC-7562.** All per-account module state is one struct at `keccak(account . slot)`, using fixed-size arrays (≤ 27 slots), so `FirewallActionPolicy` can read it during validation as associated storage. The queue is keyed `id => account => Change`.

**D7. Running a queued change must be a single call.** `account.execute([module.execute(id)])` skips the hook's balance checks (a matured `ConfigCall` may legitimately move funds), so the hook rejects any batch that contains `module.execute` alongside anything else.

**D8. Module call surface.** From an execution, the account may call only `queue`, `execute` (alone), `cancel`, `removeDestination`, `removeMarket`, `lowerCap`, `revokeSessions` and `freeze`. `onInstall` and `onUninstall` are refused: a reinstall would register new destinations instantly.

**D9. Approvals.** `approve(x, 0)`, `decreaseAllowance` and `setApprovalForAll(x, false)` are allowed for any spender, because revoking is tightening. A share token can only be approved to the market that settles it.

**D10. Freeze and sessions.** `freeze()` sets `frozen`, sets the cap to 0, empties the bucket and bumps `sessionEpoch`. `FirewallActionPolicy` (M2) will reject sessions whose recorded epoch is stale. Unfreezing is a queued change (`ChangeKind.Unfreeze`) and so is raising the cap again.

**D11. Uninstall preserves nonce and epoch.** Old queue ids can't collide after a reinstall, and revoked sessions stay revoked.

**D12. Owner validator (done; closes V8, V11 and A13).** `src/validators/FirewallOwnerValidator.sol` is the account's owner validator: one P-256 passkey per account, verified as a WebAuthn assertion (library choice in **V4**). State is keyed by account (ERC-7562 associated storage). There is no admin, upgrade path or delegatecall. Install data: `abi.encode(x, y, string[] allowedContentTypes)`.

- **User ops:** `validateUserOp` verifies an assertion over the `userOpHash`; the hook still bounds every execution.
- **ERC-1271 uses an allowlist, not a blocklist.** A blocklist fails open. EIP-3009 `TransferWithAuthorization` on USDC is one signature type that moves funds and is missing from the plan's list, and the next one may be a future token or module we haven't seen.

| Signature | Result |
|---|---|
| Raw hash, malformed bytes, ERC-7739 explicit mode | Invalid |
| `PersonalSign` with the plaintext message | Valid only if `hash` is the EIP-191 hash of that message |
| Reserved type: `EmergencyUninstall`, `MultiChainSession`, `ChainSession`, `SignedSession`, `SafeTx`, `SafeMessage`, `SafeOp`, `TypedDataSign`, `PersonalSign`, `TransferWithAuthorization`, `ReceiveWithAuthorization` | Always invalid, and can't be allowlisted |
| Permit family: `Permit`, `PermitSingle`, `PermitBatch`, `PermitTransferFrom`, `PermitBatchTransferFrom` and both witness variants | Valid only if the spender is a registered market (`marketAdapter(account, spender) != 0`). An unknown layout, such as DAI's `Permit`, is invalid |
| Any other `TypedDataSign` type | Valid only if its exact type string is on this account's allowlist. Empty by default |
| Any `TypedDataSign` while frozen | Invalid (R8). `PersonalSign` still works, so login isn't locked out |

- **Two additions to ERC-7739, both required for security.** The envelope is an ABI-encoded `SignatureEnvelope` rather than appended bytes, because it carries extra fields:
  1. `PersonalSign` carries the plaintext. Standard ERC-7739 wraps any 32-byte hash, so a hacked frontend could wrap a permit digest. An EIP-191 hash can't equal an EIP-712 digest.
  2. `TypedDataSign` carries the contents' `encodeData`, and the validator recomputes `contents = keccak(keccak(contentsType) || data)`. Otherwise a permit's struct hash could be presented under an allowlisted type name.
- **The signed digest is exactly ERC-7739's.** `keccak(0x1901 || appSeparator || contents)` must equal `hash`, then the passkey signs the nested `TypedDataSign` or `PersonalSign` digest. `test_erc7739_*` check these digests against Solady's `ERC1271`.
- **Account domain.** Safe has no ERC-5267 `eip712Domain()`, so the validator defines it: name `FirewallOwnerValidator`, version `1`, this chain, `verifyingContract` = the account, zero salt (`eip712Domain(account)`). The SDK must use these values.
- **Changes go through the queue (R6).** `setPasskey` and `setContentType` key on `msg.sender`, and the hook refuses direct account calls to the validator (`UnknownTarget`), so they are reachable only through a matured `ConfigCall`. FirewallHook and FirewallModule are unchanged.

Sessions are created only through `FirewallModule.createSession(...)` (D13), so no free-form session config is ever signed.

**Residual risk:**
- A generic dapp's plain ERC-7739 or raw signature is refused. Only our SDK can produce an accepted envelope, so unlisted integrations fail closed.
- A contract that acts on an EIP-191 personal message can still be authorised by a phished `PersonalSign`. No tracked asset does this today.
- A permit to a registered market bypasses the budget at signing time, like any approval to that market. The market's own logic bounds what it can pull.
- An allowlisted type is trusted on every domain. Allowlisting a registered market's order type would allow signed maker orders, which settle outside the hook, so keep the list empty until the v2 maker design lands.
- Removing an allowlisted type takes 24 hours, because the hook refuses direct validator calls. This differs from R6's "tightening is instant". `freeze()` is the instant stop for typed data.
- A phished signature can still queue a passkey change or a new validator. The 24-hour delay and the monitor are the defence there, and the same passkey can cancel it.

**D13. Sessions in M2 (done).** `FirewallModule.createSession(validator, initData, salt, validUntil)` builds the whole Smart Sessions config. It uses one *fallback* action (`target = address(1)`, selector `0x00000001`) guarded by `FirewallActionPolicy`, which covers every call except calls into Smart Sessions itself (those are never configured, so they always fail). It sets no user-op policies. ERC-1271 has no allowed ERC-7739 content plus `NoSignaturePolicy`. Expiry is ≤ 30 days and is returned as ERC-4337 `validUntil`, so validation never reads `TIMESTAMP`. Creating a session is instant (it is bounded by R1–R5 and the budget); `removeSession` is instant. The account calling Smart Sessions directly is `UnknownTarget`.
- `FirewallActionPolicy` allows only tracked tokens, registered markets and their share tokens, with zero value, while not frozen and while the session epoch is unchanged. Sessions therefore cannot exit to destinations, call the module, or touch the account; exits are owner-only.
- Behaviour change vs. section 8: from a session, A4, A9 and A12 are rejected **at validation** (the bundler drops the op; there is no `Frozen` / `UnknownTarget` revert to show). A1, A2, A3, A5, A6 and A7 pass validation and are stopped by the hook with the named error. See `test/integration/SafeSmartSession.t.sol` (`test_M2_*`).
- The plan's EIP-4361 login flag is **not implemented**: a 1271 policy only receives the final hash, so it can't tell a login message from a permit. Revisit with an ERC-7739 `PersonalSign` content check if a partner needs session-key login.

## Still open before testnet (plan section 9)

- **A13, V8, V11: closed by D12** (`test/integration/OwnerValidator.t.sol`). Before testnet: `V7` setup must use `NoSafeOwner`, the SDK must build the D12 envelopes, and `WebAuthn` needs audit coverage (V4).
- **Destination side effects.** A destination that is a contract forwarding funds onward inside the same transaction would trip `UnexplainedOutflow` (a false positive, not a loss). Recommend EOAs or simple vaults as destinations.

## M4 SDK verification (2026-11-07)

Runbook: `packages/sdk/README.md`. Passkey user ops and D12 envelopes are built by the SDK and tested
against the deployed FirewallOwnerValidator on an Anvil fork. The demo uses a local software P-256
authenticator, not an ECDSA owner placeholder; browser credential creation/recovery remains M5.
The suite covers onboard -> session -> trade -> blocked drain -> exit, plus NoSafeOwner, queue,
freeze/revocation/expiry and owner/session attacks. No application server or monitor authorizes it.

**V14 — Public infrastructure:** `docs/base-sepolia-infrastructure.json` records code presence, sizes
and hashes at Base Sepolia block 55476014 for EntryPoint v0.7, Safe 1.4.1, Safe7579, launchpad,
registry, OwnableValidator, CREATE2 factory and both incompatible Smart Sessions deployments.
This is runtime evidence, not explorer source verification. Firewall contract addresses exist only
on the local fork. M7 still needs V13 resolved, funded deployment, a bundler and published addresses.

**CROPS boundaries:** see `docs/crops-submission.md`. Lead property is onchain protection from a
compromised client. RP-domain-bound passkeys mean saved-file/arbitrary-origin recovery cannot be
claimed without a separately enrolled/tested recovery path. The three-minute browser video and
tracker-free client bundle audit remain M5/M8 submission gates.

## M6 monitor verification (2026-11-07)

Implementation and runbook: `apps/monitor/README.md`. The opt-in indexer and worker cover queue,
rolling 80% budget, blocked attempts, emergency hook uninstall, freeze and revocation. Subscription
writes require account signatures, timestamp and single-use nonce; signed webhooks use per-account,
per-URL secrets. Postgres persistence, retries and replay protection are covered by the unit suite.

Local results: 85 unit tests and 5 process-level Anvil/Ponder/worker/webhook tests pass. Three queued
changes were delivered in 2723, 1967 and 1909 milliseconds (<60 s each), including transaction submission.
The CI job runs lint, codegen/typecheck, unit tests and this end-to-end flow on `m6-monitor` pushes.

**M6 public-testnet acceptance remains pending M7 deployment.** No Base Sepolia module address or
provider delivery result is claimed. The test uses real module queue/budget/freeze calls; EntryPoint
and emergency events use log emitters to isolate indexing and account attribution. The worker's
application links target the settings and exit routes to be implemented in M5.
