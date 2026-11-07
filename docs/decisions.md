# Decisions and verification log

Status key: **OPEN** (not yet verified), **DECIDED** (choice made, rationale below), **VERIFIED** (checked against source, link given).

## M0 verification items (plan section 9)

Sources read on 2026-11-07: `rhinestonewtf/safe7579` @ `9f507f3` (2026-09-21), `erc7579/smartsessions` @ `f5aaf86` (2025-08-04), `rhinestonewtf/modulekit` 0.5.9 (`2210e2b`). Integration tests: `contracts/test/integration/SafeSmartSession.t.sol` (real Safe + Safe7579 + Smart Sessions bytecode via ModuleKit).

| # | Question | Status | Answer |
|---|---|---|---|
| V1 | One global hook or several? | **VERIFIED** | One global hook per account (`$globalHook[account]`); installing a second reverts `HookAlreadyInstalled` (`core/ModuleManager.sol`). We are the only hook, no multiplexer needed. Selector hooks are not used. |
| V2 | Does the hook run on every path? | **VERIFIED, with one exception** | `withHook` wraps `execute`, `executeFromExecutor`, `installModule`, `uninstallModule` and `fallback` (`Safe7579.sol`, `core/ModuleManager.sol`). Not hooked: `validateUserOp`, `isValidSignature`, `initializeAccount*` (one-shot: reverts once the executor list exists), `emergencyUninstallHook` (see **V11**). |
| V3 | Hook and policy interfaces | **VERIFIED** | `preCheck(address msgSender, uint256 msgValue, bytes msgData) returns (bytes)`, `postCheck(bytes)`. The Safe calls the hook through `execTransactionFromModule`, so `msg.sender` in the hook is the Safe. `msgData` carries 20 extra ERC-2771 bytes at the end, which our length-bounded decoder ignores. Smart Sessions: `IActionPolicy.checkAction(ConfigId, account, target, value, data) returns (uint256)`, `I1271Policy.check1271SignedAction(ConfigId, requestSender, account, hash, sig) view returns (bool)`, `IPolicy.initializeWithMultiplexer(account, ConfigId, initData)`, all ERC-165. |
| V4 | WebAuthn validator | OPEN | Must be wrapped anyway (see **D12**). |
| V5 | EntryPoint / bundler on Base Sepolia; transient storage | PARTLY | Safe7579 targets EntryPoint v0.7 (`PackedUserOperation`). Transient storage is used only during execution. Bundler support still to be checked against a live endpoint. |
| V6 | Gas | **MEASURED** | Hook overhead on the owner path (`test/unit/HookGas.t.sol`): single fill **≈ 89k**, 4-fill batch **≈ 122k** (≈ 11k per extra fill), exit transfer **38–73k** (warm vs cold). Target for v1: ≤ 100k per single fill, ≤ 150k per 4-fill batch. Main fixed costs: one cold `accountView` read (≤ 27 slots) and `consume`. |
| V7 | Safe-native bypass (`execTransaction`) | **VERIFIED, mitigated by setup** | The launchpad lets the first user operation be validated by a validator module, so Safe owners can be just `NoSafeOwner` (threshold 1), a contract that rejects every signature. This also closes the Safe-signature fallbacks in `validateUserOp`, `isValidSignature` and `emergencyUninstallHook`. `signedMessages` needs a `SignMessageLib` delegatecall, which R1 blocks. **Onboarding must use `owners = [NoSafeOwner]`**, plus a test that the deployed Safe has no other owner. |
| V8 | Smart Sessions enable mode | **VERIFIED: real bypass** | Enable mode (`SmartSession._enablePolicies`) adds any session whose digest passes `account.isValidSignature` during validation, where no hook runs. With one phished passkey signature, an attacker can enable a session with a permissive ERC-1271 policy plus ERC-7739 content, which can then sign permits (breaks R7/A13). Sessions with **no** 1271 policies can't sign: `checkERC1271` reverts `NoPoliciesSet`, and content must be allow-listed. Fix in **D12**. |
| V9 | `executeUserOp` | **VERIFIED** | Safe7579 does not implement `IAccountExecute`. The hook still rejects it. |
| V10 | Revert bubbling | **CONFLICTING** | HEAD source turns every inner revert into `ExecutionFailed()` (`core/ExecutionHelper.sol`). The ModuleKit 0.5.9 bytecode **bubbles our custom errors** (the integration tests assert the exact errors). The SDK must handle both: decode a firewall error when present, otherwise re-simulate (`debug_traceCall`, or a view `explain` helper on the hook). Re-check on the deployed Base Sepolia version. |
| V11 | **Emergency hook uninstall** (new) | **VERIFIED: bypass of R6** | `emergencyUninstallHook` is not hooked and doesn't use our queue. With a signature from any installed validator via `isValidSignatureWithSender`, it removes the hook after 1 day, and **the owner cannot cancel it** (it only resets after 3 days). Smart Sessions sessions can't sign it (no 1271 policy). Safe signers can't (`NoSafeOwner`). So the remaining vector is a phished owner passkey. Fix in **D12**. Until then the monitor must alert on `EmergencyHookUninstallRequest`, and the runbook response is to exit to a destination. |
| V13 | Smart Sessions struct ABI (new) | **NOTE: pin it** | ModuleKit 0.5.9 bundles a Smart Sessions version whose `ERC7739Data.allowedERC7739Content` is `string[]`; HEAD (`f5aaf86`) uses `ERC7739Context[]`. `FirewallModule.createSession` ABI-encodes the session itself (`src/interfaces/ISmartSessions.sol`), so the deployed Smart Sessions **must** match that ABI. Check before deploy; add a fork test against the deployed address. |
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

**D12. Wrap the owner validator (planned for M2; closes V8, V11 and A13).** `FirewallOwnerValidator` wraps the WebAuthn validator: it passes `validateUserOp` straight through, but its `isValidSignatureWithSender` accepts only ERC-7739 nested typed-data or personal-sign envelopes, so it can see what is being signed. It rejects:
- raw hashes. That disables owner-signed Smart Sessions enable mode and `emergencyUninstallHook`, which both pass bare hashes;
- `Permit`, `PermitSingle` and `PermitBatch` contents unless the spender is a registered market (A13);
- `EmergencyUninstall` contents outright.

Sessions are then created only through a new `FirewallModule.createSession(...)`. The module builds the `Session` itself, always with `FirewallActionPolicy` and `NoSignaturePolicy`, and enables it via `executeFromExecutor`, so no free-form session config is ever signed. Revocation stays instant.

**D13. Sessions in M2 (done).** `FirewallModule.createSession(validator, initData, salt, validUntil)` builds the whole Smart Sessions config. It uses one *fallback* action (`target = address(1)`, selector `0x00000001`) guarded by `FirewallActionPolicy`, which covers every call except calls into Smart Sessions itself (those are never configured, so they always fail). It sets no user-op policies. ERC-1271 has no allowed ERC-7739 content plus `NoSignaturePolicy`. Expiry is ≤ 30 days and is returned as ERC-4337 `validUntil`, so validation never reads `TIMESTAMP`. Creating a session is instant (it is bounded by R1–R5 and the budget); `removeSession` is instant. The account calling Smart Sessions directly is `UnknownTarget`.
- `FirewallActionPolicy` allows only tracked tokens, registered markets and their share tokens, with zero value, while not frozen and while the session epoch is unchanged. Sessions therefore cannot exit to destinations, call the module, or touch the account; exits are owner-only.
- Behaviour change vs. section 8: from a session, A4, A9 and A12 are rejected **at validation** (the bundler drops the op; there is no `Frozen` / `UnknownTarget` revert to show). A1, A2, A3, A5, A6 and A7 pass validation and are stopped by the hook with the named error. See `test/integration/SafeSmartSession.t.sol` (`test_M2_*`).
- The plan's EIP-4361 login flag is **not implemented**: a 1271 policy only receives the final hash, so it can't tell a login message from a permit. Revisit with an ERC-7739 `PersonalSign` content check if a partner needs session-key login.

## Still open before testnet (plan section 9)

- **A13, V8, V11.** All three are closed by D12 (M2). Until it lands, a phished passkey signature can enable a permissive session or start an emergency hook uninstall.
- **Destination side effects.** A destination that is a contract forwarding funds onward inside the same transaction would trip `UnexplainedOutflow` (a false positive, not a loss). Recommend EOAs or simple vaults as destinations.
