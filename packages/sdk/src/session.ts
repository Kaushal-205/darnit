import {
  type Address,
  type Hex,
  decodeEventLog,
  encodeFunctionData,
  isAddressEqual,
  toHex,
  zeroAddress,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { firewallModuleAbi } from "./abi/index.js";
import { type FirewallAccount, executeAsOwner } from "./account.js";
import {
  type Call,
  DUMMY_ECDSA_SIGNATURE,
  encodeExecute,
  encodeOwnableValidatorData,
  encodeSmartSessionUseSignature,
  permissionIdOf,
} from "./encoding.js";
import { type SignedOrder, encodeFill } from "./market.js";
import { type UserOpResult, type UserOpSigner, sendUserOp } from "./userop.js";

/**
 * A session key and its Smart Sessions permission. Holding `privateKey` is enough to trade within the
 * firewall's limits until `validUntil`; where it is stored (memory, IndexedDB, ...) is up to the caller.
 */
export type FirewallSession = {
  account: Address;
  privateKey: Hex;
  address: Address;
  permissionId: Hex;
  validUntil: number;
  salt: Hex;
  sessionValidator: Address;
  sessionValidatorInitData: Hex;
};

export type CreateSessionParams = {
  /** Expiry as a Date or unix seconds. At most 30 days ahead (FirewallModule.MAX_SESSION_DURATION). */
  expiresAt: Date | number;
  /**
   * Markets the caller intends to trade. Checked to be registered on the account before sending.
   * Scope note (docs/decisions.md D13): a firewall session may call every registered market, tracked token
   * and share token of the account; per-session market subsets are not enforced on-chain in v1.
   */
  markets?: readonly Address[];
  /** Bring your own key; default is a fresh random key. */
  privateKey?: Hex;
  /** Default random. */
  salt?: Hex;
};

/**
 * Create a session (D13): the owner calls `FirewallModule.createSession`, which builds the Smart Sessions
 * config itself (FirewallActionPolicy + NoSignaturePolicy) and enables it. Sessions are never enabled
 * directly on Smart Sessions. The session key is validated by OwnableValidator in stateless mode.
 */
export async function createSession(
  account: FirewallAccount,
  p: CreateSessionParams,
): Promise<FirewallSession & { result: UserOpResult }> {
  const { publicClient, addresses } = account.client;
  for (const market of p.markets ?? []) {
    const adapter = await publicClient.readContract({
      address: addresses.module,
      abi: firewallModuleAbi,
      functionName: "marketAdapter",
      args: [account.address, market],
    });
    if (isAddressEqual(adapter, zeroAddress))
      throw new Error(`Market ${market} is not registered on this account.`);
  }
  const privateKey = p.privateKey ?? generatePrivateKey();
  const key = privateKeyToAccount(privateKey);
  const validUntil =
    typeof p.expiresAt === "number"
      ? p.expiresAt
      : Math.floor(p.expiresAt.getTime() / 1000);
  const salt = p.salt ?? toHex(crypto.getRandomValues(new Uint8Array(32)));
  const sessionValidator = addresses.ownableValidator;
  const sessionValidatorInitData = encodeOwnableValidatorData([key.address]);

  const result = await executeAsOwner(account, [
    {
      to: addresses.module,
      data: encodeFunctionData({
        abi: firewallModuleAbi,
        functionName: "createSession",
        args: [sessionValidator, sessionValidatorInitData, salt, validUntil],
      }),
    },
  ]);

  let permissionId = permissionIdOf(
    sessionValidator,
    sessionValidatorInitData,
    salt,
  );
  for (const log of result.logs) {
    if (!isAddressEqual(log.address, addresses.module)) continue;
    try {
      const ev = decodeEventLog({
        abi: firewallModuleAbi,
        data: log.data,
        topics: log.topics,
      });
      if (ev.eventName === "SessionCreated")
        permissionId = ev.args.permissionId;
    } catch {
      // other module events
    }
  }
  return {
    account: account.address,
    privateKey,
    address: key.address,
    permissionId,
    validUntil,
    salt,
    sessionValidator,
    sessionValidatorInitData,
    result,
  };
}

/** Smart Sessions USE-mode signer for a session key. */
export function sessionSigner(
  account: FirewallAccount,
  session: FirewallSession,
): UserOpSigner {
  const key = privateKeyToAccount(session.privateKey);
  return {
    validator: account.client.addresses.smartSessions,
    // the deployed OwnableValidator recovers over the EIP-191 hash of the user operation hash (seen on the fork)
    signUserOpHash: async (hash) =>
      encodeSmartSessionUseSignature(
        session.permissionId,
        await key.signMessage({ message: { raw: hash } }),
      ),
    stubSignature: encodeSmartSessionUseSignature(
      session.permissionId,
      DUMMY_ECDSA_SIGNATURE,
    ),
  };
}

/** Session-signed execution of arbitrary calls. FirewallActionPolicy and the hook decide what passes. */
export function executeAsSession(
  account: FirewallAccount,
  session: FirewallSession,
  calls: readonly Call[],
): Promise<UserOpResult> {
  return sendUserOp(account.client, {
    sender: account.address,
    signer: sessionSigner(account, session),
    callData: encodeExecute(calls),
  });
}

/** Take a maker order on a registered market with the session key. Proceeds go to the account. */
export function fill(
  account: FirewallAccount,
  session: FirewallSession,
  p: { market: Address; order: SignedOrder; amount: bigint },
): Promise<UserOpResult> {
  return executeAsSession(account, session, [
    { to: p.market, data: encodeFill(p.order, p.amount, account.address) },
  ]);
}
