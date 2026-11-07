import {
  http,
  type Account,
  type Address,
  type Chain,
  type Hash,
  type Hex,
  type Log,
  type PublicClient,
  type Transport,
  type WalletClient,
  decodeEventLog,
  isAddressEqual,
  isHex,
} from "viem";
import {
  type SmartAccount,
  type UserOperation,
  createBundlerClient,
  createPaymasterClient,
  entryPoint07Abi,
  getUserOperationHash,
  toPackedUserOperation,
  toSmartAccount,
} from "viem/account-abstraction";
import type { FirewallAddresses } from "./addresses.js";
import { type Call, encodeExecute, validatorNonceKey } from "./encoding.js";
import { FirewallError, decodeFirewallError, explainRevert } from "./errors.js";

/** Gas limits used when acting as the bundler locally (no estimation endpoint). */
export type GasOverrides = {
  verificationGasLimit: bigint;
  deployVerificationGasLimit: bigint;
  callGasLimit: bigint;
  preVerificationGas: bigint;
};

const DEFAULT_LOCAL_GAS: GasOverrides = {
  verificationGasLimit: 1_500_000n,
  deployVerificationGasLimit: 3_000_000n,
  callGasLimit: 3_000_000n,
  preVerificationGas: 100_000n,
};

export type FirewallClientConfig = {
  publicClient: PublicClient<Transport, Chain>;
  addresses: FirewallAddresses;
  /** ERC-4337 bundler RPC (BUNDLER_URL). Never hardcoded; when unset, `localBundler` is used. */
  bundlerUrl?: string;
  /** Optional ERC-7677 paymaster RPC (PAYMASTER_URL). Bundler mode only. */
  paymasterUrl?: string;
  /**
   * Local mode (Anvil): an EOA that submits `EntryPoint.handleOps` itself and collects the fees.
   * Used only when `bundlerUrl` is not set.
   */
  localBundler?: WalletClient<Transport, Chain, Account>;
  /** Gas limits for local mode. */
  localGas?: Partial<GasOverrides>;
};

/** Who signs a user operation: a validator module plus a signing function for it. */
export type UserOpSigner = {
  validator: Address;
  signUserOpHash(hash: Hex): Promise<Hex>;
  stubSignature: Hex;
};

export type SendUserOpParams = {
  sender: Address;
  signer: UserOpSigner;
  callData: Hex;
  /** Present only for the deployment user operation. */
  factory?: Address;
  factoryData?: Hex;
};

export type UserOpResult = {
  userOpHash: Hash;
  transactionHash: Hash;
  success: true;
  logs: readonly Log[];
};

/** viem SmartAccount view of a firewall account for one signer (owner or session). */
export async function toFirewallSmartAccount(
  config: FirewallClientConfig,
  p: Omit<SendUserOpParams, "callData">,
): Promise<SmartAccount> {
  const { publicClient, addresses } = config;
  const key = validatorNonceKey(p.signer.validator);
  return toSmartAccount({
    client: publicClient,
    entryPoint: {
      abi: entryPoint07Abi,
      address: addresses.entryPoint,
      version: "0.7",
    },
    getAddress: async () => p.sender,
    encodeCalls: async (calls) => encodeExecute(calls as readonly Call[]),
    getFactoryArgs: async () => ({
      factory: p.factory,
      factoryData: p.factoryData,
    }),
    getNonce: async () =>
      publicClient.readContract({
        address: addresses.entryPoint,
        abi: entryPoint07Abi,
        functionName: "getNonce",
        args: [p.sender, key],
      }),
    getStubSignature: async () => p.signer.stubSignature,
    signMessage: async () => {
      throw new Error(
        "Firewall accounts do not sign messages through the SDK (see docs/decisions.md D12).",
      );
    },
    signTypedData: async () => {
      throw new Error(
        "Firewall accounts do not sign typed data through the SDK (see docs/decisions.md D12).",
      );
    },
    signUserOperation: async ({ chainId, ...userOperation }) =>
      p.signer.signUserOpHash(
        getUserOperationHash({
          chainId: chainId ?? publicClient.chain.id,
          entryPointAddress: addresses.entryPoint,
          entryPointVersion: "0.7",
          userOperation: {
            ...userOperation,
            sender: p.sender,
          } as UserOperation<"0.7">,
        }),
      ),
  });
}

/** Sign and submit one user operation; resolves when it is mined and succeeded, throws FirewallError otherwise. */
export async function sendUserOp(
  config: FirewallClientConfig,
  p: SendUserOpParams,
): Promise<UserOpResult> {
  if (config.bundlerUrl) return sendViaBundler(config, p);
  if (config.localBundler) return sendLocally(config, p, config.localBundler);
  throw new Error(
    "Set bundlerUrl (BUNDLER_URL) or localBundler to submit user operations.",
  );
}

async function sendViaBundler(
  config: FirewallClientConfig,
  p: SendUserOpParams,
): Promise<UserOpResult> {
  const account = await toFirewallSmartAccount(config, p);
  const bundler = createBundlerClient({
    client: config.publicClient,
    transport: http(config.bundlerUrl),
    paymaster: config.paymasterUrl
      ? createPaymasterClient({ transport: http(config.paymasterUrl) })
      : undefined,
  });
  let userOpHash: Hash;
  try {
    userOpHash = await bundler.sendUserOperation({
      account,
      callData: p.callData,
    });
  } catch (cause) {
    // bundlers simulate execution during gas estimation, so a firewall block surfaces here
    const decoded =
      (await explainRevert(config.publicClient, {
        revertData: extractOrUndefined(cause),
        call: {
          from: config.addresses.entryPoint,
          to: p.sender,
          data: p.callData,
        },
        hook: config.addresses.hook,
      })) ?? decodeFirewallError(cause);
    throw new FirewallError(decoded, { cause });
  }
  const receipt = await bundler.waitForUserOperationReceipt({
    hash: userOpHash,
  });
  if (!receipt.success) {
    const decoded = await explainRevert(config.publicClient, {
      revertData:
        receipt.reason && isHex(receipt.reason) ? receipt.reason : undefined,
      transactionHash: receipt.receipt.transactionHash,
      call: {
        from: config.addresses.entryPoint,
        to: p.sender,
        data: p.callData,
      },
      hook: config.addresses.hook,
    });
    throw new FirewallError(decoded, {
      userOpHash,
      transactionHash: receipt.receipt.transactionHash,
    });
  }
  return {
    userOpHash,
    transactionHash: receipt.receipt.transactionHash,
    success: true,
    logs: receipt.logs,
  };
}

function extractOrUndefined(e: unknown): Hex | undefined {
  const d = decodeFirewallError(e);
  return d?.data;
}

async function sendLocally(
  config: FirewallClientConfig,
  p: SendUserOpParams,
  wallet: WalletClient<Transport, Chain, Account>,
): Promise<UserOpResult> {
  const { publicClient, addresses } = config;
  const gas = { ...DEFAULT_LOCAL_GAS, ...config.localGas };
  const fees = await publicClient.estimateFeesPerGas();
  const nonce = await publicClient.readContract({
    address: addresses.entryPoint,
    abi: entryPoint07Abi,
    functionName: "getNonce",
    args: [p.sender, validatorNonceKey(p.signer.validator)],
  });
  const userOperation: UserOperation<"0.7"> = {
    sender: p.sender,
    nonce,
    factory: p.factory,
    factoryData: p.factoryData,
    callData: p.callData,
    callGasLimit: gas.callGasLimit,
    verificationGasLimit: p.factory
      ? gas.deployVerificationGasLimit
      : gas.verificationGasLimit,
    preVerificationGas: gas.preVerificationGas,
    maxFeePerGas: fees.maxFeePerGas,
    maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
    signature: "0x",
  };
  const userOpHash = getUserOperationHash({
    chainId: publicClient.chain.id,
    entryPointAddress: addresses.entryPoint,
    entryPointVersion: "0.7",
    userOperation,
  });
  userOperation.signature = await p.signer.signUserOpHash(userOpHash);

  let transactionHash: Hash;
  try {
    transactionHash = await wallet.writeContract({
      address: addresses.entryPoint,
      abi: entryPoint07Abi,
      functionName: "handleOps",
      args: [[toPackedUserOperation(userOperation)], wallet.account.address],
      chain: wallet.chain,
    });
  } catch (cause) {
    // validation failures (FailedOp) revert handleOps itself
    throw new FirewallError(decodeFirewallError(cause), { userOpHash, cause });
  }
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: transactionHash,
  });
  const outcome = parseUserOpOutcome(
    receipt.logs,
    addresses.entryPoint,
    userOpHash,
  );
  if (receipt.status !== "success" || !outcome.success) {
    const decoded = await explainRevert(publicClient, {
      revertData: outcome.revertReason,
      transactionHash,
      call: {
        from: addresses.entryPoint,
        to: p.sender,
        data: p.callData,
        blockNumber: receipt.blockNumber - 1n,
      },
      hook: addresses.hook,
    });
    throw new FirewallError(decoded, { userOpHash, transactionHash });
  }
  return { userOpHash, transactionHash, success: true, logs: receipt.logs };
}

/** Read UserOperationEvent / UserOperationRevertReason for one user operation from receipt logs. */
export function parseUserOpOutcome(
  logs: readonly Log[],
  entryPoint: Address,
  userOpHash: Hash,
): { success: boolean; revertReason?: Hex } {
  let success = false;
  let revertReason: Hex | undefined;
  for (const log of logs) {
    if (!isAddressEqual(log.address, entryPoint)) continue;
    try {
      const ev = decodeEventLog({
        abi: entryPoint07Abi,
        data: log.data,
        topics: log.topics,
      });
      if (
        ev.eventName === "UserOperationEvent" &&
        ev.args.userOpHash === userOpHash
      )
        success = ev.args.success;
      if (
        ev.eventName === "UserOperationRevertReason" &&
        ev.args.userOpHash === userOpHash
      )
        revertReason = ev.args.revertReason;
    } catch {
      // other EntryPoint events
    }
  }
  return { success, revertReason };
}
