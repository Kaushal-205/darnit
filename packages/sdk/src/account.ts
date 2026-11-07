import {
  type Address,
  type Hex,
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  getContractAddress,
  keccak256,
  parseAbiParameters,
  toHex,
  zeroAddress,
} from "viem";
import {
  safe7579Abi,
  safe7579LaunchpadAbi,
  safeProxyFactoryAbi,
} from "./abi/external.js";
import {
  type Call,
  MODULE_TYPE,
  type MarketEntry,
  PLACEHOLDER_ATTESTER,
  encodeExecute,
  encodeGlobalHookInitData,
  encodeModuleInitData,
} from "./encoding.js";
import type { OwnerSigner } from "./owner.js";
import {
  type FirewallClientConfig,
  type UserOpResult,
  sendUserOp,
} from "./userop.js";

/** A deployed (or counterfactual) firewall account and how to reach it. */
export type FirewallAccount = {
  address: Address;
  owner: OwnerSigner;
  client: FirewallClientConfig;
};

export type CreateFirewallAccountParams = {
  owner: OwnerSigner;
  /** Exit addresses (cold wallet, exchange deposit). Active immediately. At most 8. */
  destinations: readonly Address[];
  /** Markets with their adapters. Active immediately. At most 4. */
  markets: readonly MarketEntry[];
  /** Hourly risk budget in USDC base units (6 decimals). */
  hourlyCap: bigint;
  /** Tracked ERC-20s (USDC). At most 4. */
  tokens: readonly Address[];
  /** CREATE2 salt nonce for the Safe proxy; vary it to get several accounts per owner. */
  saltNonce?: bigint;
};

const launchpadInitDataParams = parseAbiParameters(
  "address singleton, address[] owners, uint256 threshold, address setupTo, bytes setupData, address safe7579, (address module, bytes initData)[] validators",
);

export type AccountInit = {
  address: Address;
  factory: Address;
  factoryData: Hex;
  /** First user operation's callData: Safe7579Launchpad.setupSafe(initData). */
  callData: Hex;
  initHash: Hex;
};

/**
 * Build the Safe7579-launchpad deployment for a firewall account (docs/decisions.md V7, D13):
 * - Safe owners = [NoSafeOwner], threshold 1: no Safe-native signature can ever authorise anything.
 * - Validators (installed during validation of the first user operation): the owner's validator and
 *   Smart Sessions.
 * - Then, in the same first operation, in this order: switch off Safe7579's ERC-7484 registry check on installs
 *   (the canonical launchpad hardwires the Rhinestone registry and needs at least one attester, and our modules
 *   are not attested there), install FirewallModule (executor) with its config, and install FirewallHook as the
 *   global hook. Once the hook is on, every later install or config change has to go through the 24-hour queue.
 */
export async function buildAccountInit(
  client: FirewallClientConfig,
  p: CreateFirewallAccountParams,
): Promise<AccountInit> {
  const a = client.addresses;
  const setupData = encodeFunctionData({
    abi: safe7579LaunchpadAbi,
    functionName: "initSafe7579",
    args: [a.safe7579, [], [], [], [a.attester ?? PLACEHOLDER_ATTESTER], 1],
  });
  const validators = [
    { module: p.owner.validator, initData: p.owner.validatorInitData },
    { module: a.smartSessions, initData: "0x" as Hex },
  ];
  const base = {
    singleton: a.safeSingleton,
    owners: [a.noSafeOwner],
    threshold: 1n,
    setupTo: a.safe7579Launchpad,
    setupData,
    safe7579: a.safe7579,
    validators,
  };
  // Safe7579Launchpad.hash(): every field except callData
  const initHash = keccak256(
    encodeAbiParameters(launchpadInitDataParams, [
      base.singleton,
      base.owners,
      base.threshold,
      base.setupTo,
      base.setupData,
      base.safe7579,
      base.validators,
    ]),
  );
  const initializer = encodeFunctionData({
    abi: safe7579LaunchpadAbi,
    functionName: "preValidationSetup",
    args: [initHash, zeroAddress, "0x"],
  });
  const saltNonce = p.saltNonce ?? 0n;
  const proxyCreationCode = await client.publicClient.readContract({
    address: a.safeProxyFactory,
    abi: safeProxyFactoryAbi,
    functionName: "proxyCreationCode",
  });
  const address = getContractAddress({
    opcode: "CREATE2",
    from: a.safeProxyFactory,
    salt: keccak256(
      concatHex([keccak256(initializer), toHex(saltNonce, { size: 32 })]),
    ),
    bytecode: concatHex([
      proxyCreationCode,
      toHex(BigInt(a.safe7579Launchpad), { size: 32 }),
    ]),
  });

  const install = (
    moduleType: bigint,
    module: Address,
    initData: Hex,
  ): Call => ({
    to: address,
    data: encodeFunctionData({
      abi: safe7579Abi,
      functionName: "installModule",
      args: [moduleType, module, initData],
    }),
  });
  const postSetup = encodeExecute([
    {
      to: address,
      data: encodeFunctionData({
        abi: safe7579Abi,
        functionName: "setRegistry",
        args: [zeroAddress, [], 0],
      }),
    },
    install(
      MODULE_TYPE.executor,
      a.module,
      encodeModuleInitData({
        hourlyCap: p.hourlyCap,
        tokens: p.tokens,
        destinations: p.destinations,
        markets: p.markets,
      }),
    ),
    install(MODULE_TYPE.hook, a.hook, encodeGlobalHookInitData()),
  ]);

  const callData = encodeFunctionData({
    abi: safe7579LaunchpadAbi,
    functionName: "setupSafe",
    args: [{ ...base, callData: postSetup }],
  });
  const factoryData = encodeFunctionData({
    abi: safeProxyFactoryAbi,
    functionName: "createProxyWithNonce",
    args: [a.safe7579Launchpad, initializer, saltNonce],
  });
  return {
    address,
    factory: a.safeProxyFactory,
    factoryData,
    callData,
    initHash,
  };
}

/**
 * Onboarding: deploy a Safe + Safe7579 firewall account in one user operation, signed by the owner.
 * The counterfactual address must hold enough ETH for gas (or use a paymaster) before calling this.
 * If the account already exists, nothing is sent.
 */
export async function createFirewallAccount(
  client: FirewallClientConfig,
  p: CreateFirewallAccountParams,
): Promise<FirewallAccount & { deployment?: UserOpResult }> {
  const init = await buildAccountInit(client, p);
  const account: FirewallAccount = {
    address: init.address,
    owner: p.owner,
    client,
  };
  const code = await client.publicClient.getCode({ address: init.address });
  if (code && code !== "0x") return account;
  const deployment = await sendUserOp(client, {
    sender: init.address,
    signer: p.owner,
    callData: init.callData,
    factory: init.factory,
    factoryData: init.factoryData,
  });
  return { ...account, deployment };
}

/** Reconnect to an existing account. */
export function getFirewallAccount(
  client: FirewallClientConfig,
  address: Address,
  owner: OwnerSigner,
): FirewallAccount {
  return { address, owner, client };
}

/** Owner-signed execution of arbitrary calls. The hook checks them like any other execution. */
export function executeAsOwner(
  account: FirewallAccount,
  calls: readonly Call[],
): Promise<UserOpResult> {
  return sendUserOp(account.client, {
    sender: account.address,
    signer: account.owner,
    callData: encodeExecute(calls),
  });
}
