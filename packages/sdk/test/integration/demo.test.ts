import {
  http,
  type Address,
  type BaseError,
  type Hex,
  concat,
  createPublicClient,
  createTestClient,
  createWalletClient,
  encodeAbiParameters,
  encodeFunctionData,
  hashMessage,
  keccak256,
  parseEther,
  stringToHex,
  toFunctionSelector,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { localClientConfig, runDemo } from "../../scripts/demo.js";
import {
  ANVIL_KEYS,
  type LocalEnv,
  startLocalEnv,
} from "../../scripts/local-env.js";
import {
  ETHEREUM_SEPOLIA,
  type FirewallAccount,
  FirewallError,
  type FirewallSession,
  MODULE_TYPE,
  ORDER_SIDE,
  approveMarket,
  buildAccountInit,
  cancelChange,
  createFirewallAccount,
  createSession,
  ecdsaOwner,
  executeAsOwner,
  executeAsSession,
  executeChange,
  exit,
  fill,
  firewallModuleAbi,
  firewallSmartSessionsAbi,
  freeze,
  getFirewallState,
  mockUsdcAbi,
  queueChange,
  removeSession,
  safe7579Abi,
  safe7579LaunchpadAbi,
  safeAbi,
  signFirewallMessage,
  signFirewallTypedContent,
  signReferenceOrder,
  smartSessionsAbi,
} from "../../src/index.js";

import { testPasskey } from "../../scripts/test-passkey.js";
import { firewallOwnerDomainSeparator } from "../../src/passkey.js";

let env: LocalEnv;

beforeAll(async () => {
  env = await startLocalEnv();
});

afterAll(() => env?.stop());

describe("V13: exact Smart Sessions ABI", () => {
  it("local matching build accepts the firewall ABI; canonical deployments reject it", async () => {
    const client = localClientConfig(env).publicClient;
    const data = encodeFunctionData({
      abi: firewallSmartSessionsAbi,
      functionName: "enableSessions",
      args: [[]],
    });
    /** Raw revert data of `eth_call`; throws if the call does not revert. */
    const revertData = async (to: Address, callData: Hex): Promise<string> => {
      try {
        await client.request({
          method: "eth_call",
          params: [{ to, data: callData }, "latest"],
        });
      } catch (e) {
        const hit = (e as BaseError).walk(
          (x) => typeof (x as { data?: unknown }).data === "string",
        ) as unknown as { data?: string };
        if (typeof hit.data === "string") return hit.data;
        throw e;
      }
      throw new Error(`eth_call to ${to} did not revert`);
    };
    // An empty list is refused inside enableSessions with InvalidData(), which proves the selector
    // dispatches on the matching build.
    expect(await revertData(env.addresses.smartSessions, data)).toBe(
      toFunctionSelector("InvalidData()"),
    );
    // The deployments have no such function: same bare revert as a selector nothing implements.
    for (const address of [
      ETHEREUM_SEPOLIA.smartSessionsCanonical,
      ETHEREUM_SEPOLIA.smartSessionsLegacy,
    ]) {
      expect(await revertData(address, data)).toBe("0x");
      expect(await revertData(address, "0xdeadbeef")).toBe("0x");
    }
  });
});

describe("M4 demo", () => {
  it("onboard -> session -> trade -> blocked drain -> exit", async () => {
    const lines: string[] = [];
    const r = await runDemo(env, (l) => {
      lines.push(l);
      console.log(l);
    });
    expect(r.sharesBought).toBe(100_000_000n);
    expect(r.budgetAfterTrade).toBeLessThanOrEqual(950_000_000n + 1_000_000n);
    expect(r.blockedError).toBe("UnexplainedOutflow");
    expect(r.blockedMessage).toContain("not a registered destination");
    expect(r.attackerBalance).toBe(0n);
    expect(r.destinationBalance).toBe(9_950_000_000n);
    expect(r.accountUsdcAfterExit).toBe(0n);
  });
});

describe("firewall account on real Safe7579, launchpad and EntryPoint", () => {
  const destination = privateKeyToAccount(generatePrivateKey()).address;
  const attacker = privateKeyToAccount(generatePrivateKey()).address;
  const maker = privateKeyToAccount(ANVIL_KEYS.maker);
  const hourlyCap = 1_000_000_000n;
  let account: FirewallAccount;
  let session: FirewallSession;

  const client = () => localClientConfig(env);
  const pub = () =>
    createPublicClient({
      chain: client().publicClient.chain,
      transport: http(env.rpcUrl),
    });
  const test = () =>
    createTestClient({
      chain: client().publicClient.chain,
      mode: "anvil",
      transport: http(env.rpcUrl),
    });
  const now = async () => (await pub().getBlock()).timestamp;

  const usdcCall = (
    fn: "transfer" | "approve",
    to: Address,
    amount: bigint,
  ): { to: Address; data: Hex } => ({
    to: env.fixtures.usdc,
    data: encodeFunctionData({
      abi: mockUsdcAbi,
      functionName: fn,
      args: [to, amount],
    }),
  });

  /** The name of the error an operation fails with. */
  const blockedBy = async (op: Promise<unknown>) => {
    try {
      await op;
    } catch (e) {
      if (e instanceof FirewallError) return e.decoded?.name;
      throw e;
    }
    return "NOT BLOCKED";
  };

  const buy = async (amount: bigint) => {
    const order = await signReferenceOrder(maker, {
      market: env.fixtures.market,
      chainId: client().publicClient.chain.id,
      order: {
        tokenId: BigInt(env.fixtures.yesId),
        side: ORDER_SIDE.Sell,
        price: 500_000n,
        amount,
        expiry: (await now()) + 30n * 86_400n,
        salt: BigInt(Math.floor(Math.random() * 2 ** 48)),
      },
    });
    return fill(account, session, {
      market: env.fixtures.market,
      order,
      amount,
    });
  };

  beforeAll(async () => {
    const params = {
      owner: ecdsaOwner(privateKeyToAccount(generatePrivateKey())),
      destinations: [destination],
      markets: [{ market: env.fixtures.market, adapter: env.fixtures.adapter }],
      tokens: [env.fixtures.usdc],
      hourlyCap,
      saltNonce: 42n,
    };
    const init = await buildAccountInit(client(), params);
    // the launchpad must agree with our local hash, or the deployment could never validate
    const onChainHash = await pub().readContract({
      address: env.addresses.safe7579Launchpad,
      abi: safe7579LaunchpadAbi,
      functionName: "hash",
      args: [
        {
          singleton: env.addresses.safeSingleton,
          owners: [env.addresses.noSafeOwner],
          threshold: 1n,
          setupTo: env.addresses.safe7579Launchpad,
          setupData: encodeFunctionData({
            abi: safe7579LaunchpadAbi,
            functionName: "initSafe7579",
            args: [
              env.addresses.safe7579,
              [],
              [],
              [],
              [env.addresses.attester as Address],
              1,
            ],
          }),
          safe7579: env.addresses.safe7579,
          validators: [
            {
              module: params.owner.validator,
              initData: params.owner.validatorInitData,
            },
            { module: env.addresses.smartSessions, initData: "0x" },
          ],
          callData: "0x",
        },
      ],
    });
    expect(init.initHash).toBe(onChainHash);

    await test().setBalance({ address: init.address, value: parseEther("10") });
    account = await createFirewallAccount(client(), params);
    expect(account.address).toBe(init.address);

    const deployer = createWalletClient({
      chain: client().publicClient.chain,
      transport: http(env.rpcUrl),
      account: privateKeyToAccount(ANVIL_KEYS.deployer),
    });
    await pub().waitForTransactionReceipt({
      hash: await deployer.sendTransaction({
        to: env.fixtures.usdc,
        data: encodeFunctionData({
          abi: mockUsdcAbi,
          functionName: "mint",
          args: [account.address, 10_000_000_000n],
        }),
      }),
    });
    await approveMarket(account, {
      token: env.fixtures.usdc,
      market: env.fixtures.market,
      amount: 2n ** 256n - 1n,
    });
    session = await createSession(account, {
      expiresAt: Number(await now()) + 7 * 86_400,
      markets: [env.fixtures.market],
    });
  });

  it("V7: NoSafeOwner is the only Safe owner", async () => {
    const owners = await pub().readContract({
      address: account.address,
      abi: safeAbi,
      functionName: "getOwners",
    });
    expect(owners).toEqual([env.addresses.noSafeOwner]);
    const threshold = await pub().readContract({
      address: account.address,
      abi: safeAbi,
      functionName: "getThreshold",
    });
    expect(threshold).toBe(1n);
  });

  it("installs Smart Sessions, the owner validator, the module and the hook", async () => {
    const installed = (type: bigint, module: Address) =>
      pub().readContract({
        address: account.address,
        abi: safe7579Abi,
        functionName: "isModuleInstalled",
        args: [type, module, "0x"],
      });
    expect(
      await installed(MODULE_TYPE.validator, env.addresses.smartSessions),
    ).toBe(true);
    expect(
      await installed(MODULE_TYPE.validator, env.addresses.ownableValidator),
    ).toBe(true);
    expect(await installed(MODULE_TYPE.executor, env.addresses.module)).toBe(
      true,
    );
    const hook = await pub().readContract({
      address: account.address,
      abi: safe7579Abi,
      functionName: "getActiveHook",
    });
    expect(hook).toBe(env.addresses.hook);
    const state = await getFirewallState(account);
    expect(state.config.hourlyCap).toBe(hourlyCap);
    expect(state.destinations).toEqual([destination]);
  });

  it("D13: the session exists on Smart Sessions and its permission id matches", async () => {
    const enabled = await pub().readContract({
      address: env.addresses.smartSessions,
      abi: smartSessionsAbi,
      functionName: "isPermissionEnabled",
      args: [session.permissionId, account.address],
    });
    expect(enabled).toBe(true);
  });

  it("A1: session transfer to an attacker is blocked by the hook", async () => {
    expect(
      await blockedBy(
        executeAsSession(account, session, [
          usdcCall("transfer", attacker, 1n),
        ]),
      ),
    ).toBe("UnexplainedOutflow");
  });

  it("A2: session approval to an attacker is blocked by the hook", async () => {
    expect(
      await blockedBy(
        executeAsSession(account, session, [usdcCall("approve", attacker, 1n)]),
      ),
    ).toBe("UnregisteredSpender");
  });

  it("A1 from the owner: the rules apply to every signer", async () => {
    expect(
      await blockedBy(
        executeAsOwner(account, [usdcCall("transfer", attacker, 1n)]),
      ),
    ).toBe("UnexplainedOutflow");
  });

  it("A4: an unknown target is rejected at validation for a session and by the hook for the owner", async () => {
    expect(
      await blockedBy(
        executeAsSession(account, session, [
          { to: attacker, data: "0x12345678" },
        ]),
      ),
    ).toBe("FailedOpWithRevert");
    expect(
      await blockedBy(
        executeAsOwner(account, [{ to: attacker, data: "0x12345678" }]),
      ),
    ).toBe("UnknownTarget");
  });

  it("A9: the owner cannot install a module once the hook is on", async () => {
    const install = encodeFunctionData({
      abi: safe7579Abi,
      functionName: "installModule",
      args: [MODULE_TYPE.executor, attacker, "0x"],
    });
    expect(
      await blockedBy(
        executeAsOwner(account, [{ to: account.address, data: install }]),
      ),
    ).toBe("ForbiddenExecution");
  });

  it("A7: buying past the hourly cap raises BudgetExceeded from the post-check", async () => {
    await buy(100_000_000n);
    expect(await blockedBy(buy(4_000_000_000n))).toBe("BudgetExceeded");
  });

  it("exit refuses an unregistered destination before sending anything", async () => {
    expect(
      await blockedBy(
        exit(account, {
          token: env.fixtures.usdc,
          amount: 1n,
          destination: attacker,
        }),
      ),
    ).toBe("UnexplainedOutflow");
  });

  it("R6 queue: too early, cancel, then a matured change takes effect", async () => {
    const newDest = privateKeyToAccount(generatePrivateKey()).address;
    const first = await queueChange(account, {
      kind: "addDestination",
      destination: newDest,
    });
    expect(first.eta).toBeGreaterThan(await now());
    expect(await blockedBy(executeChange(account, first.id))).toBe("TooEarly");
    await cancelChange(account, first.id);
    expect(await blockedBy(executeChange(account, first.id))).toBe(
      "UnknownChange",
    );

    const second = await queueChange(account, {
      kind: "addDestination",
      destination: newDest,
    });
    await test().increaseTime({ seconds: 86_401 });
    await test().mine({ blocks: 1 });
    await executeChange(account, second.id);
    expect((await getFirewallState(account)).destinations).toContain(newDest);
  });

  it("removeSession stops one session immediately", async () => {
    const other = await createSession(account, {
      expiresAt: Number(await now()) + 3_600,
    });
    await removeSession(account, other.permissionId);
    const enabled = await pub().readContract({
      address: env.addresses.smartSessions,
      abi: smartSessionsAbi,
      functionName: "isPermissionEnabled",
      args: [other.permissionId, account.address],
    });
    expect(enabled).toBe(false);
  });

  it("InvalidExpiry: a session cannot outlive the 30-day limit", async () => {
    const expiresAt = Number(await now()) + 31 * 86_400;
    expect(await blockedBy(createSession(account, { expiresAt }))).toBe(
      "InvalidExpiry",
    );
  });

  it("A12 + C1: freeze kills the session at validation, and the owner can still exit", async () => {
    await freeze(account);
    const state = await getFirewallState(account);
    expect(state.config.frozen).toBe(true);
    expect(state.availableBudget).toBe(0n);
    expect(await blockedBy(buy(1_000_000n))).toBe("FailedOpWithRevert");
    expect(
      await blockedBy(
        executeAsOwner(account, [usdcCall("approve", env.fixtures.market, 1n)]),
      ),
    ).not.toBe("UnknownTarget");

    const balance = await pub().readContract({
      address: env.fixtures.usdc,
      abi: mockUsdcAbi,
      functionName: "balanceOf",
      args: [account.address],
    });
    expect(balance).toBeGreaterThan(0n);
    await exit(account, {
      token: env.fixtures.usdc,
      amount: balance,
      destination,
    });
    const atDestination = await pub().readContract({
      address: env.fixtures.usdc,
      abi: mockUsdcAbi,
      functionName: "balanceOf",
      args: [destination],
    });
    expect(atDestination).toBe(balance);
    // module ABI sanity: the account stays initialised while frozen
    expect(
      await pub().readContract({
        address: env.addresses.module,
        abi: firewallModuleAbi,
        functionName: "isInitialized",
        args: [account.address],
      }),
    ).toBe(true);
  });
});

describe("D12 passkey envelopes on deployed FirewallOwnerValidator", () => {
  let account: FirewallAccount;
  const type = "Mail(address to,uint256 id)";
  beforeAll(async () => {
    const client = localClientConfig(env);
    const params = {
      owner: testPasskey(env.addresses.ownerValidator, [type]),
      destinations: [privateKeyToAccount(generatePrivateKey()).address],
      markets: [{ market: env.fixtures.market, adapter: env.fixtures.adapter }],
      tokens: [env.fixtures.usdc],
      hourlyCap: 1_000_000_000n,
      saltNonce: 981n,
    };
    const init = await buildAccountInit(client, params);
    await createTestClient({
      chain: client.publicClient.chain,
      mode: "anvil",
      transport: http(env.rpcUrl),
    }).setBalance({ address: init.address, value: parseEther("2") });
    account = await createFirewallAccount(client, params);
  });
  const valid = async (hash: Hex, signature: Hex) =>
    account.client.publicClient.readContract({
      address: account.address,
      abi: [
        {
          type: "function",
          name: "isValidSignature",
          stateMutability: "view",
          inputs: [{ type: "bytes32" }, { type: "bytes" }],
          outputs: [{ type: "bytes4" }],
        },
      ],
      functionName: "isValidSignature",
      args: [hash, signature],
    });
  it("PersonalSign binds the plaintext and uses the D12 account domain", async () => {
    const message =
      "Session Firewall monitor: subscribe\nAccount under my control";
    const signature = await signFirewallMessage(account, message);
    expect(await valid(hashMessage(message), signature)).toBe("0x1626ba7e");
    expect(await valid(hashMessage(`${message}!`), signature)).not.toBe(
      "0x1626ba7e",
    );
    const abi = [
      {
        type: "function",
        name: "domainSeparator",
        stateMutability: "view",
        inputs: [{ type: "address" }],
        outputs: [{ type: "bytes32" }],
      },
    ] as const;
    const separator = await account.client.publicClient.readContract({
      address: env.addresses.ownerValidator,
      abi,
      functionName: "domainSeparator",
      args: [account.address],
    });
    expect(separator).toBe(
      firewallOwnerDomainSeparator({
        account: account.address,
        chainId: 31337,
      }),
    );
  });
  it("A13: typed permit to an attacker is invalid", async () => {
    const permit =
      "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
    const content = {
      appDomainSeparator: keccak256(stringToHex("permit token")),
      contentsType: permit,
      data: encodeAbiParameters(
        [
          { type: "address" },
          { type: "address" },
          { type: "uint256" },
          { type: "uint256" },
          { type: "uint256" },
        ],
        [
          account.address,
          privateKeyToAccount(generatePrivateKey()).address,
          100n,
          0n,
          2n ** 200n,
        ],
      ),
    };
    const hash = keccak256(
      concat([
        "0x1901",
        content.appDomainSeparator,
        keccak256(concat([keccak256(stringToHex(permit)), content.data])),
      ]),
    );
    expect(
      await valid(hash, await signFirewallTypedContent(account, content)),
    ).not.toBe("0x1626ba7e");
  });
  it("TypedDataSign matches the contract and is invalid after freeze", async () => {
    const content = {
      appDomainSeparator: keccak256(stringToHex("test app")),
      contentsType: type,
      data: encodeAbiParameters(
        [{ type: "address" }, { type: "uint256" }],
        [account.address, 7n],
      ),
    };
    const hash = keccak256(
      concat([
        "0x1901",
        content.appDomainSeparator,
        keccak256(concat([keccak256(stringToHex(type)), content.data])),
      ]),
    );
    const signature = await signFirewallTypedContent(account, content);
    expect(await valid(hash, signature)).toBe("0x1626ba7e");
    await freeze(account);
    expect(await valid(hash, signature)).not.toBe("0x1626ba7e");
    const login = await signFirewallMessage(account, "login while frozen");
    expect(await valid(hashMessage("login while frozen"), login)).toBe(
      "0x1626ba7e",
    );
  });
});
