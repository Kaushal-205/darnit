import {
  erc20Abi,
  firewallHookAbi,
  firewallModuleAbi,
  firewallOwnerValidatorAbi,
  outcomeSharesAbi,
  safe7579Abi,
} from "@session-firewall/sdk";
import {
  type Address,
  type Chain,
  type Hex,
  type PublicClient,
  type Transport,
  getAddress,
  isAddressEqual,
  zeroAddress,
} from "viem";

/** Safe7579 enumerates validators as a linked list starting at SENTINEL (0x...01). */
const SENTINEL: Address = "0x0000000000000000000000000000000000000001";
const paginationAbi = [
  {
    type: "function",
    name: "getValidatorsPaginated",
    stateMutability: "view",
    inputs: [
      { name: "cursor", type: "address" },
      { name: "pageSize", type: "uint256" },
    ],
    outputs: [
      { name: "array", type: "address[]" },
      { name: "next", type: "address" },
    ],
  },
] as const;
/** ReferenceMarket-style markets number their markets; other markets fall back to share ids typed in. */
const marketEnumerationAbi = [
  {
    type: "function",
    name: "nextMarketId",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "outcomeIds",
    stateMutability: "pure",
    inputs: [{ name: "marketId", type: "uint256" }],
    outputs: [
      { name: "yesId", type: "uint256" },
      { name: "noId", type: "uint256" },
    ],
  },
] as const;
const MAX_MARKETS_SCANNED = 64n;

export type Client = PublicClient<Transport, Chain>;

export type PasskeyValidator = { address: Address; x: Hex; y: Hex };
export type TokenBalance = {
  kind: "token";
  token: Address;
  symbol: string;
  decimals: number;
  balance: bigint;
};
export type ShareBalance = {
  kind: "share";
  token: Address;
  id: bigint;
  label: string;
  balance: bigint;
};
export type Asset = TokenBalance | ShareBalance;

export type AccountSnapshot = {
  account: Address;
  module: Address;
  hook: Address;
  frozen: boolean;
  hourlyCap: bigint;
  availableBudget: bigint;
  destinations: Address[];
  validators: PasskeyValidator[];
  tokens: TokenBalance[];
  shares: ShareBalance[];
  ethBalance: bigint;
};

/**
 * Everything the page needs, read from the account itself: no deployment file, no server.
 * account -> Safe7579.getActiveHook() -> FirewallHook.MODULE() -> FirewallModule.accountView(account).
 */
export async function readAccount(
  client: Client,
  account: Address,
  extraShareIds: readonly bigint[] = [],
): Promise<AccountSnapshot> {
  const code = await client.getCode({ address: account });
  if (!code || code === "0x")
    throw new Error(
      "There is no account at this address on this network. Check the address and the network.",
    );
  let hook: Address;
  try {
    hook = await client.readContract({
      address: account,
      abi: safe7579Abi,
      functionName: "getActiveHook",
    });
  } catch {
    throw new Error("This address is not a Session Firewall account.");
  }
  if (isAddressEqual(hook, zeroAddress))
    throw new Error("This account has no firewall installed.");
  const module = await client.readContract({
    address: hook,
    abi: firewallHookAbi,
    functionName: "MODULE",
  });
  const [view, availableBudget, validators, ethBalance] = await Promise.all([
    client.readContract({
      address: module,
      abi: firewallModuleAbi,
      functionName: "accountView",
      args: [account],
    }),
    client.readContract({
      address: module,
      abi: firewallModuleAbi,
      functionName: "availableBudget",
      args: [account],
    }),
    readPasskeyValidators(client, account),
    client.getBalance({ address: account }),
  ]);

  const tokens = await Promise.all(
    view.tokens.map((t) => readToken(client, t, account)),
  );
  const shares = await readShares(
    client,
    account,
    view.markets,
    view.shareTokens,
    extraShareIds,
  );
  return {
    account,
    module,
    hook,
    frozen: view.config.frozen,
    hourlyCap: view.config.hourlyCap,
    availableBudget,
    destinations: [...view.destinations],
    validators,
    tokens,
    shares,
    ethBalance,
  };
}

/** Installed validators that hold a passkey for this account (FirewallOwnerValidator deployments). */
export async function readPasskeyValidators(
  client: Client,
  account: Address,
): Promise<PasskeyValidator[]> {
  const [list] = await client.readContract({
    address: account,
    abi: paginationAbi,
    functionName: "getValidatorsPaginated",
    args: [SENTINEL, 16n],
  });
  const out: PasskeyValidator[] = [];
  for (const v of list) {
    try {
      const [x, y] = await client.readContract({
        address: v,
        abi: firewallOwnerValidatorAbi,
        functionName: "passkey",
        args: [account],
      });
      if (BigInt(x) !== 0n || BigInt(y) !== 0n)
        out.push({ address: getAddress(v), x, y });
    } catch {
      // not a passkey validator (e.g. Smart Sessions)
    }
  }
  return out;
}

async function readToken(
  client: Client,
  token: Address,
  account: Address,
): Promise<TokenBalance> {
  const [balance, symbol, decimals] = await Promise.all([
    client.readContract({
      address: token,
      abi: erc20Abi,
      functionName: "balanceOf",
      args: [account],
    }),
    client
      .readContract({ address: token, abi: symbolAbi, functionName: "symbol" })
      .catch(() => "token"),
    client
      .readContract({
        address: token,
        abi: symbolAbi,
        functionName: "decimals",
      })
      .catch(() => 18),
  ]);
  return {
    kind: "token",
    token,
    symbol: String(symbol),
    decimals: Number(decimals),
    balance,
  };
}

const symbolAbi = [
  {
    type: "function",
    name: "symbol",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "string" }],
  },
  {
    type: "function",
    name: "decimals",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint8" }],
  },
] as const;

async function readShares(
  client: Client,
  account: Address,
  markets: readonly Address[],
  shareTokens: readonly Address[],
  extraIds: readonly bigint[],
): Promise<ShareBalance[]> {
  const found: ShareBalance[] = [];
  const seen = new Set<string>();
  for (let m = 0; m < markets.length; m++) {
    const token = shareTokens[m];
    const ids: { id: bigint; label: string }[] = extraIds.map((id) => ({
      id,
      label: `Share #${id}`,
    }));
    try {
      const next = await client.readContract({
        address: markets[m],
        abi: marketEnumerationAbi,
        functionName: "nextMarketId",
      });
      const last =
        next - 1n < MAX_MARKETS_SCANNED ? next - 1n : MAX_MARKETS_SCANNED;
      for (let id = 1n; id <= last; id++) {
        const [yesId, noId] = await client.readContract({
          address: markets[m],
          abi: marketEnumerationAbi,
          functionName: "outcomeIds",
          args: [id],
        });
        ids.push(
          { id: yesId, label: `Market ${id} YES` },
          { id: noId, label: `Market ${id} NO` },
        );
      }
    } catch {
      // market without enumeration: only typed-in share ids are checked
    }
    const balances = await Promise.all(
      ids.map(({ id }) =>
        client.readContract({
          address: token,
          abi: outcomeSharesAbi,
          functionName: "balanceOf",
          args: [account, id],
        }),
      ),
    );
    ids.forEach(({ id, label }, i) => {
      const key = `${token}:${id}`;
      if (seen.has(key)) return;
      seen.add(key);
      if (balances[i] > 0n)
        found.push({ kind: "share", token, id, label, balance: balances[i] });
    });
  }
  return found;
}
