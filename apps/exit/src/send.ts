import {
  type Call,
  type FirewallAddresses,
  type FirewallClientConfig,
  type UserOpResult,
  type WebAuthnAuth,
  encodeExecute,
  passkeyOwner,
  sendUserOp,
} from "@session-firewall/sdk";
import {
  http,
  type Address,
  type Chain,
  type Hex,
  createPublicClient,
  createWalletClient,
  defineChain,
  zeroAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { Client, PasskeyValidator } from "./reads.js";
import { stubAuth, verifyAuth } from "./webauthn.js";

/** ERC-4337 EntryPoint v0.7, the same address on every chain the firewall supports. */
export const ENTRY_POINT_V07: Address =
  "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

export function userChain(chainId: number, rpcUrl: string): Chain {
  return defineChain({
    id: chainId,
    name: `Chain ${chainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

export function userClient(chainId: number, rpcUrl: string): Client {
  return createPublicClient({
    chain: userChain(chainId, rpcUrl),
    transport: http(rpcUrl, { retryCount: 1 }),
    pollingInterval: 1_000,
  });
}

export type Submitter =
  | { kind: "bundler"; bundlerUrl: string }
  | { kind: "eoa"; privateKey: Hex };

/**
 * The SDK only needs `entryPoint` and `hook` from the address book to send an owner user operation and
 * explain a refusal; the rest is for onboarding and sessions, which this page never does.
 */
function addressBook(entryPoint: Address, hook: Address): FirewallAddresses {
  return {
    entryPoint,
    hook,
    module: zeroAddress,
    safeSingleton: zeroAddress,
    safeProxyFactory: zeroAddress,
    safe7579: zeroAddress,
    safe7579Launchpad: zeroAddress,
    smartSessions: zeroAddress,
    ownableValidator: zeroAddress,
    actionPolicy: zeroAddress,
    signaturePolicy: zeroAddress,
    noSafeOwner: zeroAddress,
    ownerValidator: zeroAddress,
  };
}

export type SendExitParams = {
  client: Client;
  rpcUrl: string;
  entryPoint: Address;
  hook: Address;
  account: Address;
  validator: PasskeyValidator;
  calls: readonly Call[];
  submitter: Submitter;
  /** RP ID used for the gas-estimation stub (byte lengths only). */
  rpId: string;
  /** Produce the passkey assertion over the user operation hash. */
  sign: (userOpHash: Hex) => Promise<WebAuthnAuth>;
  onStatus?: (text: string) => void;
};

/** Sign with the passkey and submit one owner user operation that moves funds out. */
export async function sendExit(p: SendExitParams): Promise<UserOpResult> {
  const config: FirewallClientConfig = {
    publicClient: p.client,
    addresses: addressBook(p.entryPoint, p.hook),
  };
  if (p.submitter.kind === "bundler")
    config.bundlerUrl = p.submitter.bundlerUrl;
  else
    config.localBundler = createWalletClient({
      chain: p.client.chain,
      transport: http(p.rpcUrl),
      account: privateKeyToAccount(p.submitter.privateKey),
    });

  const owner = passkeyOwner({
    validator: p.validator.address,
    x: p.validator.x,
    y: p.validator.y,
    stubAuth: stubAuth(p.rpId),
    signAssertion: async (hash) => {
      p.onStatus?.("Waiting for your passkey…");
      const auth = await p.sign(hash);
      const check = verifyAuth(auth, hash, p.validator);
      if (!check.ok) throw new Error(check.reason);
      p.onStatus?.("Signed. Sending…");
      return auth;
    },
  });
  return sendUserOp(config, {
    sender: p.account,
    signer: owner,
    callData: encodeExecute(p.calls),
  });
}
