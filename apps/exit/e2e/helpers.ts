import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import type { CDPSession, Page } from "@playwright/test";
import {
  http,
  type Account,
  type Address,
  type Chain,
  type Hex,
  type PublicClient,
  type Transport,
  type WalletClient,
  concat,
  numberToHex,
  toHex,
} from "viem";
import {
  type UserOperation,
  entryPoint07Abi,
  getUserOperationHash,
  toPackedUserOperation,
} from "viem/account-abstraction";
import {
  type WebAuthnAuth,
  passkeyOwner,
} from "../../../packages/sdk/src/index.js";

const sha256 = (d: Uint8Array | string) =>
  createHash("sha256").update(d).digest();

/**
 * A software P-256 key standing in for a security key whose passkey was made for the app's website.
 * `rawSign` plays the part of the authenticator: it signs without any browser, as fido2-assert would.
 */
export function softwareKey(validator: Address, rpId: string) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const jwk = publicKey.export({ format: "jwk" });
  const x = toHex(Buffer.from(jwk.x as string, "base64url"));
  const y = toHex(Buffer.from(jwk.y as string, "base64url"));
  const authData = Buffer.concat([
    sha256(rpId),
    Buffer.from([0x05]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const rawSign = (clientDataHash: Buffer) =>
    sign("sha256", Buffer.concat([authData, clientDataHash]), {
      key: privateKey,
    });
  const assertion = async (challenge: Hex): Promise<WebAuthnAuth> => {
    const clientDataJSON = JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(challenge.slice(2), "hex").toString("base64url"),
      origin: `https://${rpId}`,
      crossOrigin: false,
    });
    const sig = sign(
      "sha256",
      Buffer.concat([authData, sha256(clientDataJSON)]),
      { key: privateKey, dsaEncoding: "ieee-p1363" },
    );
    return {
      authenticatorData: toHex(authData),
      clientDataJSON,
      challengeIndex: 23n,
      typeIndex: 1n,
      r: toHex(sig.subarray(0, 32)),
      s: toHex(sig.subarray(32, 64)),
    };
  };
  const owner = passkeyOwner({
    validator,
    x,
    y,
    signAssertion: assertion,
    stubAuth: {
      r: numberToHex(1, { size: 32 }),
      s: numberToHex(1, { size: 32 }),
      challengeIndex: 23n,
      typeIndex: 1n,
      authenticatorData: concat([toHex(sha256(rpId)), "0x05", "0x00000001"]),
      clientDataJSON: `{"type":"webauthn.get","challenge":"${Buffer.alloc(32).toString("base64url")}","origin":"https://${rpId}","crossOrigin":false}`,
    },
  });
  /** What fido2-assert prints for a request: hash, rp id, CBOR-wrapped authdata, DER signature. */
  const fido2AssertOutput = (clientDataHashB64: string) =>
    [
      clientDataHashB64,
      rpId,
      Buffer.concat([
        Buffer.from([0x58, authData.length]),
        authData,
      ]).toString("base64"),
      rawSign(Buffer.from(clientDataHashB64, "base64")).toString("base64"),
    ].join("\n");
  return { owner, x, y, fido2AssertOutput };
}

/** Chromium's virtual authenticator with a passkey-like configuration. */
export async function addVirtualAuthenticator(
  page: Page,
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send(
    "WebAuthn.addVirtualAuthenticator",
    {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    },
  );
  return { cdp, authenticatorId };
}

/** Serve one file from a local web server; the page is then on http://localhost:<port>. */
export async function serveFile(
  html: string,
): Promise<{ url: string; close: () => void }> {
  const server: Server = createServer((req, res) => {
    if (req.url?.startsWith("/exit.html")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(html);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://localhost:${port}/exit.html`,
    close: () => server.close(),
  };
}

/**
 * The bundler JSON-RPC calls the page makes, answered by submitting handleOps to Anvil. It checks the
 * page's bundler path end to end, but does none of a real bundler's validation (stub signature handling,
 * ERC-7562 rules, fee policy), so it does not prove any hosted bundler accepts these operations.
 */
export async function startMockBundler(
  client: PublicClient<Transport, Chain>,
  wallet: WalletClient<Transport, Chain, Account>,
  entryPoint: Address,
): Promise<{ url: string; methods: string[]; close: () => void }> {
  const methods: string[] = [];
  const mined = new Map<Hex, { tx: Hex; sender: Address; nonce: Hex }>();
  const cors = {
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "*",
    "access-control-allow-methods": "*",
  };
  const handle = async (method: string, params: unknown[]) => {
    methods.push(method);
    if (method === "eth_supportedEntryPoints") return [entryPoint];
    if (method === "eth_chainId") return numberToHex(client.chain.id);
    if (method === "eth_estimateUserOperationGas")
      return {
        preVerificationGas: "0x186a0",
        verificationGasLimit: "0x16e360",
        callGasLimit: "0x2dc6c0",
      };
    if (method === "eth_sendUserOperation") {
      const o = params[0] as Record<string, Hex>;
      const op: UserOperation<"0.7"> = {
        sender: o.sender,
        nonce: BigInt(o.nonce),
        callData: o.callData,
        callGasLimit: BigInt(o.callGasLimit),
        verificationGasLimit: BigInt(o.verificationGasLimit),
        preVerificationGas: BigInt(o.preVerificationGas),
        maxFeePerGas: BigInt(o.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(o.maxPriorityFeePerGas),
        signature: o.signature,
      };
      const hash = getUserOperationHash({
        chainId: client.chain.id,
        entryPointAddress: entryPoint,
        entryPointVersion: "0.7",
        userOperation: op,
      });
      const tx = await wallet.writeContract({
        address: entryPoint,
        abi: entryPoint07Abi,
        functionName: "handleOps",
        args: [[toPackedUserOperation(op)], wallet.account.address],
        chain: client.chain,
      });
      await client.waitForTransactionReceipt({ hash: tx });
      mined.set(hash, { tx, sender: op.sender, nonce: o.nonce });
      return hash;
    }
    if (method === "eth_getUserOperationReceipt") {
      const m = mined.get(params[0] as Hex);
      if (!m) return null;
      const receipt = await client.request({
        method: "eth_getTransactionReceipt",
        params: [m.tx],
      });
      return {
        userOpHash: params[0],
        entryPoint,
        sender: m.sender,
        nonce: m.nonce,
        actualGasCost: "0x0",
        actualGasUsed: "0x0",
        success: true,
        logs: receipt?.logs ?? [],
        receipt,
      };
    }
    throw new Error(`mock bundler: ${method} not supported`);
  };
  const server = createServer((req, res) => {
    if (req.method === "OPTIONS") {
      res.writeHead(204, cors);
      res.end();
      return;
    }
    let body = "";
    req.on("data", (d) => {
      body += d;
    });
    req.on("end", async () => {
      const { id, method, params } = JSON.parse(body);
      const reply = await handle(method, params).then(
        (result) => ({ jsonrpc: "2.0", id, result }),
        (e: Error) => ({
          jsonrpc: "2.0",
          id,
          error: { code: -32000, message: e.message },
        }),
      );
      res.writeHead(200, { ...cors, "content-type": "application/json" });
      res.end(JSON.stringify(reply));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    methods,
    close: () => server.close(),
  };
}

export { http };
