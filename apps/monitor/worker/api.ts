import { type Context, Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { type Address, type Hex, getAddress, isAddress, isHex } from "viem";
import { deriveWebhookSecret } from "../src/lib/webhook.ts";
import type { Contact, ContactType } from "./channels.ts";
import type { Store } from "./store.ts";

/**
 * Subscriptions API. Proof of control: every write carries an EIP-191 `personal_sign` signature over
 * `subscriptionMessage(...)`, checked with ERC-1271 for smart accounts (the Safe forwards
 * isValidSignature to its validator; with the D12 owner-validator wrapper the passkey signs an
 * ERC-7739 PersonalSign envelope of the same message) and ERC-6492 for undeployed ones.
 * Replay protection: `issuedAt` must be within MAX_SKEW seconds and each (account, nonce) works once.
 */

export const MAX_SKEW_SECONDS = 600;
const MAX_CONTACTS = 5;

export type Action = "subscribe" | "unsubscribe";

export type VerifySignature = (p: {
  address: Address;
  message: string;
  signature: Hex;
}) => Promise<boolean>;

export function contactLabel(c: Contact): string {
  return c.type === "email"
    ? `email:${c.to.toLowerCase()}`
    : c.type === "telegram"
      ? `telegram:${c.chatId}`
      : `webhook:${c.url}`;
}

/** The exact text the account signs. Clients may build it themselves or call POST /v1/message. */
export function subscriptionMessage(p: {
  action: Action;
  account: Address;
  chainId: number;
  contacts: Contact[] | null;
  issuedAt: number;
  nonce: string;
}): string {
  const channels =
    p.contacts === null
      ? ["- all"]
      : p.contacts.map((c) => `- ${contactLabel(c)}`);
  return [
    `Session Firewall monitor: ${p.action}`,
    `Account: ${getAddress(p.account)}`,
    `Chain ID: ${p.chainId}`,
    "Channels:",
    ...channels,
    `Issued at: ${p.issuedAt}`,
    `Nonce: ${p.nonce}`,
  ].join("\n");
}

const PRIVATE_HOST =
  /^(localhost|.*\.localhost|.*\.internal|.*\.local|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|0\.0\.0\.0|\[.*\])$/i;

export class BadRequest extends Error {}
export class AuthError extends Error {}

export function parseContacts(
  raw: unknown,
  opts: { allowInsecureWebhooks: boolean },
): Contact[] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_CONTACTS) {
    throw new BadRequest(
      `channels must be a list of 1-${MAX_CONTACTS} contacts`,
    );
  }
  return raw.map((c: unknown): Contact => {
    const o = (c ?? {}) as Record<string, unknown>;
    if (
      o.type === "email" &&
      typeof o.to === "string" &&
      o.to.length <= 254 &&
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(o.to)
    ) {
      return { type: "email", to: o.to.toLowerCase() };
    }
    if (
      o.type === "telegram" &&
      typeof o.chatId === "string" &&
      /^-?\d{1,20}$/.test(o.chatId)
    ) {
      return { type: "telegram", chatId: o.chatId };
    }
    if (
      o.type === "webhook" &&
      typeof o.url === "string" &&
      o.url.length <= 2048
    ) {
      let u: URL;
      try {
        u = new URL(o.url);
      } catch {
        throw new BadRequest("webhook url is not a URL");
      }
      if (u.username || u.password)
        throw new BadRequest("webhook url must not contain credentials");
      if (!opts.allowInsecureWebhooks) {
        if (u.protocol !== "https:")
          throw new BadRequest("webhook url must be https");
        if (PRIVATE_HOST.test(u.hostname))
          throw new BadRequest("webhook url must be a public host");
      } else if (u.protocol !== "https:" && u.protocol !== "http:") {
        throw new BadRequest("webhook url must be http(s)");
      }
      return { type: "webhook", url: u.toString() };
    }
    throw new BadRequest(
      "invalid contact: expected {type:'email',to} | {type:'telegram',chatId} | {type:'webhook',url}",
    );
  });
}

type Body = {
  account?: unknown;
  channels?: unknown;
  issuedAt?: unknown;
  nonce?: unknown;
  signature?: unknown;
};

export function createApi(p: {
  store: Store;
  chainId: number;
  verify: VerifySignature;
  webhookMasterSecret?: string;
  allowInsecureWebhooks?: boolean;
  /** Channel types this deployment can deliver. Defaults to all. */
  enabledChannels?: readonly ContactType[];
  now?: () => number;
  onError?: (err: unknown) => void;
}) {
  const now = p.now ?? (() => Math.floor(Date.now() / 1000));
  const app = new Hono();
  app.use(
    "/v1/*",
    bodyLimit({
      maxSize: 16 * 1024,
      onError: (c) => c.json({ error: "body too large" }, 413),
    }),
  );

  // Only our own messages reach the client: an RPC or database error can contain a keyed URL.
  function fail(c: Context, e: unknown) {
    if (e instanceof AuthError) return c.json({ error: e.message }, 401);
    if (e instanceof BadRequest) return c.json({ error: e.message }, 400);
    p.onError?.(e);
    return c.json({ error: "internal error" }, 500);
  }

  function parseCommon(b: Body, action: Action, allowAll: boolean) {
    if (typeof b.account !== "string" || !isAddress(b.account))
      throw new BadRequest("account must be an address");
    if (typeof b.issuedAt !== "number" || !Number.isSafeInteger(b.issuedAt))
      throw new BadRequest("issuedAt must be unix seconds");
    if (typeof b.nonce !== "string" || !/^[A-Za-z0-9_-]{8,64}$/.test(b.nonce))
      throw new BadRequest("nonce must be 8-64 url-safe chars");
    const contacts =
      allowAll && (b.channels === null || b.channels === undefined)
        ? null
        : parseContacts(b.channels, {
            allowInsecureWebhooks: p.allowInsecureWebhooks ?? false,
          });
    const account = getAddress(b.account);
    const message = subscriptionMessage({
      action,
      account,
      chainId: p.chainId,
      contacts,
      issuedAt: b.issuedAt,
      nonce: b.nonce,
    });
    return { account, contacts, message, issuedAt: b.issuedAt, nonce: b.nonce };
  }

  async function authorize(b: Body, action: Action, allowAll: boolean) {
    const req = parseCommon(b, action, allowAll);
    if (Math.abs(now() - req.issuedAt) > MAX_SKEW_SECONDS)
      throw new AuthError("issuedAt is outside the allowed window");
    if (typeof b.signature !== "string" || !isHex(b.signature))
      throw new AuthError("signature must be hex");
    const ok = await p
      .verify({
        address: req.account,
        message: req.message,
        signature: b.signature,
      })
      .catch((e) => {
        // A malformed signature or an RPC failure. Either way, control of the account is not proven.
        p.onError?.(e);
        return false;
      });
    if (!ok) throw new AuthError("signature does not verify for this account");
    const fresh = await p.store.useNonce(
      `${req.account.toLowerCase()}:${req.nonce}`,
      req.issuedAt + MAX_SKEW_SECONDS,
    );
    if (!fresh) throw new AuthError("nonce already used");
    return req;
  }

  app.get("/health", (c) => c.json({ ok: true }));

  app.post("/v1/message", async (c) => {
    const b = ((await c.req.json().catch(() => null)) ?? {}) as Body & {
      action?: unknown;
    };
    try {
      if (b.action !== "subscribe" && b.action !== "unsubscribe")
        throw new BadRequest("action must be subscribe or unsubscribe");
      return c.json({
        message: parseCommon(b, b.action, b.action === "unsubscribe").message,
      });
    } catch (e) {
      return fail(c, e);
    }
  });

  app.post("/v1/subscribe", async (c) => {
    const b = ((await c.req.json().catch(() => null)) ?? {}) as Body;
    try {
      const req = await authorize(b, "subscribe", false);
      const contacts = req.contacts ?? [];
      const webhooks = contacts.filter((x) => x.type === "webhook");
      const disabled = contacts.find(
        (x) => p.enabledChannels && !p.enabledChannels.includes(x.type),
      );
      if (disabled)
        throw new BadRequest(`${disabled.type} is not enabled on this monitor`);
      if (webhooks.length > 0 && !p.webhookMasterSecret)
        throw new BadRequest("webhook is not enabled on this monitor");
      await p.store.addSubscriptions(req.account, contacts);
      const webhookSecrets = Object.fromEntries(
        webhooks.map((w) => [
          w.url,
          deriveWebhookSecret(
            p.webhookMasterSecret as string,
            req.account,
            w.url,
          ),
        ]),
      );
      return c.json({
        ok: true,
        account: req.account,
        subscribed: contacts.length,
        webhookSecrets,
      });
    } catch (e) {
      return fail(c, e);
    }
  });

  app.post("/v1/unsubscribe", async (c) => {
    const b = ((await c.req.json().catch(() => null)) ?? {}) as Body;
    try {
      const req = await authorize(b, "unsubscribe", true);
      const removed = await p.store.removeSubscriptions(
        req.account,
        req.contacts,
      );
      return c.json({ ok: true, account: req.account, removed });
    } catch (e) {
      return fail(c, e);
    }
  });

  return app;
}
