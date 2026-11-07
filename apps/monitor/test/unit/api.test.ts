import { verifyMessage } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { deriveWebhookSecret } from "../../src/lib/webhook.ts";
import {
  type Action,
  createApi,
  parseContacts,
  subscriptionMessage,
} from "../../worker/api.ts";
import type { Contact } from "../../worker/channels.ts";
import { memoryStore } from "../../worker/store.ts";

const NOW = 1_700_000_000;
const owner = privateKeyToAccount(generatePrivateKey());
const stranger = privateKeyToAccount(generatePrivateKey());

function setup() {
  const store = memoryStore();
  const app = createApi({
    store,
    chainId: 84532,
    webhookMasterSecret: "master",
    now: () => NOW,
    verify: ({ address, message, signature }) =>
      verifyMessage({ address, message, signature }),
  });
  return { store, app };
}

async function signed(
  action: Action,
  contacts: Contact[] | null,
  opts: { signer?: typeof owner; issuedAt?: number; nonce?: string } = {},
) {
  const issuedAt = opts.issuedAt ?? NOW;
  const nonce = opts.nonce ?? `n${Math.random().toString(36).slice(2, 12)}`;
  const message = subscriptionMessage({
    action,
    account: owner.address,
    chainId: 84532,
    contacts,
    issuedAt,
    nonce,
  });
  const signature = await (opts.signer ?? owner).signMessage({ message });
  return {
    account: owner.address,
    channels: contacts,
    issuedAt,
    nonce,
    signature,
  };
}

type Reply = {
  subscribed?: number;
  webhookSecrets: Record<string, string>;
  error?: string;
  removed?: number;
  message?: string;
};
const json = async (r: Response) => (await r.json()) as Reply;

const post = (
  app: ReturnType<typeof setup>["app"],
  path: string,
  body: unknown,
) =>
  app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

describe("subscriptions API", () => {
  const contacts: Contact[] = [
    { type: "email", to: "Me@Example.com" },
    { type: "telegram", chatId: "12345" },
    { type: "webhook", url: "https://hooks.example/fw" },
  ];

  it("subscribes with an EIP-191 signature and returns the webhook secret", async () => {
    const { app, store } = setup();
    const res = await post(
      app,
      "/v1/subscribe",
      await signed("subscribe", contacts),
    );
    expect(res.status).toBe(200);
    const body = await json(res);
    expect(body.subscribed).toBe(3);
    expect(body.webhookSecrets["https://hooks.example/fw"]).toBe(
      deriveWebhookSecret("master", owner.address, "https://hooks.example/fw"),
    );
    const saved = await store.subscriptionsFor(owner.address);
    expect(saved).toHaveLength(3);
    expect(saved).toContainEqual({ type: "email", to: "me@example.com" });
  });

  it("stores only account + contact (no other fields)", async () => {
    const { app, store } = setup();
    await post(
      app,
      "/v1/subscribe",
      await signed("subscribe", [contacts[0] as Contact]),
    );
    const saved = await store.subscriptionsFor(owner.address.toLowerCase());
    expect(Object.keys(saved[0] ?? {}).sort()).toEqual(["to", "type"]);
  });

  it("rejects a signature from another key", async () => {
    const { app } = setup();
    const res = await post(
      app,
      "/v1/subscribe",
      await signed("subscribe", contacts, { signer: stranger }),
    );
    expect(res.status).toBe(401);
  });

  it("rejects a signature for a different action or channel list", async () => {
    const { app } = setup();
    const req = await signed("unsubscribe", contacts);
    expect((await post(app, "/v1/subscribe", req)).status).toBe(401);
    const req2 = await signed("subscribe", contacts);
    expect(
      (
        await post(app, "/v1/subscribe", {
          ...req2,
          channels: [{ type: "email", to: "attacker@evil.example" }],
        })
      ).status,
    ).toBe(401);
  });

  it("rejects replays and stale requests", async () => {
    const { app } = setup();
    const req = await signed("subscribe", contacts, { nonce: "fixednonce1" });
    expect((await post(app, "/v1/subscribe", req)).status).toBe(200);
    const again = await post(app, "/v1/subscribe", req);
    expect(again.status).toBe(401);
    expect((await json(again)).error).toBe("nonce already used");
    const stale = await signed("subscribe", contacts, { issuedAt: NOW - 601 });
    expect((await post(app, "/v1/subscribe", stale)).status).toBe(401);
  });

  it("unsubscribes one contact or all", async () => {
    const { app, store } = setup();
    await post(app, "/v1/subscribe", await signed("subscribe", contacts));
    const one = await post(
      app,
      "/v1/unsubscribe",
      await signed("unsubscribe", [{ type: "telegram", chatId: "12345" }]),
    );
    expect((await json(one)).removed).toBe(1);
    const all = await post(
      app,
      "/v1/unsubscribe",
      await signed("unsubscribe", null),
    );
    expect((await json(all)).removed).toBe(2);
    expect(await store.subscriptionsFor(owner.address)).toHaveLength(0);
  });

  it("returns the message to sign", async () => {
    const { app } = setup();
    const res = await post(app, "/v1/message", {
      action: "subscribe",
      account: owner.address,
      channels: [{ type: "telegram", chatId: "1" }],
      issuedAt: NOW,
      nonce: "abcdefgh",
    });
    expect((await json(res)).message).toBe(
      `Session Firewall monitor: subscribe\nAccount: ${owner.address}\nChain ID: 84532\nChannels:\n- telegram:1\nIssued at: ${NOW}\nNonce: abcdefgh`,
    );
  });
});

describe("subscriptions API failure paths", () => {
  it("never echoes an RPC error, which can contain a keyed URL", async () => {
    const errors: unknown[] = [];
    const app = createApi({
      store: memoryStore(),
      chainId: 84532,
      now: () => NOW,
      onError: (e) => errors.push(e),
      verify: async () => {
        throw new Error("request to https://rpc.example/SECRET_KEY failed");
      },
    });
    const res = await post(
      app,
      "/v1/subscribe",
      await signed("subscribe", [{ type: "telegram", chatId: "1" }]),
    );
    expect(res.status).toBe(401);
    expect(await res.text()).not.toContain("SECRET_KEY");
    expect(errors).toHaveLength(1);
  });

  it("answers 500 without details when the store fails", async () => {
    const store = memoryStore();
    store.addSubscriptions = async () => {
      throw new Error("password authentication failed for neon_user");
    };
    const app = createApi({
      store,
      chainId: 84532,
      now: () => NOW,
      verify: async () => true,
    });
    const res = await post(
      app,
      "/v1/subscribe",
      await signed("subscribe", [{ type: "telegram", chatId: "1" }]),
    );
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "internal error" });
  });

  it("rejects a channel this deployment cannot deliver", async () => {
    const app = createApi({
      store: memoryStore(),
      chainId: 84532,
      now: () => NOW,
      enabledChannels: ["email"],
      verify: async () => true,
    });
    const res = await post(
      app,
      "/v1/subscribe",
      await signed("subscribe", [{ type: "telegram", chatId: "1" }]),
    );
    expect(res.status).toBe(400);
    expect((await json(res)).error).toBe(
      "telegram is not enabled on this monitor",
    );
  });

  it("handles a null body and an oversized body", async () => {
    const { app } = setup();
    expect((await post(app, "/v1/subscribe", null)).status).toBe(400);
    const big = await app.request("/v1/subscribe", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": "20000",
      },
      body: "x".repeat(20_000),
    });
    expect(big.status).toBe(413);
  });
});

describe("contact validation", () => {
  const strict = { allowInsecureWebhooks: false };
  it("rejects bad contacts", () => {
    expect(() => parseContacts([], strict)).toThrow();
    expect(() =>
      parseContacts([{ type: "email", to: "nope" }], strict),
    ).toThrow();
    expect(() =>
      parseContacts([{ type: "telegram", chatId: "@user" }], strict),
    ).toThrow();
    expect(() =>
      parseContacts([{ type: "webhook", url: "http://hooks.example" }], strict),
    ).toThrow(/https/);
    expect(() =>
      parseContacts([{ type: "webhook", url: "https://127.0.0.1/x" }], strict),
    ).toThrow(/public/);
    expect(() =>
      parseContacts([{ type: "webhook", url: "https://localhost/x" }], strict),
    ).toThrow(/public/);
    expect(() =>
      parseContacts(
        [{ type: "webhook", url: "https://u:p@hooks.example" }],
        strict,
      ),
    ).toThrow(/credentials/);
    expect(() =>
      parseContacts(Array(6).fill({ type: "telegram", chatId: "1" }), strict),
    ).toThrow();
  });
  it("allows local webhooks only when explicitly enabled", () => {
    expect(
      parseContacts([{ type: "webhook", url: "http://localhost:9000/x" }], {
        allowInsecureWebhooks: true,
      }),
    ).toEqual([{ type: "webhook", url: "http://localhost:9000/x" }]);
  });
});
