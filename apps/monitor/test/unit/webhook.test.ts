import { getAddress } from "viem";
import { describe, expect, it } from "vitest";
import { renderAlert } from "../../src/lib/rules.ts";
import {
  EVENT_ID_HEADER,
  SIGNATURE_HEADER,
  computeSignature,
  deriveWebhookSecret,
  signWebhook,
  verifyWebhookSignature,
} from "../../src/lib/webhook.ts";
import { webhookChannel } from "../../worker/channels.ts";

const SECRET = "whsec_test";
const BODY = '{"id":"a","type":"change_queued"}';
const T = 1_700_000_000;

describe("webhook signing", () => {
  it("uses t=<ts>,v1=<hmac-sha256 of ts.body>", () => {
    const h = signWebhook(SECRET, BODY, T);
    expect(h).toBe(`t=${T},v1=${computeSignature(SECRET, T, BODY)}`);
    // Known answer, from: printf '%s' '1700000000.<BODY>' | openssl dgst -sha256 -hmac whsec_test
    expect(computeSignature(SECRET, T, BODY)).toBe("2274ad5981328d7226b95236b7951dc48eeacf95b2647ff7b453cff46846dd22");
  });

  it("verifies a valid signature", () => {
    expect(verifyWebhookSignature({ secret: SECRET, header: signWebhook(SECRET, BODY, T), body: BODY, now: T + 10 })).toEqual({
      ok: true,
      timestamp: T,
    });
  });

  it("rejects a tampered body, a wrong secret and a missing header", () => {
    const h = signWebhook(SECRET, BODY, T);
    expect(verifyWebhookSignature({ secret: SECRET, header: h, body: `${BODY} `, now: T }).ok).toBe(false);
    expect(verifyWebhookSignature({ secret: "other", header: h, body: BODY, now: T }).ok).toBe(false);
    expect(verifyWebhookSignature({ secret: SECRET, header: undefined, body: BODY, now: T })).toEqual({
      ok: false,
      reason: "missing signature header",
    });
  });

  it("enforces the replay window in both directions", () => {
    const h = signWebhook(SECRET, BODY, T);
    expect(verifyWebhookSignature({ secret: SECRET, header: h, body: BODY, now: T + 300 }).ok).toBe(true);
    expect(verifyWebhookSignature({ secret: SECRET, header: h, body: BODY, now: T + 301 })).toEqual({
      ok: false,
      reason: "timestamp outside replay window",
    });
    expect(verifyWebhookSignature({ secret: SECRET, header: h, body: BODY, now: T - 301 }).ok).toBe(false);
    expect(verifyWebhookSignature({ secret: SECRET, header: h, body: BODY, now: T + 1_000, toleranceSeconds: 2_000 }).ok).toBe(true);
  });

  it("accepts any of several v1 entries (rotation) and ignores garbage", () => {
    const good = computeSignature(SECRET, T, BODY);
    const header = `t=${T}, v1=${"0".repeat(64)}, v0=zzz, v1=${good}`;
    expect(verifyWebhookSignature({ secret: SECRET, header, body: BODY, now: T }).ok).toBe(true);
    expect(verifyWebhookSignature({ secret: SECRET, header: `v1=${good}`, body: BODY, now: T }).ok).toBe(false);
    expect(verifyWebhookSignature({ secret: SECRET, header: `t=${T},v1=short`, body: BODY, now: T }).ok).toBe(false);
  });

  it("derives a stable per-subscription secret", () => {
    const a = deriveWebhookSecret("master", "0xAbC0000000000000000000000000000000000001", "https://h.example/x");
    expect(a).toBe(deriveWebhookSecret("master", "0xabc0000000000000000000000000000000000001", "https://h.example/x"));
    expect(a).not.toBe(deriveWebhookSecret("master", "0xabc0000000000000000000000000000000000001", "https://h.example/y"));
    expect(a).not.toBe(deriveWebhookSecret("master2", "0xabc0000000000000000000000000000000000001", "https://h.example/x"));
  });
});

describe("webhook channel", () => {
  it("posts a body the receiver can verify with the derived secret", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fakeFetch = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response("ok");
    }) as unknown as typeof fetch;
    const ch = webhookChannel({ masterSecret: "master", fetch: fakeFetch, now: () => T });
    const account = "0x00000000000000000000000000000000000000aa";
    const alert = renderAlert(
      {
        id: "evt:freeze",
        rule: "freeze",
        severity: "info",
        account,
        facts: {},
        blockNumber: 1n,
        logIndex: 0,
        occurredAt: 1n,
        expiresAt: 2n,
        txHash: "0x01",
      },
      "https://app.example",
    );
    await ch.send(account, { type: "webhook", url: "https://h.example/hook" }, alert);
    const call = calls[0];
    expect(call?.url).toBe("https://h.example/hook");
    const headers = call?.init.headers as Record<string, string>;
    expect(headers[EVENT_ID_HEADER]).toBe("evt:freeze");
    const secret = deriveWebhookSecret("master", account, "https://h.example/hook");
    const res = verifyWebhookSignature({ secret, header: headers[SIGNATURE_HEADER], body: String(call?.init.body), now: T });
    expect(res.ok).toBe(true);
    expect(JSON.parse(String(call?.init.body))).toMatchObject({ id: "evt:freeze", type: "freeze", account: getAddress(account) });
  });

  it("throws on non-2xx so the dispatcher retries", async () => {
    const ch = webhookChannel({
      masterSecret: "m",
      fetch: (async () => new Response("nope", { status: 500 })) as unknown as typeof fetch,
    });
    const alert = renderAlert(
      { id: "x", rule: "freeze", severity: "info", account: "0x00000000000000000000000000000000000000aa", facts: {}, blockNumber: 1n, logIndex: 0, occurredAt: 1n, expiresAt: 2n, txHash: "0x01" },
      "https://a",
    );
    await expect(ch.send("0x00000000000000000000000000000000000000aa", { type: "webhook", url: "https://h" }, alert)).rejects.toThrow(
      /HTTP 500/,
    );
  });
});
