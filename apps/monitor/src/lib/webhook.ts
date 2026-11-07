import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Signed webhooks.
 *
 * Every delivery is a POST with a JSON body and these headers:
 *
 *   Content-Type: application/json
 *   X-Firewall-Event-Id: <alert id, stable across retries; use it to dedupe>
 *   X-Firewall-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>
 *
 * Verify by recomputing the HMAC over the exact raw body bytes, comparing in constant time, and
 * rejecting timestamps outside the replay window (default 300 s). `verifyWebhookSignature` below does
 * all three. Several `v1=` entries may appear during secret rotation; any match is accepted.
 *
 * The secret for a subscription is derived, not stored: HMAC-SHA256(WEBHOOK_SIGNING_SECRET,
 * "webhook:" + account + ":" + url), returned once to the subscriber when they subscribe.
 */

export const SIGNATURE_HEADER = "X-Firewall-Signature";
export const EVENT_ID_HEADER = "X-Firewall-Event-Id";
export const DEFAULT_TOLERANCE_SECONDS = 300;

export function computeSignature(secret: string, timestamp: number, body: string): string {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

export function signWebhook(secret: string, body: string, timestamp = Math.floor(Date.now() / 1000)): string {
  return `t=${timestamp},v1=${computeSignature(secret, timestamp, body)}`;
}

export type VerifyResult = { ok: true; timestamp: number } | { ok: false; reason: string };

export function parseSignatureHeader(header: string): { t: number | null; v1: string[] } {
  let t: number | null = null;
  const v1: string[] = [];
  for (const part of header.split(",")) {
    const [k, v] = part.trim().split("=", 2);
    if (!k || v === undefined) continue;
    if (k === "t" && /^\d+$/.test(v)) t = Number(v);
    if (k === "v1" && /^[0-9a-f]{64}$/i.test(v)) v1.push(v.toLowerCase());
  }
  return { t, v1 };
}

/** Verification helper for webhook receivers. `body` must be the raw request body, unparsed. */
export function verifyWebhookSignature(p: {
  secret: string;
  header: string | null | undefined;
  body: string;
  toleranceSeconds?: number;
  now?: number;
}): VerifyResult {
  if (!p.header) return { ok: false, reason: "missing signature header" };
  const { t, v1 } = parseSignatureHeader(p.header);
  if (t === null) return { ok: false, reason: "missing timestamp" };
  if (v1.length === 0) return { ok: false, reason: "missing v1 signature" };
  const now = p.now ?? Math.floor(Date.now() / 1000);
  const tolerance = p.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  if (Math.abs(now - t) > tolerance) return { ok: false, reason: "timestamp outside replay window" };
  const expected = Buffer.from(computeSignature(p.secret, t, p.body), "hex");
  const match = v1.some((s) => {
    const got = Buffer.from(s, "hex");
    return got.length === expected.length && timingSafeEqual(got, expected);
  });
  return match ? { ok: true, timestamp: t } : { ok: false, reason: "signature mismatch" };
}

export function deriveWebhookSecret(masterSecret: string, account: string, url: string): string {
  return createHmac("sha256", masterSecret).update(`webhook:${account.toLowerCase()}:${url}`).digest("hex");
}
