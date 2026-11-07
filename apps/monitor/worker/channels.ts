import { type RenderedAlert, alertText } from "../src/lib/rules.ts";
import {
  EVENT_ID_HEADER,
  SIGNATURE_HEADER,
  deriveWebhookSecret,
  signWebhook,
} from "../src/lib/webhook.ts";

export type Contact =
  | { type: "email"; to: string }
  | { type: "telegram"; chatId: string }
  | { type: "webhook"; url: string };

export type ContactType = Contact["type"];

export function contactKey(c: Contact): string {
  switch (c.type) {
    case "email":
      return `email:${c.to.toLowerCase()}`;
    case "telegram":
      return `telegram:${c.chatId}`;
    case "webhook":
      return `webhook:${c.url}`;
  }
}

/** A delivery channel. `send` throws on failure so the dispatcher can retry. */
export type Channel = {
  type: ContactType;
  send(account: string, contact: Contact, alert: RenderedAlert): Promise<void>;
};

type Fetch = typeof fetch;

const SEVERITY_PREFIX: Record<RenderedAlert["severity"], string> = {
  critical: "[CRITICAL]",
  high: "[ACTION NEEDED]",
  warning: "[WARNING]",
  info: "[INFO]",
};

async function ensureOk(res: Response, what: string) {
  if (res.ok) return;
  const body = await res.text().catch(() => "");
  throw new Error(`${what} failed: HTTP ${res.status} ${body.slice(0, 200)}`);
}

// ------------------------------------------------------------------ email

export type EmailMessage = { to: string; subject: string; text: string };

/** Provider-agnostic email interface; swap the implementation without touching the dispatcher. */
export type EmailProvider = {
  name: string;
  send(msg: EmailMessage): Promise<void>;
};

/** Resend (https://resend.com/docs/api-reference/emails/send-email). Key: EMAIL_API_KEY. */
export function resendProvider(p: {
  apiKey: string;
  from: string;
  fetch?: Fetch;
  endpoint?: string;
}): EmailProvider {
  const f = p.fetch ?? fetch;
  return {
    name: "resend",
    async send(msg) {
      const res = await f(p.endpoint ?? "https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${p.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: p.from,
          to: [msg.to],
          subject: msg.subject,
          text: msg.text,
        }),
        signal: AbortSignal.timeout(10_000),
      });
      await ensureOk(res, "resend");
    },
  };
}

export function emailChannel(provider: EmailProvider): Channel {
  return {
    type: "email",
    async send(_account, contact, alert) {
      if (contact.type !== "email")
        throw new Error("email channel got a non-email contact");
      await provider.send({
        to: contact.to,
        subject: `${SEVERITY_PREFIX[alert.severity]} ${alert.title}`,
        text: alertText(alert),
      });
    },
  };
}

// ------------------------------------------------------------------ telegram

/** Telegram Bot API sendMessage. The user starts a chat with the bot and subscribes with its chat id. */
export function telegramChannel(p: {
  botToken: string;
  fetch?: Fetch;
  apiBase?: string;
}): Channel {
  const f = p.fetch ?? fetch;
  return {
    type: "telegram",
    async send(_account, contact, alert) {
      if (contact.type !== "telegram")
        throw new Error("telegram channel got a non-telegram contact");
      const res = await f(
        `${p.apiBase ?? "https://api.telegram.org"}/bot${p.botToken}/sendMessage`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          // Plain text (no parse_mode) so addresses and URLs never need escaping.
          body: JSON.stringify({
            chat_id: contact.chatId,
            text: `${SEVERITY_PREFIX[alert.severity]} ${alertText(alert)}`,
            disable_web_page_preview: true,
          }),
          signal: AbortSignal.timeout(10_000),
        },
      );
      await ensureOk(res, "telegram");
    },
  };
}

// ------------------------------------------------------------------ signed webhooks

export function webhookPayload(alert: RenderedAlert) {
  return {
    id: alert.id,
    type: alert.rule,
    severity: alert.severity,
    account: alert.account,
    title: alert.title,
    lines: alert.lines,
    links: alert.links,
    occurredAt: alert.occurredAt,
    txHash: alert.txHash,
    facts: alert.facts,
  };
}

export function webhookChannel(p: {
  masterSecret: string;
  fetch?: Fetch;
  now?: () => number;
}): Channel {
  const f = p.fetch ?? fetch;
  return {
    type: "webhook",
    async send(account, contact, alert) {
      if (contact.type !== "webhook")
        throw new Error("webhook channel got a non-webhook contact");
      const body = JSON.stringify(webhookPayload(alert));
      const secret = deriveWebhookSecret(p.masterSecret, account, contact.url);
      const ts = p.now ? p.now() : Math.floor(Date.now() / 1000);
      const res = await f(contact.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [SIGNATURE_HEADER]: signWebhook(secret, body, ts),
          [EVENT_ID_HEADER]: alert.id,
        },
        body,
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      await ensureOk(res, "webhook");
    },
  };
}

// ------------------------------------------------------------------ test double

export type FakeDelivery = {
  at: number;
  account: string;
  contact: Contact;
  alert: RenderedAlert;
};

export function fakeChannel(
  type: ContactType,
  opts: { failTimes?: number } = {},
) {
  const deliveries: FakeDelivery[] = [];
  let failures = opts.failTimes ?? 0;
  const channel: Channel = {
    type,
    async send(account, contact, alert) {
      if (failures > 0) {
        failures--;
        throw new Error("fake failure");
      }
      deliveries.push({ at: Date.now(), account, contact, alert });
    },
  };
  return { channel, deliveries };
}
