import { createHash } from "node:crypto";
import type { Contact } from "./channels.ts";

/**
 * Worker state. Per the plan ("Data kept"), the only personal data is the subscription itself:
 * account address + contact channel. Delivery and nonce records are one-way hashes.
 */
export type Store = {
  init(): Promise<void>;
  addSubscriptions(account: string, contacts: Contact[]): Promise<void>;
  /** Removes the given contacts, or every contact of the account when `contacts` is null. */
  removeSubscriptions(
    account: string,
    contacts: Contact[] | null,
  ): Promise<number>;
  subscriptionsFor(account: string): Promise<Contact[]>;
  /** Dedupe: true when `key` was already delivered. */
  wasDelivered(key: string): Promise<boolean>;
  markDelivered(key: string, at: number): Promise<void>;
  getCursor(): Promise<bigint>;
  setCursor(block: bigint): Promise<void>;
  /** Replay protection for signed subscription requests: false when the nonce was already used. */
  useNonce(nonce: string, expiresAt: number): Promise<boolean>;
  /** Drops delivery and nonce records older than `before` (unix seconds). */
  prune(before: number): Promise<void>;
  close(): Promise<void>;
};

export const hashKey = (k: string) =>
  createHash("sha256").update(k).digest("hex");

export function contactFromRow(type: string, target: string): Contact | null {
  if (type === "email") return { type, to: target };
  if (type === "telegram") return { type, chatId: target };
  if (type === "webhook") return { type, url: target };
  return null;
}

export function contactTarget(c: Contact): string {
  return c.type === "email"
    ? c.to.toLowerCase()
    : c.type === "telegram"
      ? c.chatId
      : c.url;
}

export function memoryStore(): Store {
  const subs = new Map<string, Map<string, Contact>>();
  const delivered = new Map<string, number>();
  const nonces = new Map<string, number>();
  let cursor = 0n;
  const ck = (c: Contact) => `${c.type}:${contactTarget(c)}`;
  return {
    async init() {},
    async addSubscriptions(account, contacts) {
      const a = account.toLowerCase();
      const m = subs.get(a) ?? new Map<string, Contact>();
      for (const c of contacts) m.set(ck(c), c);
      subs.set(a, m);
    },
    async removeSubscriptions(account, contacts) {
      const a = account.toLowerCase();
      const m = subs.get(a);
      if (!m) return 0;
      if (contacts === null) {
        subs.delete(a);
        return m.size;
      }
      let n = 0;
      for (const c of contacts) if (m.delete(ck(c))) n++;
      return n;
    },
    async subscriptionsFor(account) {
      return [...(subs.get(account.toLowerCase())?.values() ?? [])];
    },
    async wasDelivered(key) {
      return delivered.has(hashKey(key));
    },
    async markDelivered(key, at) {
      delivered.set(hashKey(key), at);
    },
    async getCursor() {
      return cursor;
    },
    async setCursor(b) {
      cursor = b;
    },
    async useNonce(nonce, expiresAt) {
      const h = hashKey(nonce);
      if (nonces.has(h)) return false;
      nonces.set(h, expiresAt);
      return true;
    },
    async prune(before) {
      for (const [k, at] of delivered) if (at < before) delivered.delete(k);
      for (const [k, exp] of nonces) if (exp < before) nonces.delete(k);
    },
    async close() {},
  };
}
