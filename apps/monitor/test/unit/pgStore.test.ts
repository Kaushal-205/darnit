import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Queryable, pgStore } from "../../worker/pgStore.ts";

// Runs the real SQL against PGlite, the Postgres build Ponder itself uses for local development.
const db = new PGlite();
const pool: Queryable = {
  async query<R extends Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ) {
    const r = await db.query<R>(sql, params as never);
    return { rows: r.rows, rowCount: r.affectedRows || r.rows.length };
  },
  end: async () => {},
};
const store = pgStore({ pool, schema: "monitor_test" });
const A = "0xAAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa";

describe("pgStore", () => {
  beforeAll(async () => {
    await store.init();
    await store.init(); // idempotent
  });
  afterAll(() => db.close());

  it("adds, lists and removes subscriptions, keyed on the lowercase account", async () => {
    await store.addSubscriptions(A, [
      { type: "email", to: "Me@Example.com" },
      { type: "telegram", chatId: "7" },
      { type: "webhook", url: "https://h.example/x" },
    ]);
    await store.addSubscriptions(A, [{ type: "telegram", chatId: "7" }]); // no duplicate
    const saved = await store.subscriptionsFor(A.toLowerCase());
    expect(saved).toHaveLength(3);
    expect(saved).toContainEqual({ type: "email", to: "me@example.com" });
    expect(
      await store.removeSubscriptions(A, [{ type: "telegram", chatId: "7" }]),
    ).toBe(1);
    expect(await store.removeSubscriptions(A, null)).toBe(2);
    expect(await store.subscriptionsFor(A)).toEqual([]);
  });

  it("stores only hashes for deliveries, so no contact detail is duplicated", async () => {
    const key = "change_queued:0xaa:0x1|email:me@example.com";
    expect(await store.wasDelivered(key)).toBe(false);
    await store.markDelivered(key, 100);
    await store.markDelivered(key, 100);
    expect(await store.wasDelivered(key)).toBe(true);
    const { rows } = await db.query<{ key: string }>(
      'SELECT key FROM "monitor_test"."delivery"',
    );
    expect(rows.map((r) => r.key).join()).not.toContain("example.com");
    await store.prune(101);
    expect(await store.wasDelivered(key)).toBe(false);
  });

  it("keeps the cursor and uses each nonce once", async () => {
    expect(await store.getCursor()).toBe(0n);
    await store.setCursor(40_000_000_000n);
    await store.setCursor(40_000_000_001n);
    expect(await store.getCursor()).toBe(40_000_000_001n);
    expect(await store.useNonce("a:n", 500)).toBe(true);
    expect(await store.useNonce("a:n", 500)).toBe(false);
    await store.prune(501);
    expect(await store.useNonce("a:n", 500)).toBe(true);
  });
});
