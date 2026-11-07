import pg from "pg";
import type { Contact } from "./channels.ts";
import { type Store, contactFromRow, contactTarget, hashKey } from "./store.ts";

/**
 * Postgres store (Neon in production). Uses its own schema so it never collides with the tables
 * Ponder manages. Created on first start.
 */
export function pgStore(p: { connectionString: string; schema?: string }): Store {
  const schema = p.schema ?? "monitor_worker";
  if (!/^[a-z_][a-z0-9_]*$/.test(schema)) throw new Error("WORKER_DB_SCHEMA must be a lowercase identifier");
  const pool = new pg.Pool({ connectionString: p.connectionString, max: 5 });
  const t = (name: string) => `"${schema}"."${name}"`;

  return {
    async init() {
      await pool.query(`
        CREATE SCHEMA IF NOT EXISTS "${schema}";
        CREATE TABLE IF NOT EXISTS ${t("subscription")} (
          account text NOT NULL,
          type text NOT NULL,
          target text NOT NULL,
          PRIMARY KEY (account, type, target)
        );
        CREATE TABLE IF NOT EXISTS ${t("delivery")} (key text PRIMARY KEY, at bigint NOT NULL);
        CREATE TABLE IF NOT EXISTS ${t("nonce")} (key text PRIMARY KEY, expires_at bigint NOT NULL);
        CREATE TABLE IF NOT EXISTS ${t("cursor")} (id int PRIMARY KEY, block bigint NOT NULL);
      `);
    },
    async addSubscriptions(account, contacts) {
      for (const c of contacts) {
        await pool.query(
          `INSERT INTO ${t("subscription")} (account, type, target) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
          [account.toLowerCase(), c.type, contactTarget(c)],
        );
      }
    },
    async removeSubscriptions(account, contacts) {
      if (contacts === null) {
        const r = await pool.query(`DELETE FROM ${t("subscription")} WHERE account = $1`, [account.toLowerCase()]);
        return r.rowCount ?? 0;
      }
      let n = 0;
      for (const c of contacts) {
        const r = await pool.query(`DELETE FROM ${t("subscription")} WHERE account = $1 AND type = $2 AND target = $3`, [
          account.toLowerCase(),
          c.type,
          contactTarget(c),
        ]);
        n += r.rowCount ?? 0;
      }
      return n;
    },
    async subscriptionsFor(account) {
      const r = await pool.query<{ type: string; target: string }>(
        `SELECT type, target FROM ${t("subscription")} WHERE account = $1`,
        [account.toLowerCase()],
      );
      return r.rows.map((row) => contactFromRow(row.type, row.target)).filter((c): c is Contact => c !== null);
    },
    async wasDelivered(key) {
      const r = await pool.query(`SELECT 1 FROM ${t("delivery")} WHERE key = $1`, [hashKey(key)]);
      return (r.rowCount ?? 0) > 0;
    },
    async markDelivered(key, at) {
      await pool.query(`INSERT INTO ${t("delivery")} (key, at) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [hashKey(key), at]);
    },
    async getCursor() {
      const r = await pool.query<{ block: string }>(`SELECT block FROM ${t("cursor")} WHERE id = 1`);
      return r.rows[0] ? BigInt(r.rows[0].block) : 0n;
    },
    async setCursor(block) {
      await pool.query(
        `INSERT INTO ${t("cursor")} (id, block) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET block = EXCLUDED.block`,
        [block.toString()],
      );
    },
    async useNonce(nonce, expiresAt) {
      const r = await pool.query(`INSERT INTO ${t("nonce")} (key, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [
        hashKey(nonce),
        expiresAt,
      ]);
      return (r.rowCount ?? 0) === 1;
    },
    async prune(before) {
      await pool.query(`DELETE FROM ${t("delivery")} WHERE at < $1`, [before]);
      await pool.query(`DELETE FROM ${t("nonce")} WHERE expires_at < $1`, [before]);
    },
    async close() {
      await pool.end();
    },
  };
}
