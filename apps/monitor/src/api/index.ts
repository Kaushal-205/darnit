import { db } from "ponder:api";
import schema from "ponder:schema";
import { Hono } from "hono";
import { asc, eq, gte, replaceBigInts } from "ponder";

// Read-only HTTP surface of the indexer, consumed by the alert worker (worker/dispatcher.ts, httpSource).
// Everything served here is public chain data; no contact details live in the indexer.
const app = new Hono();

app.get("/alerts", async (c) => {
  const raw = c.req.query("fromBlock") ?? "0";
  if (!/^\d{1,20}$/.test(raw)) return c.json({ error: "fromBlock must be a block number" }, 400);
  const fromBlock = BigInt(raw);
  const limit = Math.min(Number(c.req.query("limit") ?? "500") || 500, 1_000);
  const rows = await db
    .select()
    .from(schema.alert)
    .where(gte(schema.alert.blockNumber, fromBlock))
    .orderBy(asc(schema.alert.blockNumber), asc(schema.alert.logIndex), asc(schema.alert.id))
    .limit(limit);
  return c.json(replaceBigInts(rows, (v) => v.toString()));
});

app.get("/accounts/:address/changes", async (c) => {
  const address = c.req.param("address").toLowerCase() as `0x${string}`;
  if (!/^0x[0-9a-f]{40}$/.test(address)) return c.json({ error: "bad address" }, 400);
  const rows = await db.select().from(schema.change).where(eq(schema.change.account, address));
  return c.json(replaceBigInts(rows, (v) => v.toString()));
});

export default app;
