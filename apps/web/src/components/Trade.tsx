import { fill } from "@session-firewall/sdk";
import { useState } from "react";
import { formatPrice, formatShares, formatUsd, parseAmount } from "../lib/format";
import { allowMarket } from "../lib/onboard";
import { type Book, fillCost, pickLevel, worstCaseLoss } from "../lib/orderbook";
import { useApp } from "./context";
import { Button, Card, Field } from "./ui";

function BookTable(p: { book: Book; testId: string }) {
  const row = (kind: "Sell" | "Buy", price: bigint, remaining: bigint, key: string) => (
    <tr key={key} className="border-t border-slate-100">
      <td className={kind === "Sell" ? "py-1 text-red-700" : "py-1 text-green-700"}>
        {kind === "Sell" ? "Offered at" : "Wanted at"}
      </td>
      <td className="py-1 text-right font-mono">{formatPrice(price)}</td>
      <td className="py-1 text-right font-mono">{formatShares(remaining)}</td>
    </tr>
  );
  return (
    <table className="w-full text-sm" data-testid={p.testId}>
      <thead>
        <tr className="text-left text-xs text-slate-500">
          <th className="font-normal">Order</th>
          <th className="text-right font-normal">Price</th>
          <th className="text-right font-normal">Shares</th>
        </tr>
      </thead>
      <tbody>
        {[...p.book.asks].reverse().map((l) => row("Sell", l.price, l.remaining, l.hash))}
        {p.book.bids.map((l) => row("Buy", l.price, l.remaining, l.hash))}
      </tbody>
    </table>
  );
}

function Outcome(p: { name: "YES" | "NO"; book: Book; held: bigint }) {
  const { account, deployment, snap, run, busy } = useApp();
  const [amount, setAmount] = useState("100");
  const shares = parseAmount(amount);
  const session = snap?.sessions.find((s) => s.status === "active");
  const lower = p.name.toLowerCase();

  const buy = shares ? pickLevel(p.book, "buy", shares) : undefined;
  const sell = shares ? pickLevel(p.book, "sell", shares) : undefined;

  function trade(action: "buy" | "sell") {
    const level = action === "buy" ? buy : sell;
    if (!session || !level || !shares) return;
    void run(`${action === "buy" ? "Buy" : "Sell"} ${formatShares(shares)} ${p.name}`, () =>
      fill(account, session, { market: deployment.market.address, order: level.signed, amount: shares }),
    );
  }

  return (
    <Card title={`${p.name} shares`} testId={`outcome-${lower}`}>
      <p className="mb-2 text-sm">
        You hold <span className="font-semibold" data-testid={`held-${lower}`}>{formatShares(p.held)}</span>{" "}
        {p.name}. Each pays $1 if {p.name} wins.
      </p>
      <BookTable book={p.book} testId={`book-${lower}`} />
      <div className="mt-3 space-y-2">
        <Field label="Shares" value={amount} onChange={setAmount} testId={`amount-${lower}`} />
        <div className="text-xs text-slate-600">
          {buy && shares && (
            <div>
              Buying costs {formatUsd(fillCost(buy, shares, "buy"))}, uses{" "}
              {formatUsd(worstCaseLoss(buy, shares, "buy"))} of your hourly limit.
            </div>
          )}
          {sell && shares && (
            <div>
              Selling pays {formatUsd(fillCost(sell, shares, "sell"))}, uses{" "}
              {formatUsd(worstCaseLoss(sell, shares, "sell"))} of your hourly limit.
            </div>
          )}
        </div>
        <div className="flex gap-2">
          <Button onClick={() => trade("buy")} disabled={busy || !session || !buy} testId={`buy-${lower}`}>
            Buy
          </Button>
          <Button
            variant="secondary"
            onClick={() => trade("sell")}
            disabled={busy || !session || !sell || !shares || p.held < shares}
            testId={`sell-${lower}`}
          >
            Sell
          </Button>
        </div>
      </div>
    </Card>
  );
}

export function Trade() {
  const { deployment, snap, account, run, busy } = useApp();
  if (!snap) return <Card>Loading the market…</Card>;
  const session = snap.sessions.find((s) => s.status === "active");
  return (
    <div className="space-y-4">
      <Card title={deployment.market.question}>
        <p className="text-sm text-slate-600">
          Trades are signed by this device's session key with no prompts. The firewall checks every one.
        </p>
        {!session && (
          <p className="mt-2 rounded bg-amber-100 p-3 text-sm" data-testid="no-session">
            {snap.frozen
              ? "Trading is paused."
              : "No active trading session. Start one on the Sessions screen to trade."}
          </p>
        )}
        {snap.marketAllowance === 0n && (
          <div className="mt-2 flex items-center gap-3 rounded bg-amber-100 p-3 text-sm">
            <span>The market is not yet allowed to use your funds.</span>
            <Button
              disabled={busy}
              onClick={() => void run("Allow the market", () => allowMarket(account, deployment))}
            >
              Allow market
            </Button>
          </div>
        )}
      </Card>
      <div className="grid gap-4 md:grid-cols-2">
        <Outcome name="YES" book={snap.yesBook} held={snap.yes} />
        <Outcome name="NO" book={snap.noBook} held={snap.no} />
      </div>
    </div>
  );
}
