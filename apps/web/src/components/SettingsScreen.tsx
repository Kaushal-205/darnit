import {
  cancelChange,
  executeChange,
  exit,
  freeze,
  lowerCap,
  queueChange,
} from "@session-firewall/sdk";
import { useState } from "react";
import { type Address, getAddress, isAddress } from "viem";
import { formatDate, formatEta, formatUsd, parseAmount } from "../lib/format";
import { useApp } from "./context";
import { Button, Card, Field, Stat } from "./ui";

export function SettingsScreen() {
  const { account, deployment, snap, run, busy } = useApp();
  const [newCap, setNewCap] = useState("");
  const [raiseCap, setRaiseCap] = useState("");
  const [newDest, setNewDest] = useState("");
  const [exitAmount, setExitAmount] = useState("");
  const [exitTo, setExitTo] = useState("");
  if (!snap) return <Card>Loading your settings…</Card>;
  const lowered = parseAmount(newCap);
  const raised = parseAmount(raiseCap);
  const to = (exitTo || snap.destinations[0]) as Address | undefined;
  const exitValue = exitAmount ? parseAmount(exitAmount) : snap.usdc;

  return (
    <div className="space-y-4">
      <Card title="Your limits" testId="config">
        <div className="grid gap-4 sm:grid-cols-3">
          <Stat
            label="Hourly limit"
            value={formatUsd(snap.hourlyCap)}
            testId="config-cap"
          />
          <Stat
            label="Left this hour"
            value={formatUsd(snap.budgetLeft)}
            testId="budget-left"
          />
          <Stat
            label="Trading"
            value={snap.frozen ? "Paused" : "On"}
            testId="trading-state"
          />
        </div>
        <h3 className="mt-4 text-sm font-medium">Withdrawal addresses</h3>
        <ul className="font-mono text-xs break-all" data-testid="destinations">
          {snap.destinations.map((d) => (
            <li key={d}>{d}</li>
          ))}
        </ul>
        <h3 className="mt-3 text-sm font-medium">Markets</h3>
        <ul className="font-mono text-xs break-all">
          {snap.markets.map((m) => (
            <li key={m}>{m}</li>
          ))}
        </ul>
      </Card>

      <Card title="Move funds out" testId="exit">
        <p className="mb-3 text-sm text-slate-700">
          Sends USDC to a withdrawal address. This always works, even when
          paused or past your hourly limit.
        </p>
        <div className="space-y-3">
          <label className="block text-sm">
            <span className="font-medium">To</span>
            <select
              className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs"
              value={to}
              onChange={(e) => setExitTo(e.target.value)}
              data-testid="exit-to"
            >
              {snap.destinations.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
          </label>
          <Field
            label={`Amount in USDC (leave empty for everything: ${formatUsd(snap.usdc)})`}
            value={exitAmount}
            onChange={setExitAmount}
            testId="exit-amount"
          />
          <Button
            disabled={busy || !exitValue || !to}
            testId="exit-submit"
            onClick={() => {
              if (!exitValue || !to) return;
              void run("Move funds out", () =>
                exit(account, {
                  token: deployment.market.usdc,
                  amount: exitValue,
                  destination: to,
                }),
              );
            }}
          >
            Move funds out
          </Button>
        </div>
      </Card>

      <Card title="Tighten instantly" testId="tighten">
        <div className="space-y-3">
          <div>
            <p className="mb-2 text-sm text-slate-700">
              Pausing ends every session and stops trading right away.
              Withdrawals still work. Resuming takes 24 hours.
            </p>
            <Button
              variant="danger"
              disabled={busy || snap.frozen}
              testId="freeze"
              onClick={() => void run("Pause trading", () => freeze(account))}
            >
              Pause trading
            </Button>
          </div>
          <Field
            label="Lower the hourly limit to (USD)"
            value={newCap}
            onChange={setNewCap}
            testId="lower-cap-amount"
          />
          <Button
            variant="secondary"
            disabled={busy || !lowered}
            testId="lower-cap"
            onClick={() => {
              if (lowered)
                void run("Lower the hourly limit", () =>
                  lowerCap(account, lowered),
                );
            }}
          >
            Lower limit
          </Button>
        </div>
      </Card>

      <Card title="Loosen after 24 hours" testId="loosen">
        <p className="mb-3 text-sm text-slate-700">
          Anything that gives more power waits 24 hours, so you can cancel it if
          it was not you.
        </p>
        <div className="space-y-3">
          <Field
            label="Add a withdrawal address"
            value={newDest}
            onChange={setNewDest}
            placeholder="0x…"
            testId="queue-destination"
          />
          <Button
            variant="secondary"
            disabled={busy || !isAddress(newDest, { strict: false })}
            testId="queue-destination-submit"
            onClick={() =>
              void run("Queue new withdrawal address", async () => {
                const q = await queueChange(account, {
                  kind: "addDestination",
                  destination: getAddress(newDest),
                });
                return q.result;
              })
            }
          >
            Queue address
          </Button>
          <Field
            label="Raise the hourly limit to (USD)"
            value={raiseCap}
            onChange={setRaiseCap}
            testId="queue-cap"
          />
          <Button
            variant="secondary"
            disabled={busy || !raised}
            onClick={() => {
              if (raised)
                void run("Queue higher limit", async () => {
                  const q = await queueChange(account, {
                    kind: "raiseCap",
                    hourlyCap: raised,
                  });
                  return q.result;
                });
            }}
          >
            Queue limit
          </Button>
          {snap.frozen && (
            <div>
              <Button
                variant="secondary"
                disabled={busy}
                onClick={() =>
                  void run("Queue resume trading", async () => {
                    const q = await queueChange(account, { kind: "unfreeze" });
                    return q.result;
                  })
                }
              >
                Queue resume trading
              </Button>
            </div>
          )}
        </div>
      </Card>

      <Card title="Waiting changes" testId="pending">
        {!snap.pending.length && (
          <p className="text-sm text-slate-600">Nothing is waiting.</p>
        )}
        <ul className="divide-y divide-slate-100">
          {snap.pending.map((c) => (
            <li
              key={c.id}
              className="py-2 text-sm"
              data-testid="pending-change"
            >
              <div className="break-all">{c.description}</div>
              <div
                className="mb-2 text-xs text-slate-600"
                data-testid="pending-eta"
              >
                Can take effect {formatEta(c.eta, snap.now)} (
                {formatDate(c.eta)})
              </div>
              <div className="flex gap-2">
                <Button
                  variant="danger"
                  disabled={busy}
                  testId="cancel-change"
                  onClick={() =>
                    void run("Cancel change", () => cancelChange(account, c.id))
                  }
                >
                  Cancel
                </Button>
                {c.eta <= snap.now && (
                  <Button
                    variant="secondary"
                    disabled={busy}
                    onClick={() =>
                      void run("Apply change", () =>
                        executeChange(account, c.id),
                      )
                    }
                  >
                    Apply
                  </Button>
                )}
              </div>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
