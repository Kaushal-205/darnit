import { createSession, removeSession, revokeSessions } from "@session-firewall/sdk";
import { useState } from "react";
import { formatDate, formatRemaining, shortHex } from "../lib/format";
import { deleteSession, putSession } from "../lib/store";
import { useApp } from "./context";
import { Button, Card, Field } from "./ui";

export const MAX_SESSION_DAYS = 30;

const LABEL = { active: "Active", expired: "Expired", ended: "Ended", paused: "Paused" };

export function Sessions() {
  const { account, config, deployment, snap, run, busy } = useApp();
  const [days, setDays] = useState("7");
  const n = Number(days);
  const validDays = Number.isFinite(n) && n > 0 && n <= MAX_SESSION_DAYS;

  function create() {
    if (!snap || !validDays) return;
    void run("Start trading session", async () => {
      const { result, ...session } = await createSession(account, {
        expiresAt: Number(snap.now) + Math.floor(n * 86_400),
        markets: [deployment.market.address],
      });
      await putSession({
        ...session,
        chainId: config.network.chainId,
        epoch: snap.epoch.toString(),
        createdAt: Date.now(),
      });
      return result;
    });
  }

  return (
    <div className="space-y-4">
      <Card title="Start a trading session" testId="new-session">
        <p className="mb-3 text-sm text-slate-700">
          A session lets this device trade without a passkey prompt each time. Its key stays in this browser.
          Even if the key is stolen, it can only trade on your market within your hourly limit. It can never
          withdraw or change your settings.
        </p>
        <Field
          label={`Ends after how many days? (at most ${MAX_SESSION_DAYS})`}
          value={days}
          onChange={setDays}
          testId="session-days"
        />
        <div className="mt-3">
          <Button onClick={create} disabled={busy || !snap || !validDays || snap.frozen} testId="create-session">
            Start session
          </Button>
        </div>
      </Card>
      <Card title="Your sessions" testId="session-list">
        {!snap?.sessions.length && <p className="text-sm text-slate-600">No sessions yet.</p>}
        <ul className="divide-y divide-slate-100">
          {snap?.sessions.map((s) => (
            <li key={s.permissionId} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
              <div>
                <span className="font-semibold" data-testid="session-status">
                  {LABEL[s.status]}
                </span>{" "}
                <span className="font-mono text-xs">{shortHex(s.address)}</span>
                <div className="text-xs text-slate-600">
                  Ends {formatDate(s.validUntil)} ({formatRemaining(BigInt(s.validUntil), snap.now)})
                </div>
              </div>
              {s.status === "active" ? (
                <Button
                  variant="secondary"
                  disabled={busy}
                  testId="revoke-session"
                  onClick={() =>
                    void run("End session", async () => {
                      const r = await removeSession(account, s.permissionId);
                      await deleteSession(s.permissionId);
                      return r;
                    })
                  }
                >
                  End session
                </Button>
              ) : (
                <Button
                  variant="secondary"
                  disabled={busy}
                  onClick={() => void run("Delete session key", () => deleteSession(s.permissionId).then(() => undefined))}
                >
                  Delete key
                </Button>
              )}
            </li>
          ))}
        </ul>
        {!!snap?.sessions.some((s) => s.status === "active") && (
          <div className="mt-3">
            <Button
              variant="secondary"
              disabled={busy}
              testId="revoke-all"
              onClick={() => void run("End all sessions", () => revokeSessions(account))}
            >
              End all sessions
            </Button>
          </div>
        )}
      </Card>
    </div>
  );
}
