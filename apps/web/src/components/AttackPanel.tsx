import { useState } from "react";
import {
  ATTACKER,
  type Attempt,
  type FundsSnapshot,
  fundsUnchanged,
  initialAttempts,
  runCompromisedScript,
  snapshotFunds,
} from "../attack/compromised";
import { explorerTx } from "../lib/client";
import { explainError } from "../lib/errors";
import { formatShares, formatUsd } from "../lib/format";
import { useApp } from "./context";
import { Button, Card, Hash } from "./ui";

const BADGE: Record<Attempt["status"], { text: string; cls: string }> = {
  pending: { text: "Waiting", cls: "bg-slate-100 text-slate-700" },
  running: { text: "Trying…", cls: "bg-amber-100 text-amber-900" },
  blocked: { text: "Blocked", cls: "bg-green-100 text-green-900" },
  "not-blocked": { text: "NOT BLOCKED", cls: "bg-red-700 text-white" },
  "not-signed": {
    text: "You refused to sign",
    cls: "bg-green-100 text-green-900",
  },
  error: { text: "Could not run", cls: "bg-amber-100 text-amber-900" },
};

function Funds(p: { label: string; s: FundsSnapshot; testId: string }) {
  return (
    <div className="text-sm" data-testid={p.testId}>
      <div className="font-medium">{p.label}</div>
      Your account: {formatUsd(p.s.accountUsdc)} USDC,{" "}
      {formatShares(p.s.accountYes)} YES, {formatShares(p.s.accountNo)} NO
      <br />
      Attacker: {formatUsd(p.s.attackerUsdc)} USDC,{" "}
      {formatShares(p.s.attackerYes)} YES, {formatShares(p.s.attackerNo)} NO
    </div>
  );
}

export function AttackPanel() {
  const { account, config, deployment, refresh } = useApp();
  const [attempts, setAttempts] = useState<Attempt[]>(initialAttempts);
  const [running, setRunning] = useState(false);
  const [before, setBefore] = useState<FundsSnapshot>();
  const [after, setAfter] = useState<FundsSnapshot>();
  const [error, setError] = useState("");

  async function start() {
    const ctx = { account, market: { ...deployment.market } };
    setRunning(true);
    setError("");
    setAfter(undefined);
    setAttempts(initialAttempts());
    try {
      setBefore(await snapshotFunds(ctx));
      await runCompromisedScript(ctx, (a) =>
        setAttempts((list) => list.map((x) => (x.id === a.id ? a : x))),
      );
      setAfter(await snapshotFunds(ctx));
      await refresh();
    } catch (e) {
      setError(explainError(e).message);
    } finally {
      setRunning(false);
    }
  }

  const finished = !!after && !running;
  const safe = finished && before && after && fundsUnchanged(before, after);
  return (
    <div
      className="rounded-xl border-2 border-red-600 bg-red-50 p-1"
      data-testid="attack-panel"
    >
      <Card title="Simulated attack: this website has been compromised">
        <p className="mb-3 text-sm text-slate-700">
          This runs a script playing an attacker who has taken over this
          website. It reads your session key from this browser, signs real
          transactions and even asks your passkey to sign one. Your account's
          rules on the blockchain are the only thing in its way. Attacker's
          address:{" "}
          <span className="font-mono text-xs break-all">{ATTACKER}</span>
        </p>
        <Button
          variant="danger"
          onClick={start}
          disabled={running}
          testId="run-attack"
        >
          {running ? "Attack running…" : "Run the malicious script"}
        </Button>
        {error && (
          <p
            className="mt-3 rounded bg-amber-100 p-3 text-sm"
            data-testid="attack-error"
          >
            {error}
          </p>
        )}
        <ul className="mt-4 space-y-3">
          {attempts.map((a) => (
            <li
              key={a.id}
              className="rounded-lg border border-slate-200 p-3"
              data-testid={`attempt-${a.id}`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-medium">
                  {a.title}{" "}
                  <span className="font-normal text-slate-500">
                    (signed with {a.signer})
                  </span>
                </div>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-semibold ${BADGE[a.status].cls}`}
                  data-testid={`attempt-${a.id}-status`}
                  data-status={a.status}
                >
                  {BADGE[a.status].text}
                </span>
              </div>
              {a.message && (
                <p
                  className="mt-1 text-sm"
                  data-testid={`attempt-${a.id}-message`}
                >
                  {a.message}
                </p>
              )}
              {a.code && (
                <div className="mt-1 text-xs text-slate-500">
                  Rule: {a.rule} ({a.code})
                </div>
              )}
              {a.status === "blocked" && !a.mined && (
                <div className="text-xs text-slate-500">
                  Refused at the signature check, so no transaction exists.
                </div>
              )}
              <Hash label="User operation" value={a.userOpHash} />
              <Hash
                label="Reverted transaction"
                value={a.transactionHash}
                href={
                  a.transactionHash
                    ? explorerTx(config, a.transactionHash)
                    : undefined
                }
              />
            </li>
          ))}
        </ul>
        {before && after && (
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <Funds label="Before" s={before} testId="funds-before" />
            <Funds label="After" s={after} testId="funds-after" />
          </div>
        )}
        {finished && (
          <p
            className={`mt-3 rounded p-3 text-sm font-semibold ${safe ? "bg-green-100 text-green-900" : "bg-red-700 text-white"}`}
            data-testid="attack-verdict"
          >
            {safe
              ? "Your funds are unchanged and the attacker got nothing. Your only cost is a little ETH in network fees for the failed attempts."
              : "Funds changed during the attack. Check the results above."}
          </p>
        )}
      </Card>
    </div>
  );
}
