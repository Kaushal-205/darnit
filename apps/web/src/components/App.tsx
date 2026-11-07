import { type FirewallAccount, getFirewallAccount } from "@session-firewall/sdk";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { explorerTx, makeClient } from "../lib/client";
import { type Deployment, type RuntimeConfig, loadRuntimeConfig } from "../lib/config";
import { explainError } from "../lib/errors";
import { formatUsd } from "../lib/format";
import { localMintUsdc } from "../lib/onboard";
import { passkeyOwnerFor } from "../lib/passkey";
import { type NetworkSettings, loadSettings } from "../lib/settings";
import { type Snapshot, loadSnapshot } from "../lib/snapshot";
import { type AccountRecord, loadAccount } from "../lib/store";
import { AttackPanel } from "./AttackPanel";
import { NetworkScreen } from "./NetworkScreen";
import { Onboarding } from "./Onboarding";
import { Sessions } from "./Sessions";
import { SettingsScreen } from "./SettingsScreen";
import { Trade } from "./Trade";
import { type AppCtx, Ctx } from "./context";
import { Button, Card, Hash, Stat } from "./ui";

const TABS = ["trade", "sessions", "settings", "network"] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = {
  trade: "Trade",
  sessions: "Sessions",
  settings: "Settings",
  network: "Network",
};

function tabFromHash(): Tab {
  const h = window.location.hash.replace(/^#\/?/, "") as Tab;
  return TABS.includes(h) ? h : "trade";
}

type Outcome = { ok: boolean; label: string; message: string; userOpHash?: string; transactionHash?: string };

function Header(p: {
  network?: string;
  attack: boolean;
  onAttack: (v: boolean) => void;
  canAttack: boolean;
}) {
  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-3 px-4 py-3">
        <div>
          <div className="text-lg font-bold">Session Firewall</div>
          <div className="text-xs text-slate-500">{p.network}</div>
        </div>
        {p.canAttack && (
          <label className="flex cursor-pointer items-center gap-2 text-sm font-medium text-red-800">
            <input
              type="checkbox"
              checked={p.attack}
              onChange={(e) => p.onAttack(e.target.checked)}
              data-testid="attack-toggle"
              className="h-4 w-4 accent-red-700"
            />
            Simulate compromised website
          </label>
        )}
      </div>
    </header>
  );
}

function Account(p: {
  config: RuntimeConfig;
  deployment: Deployment;
  settings: NetworkSettings;
  record: AccountRecord;
  attack: boolean;
  tab: Tab;
  setTab: (t: Tab) => void;
  onSettings: (s: NetworkSettings) => void;
}) {
  const { config, deployment, settings, record } = p;
  const [clientError, client] = useMemo(() => {
    try {
      return [undefined, makeClient(config, deployment, settings)] as const;
    } catch (e) {
      return [(e as Error).message, undefined] as const;
    }
  }, [config, deployment, settings]);
  const account: FirewallAccount | undefined = useMemo(
    () =>
      client &&
      getFirewallAccount(
        client,
        record.address,
        passkeyOwnerFor(record.passkey, deployment.addresses.ownerValidator),
      ),
    [client, record, deployment],
  );
  const [snap, setSnap] = useState<Snapshot>();
  const [readError, setReadError] = useState("");
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome>();
  // Ignore a slow poll that finishes after a newer read started.
  const readSeq = useRef(0);

  const refresh = useCallback(async () => {
    if (!account) return;
    const seq = ++readSeq.current;
    try {
      const s = await loadSnapshot(config, deployment, account);
      if (seq === readSeq.current) {
        setSnap(s);
        setReadError("");
      }
    } catch (e) {
      if (seq === readSeq.current) setReadError(explainError(e).message);
    }
  }, [account, config, deployment]);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 4000);
    return () => clearInterval(t);
  }, [refresh]);

  const run = useCallback<AppCtx["run"]>(
    async (label, fn) => {
      setBusy(true);
      setOutcome({ ok: true, label, message: "Working… confirm with your passkey if asked." });
      try {
        const r = await fn();
        setOutcome({
          ok: true,
          label,
          message: "Done.",
          userOpHash: r?.userOpHash,
          transactionHash: r?.transactionHash,
        });
        await refresh();
        return true;
      } catch (e) {
        const plain = explainError(e, {
          usdc: deployment.market.usdc,
          market: deployment.market.address,
          shares: deployment.market.shares,
          account: record.address,
        });
        setOutcome({
          ok: false,
          label,
          message: plain.message,
          userOpHash: plain.userOpHash,
          transactionHash: plain.transactionHash,
        });
        await refresh();
        return false;
      } finally {
        setBusy(false);
      }
    },
    [refresh, deployment, record],
  );

  const network = (
    <NetworkScreen config={config} settings={settings} onChange={p.onSettings} />
  );
  if (!client || !account) {
    return (
      <div className="space-y-4">
        <p className="rounded bg-amber-100 p-3 text-sm">{clientError}</p>
        {network}
      </div>
    );
  }

  const ctx: AppCtx = { config, deployment, settings, client, account, snap, refresh, busy, run };
  return (
    <Ctx.Provider value={ctx}>
      <div className="space-y-4">
        <Card testId="summary">
          <div className="mb-3 font-mono text-xs break-all" data-testid="account-address">
            {record.address}
          </div>
          <div className="grid gap-4 sm:grid-cols-4">
            <Stat label="USDC" value={snap ? formatUsd(snap.usdc) : "…"} testId="balance-usdc" />
            <Stat label="Left this hour" value={snap ? formatUsd(snap.budgetLeft) : "…"} testId="summary-budget" />
            <Stat
              label="Hourly limit"
              value={snap ? formatUsd(snap.hourlyCap) : "…"}
              testId="summary-cap"
            />
            <Stat label="Trading" value={snap ? (snap.frozen ? "Paused" : "On") : "…"} testId="summary-trading" />
          </div>
          {config.local?.faucet && (
            <div className="mt-3">
              <Button
                variant="secondary"
                disabled={busy}
                testId="faucet"
                onClick={() =>
                  void run("Add test USDC", () =>
                    localMintUsdc(config, settings, deployment, record.address).then(() => undefined),
                  )
                }
              >
                Add $10,000 test USDC (local demo)
              </Button>
            </div>
          )}
        </Card>

        {readError && (
          <p className="rounded bg-amber-100 p-3 text-sm" data-testid="read-error">
            {readError}
          </p>
        )}

        {outcome && (
          <div
            className={`rounded-lg p-3 text-sm ${outcome.ok ? "bg-indigo-50 text-indigo-950" : "bg-red-50 text-red-900"}`}
            data-testid={outcome.ok ? "outcome-ok" : "outcome-error"}
          >
            <span className="font-semibold">{outcome.label}:</span> {outcome.message}
            <Hash label="User operation" value={outcome.userOpHash} />
            <Hash
              label="Transaction"
              value={outcome.transactionHash}
              href={outcome.transactionHash ? explorerTx(config, outcome.transactionHash) : undefined}
            />
          </div>
        )}

        {p.attack && <AttackPanel />}

        <nav className="flex gap-1 border-b border-slate-200" aria-label="Screens">
          {TABS.map((t) => (
            <a
              key={t}
              href={`#/${t}`}
              data-testid={`tab-${t}`}
              className={`rounded-t-lg px-4 py-2 text-sm font-medium ${
                p.tab === t ? "border-b-2 border-indigo-700 text-indigo-800" : "text-slate-600"
              }`}
            >
              {TAB_LABEL[t]}
            </a>
          ))}
        </nav>
        {p.tab === "trade" && <Trade />}
        {p.tab === "sessions" && <Sessions />}
        {p.tab === "settings" && <SettingsScreen />}
        {p.tab === "network" && network}
      </div>
    </Ctx.Provider>
  );
}

export function App() {
  const [config, setConfig] = useState<RuntimeConfig>();
  const [settings, setSettings] = useState<NetworkSettings>();
  const [record, setRecord] = useState<AccountRecord>();
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("trade");
  const [attack, setAttack] = useState(false);

  useEffect(() => {
    loadRuntimeConfig()
      .then((c) => {
        setConfig(c);
        setSettings(loadSettings(c));
        if (c.deployment)
          setRecord(loadAccount(c.network.chainId, c.deployment.addresses.module));
      })
      .catch((e) => setError((e as Error).message));
    const onHash = () => setTab(tabFromHash());
    onHash();
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const deployment = config?.deployment ?? undefined;
  return (
    <div className="min-h-screen">
      <Header
        network={config?.network.name}
        attack={attack}
        onAttack={setAttack}
        canAttack={!!record}
      />
      <main className="mx-auto max-w-5xl space-y-4 px-4 py-6">
        {error && <p className="rounded bg-red-50 p-3 text-sm text-red-800">{error}</p>}
        {!config && !error && <p className="text-sm text-slate-600">Loading…</p>}
        {config && settings && !deployment && (
          <>
            <p className="rounded bg-amber-100 p-3 text-sm" data-testid="no-deployment">
              The firewall contracts are not deployed on {config.network.name} yet. Run the local demo
              (pnpm demo:web) to try the full app.
            </p>
            <NetworkScreen config={config} settings={settings} onChange={setSettings} />
          </>
        )}
        {config && settings && deployment && !record && (
          <Onboarding
            config={config}
            deployment={deployment}
            settings={settings}
            makeClient={() => makeClient(config, deployment, settings)}
            onDone={setRecord}
          />
        )}
        {config && settings && deployment && record && (
          <Account
            config={config}
            deployment={deployment}
            settings={settings}
            record={record}
            attack={attack}
            tab={tab}
            setTab={setTab}
            onSettings={setSettings}
          />
        )}
      </main>
    </div>
  );
}
