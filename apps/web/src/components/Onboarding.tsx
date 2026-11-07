import type {
  FirewallAccount,
  FirewallClientConfig,
} from "@session-firewall/sdk";
import { useState } from "react";
import { type Address, getAddress } from "viem";
import type { Deployment, RuntimeConfig } from "../lib/config";
import { explainError } from "../lib/errors";
import { formatUsd, parseAmount, shortHex } from "../lib/format";
import {
  allowMarket,
  deployAccount,
  localMintUsdc,
  validateOnboarding,
} from "../lib/onboard";
import { createPasskey, webAuthnSupported } from "../lib/passkey";
import type { NetworkSettings } from "../lib/settings";
import {
  type AccountRecord,
  loadPendingPasskey,
  saveAccount,
  savePendingPasskey,
} from "../lib/store";
import { Button, Card, Field } from "./ui";

export function Onboarding(p: {
  config: RuntimeConfig;
  deployment: Deployment;
  settings: NetworkSettings;
  makeClient: () => FirewallClientConfig;
  onDone: (record: AccountRecord) => void;
}) {
  const [passkey, setPasskey] = useState(() => loadPendingPasskey());
  const [destination, setDestination] = useState("");
  const [cap, setCap] = useState("1,000");
  const [step, setStep] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const capValue = parseAmount(cap);

  async function makePasskey() {
    setError("");
    setBusy(true);
    try {
      const k = await createPasskey("Session Firewall account");
      savePendingPasskey(k);
      setPasskey(k);
    } catch (e) {
      setError(explainError(e).message);
    } finally {
      setBusy(false);
    }
  }

  async function create() {
    const invalid = validateOnboarding(destination, capValue);
    if (invalid) {
      setError(invalid);
      return;
    }
    if (!passkey || !capValue) return;
    setError("");
    setBusy(true);
    try {
      const client = p.makeClient();
      const dest: Address = getAddress(destination.trim());
      const account: FirewallAccount = await deployAccount({
        config: p.config,
        deployment: p.deployment,
        client,
        passkey,
        destination: dest,
        hourlyCap: capValue,
        onStep: setStep,
      });
      const record: AccountRecord = {
        chainId: p.config.network.chainId,
        address: account.address,
        passkey,
        ownerValidator: p.deployment.addresses.ownerValidator,
        createdAt: Date.now(),
      };
      saveAccount(p.deployment.addresses.module, record);
      savePendingPasskey(undefined);
      setStep(
        "Confirm with your passkey once more to let the market use your funds…",
      );
      await allowMarket(account, p.deployment);
      if (p.config.local?.faucet) {
        setStep("Adding test USDC (local demo only)…");
        await localMintUsdc(
          p.config,
          p.settings,
          p.deployment,
          account.address,
        );
      }
      p.onDone(record);
    } catch (e) {
      setError(explainError(e).message);
    } finally {
      setStep("");
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-xl space-y-4">
      <Card title="Set up your trading account" testId="onboarding">
        <p className="mb-4 text-sm text-slate-700">
          Your account has limits written into the blockchain. They hold even if
          this website is hacked or goes away. You sign with a passkey on this
          device; we never see it and have no servers involved.
        </p>
        {!webAuthnSupported() && (
          <p className="mb-3 rounded bg-amber-100 p-3 text-sm">
            This browser cannot use passkeys here. Use a current browser over
            https or localhost.
          </p>
        )}
        <ol className="space-y-5">
          <li>
            <h3 className="mb-1 font-medium">1. Create your passkey</h3>
            {passkey ? (
              <p className="text-sm text-green-800" data-testid="passkey-ready">
                Passkey ready ({shortHex(passkey.publicKey)}).
              </p>
            ) : (
              <Button
                onClick={makePasskey}
                disabled={busy}
                testId="create-passkey"
              >
                Create passkey
              </Button>
            )}
          </li>
          <li className="space-y-3">
            <h3 className="font-medium">2. Choose your limits</h3>
            <Field
              label="Safe address to withdraw to"
              hint="The only place money can ever leave to. Use a wallet you control. Adding another later takes 24 hours."
              value={destination}
              onChange={setDestination}
              placeholder="0x…"
              testId="destination"
            />
            <Field
              label="Most this app can lose per hour (USD)"
              hint={
                capValue
                  ? `Trades stop once ${formatUsd(capValue)} is at risk within an hour.`
                  : undefined
              }
              value={cap}
              onChange={setCap}
              testId="hourly-cap"
            />
            <p className="text-sm text-slate-600">
              Market:{" "}
              <span className="font-medium">
                {p.deployment.market.question}
              </span>{" "}
              (the demo market)
            </p>
          </li>
          <li>
            <h3 className="mb-1 font-medium">3. Create the account</h3>
            <Button
              onClick={create}
              disabled={busy || !passkey}
              testId="create-account"
            >
              Create my account
            </Button>
          </li>
        </ol>
        {step && (
          <p
            className="mt-4 text-sm text-indigo-800"
            data-testid="onboarding-step"
          >
            {step}
          </p>
        )}
        {error && (
          <p
            className="mt-4 rounded bg-red-50 p-3 text-sm text-red-800"
            data-testid="onboarding-error"
          >
            {error}
          </p>
        )}
      </Card>
    </div>
  );
}
