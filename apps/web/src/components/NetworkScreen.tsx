import { useState } from "react";
import type { RuntimeConfig } from "../lib/config";
import {
  type NetworkSettings,
  defaultSettings,
  resetSettings,
  saveSettings,
  validateSettings,
} from "../lib/settings";
import { Button, Card, Field } from "./ui";

/** Works with no account and no deployment: changing the RPC must never depend on anything else. */
export function NetworkScreen(p: {
  config: RuntimeConfig;
  settings: NetworkSettings;
  onChange: (s: NetworkSettings) => void;
}) {
  const [draft, setDraft] = useState(p.settings);
  const [message, setMessage] = useState("");
  const errors = validateSettings(draft);
  const set = (k: keyof NetworkSettings) => (v: string) => {
    setDraft({ ...draft, [k]: v.trim() });
    setMessage("");
  };
  return (
    <Card title="Network" testId="network">
      <p className="mb-3 text-sm text-slate-700">
        This app talks directly to the blockchain, with no server of ours in between. Choose whose servers carry
        your requests. These providers can see your address and activity. Saved only in this browser.
      </p>
      <p className="mb-3 text-sm">
        Network: <span className="font-medium">{p.config.network.name}</span> (chain {p.config.network.chainId})
      </p>
      <div className="space-y-3">
        <Field label="RPC address" value={draft.rpcUrl} onChange={set("rpcUrl")} testId="rpc-url" />
        <Field
          label="Bundler address"
          hint={
            p.config.local
              ? "Optional in the local demo: when empty, a local test key submits your transactions."
              : "Submits your signed transactions. Needed to send anything."
          }
          value={draft.bundlerUrl}
          onChange={set("bundlerUrl")}
          testId="bundler-url"
        />
        <Field
          label="Paymaster address (optional)"
          hint="Pays network fees for you, if your provider offers it."
          value={draft.paymasterUrl}
          onChange={set("paymasterUrl")}
          testId="paymaster-url"
        />
      </div>
      {errors.map((e) => (
        <p key={e} className="mt-2 text-sm text-red-800">
          {e}
        </p>
      ))}
      <div className="mt-3 flex gap-2">
        <Button
          disabled={errors.length > 0}
          testId="save-network"
          onClick={() => {
            saveSettings(p.config, draft);
            p.onChange(draft);
            setMessage("Saved.");
          }}
        >
          Save
        </Button>
        <Button
          variant="secondary"
          onClick={() => {
            resetSettings(p.config);
            const d = defaultSettings(p.config);
            setDraft(d);
            p.onChange(d);
            setMessage("Back to the defaults.");
          }}
        >
          Use defaults
        </Button>
      </div>
      {message && (
        <p className="mt-2 text-sm text-green-800" data-testid="network-message">
          {message}
        </p>
      )}
    </Card>
  );
}
