import type { FirewallAccount, FirewallClientConfig, UserOpResult } from "@session-firewall/sdk";
import { createContext, useContext } from "react";
import type { Deployment, RuntimeConfig } from "../lib/config";
import type { NetworkSettings } from "../lib/settings";
import type { Snapshot } from "../lib/snapshot";

export type AppCtx = {
  config: RuntimeConfig;
  deployment: Deployment;
  settings: NetworkSettings;
  client: FirewallClientConfig;
  account: FirewallAccount;
  snap: Snapshot | undefined;
  refresh: () => Promise<void>;
  busy: boolean;
  /** Run an action; show its outcome (hash or plain-sentence error) and refresh. */
  run: (label: string, fn: () => Promise<UserOpResult | undefined | void>) => Promise<boolean>;
};

export const Ctx = createContext<AppCtx | null>(null);

export function useApp(): AppCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("App context missing");
  return c;
}
